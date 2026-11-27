// Ryder control bot - Cloudflare Worker (Discord Interactions over HTTP, no always-on server needed)
//
//   POST /        Discord interactions: /start /stop /status /logs /history /help /exec + buttons
//   POST /event   session events sent by main.yml (signed with HMAC), rendered here and posted to the notify channel
//   GET  /        health check
//
// Only the owner (OWNER_ID) in the configured server (GUILD_ID) can use the commands.
// All message design lives in ui.mjs (Components V2, with an automatic classic-embed fallback).
//
// Settings (bot/wrangler.toml [vars]):
//   PUBLIC_REPLIES  "true" (default): command replies are visible to everyone in the channel; "false": only you see them
//   UI_MODE         "v2" (default): Components V2 cards; "classic": plain embeds

import {
  SESSION_LIMIT_MIN,
  FLAG_EPHEMERAL,
  bar,
  button,
  link,
  code,
  ts,
  fmtDuration,
  presetLabel,
  yesNo,
  statusAr,
  render,
  uiMode,
  postWebhook,
  eventSpec,
  auditSpec,
} from './ui.mjs';

const DISCORD_API = 'https://discord.com/api/v10';
const GH_API = 'https://api.github.com';
const ACTIVE = new Set(['queued', 'in_progress', 'waiting', 'requested', 'pending']);
const enc = new TextEncoder();

// ------------------------------------------------------------------ small helpers
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
const isPublic = (env) => String(env.PUBLIC_REPLIES ?? 'true').toLowerCase() !== 'false';
const deferred = (env) => json(isPublic(env) ? { type: 5 } : { type: 5, data: { flags: FLAG_EPHEMERAL } });
const deferredUpdate = () => json({ type: 6 });
const newId = () => crypto.randomUUID().slice(0, 8);

// refusals are always private, even when normal replies are public
function privateCard(env, spec) {
  const p = render(spec, uiMode(env));
  return json({ type: 4, data: { ...p, flags: (p.flags || 0) | FLAG_EPHEMERAL } });
}

function hexToBytes(hex) {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2) throw new Error('bad hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function b64(str) {
  const bytes = enc.encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// ------------------------------------------------------------------ signature checks
async function importKey(publicKeyHex) {
  const raw = hexToBytes(publicKeyHex);
  try {
    return await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
  } catch {
    // older Workers runtimes
    return await crypto.subtle.importKey('raw', raw, { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' }, false, ['verify']);
  }
}

// Discord -> Worker (Ed25519)
async function verifySignature(request, rawBody, publicKeyHex) {
  const sig = request.headers.get('x-signature-ed25519');
  const ts_ = request.headers.get('x-signature-timestamp');
  if (!sig || !ts_ || !publicKeyHex) return false;
  if (Math.abs(Date.now() / 1000 - Number(ts_)) > 300) return false; // replay protection (5 min)
  try {
    const key = await importKey(publicKeyHex);
    return await crypto.subtle.verify(key.algorithm.name, key, hexToBytes(sig), enc.encode(ts_ + rawBody));
  } catch {
    return false;
  }
}

// main.yml -> Worker (HMAC-SHA256 keyed with the notify webhook URL, which only the repo and the Worker know)
async function verifyHmac(secret, tsHeader, rawBody, sigHex) {
  if (!secret || !tsHeader || !sigHex) return false;
  if (Math.abs(Date.now() / 1000 - Number(tsHeader)) > 300) return false;
  try {
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    return await crypto.subtle.verify('HMAC', key, hexToBytes(sigHex), enc.encode(`${tsHeader}.${rawBody}`));
  } catch {
    return false;
  }
}

// ------------------------------------------------------------------ GitHub API
class GhError extends Error {
  constructor(status, body) {
    super(`GitHub ${status}`);
    this.status = status;
    this.body = String(body).slice(0, 300);
  }
}

function gh(env, path, { method = 'GET', body, token, manualRedirect = false } = {}) {
  return fetch(`${GH_API}${path}`, {
    method,
    redirect: manualRedirect ? 'manual' : 'follow',
    headers: {
      Authorization: `Bearer ${token || env.GH_BOT_PAT}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'ryder-bot',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function ghJson(env, path, opts) {
  const res = await gh(env, path, opts);
  if (res.status === 204) return null;
  if (!res.ok) throw new GhError(res.status, await res.text());
  return res.json();
}

const wfPath = (env) => `/repos/${env.REPO}/actions/workflows/${env.WORKFLOW}`;
const listRuns = async (env, perPage = 8) => (await ghJson(env, `${wfPath(env)}/runs?per_page=${perPage}`)).workflow_runs || [];
const activeRuns = async (env) => (await listRuns(env, 10)).filter((r) => ACTIVE.has(r.status));

// ------------------------------------------------------------------ errors
function explain(e) {
  if (e instanceof GhError) {
    if (e.status === 401) return { cause: 'توكن GH_BOT_PAT منتهي الصلاحية أو غير صحيح.', fix: `أنشئ توكناً جديداً، وحدّث السر ${code('GH_BOT_PAT')} في المستودع، ثم أعد نشر البوت.` };
    if (e.status === 403) return { cause: 'التوكن لا يملك الصلاحية الكافية.', fix: `امنحه الصلاحية ${code('Actions: Read and write')} على مستودع Ryder.` };
    if (e.status === 404) return { cause: 'تعذّر العثور على المستودع أو الـ workflow، أو أن التوكن لا يصل إليهما.', fix: `راجع القيمتين ${code('REPO')} و${code('WORKFLOW')} في ملف bot/wrangler.toml وصلاحيات التوكن.` };
    if (e.status === 422) return { cause: 'رفض GitHub المدخلات المرسلة.', fix: `غالباً أن ملف main.yml المرفوع لا يحتوي المدخلات (inputs) الجديدة. ارفع آخر نسخة منه.` };
    return { cause: `ردّ GitHub بخطأ (${e.status}).`, fix: 'أعد المحاولة بعد قليل، وإن تكرر الأمر فراجع سجل Cloudflare Workers.' };
  }
  return { cause: 'حدث خطأ غير متوقع داخل البوت.', fix: 'أعد المحاولة، وإن تكرر الأمر فابحث عن معرّف الخطأ في سجل Cloudflare Workers.' };
}

const errorSpec = (e, errorId) => ({
  kind: 'err',
  title: '❌ تعذّر تنفيذ الأمر',
  lead: explain(e).cause,
  sections: [{ heading: 'الحل المقترح', text: explain(e).fix }],
  footer: `Ryder · معرّف الخطأ ${errorId}`,
  compact: true,
});

const noteSpec = (kind, title, lead, extra = {}) => ({ kind, title, lead, compact: true, ...extra });

// ------------------------------------------------------------------ logging (console JSON + Discord log channel)
async function audit(env, entry) {
  const { detail, ...forConsole } = entry; // free-text details (e.g. the /exec command) go to the log channel only
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...forConsole }));
  if (!env.DISCORD_LOG_WEBHOOK) return;
  try {
    await postWebhook(env.DISCORD_LOG_WEBHOOK, auditSpec(entry), { mode: uiMode(env), username: 'Ryder Log' });
  } catch (e) {
    console.error(JSON.stringify({ level: 'error', msg: 'log webhook failed', err: String(e) }));
  }
}

// ------------------------------------------------------------------ log text cleaning
function sanitizeLog(text) {
  return text
    .replace(/\x1b\[[0-9;]*m/g, '')
    .replace(/^\d{4}-\d\d-\d\dT[\d:.]+Z /gm, '')
    .replace(/^##\[(group|endgroup)\].*$/gm, '')
    .replace(/https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\S+/g, '[webhook]')
    .replace(/tskey-[A-Za-z0-9-]+/g, '[tskey]')
    .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/g, '[token]')
    .replace(/github_pat_[A-Za-z0-9_]{20,}/g, '[token]')
    .replace(/[MN][A-Za-z\d_-]{23,}\.[\w-]{6}\.[\w-]{27,}/g, '[bot-token]')
    .replace(/\n{3,}/g, '\n\n');
}

// ------------------------------------------------------------------ session helpers
const PHASES = [
  ['Configure Core RDP', 'ضبط RDP'],
  ['Create RDP User', 'إنشاء المستخدم'],
  ['Tune display', 'ضبط الأداء'],
  ['Write helper', 'تجهيز الأدوات'],
  ['Provision', 'تثبيت البرامج'],
  ['Restore files', 'استرجاع الملفات'],
  ['Install Tailscale', 'تثبيت Tailscale'],
  ['Establish Tailscale', 'اتصال Tailscale'],
  ['Verify RDP', 'فحص RDP'],
  ['Announce', 'إرسال إشعار الجاهزية'],
];
const PROGRESS_TOTAL = PHASES.length + 1; // +1 = "ready for connection"
const stepAr = (name = '') => (PHASES.find(([k]) => name.includes(k)) || [null, name])[1];

const mdLink = (r) => `[#${r.run_number}](${r.html_url})`;
const runDuration = (r) => Date.parse(r.updated_at) - Date.parse(r.run_started_at || r.created_at);

function outcome(r) {
  if (r.status !== 'completed') return '⏳ جارية';
  if (r.conclusion === 'success') return '✅ اكتملت';
  if (r.conclusion === 'failure') return '❌ انتهت بخطأ';
  if (r.conclusion === 'cancelled') return '⏹️ أُلغيت';
  return `⚪ ${r.conclusion || r.status}`;
}

async function describeRun(env, run) {
  const jobs = await ghJson(env, `/repos/${env.REPO}/actions/runs/${run.id}/jobs`);
  const job = jobs.jobs?.[0];
  const steps = job?.steps || [];
  const stepOf = (key) => steps.find((s) => s.name.includes(key));
  const ready = stepOf('Maintain')?.status === 'in_progress';
  const cur = steps.find((s) => s.status === 'in_progress');
  const queued = !job || job.status === 'queued';
  const done = ready ? PROGRESS_TOTAL : PHASES.filter(([k]) => stepOf(k)?.status === 'completed').length;
  const startMs = Date.parse(job?.started_at || run.run_started_at || run.created_at);
  return {
    ready,
    done,
    phase: queued ? 'بالانتظار على GitHub' : ready ? 'جاهزة للاتصال' : cur ? stepAr(cur.name) : 'جارٍ التجهيز',
    startMs,
    elapsed: Date.now() - startMs,
    endMs: startMs + SESSION_LIMIT_MIN * 60000,
  };
}

function idleSpec(env, last) {
  const quick = button('تشغيل جلسة جديدة', 'start:quick', 3, '▶️');
  if (!last) {
    return { kind: 'idle', title: '⚪ لا توجد جلسة جارية', lead: 'لا توجد جلسات سابقة بعد. ابدأ بتشغيل أول جلسة.', buttons: [quick] };
  }
  return {
    kind: 'idle',
    title: '⚪ لا توجد جلسة جارية',
    lead: `آخر جلسة كانت ${mdLink(last)}، وقد ${outcome(last).replace(/^\S+\s/, '')} ${ts(Date.parse(last.updated_at))}.`,
    sections: [
      {
        heading: 'آخر جلسة',
        facts: [
          ['الرقم', mdLink(last)],
          ['النتيجة', outcome(last)],
          ['المدة', fmtDuration(runDuration(last))],
          ['انتهت', ts(Date.parse(last.updated_at))],
        ],
      },
    ],
    buttons: [quick, link('سجل آخر جلسة', last.html_url, '📄')],
  };
}

// ------------------------------------------------------------------ commands (each returns a message spec; ui.mjs renders it)
const COMMANDS = {
  async help() {
    return {
      kind: 'info',
      title: '🧭 دليل أوامر YjaRdp',
      subtitle: 'لوحة التحكم بجلسات سطح المكتب البعيد',
      lead: 'تدير هذه الأوامر جلسة Windows البعيدة العاملة عبر GitHub Actions وTailscale. الاستخدام مقصور على مالك الخادم.',
      sections: [
        {
          heading: 'إدارة الجلسة',
          items: [
            `${code('/start')} يُطلق جلسة جديدة بالإعداد الذي تختاره، مع تجديد تلقائي قبل بلوغ حدّ الست ساعات.`,
            `${code('/stop')} يُنهي الجلسات الجارية بعد طلب تأكيد صريح.`,
            `${code('/status')} يعرض حالة الجلسة ومراحل التجهيز والوقت المتبقي، مع زر تحديث فوري.`,
          ],
        },
        {
          heading: 'المتابعة والتدقيق',
          items: [`${code('/logs')} يعرض أحدث أسطر السجل بعد حجب الأسرار تلقائياً.`, `${code('/history')} يلخّص آخر الجلسات ونتائجها وإحصاءاتها.`],
        },
        { heading: 'متقدّم', items: [`${code('/exec')} ينفّذ أمراً داخل الجلسة، وهو معطَّل افتراضياً لأسباب أمنية.`] },
        {
          heading: 'نصائح',
          items: ['تصلك رسالة «الجلسة جاهزة» في قناة ryder-notify فور اكتمال التجهيز.', 'تُحجب المفاتيح والتوكنات من أي سجل يعرضه البوت.', 'استخدم زر «تشغيل سريع» للبدء بالإعدادات الافتراضية دون كتابة أي خيار.'],
        },
      ],
      buttons: [button('حالة الجلسة', 'status:refresh', 2, '📡'), button('تشغيل سريع', 'start:quick', 3, '▶️')],
    };
  },

  async start(i, env, o = {}) {
    const active = await activeRuns(env);
    if (active.length) {
      return noteSpec('warn', '⚠️ توجد جلسة جارية بالفعل', `الجلسة ${mdLink(active[0])} حالتها: ${statusAr(active[0].status)}.`, {
        sections: [{ heading: 'الخيارات المتاحة', items: [`تابع حالتها بالأمر ${code('/status')}.`, `أو أوقفها بالأمر ${code('/stop')} ثم أطلق جلسة جديدة.`] }],
        buttons: [button('حالة الجلسة', 'status:refresh', 2, '📡'), link('فتح السجل', active[0].html_url, '📄')],
      });
    }
    const extra = (o.extra_tools || '').trim();
    if (extra && !/^[a-z0-9][a-z0-9.,\s-]{0,198}$/i.test(extra)) {
      return noteSpec('err', '❌ أسماء الحزم غير صالحة', `استخدم أسماء حزم Chocolatey مفصولة بفاصلة فقط، مثل: ${code('nmap,7zip')}.`);
    }
    const execAllowed = env.ENABLE_EXEC === 'true';
    const inputs = {
      preset: o.preset || 'minimal',
      install_vscode: String(o.vscode ?? true),
      install_discord: String(o.discord ?? true),
      extra_tools: extra,
      auto_renew: String(o.auto_renew ?? true),
      max_renewals: String(o.max_renewals ?? 8),
      remote_exec: String(execAllowed && (o.remote_exec ?? false)),
      renew_count: '0',
    };
    const res = await gh(env, `${wfPath(env)}/dispatches`, { method: 'POST', body: { ref: env.REF || 'main', inputs } });
    if (res.status !== 204) throw new GhError(res.status, await res.text());

    const renew = inputs.auto_renew === 'true' ? `مفعّل (${inputs.max_renewals === '0' ? 'بلا حدّ' : `حتى ${inputs.max_renewals} مرات`})` : 'معطّل';
    return {
      kind: 'ok',
      title: '🚀 أُرسل أمر التشغيل',
      lead: 'بدأ تجهيز الجلسة على GitHub. ستصلك رسالة «الجلسة جاهزة» في قناة ryder-notify فور اكتمال التجهيز، وعادةً يستغرق ذلك من 5 إلى 10 دقائق.',
      sections: [
        {
          heading: 'الإعداد المختار',
          facts: [
            ['الإعداد المسبق', presetLabel(inputs.preset)],
            ['Visual Studio Code', yesNo(inputs.install_vscode)],
            ['Discord', yesNo(inputs.install_discord)],
            extra ? ['حزم إضافية', code(extra)] : null,
            ['التجديد التلقائي', renew],
            ['أوامر عن بُعد', inputs.remote_exec === 'true' ? 'مفعّلة' : 'معطّلة'],
          ],
        },
        { heading: 'الخطوات التالية', items: ['تجهيز الجلسة على GitHub، ويستغرق من 5 إلى 10 دقائق.', 'وصول رسالة «الجلسة جاهزة» إلى قناة ryder-notify.', 'الاتصال عبر Windows App باستخدام العنوان المرسل.'] },
      ],
      buttons: [button('حالة الجلسة', 'status:refresh', 2, '📡'), link('صفحة التشغيل', `https://github.com/${env.REPO}/actions/workflows/${env.WORKFLOW}`, '🔗')],
    };
  },

  async status(i, env) {
    const runs = await listRuns(env, 5);
    const active = runs.filter((r) => ACTIVE.has(r.status));
    if (!active.length) return idleSpec(env, runs[0]);

    const run = active[0];
    const d = await describeRun(env, run);
    const sections = [
      { heading: 'التقدّم', text: `${bar(d.done, PROGRESS_TOTAL)} · ${d.done} / ${PROGRESS_TOTAL}\nالمرحلة الحالية: **${d.phase}**` },
      {
        heading: 'الزمن',
        facts: [
          ['المدة المنقضية', fmtDuration(d.elapsed)],
          ['المتبقي', `${ts(d.endMs, 'R')} (${ts(d.endMs, 't')})`],
        ],
      },
    ];
    if (d.ready) {
      sections.push({ heading: 'الاتصال', facts: [['الاسم', code('ryder')], ['المستخدم', code('RDP')]], text: 'العنوان وبقية البيانات في رسالة «الجلسة جاهزة» بقناة ryder-notify.' });
    }
    return {
      kind: d.ready ? 'ok' : 'info',
      title: d.ready ? `🟢 الجلسة #${run.run_number} جاهزة للاتصال` : `⏳ الجلسة #${run.run_number} قيد التجهيز`,
      subtitle: `بدأت ${ts(d.startMs, 'R')}`,
      lead: active.length > 1 ? 'توجد أكثر من جلسة جارية، وغالباً أن ذلك بسبب التجديد التلقائي. انتقل إلى الأحدث.' : undefined,
      sections,
      buttons: [button('تحديث', 'status:refresh', 2, '🔄'), link('سجل التشغيل', run.html_url, '📄'), button('إيقاف', 'stop:ask', 4, '⏹️')],
    };
  },

  async stop(i, env) {
    const active = await activeRuns(env);
    if (!active.length) return idleSpec(env, (await listRuns(env, 1))[0]);
    return {
      kind: 'warn',
      title: '⏹️ تأكيد إيقاف الجلسة',
      lead: 'سيُنهي هذا الإجراء الجلسات الجارية فوراً، وينقطع اتصالك بها.',
      sections: [
        { heading: 'الجلسات المستهدفة', items: active.map((r) => `${mdLink(r)} · ${statusAr(r.status)}`) },
        { heading: 'ما يحدث عند الإيقاف', items: ['ينقطع اتصال سطح المكتب البعيد فوراً.', 'تعمل خطوة التنظيف تلقائياً لحفظ Work ورفع Outbox قبل الإغلاق، قدر الإمكان.', 'تُلغى كذلك أي جلسة تجديد قيد التشغيل.'] },
      ],
      buttons: [button('تأكيد الإيقاف', 'stop:all', 4, '⏹️'), button('تراجع', 'stop:cancel', 2, '↩️')],
    };
  },

  async logs(i, env, o = {}) {
    const lines = Math.min(100, Math.max(5, Number(o.lines) || 40));
    const run = (await listRuns(env, 1))[0];
    if (!run) return noteSpec('info', '📜 لا توجد سجلات', 'لم تُشغَّل أي جلسة بعد.');
    const jobs = await ghJson(env, `/repos/${env.REPO}/actions/runs/${run.id}/jobs`);
    const job = jobs.jobs?.[0];
    if (!job) return noteSpec('info', '📜 السجل غير جاهز بعد', 'الجلسة ما زالت بالانتظار على GitHub.', { buttons: [link('فتح السجل', run.html_url, '📄')] });

    const res = await gh(env, `/repos/${env.REPO}/actions/jobs/${job.id}/logs`, { manualRedirect: true });
    let text = null;
    if (res.status === 302) {
      const loc = res.headers.get('location');
      if (loc) text = await (await fetch(loc)).text();
    } else if (res.ok) {
      text = await res.text();
    }
    if (!text) {
      return noteSpec('warn', '📜 السجل غير متاح الآن', 'لا يوفّر GitHub سجل الـ job كاملاً أثناء التشغيل. افتح الرابط لمتابعة الأسطر الحيّة.', {
        buttons: [button('إعادة المحاولة', `logs:${lines}`, 2, '🔄'), link('فتح السجل', run.html_url, '📄')],
      });
    }
    const out = sanitizeLog(text).split('\n').filter((l) => l.trim()).slice(-lines).join('\n');
    return {
      kind: 'info',
      title: `📜 آخر ${lines <= 10 ? (lines === 1 ? 'سطر' : lines === 2 ? 'سطرين' : lines + ' أسطر') : lines + ' سطراً'} من السجل`,
      subtitle: `الجلسة #${run.run_number} · ${ts(Date.now(), 'R')}`,
      sections: [{ code: out }],
      buttons: [button('تحديث', `logs:${lines}`, 2, '🔄'), link('السجل الكامل', run.html_url, '📄')],
    };
  },

  async history(i, env) {
    const runs = await listRuns(env, 8);
    if (!runs.length) return noteSpec('info', '🗂️ لا توجد جلسات', 'لم تُشغَّل أي جلسة بعد.', { buttons: [button('تشغيل جلسة جديدة', 'start:quick', 3, '▶️')] });
    const rows = runs.map((r) => {
      const dur = runDuration(r);
      let note = '';
      if (r.status === 'completed' && r.conclusion === 'cancelled') note = dur >= (SESSION_LIMIT_MIN - 8) * 60000 ? ' · بلغت حدّ الوقت' : ' · إيقاف يدوي';
      return `${outcome(r).split(' ')[0]} ${mdLink(r)} · ${fmtDuration(dur)}${note} · ${ts(Date.parse(r.created_at))}`;
    });
    const finished = runs.filter((r) => r.status === 'completed');
    const count = (c) => finished.filter((r) => r.conclusion === c).length;
    const total = finished.reduce((n, r) => n + Math.max(0, runDuration(r)), 0);
    return {
      kind: 'info',
      title: '🗂️ سجلّ الجلسات',
      subtitle: `آخر ${runs.length} جلسات`,
      sections: [
        { heading: 'الجلسات', items: rows },
        {
          heading: 'إحصاءات',
          facts: [
            ['المكتملة', `${count('success')}`],
            ['المُلغاة', `${count('cancelled')}`],
            ['المنتهية بخطأ', `${count('failure')}`],
            ['إجمالي مدة التشغيل', fmtDuration(total)],
          ],
        },
      ],
      buttons: [button('تحديث', 'history:refresh', 2, '🔄'), button('تشغيل جلسة جديدة', 'start:quick', 3, '▶️')],
    };
  },

  async exec(i, env, o = {}) {
    if (env.ENABLE_EXEC !== 'true') {
      return noteSpec('warn', '🔒 الأمر معطّل', `فعّله بضبط ${code('ENABLE_EXEC = "true"')} في ملف bot/wrangler.toml، ثم شغّل الجلسة مع الخيار ${code('remote_exec')}.`);
    }
    const cmd = String(o.command || '').trim();
    if (!cmd || cmd.length > 1500) return noteSpec('err', '❌ أمر غير صالح', 'الأمر فارغ أو يتجاوز 1500 حرف.');
    const active = await activeRuns(env);
    if (!active.length) return noteSpec('warn', '⚠️ لا توجد جلسة جارية', `شغّل جلسة أولاً بالأمر ${code('/start')} مع الخيار ${code('remote_exec')}.`);

    const path = `/repos/${env.FILES_REPO}/contents/control/cmd.json`;
    let sha;
    const cur = await gh(env, path, { token: env.FILES_PAT });
    if (cur.ok) sha = (await cur.json()).sha;
    else if (cur.status !== 404) throw new GhError(cur.status, await cur.text());

    const userId = i.member?.user?.id ?? i.user?.id;
    const payload = { id: newId() + newId(), cmd, by: userId, ts: Date.now() };
    const put = await gh(env, path, {
      method: 'PUT',
      token: env.FILES_PAT,
      body: { message: 'ryder: command', content: b64(JSON.stringify(payload)), ...(sha ? { sha } : {}) },
    });
    if (!put.ok) throw new GhError(put.status, await put.text());

    await audit(env, { command: 'exec', user: userId, ok: true, options: { id: payload.id }, detail: cmd });
    return {
      kind: 'ok',
      title: '🔧 أُرسل الأمر إلى الجلسة',
      lead: 'ستظهر النتيجة في قناة ryder-notify خلال ثوانٍ. تأكد أن الجلسة بدأت مع الخيار remote_exec.',
      sections: [{ facts: [['معرّف الأمر', code(payload.id)], ['طول الأمر', `${cmd.length} حرفاً`]] }],
      compact: true,
    };
  },
};

// ------------------------------------------------------------------ buttons
async function stopAll(i, env) {
  const active = await activeRuns(env);
  if (!active.length) return idleSpec(env, (await listRuns(env, 1))[0]);
  const results = await Promise.all(
    active.map(async (r) => {
      const res = await gh(env, `/repos/${env.REPO}/actions/runs/${r.id}/cancel`, { method: 'POST' });
      return `${res.status === 202 ? '✅' : '⚠️'} ${mdLink(r)} · ${res.status === 202 ? 'أُرسل أمر الإلغاء' : `تعذّر الإلغاء (HTTP ${res.status})`}`;
    }),
  );
  return {
    kind: 'ok',
    title: '✅ أُرسل أمر الإيقاف',
    lead: `تأكد من النتيجة بالأمر ${code('/status')} بعد لحظات.`,
    sections: [{ heading: 'النتيجة', items: results }],
    buttons: [button('حالة الجلسة', 'status:refresh', 2, '📡')],
    compact: true,
  };
}

const BUTTONS = {
  'stop:ask': (i, env) => COMMANDS.stop(i, env),
  'stop:all': stopAll,
  'stop:cancel': async () => noteSpec('info', '↩️ تم التراجع', 'لم تُوقَف أي جلسة.', { buttons: [button('حالة الجلسة', 'status:refresh', 2, '📡')] }),
  'status:refresh': (i, env) => COMMANDS.status(i, env),
  'history:refresh': (i, env) => COMMANDS.history(i, env),
  'start:quick': (i, env) => COMMANDS.start(i, env, {}),
};

// ------------------------------------------------------------------ interaction plumbing
async function editOriginal(env, token, spec) {
  const mode = uiMode(env);
  for (const m of mode === 'v2' ? ['v2', 'classic'] : ['classic']) {
    const res = await fetch(`${DISCORD_API}/webhooks/${env.APP_ID}/${token}/messages/@original`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ allowed_mentions: { parse: [] }, ...render(spec, m) }),
    });
    if (res.ok) return true;
    console.error(JSON.stringify({ level: 'error', msg: 'edit original failed', mode: m, status: res.status, body: (await res.text()).slice(0, 300) }));
  }
  return false;
}

async function execute(i, env, name, opts) {
  const t0 = Date.now();
  const user = i.member?.user?.id ?? i.user?.id;
  let spec;
  let ok = true;
  let errorId;
  try {
    spec = await COMMANDS[name](i, env, opts);
  } catch (e) {
    ok = false;
    errorId = newId();
    console.error(JSON.stringify({ level: 'error', errorId, command: name, err: String(e), body: e.body }));
    spec = errorSpec(e, errorId);
  }
  await editOriginal(env, i.token, spec);
  const logged = { ...opts };
  delete logged.command; // the /exec command text is never logged
  if (name !== 'exec' || !ok) await audit(env, { command: name, user, options: logged, ok, ms: Date.now() - t0, errorId });
}

async function handleButton(i, env) {
  const user = i.member?.user?.id ?? i.user?.id;
  const id = i.data.custom_id;
  const t0 = Date.now();
  let spec;
  let ok = true;
  let errorId;
  try {
    const logsMatch = /^logs:(\d{1,3})$/.exec(id);
    if (logsMatch) spec = await COMMANDS.logs(i, env, { lines: Number(logsMatch[1]) });
    else if (BUTTONS[id]) spec = await BUTTONS[id](i, env);
    else spec = noteSpec('warn', '⚠️ زر غير معروف', 'هذا الزر لم يعد مدعوماً. أعد تشغيل الأمر من جديد.');
  } catch (e) {
    ok = false;
    errorId = newId();
    console.error(JSON.stringify({ level: 'error', errorId, button: id, err: String(e) }));
    spec = errorSpec(e, errorId);
  }
  await editOriginal(env, i.token, spec);
  await audit(env, { action: id, user, ok, ms: Date.now() - t0, errorId });
}

async function handleInteraction(i, env, ctx) {
  if (i.type === 1) return json({ type: 1 }); // PING -> PONG

  const user = i.member?.user?.id ?? i.user?.id;
  if (i.guild_id !== env.GUILD_ID || user !== env.OWNER_ID) {
    ctx.waitUntil(audit(env, { command: i.data?.name, action: i.data?.custom_id, user, denied: true }));
    return privateCard(env, noteSpec('err', '⛔ غير مصرّح لك', 'هذا البوت مخصّص لمالك الخادم فقط.', { footer: false }));
  }

  if (i.type === 2) {
    const name = i.data.name;
    if (!COMMANDS[name]) return privateCard(env, noteSpec('warn', '⚠️ أمر غير معروف', `استخدم ${code('/help')} لعرض الأوامر المتاحة.`));
    const opts = Object.fromEntries((i.data.options || []).map((o) => [o.name, o.value]));
    ctx.waitUntil(execute(i, env, name, opts));
    return deferred(env);
  }

  if (i.type === 3) {
    ctx.waitUntil(handleButton(i, env));
    return deferredUpdate();
  }

  return privateCard(env, noteSpec('warn', '⚠️ نوع تفاعل غير مدعوم', 'لا يدعم البوت هذا النوع من التفاعلات.'));
}

// ------------------------------------------------------------------ session events from main.yml
async function handleEvent(request, env) {
  const raw = await request.text();
  if (raw.length > 20000) return json({ ok: false, error: 'too large' }, 413);
  const secret = (env.DISCORD_NOTIFY_WEBHOOK || '').trim();
  if (!secret) return json({ ok: false, error: 'notify webhook is not configured on the Worker' }, 503);
  if (!(await verifyHmac(secret, request.headers.get('x-ryder-ts'), raw, request.headers.get('x-ryder-sig')))) return json({ ok: false, error: 'bad signature' }, 401);

  let evt;
  try {
    evt = JSON.parse(raw);
  } catch {
    return json({ ok: false, error: 'bad json' }, 400);
  }
  const spec = eventSpec(evt?.type, evt, Date.now());
  if (!spec) return json({ ok: false, error: 'unknown event' }, 400);

  const r = await postWebhook(secret, spec, { mode: uiMode(env), username: 'Ryder' });
  console.log(JSON.stringify({ ts: new Date().toISOString(), event: evt.type, via: r.via, status: r.status }));
  return json({ ok: r.ok, via: r.via }, r.ok ? 200 : 502);
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'GET') return new Response('ryder-bot ok', { status: 200 });
    if (request.method !== 'POST') return new Response('method not allowed', { status: 405 });
    if (new URL(request.url).pathname === '/event') return handleEvent(request, env);

    const body = await request.text();
    if (!(await verifySignature(request, body, env.DISCORD_PUBLIC_KEY))) return new Response('bad signature', { status: 401 });
    let interaction;
    try {
      interaction = JSON.parse(body);
    } catch {
      return new Response('bad request', { status: 400 });
    }
    return handleInteraction(interaction, env, ctx);
  },
};
