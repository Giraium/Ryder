// Ryder control bot - Cloudflare Worker (Discord Interactions over HTTP, no always-on server needed)
// Commands: /start /stop /status /logs /history /help /exec
// Only the owner (OWNER_ID) in the configured server (GUILD_ID) can use it.

const DISCORD_API = 'https://discord.com/api/v10';
const GH_API = 'https://api.github.com';
const SESSION_LIMIT_MIN = 355; // keep equal to timeout-minutes in main.yml
const ACTIVE = new Set(['queued', 'in_progress', 'waiting', 'requested', 'pending']);
const COLORS = { ok: 0x2ecc71, warn: 0xf1c40f, err: 0xe74c3c, info: 0x3498db };
const enc = new TextEncoder();

// ------------------------------------------------------------------ small helpers
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
const ephemeral = (content) => json({ type: 4, data: { content, flags: 64 } });
const deferred = () => json({ type: 5, data: { flags: 64 } });
const deferredUpdate = () => json({ type: 6 });
const newId = () => crypto.randomUUID().slice(0, 8);

function embed(kind, title, description = '', fields = []) {
  return {
    title,
    description: description.slice(0, 4000),
    color: COLORS[kind] ?? COLORS.info,
    fields: fields.map((f) => ({ name: f.name, value: String(f.value).slice(0, 1000) || '-', inline: !!f.inline })),
    timestamp: new Date().toISOString(),
    footer: { text: 'Ryder' },
  };
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

function fmtDuration(ms) {
  const m = Math.max(0, Math.round(ms / 60000));
  const h = Math.floor(m / 60);
  return h ? `${h}س ${m % 60}د` : `${m}د`;
}

const unix = (ms) => Math.floor(ms / 1000);

// ------------------------------------------------------------------ Discord signature check
async function importKey(publicKeyHex) {
  const raw = hexToBytes(publicKeyHex);
  try {
    return await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
  } catch {
    // older Workers runtimes
    return await crypto.subtle.importKey('raw', raw, { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' }, false, ['verify']);
  }
}

async function verifySignature(request, rawBody, publicKeyHex) {
  const sig = request.headers.get('x-signature-ed25519');
  const ts = request.headers.get('x-signature-timestamp');
  if (!sig || !ts || !publicKeyHex) return false;
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false; // replay protection (5 min)
  try {
    const key = await importKey(publicKeyHex);
    return await crypto.subtle.verify(key.algorithm.name, key, hexToBytes(sig), enc.encode(ts + rawBody));
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

function friendlyError(e) {
  if (e instanceof GhError) {
    if (e.status === 401) return 'توكن GH_BOT_PAT منتهي أو غير صحيح.';
    if (e.status === 403) return 'توكن GH_BOT_PAT ما عنده صلاحية (لازم Actions: Read and write على ريبو Ryder).';
    if (e.status === 404) return 'ما لقيت الريبو أو الـ workflow، أو التوكن ما يصل له. تأكد من REPO و WORKFLOW.';
    if (e.status === 422) return 'GitHub رفض المدخلات. غالباً ملف main.yml المرفوع ما فيه الـ inputs الجديدة.';
    return `خطأ من GitHub (${e.status}): ${e.body}`;
  }
  return 'خطأ غير متوقع بالبوت.';
}

// ------------------------------------------------------------------ logging (console JSON + Discord log channel)
async function logToDiscord(env, kind, title, fields) {
  if (!env.DISCORD_LOG_WEBHOOK) return;
  try {
    await fetch(env.DISCORD_LOG_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'Ryder Log', allowed_mentions: { parse: [] }, embeds: [embed(kind, title, '', fields)] }),
    });
  } catch (e) {
    console.error(JSON.stringify({ level: 'error', msg: 'log webhook failed', err: String(e) }));
  }
}

async function audit(env, entry) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...entry }));
  const kind = entry.ok === false ? 'err' : entry.denied ? 'warn' : 'info';
  const title = entry.denied ? '⛔ محاولة غير مصرّح بها' : `/${entry.command ?? entry.action}`;
  const fields = [
    { name: 'المستخدم', value: `<@${entry.user}> (${entry.user})`, inline: true },
    { name: 'النتيجة', value: entry.denied ? 'مرفوض' : entry.ok === false ? 'خطأ' : 'نجح', inline: true },
  ];
  if (entry.ms !== undefined) fields.push({ name: 'الزمن', value: `${entry.ms}ms`, inline: true });
  if (entry.options && Object.keys(entry.options).length) fields.push({ name: 'الخيارات', value: '```json\n' + JSON.stringify(entry.options).slice(0, 900) + '\n```' });
  if (entry.errorId) fields.push({ name: 'معرّف الخطأ', value: entry.errorId, inline: true });
  await logToDiscord(env, kind, title, fields);
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

// ------------------------------------------------------------------ commands
const STEP_AR = [
  ['Configure Core RDP', 'ضبط RDP'],
  ['Create RDP User', 'إنشاء المستخدم'],
  ['Tune display', 'ضبط الأداء'],
  ['Write helper', 'تجهيز الأدوات'],
  ['Provision', 'تثبيت البرامج'],
  ['Restore files', 'استرجاع الملفات'],
  ['Install Tailscale', 'تثبيت Tailscale'],
  ['Establish Tailscale', 'اتصال Tailscale'],
  ['Verify RDP', 'فحص RDP'],
  ['Announce', 'إرسال الإشعار'],
  ['Maintain', 'جاهزة للاتصال'],
  ['Cleanup', 'إنهاء الجلسة'],
];
const stepAr = (name = '') => (STEP_AR.find(([k]) => name.includes(k)) || [null, name])[1];

async function describeRun(env, run) {
  const jobs = await ghJson(env, `/repos/${env.REPO}/actions/runs/${run.id}/jobs`);
  const job = jobs.jobs?.[0];
  let phase = 'بالانتظار على GitHub';
  if (job && job.status !== 'queued') {
    const cur = (job.steps || []).find((s) => s.status === 'in_progress');
    phase = cur ? (cur.name.includes('Maintain') ? '🟢 جاهزة للاتصال' : `⏳ ${stepAr(cur.name)}`) : '⏳ جاري التجهيز';
  }
  const startMs = Date.parse(job?.started_at || run.run_started_at || run.created_at);
  const elapsed = Date.now() - startMs;
  const endMs = startMs + SESSION_LIMIT_MIN * 60000;
  return { phase, elapsed, endMs, job };
}

const COMMANDS = {
  async help() {
    return {
      embeds: [
        embed('info', 'أوامر Ryder', '', [
          { name: '/start', value: 'تشغيل جلسة جديدة (preset، vscode، discord، extra_tools، auto_renew، max_renewals).' },
          { name: '/stop', value: 'إيقاف الجلسة الشغالة (مع تأكيد). يوقف أيضاً أي جلسة تجديد جديدة.' },
          { name: '/status', value: 'حالة الجلسة والوقت المتبقي.' },
          { name: '/logs', value: 'آخر أسطر سجل الجلسة (الأسرار تنخفي).' },
          { name: '/history', value: 'آخر الجلسات ونتيجة كل وحدة.' },
          { name: '/exec', value: 'تنفيذ أمر داخل الجلسة (معطّل افتراضياً).' },
        ]),
      ],
    };
  },

  async start(i, env, o) {
    const active = await activeRuns(env);
    if (active.length) {
      return { embeds: [embed('warn', 'فيه جلسة شغالة', `الجلسة #${active[0].run_number} بحالة \`${active[0].status}\`. استخدم /status أو /stop.`, [{ name: 'الرابط', value: active[0].html_url }])] };
    }
    const extra = (o.extra_tools || '').trim();
    if (extra && !/^[a-z0-9][a-z0-9.,\s-]{0,198}$/i.test(extra)) {
      return { embeds: [embed('err', 'أسماء الحزم غير صالحة', 'استخدم أسماء حزم Chocolatey مفصولة بفاصلة فقط.')] };
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
    return {
      embeds: [
        embed('ok', '🚀 تم إرسال أمر التشغيل', 'تجيك رسالة بقناة ryder-notify لما تصير الجلسة جاهزة (عادة 5-10 دقائق).', [
          { name: 'الإعداد', value: inputs.preset, inline: true },
          { name: 'تجديد تلقائي', value: inputs.auto_renew === 'true' ? `نعم (حتى ${inputs.max_renewals === '0' ? 'بلا حد' : inputs.max_renewals})` : 'لا', inline: true },
          { name: 'أوامر عن بعد', value: inputs.remote_exec === 'true' ? 'مفعّلة' : 'معطّلة', inline: true },
        ]),
      ],
    };
  },

  async status(i, env) {
    const runs = await listRuns(env, 5);
    const active = runs.filter((r) => ACTIVE.has(r.status));
    if (!active.length) {
      const last = runs[0];
      return {
        embeds: [
          embed('info', 'ما فيه جلسة شغالة', last ? `آخر جلسة: #${last.run_number} (${last.conclusion || last.status}) <t:${unix(Date.parse(last.updated_at))}:R>` : 'ما فيه جلسات سابقة.', last ? [{ name: 'الرابط', value: last.html_url }] : []),
        ],
      };
    }
    const embeds = [];
    for (const run of active.slice(0, 2)) {
      const d = await describeRun(env, run);
      embeds.push(
        embed('ok', `الجلسة #${run.run_number}`, '', [
          { name: 'الحالة', value: d.phase, inline: true },
          { name: 'المدة', value: fmtDuration(d.elapsed), inline: true },
          { name: 'تنتهي تقريباً', value: `<t:${unix(d.endMs)}:R>`, inline: true },
          { name: 'الاسم', value: 'ryder (Tailscale)', inline: true },
          { name: 'الرابط', value: run.html_url },
        ]),
      );
    }
    if (active.length > 1) embeds.push(embed('info', 'ملاحظة', 'فيه جلستين بنفس الوقت: غالباً تجديد تلقائي. انتقل للأحدث.'));
    return { embeds };
  },

  async stop(i, env) {
    const active = await activeRuns(env);
    if (!active.length) return { embeds: [embed('info', 'ما فيه جلسة شغالة')] };
    return {
      embeds: [embed('warn', 'تأكيد الإيقاف', `راح أوقف ${active.length} جلسة:\n` + active.map((r) => `• #${r.run_number} (${r.status})`).join('\n'))],
      components: [
        {
          type: 1,
          components: [
            { type: 2, style: 4, label: 'أوقف الكل', custom_id: 'stop:all' },
            { type: 2, style: 2, label: 'إلغاء', custom_id: 'stop:cancel' },
          ],
        },
      ],
    };
  },

  async logs(i, env, o) {
    const lines = Math.min(100, Math.max(5, Number(o.lines) || 40));
    const run = (await listRuns(env, 1))[0];
    if (!run) return { embeds: [embed('info', 'ما فيه سجلات')] };
    const jobs = await ghJson(env, `/repos/${env.REPO}/actions/runs/${run.id}/jobs`);
    const job = jobs.jobs?.[0];
    if (!job) return { embeds: [embed('info', 'السجل غير جاهز بعد', 'الجلسة لسا بالانتظار.', [{ name: 'الرابط', value: run.html_url }])] };

    const res = await gh(env, `/repos/${env.REPO}/actions/jobs/${job.id}/logs`, { manualRedirect: true });
    let text = null;
    if (res.status === 302) {
      const loc = res.headers.get('location');
      if (loc) text = await (await fetch(loc)).text();
    } else if (res.ok) {
      text = await res.text();
    }
    if (!text) {
      return { embeds: [embed('warn', 'السجل غير متاح الحين', 'GitHub ما يعطي سجل الـ job كامل أثناء التشغيل. افتح الرابط لتشوف الأسطر الحية.', [{ name: 'الرابط', value: run.html_url }])] };
    }
    let out = sanitizeLog(text).split('\n').filter((l) => l.trim()).slice(-lines).join('\n');
    if (out.length > 1800) out = '…' + out.slice(-1800);
    return { embeds: [embed('info', `آخر ${lines} سطر - جلسة #${run.run_number}`, '```\n' + out.replace(/```/g, "'''") + '\n```', [{ name: 'الرابط', value: run.html_url }])] };
  },

  async history(i, env) {
    const runs = await listRuns(env, 8);
    if (!runs.length) return { embeds: [embed('info', 'ما فيه جلسات')] };
    const rows = runs.map((r) => {
      const dur = Date.parse(r.updated_at) - Date.parse(r.run_started_at || r.created_at);
      let icon = '⏳';
      let note = '';
      if (r.status === 'completed') {
        if (r.conclusion === 'success') icon = '✅';
        else if (r.conclusion === 'failure') icon = '❌';
        else if (r.conclusion === 'cancelled') {
          icon = '⏹️';
          note = dur >= (SESSION_LIMIT_MIN - 8) * 60000 ? ' (وصلت سقف الوقت ~6 ساعات)' : ' (إيقاف/إلغاء)';
        } else icon = '⚪';
      }
      return `${icon} #${r.run_number} - ${fmtDuration(dur)}${note} - <t:${unix(Date.parse(r.created_at))}:R>`;
    });
    return { embeds: [embed('info', 'آخر الجلسات', rows.join('\n'))] };
  },

  async exec(i, env, o) {
    if (env.ENABLE_EXEC !== 'true') {
      return { embeds: [embed('warn', 'الأمر معطّل', 'فعّله بـ ENABLE_EXEC = "true" بملف bot/wrangler.toml، وشغّل الجلسة مع remote_exec.')] };
    }
    const cmd = String(o.command || '').trim();
    if (!cmd || cmd.length > 1500) return { embeds: [embed('err', 'أمر غير صالح', 'الأمر فاضي أو أطول من 1500 حرف.')] };
    const active = await activeRuns(env);
    if (!active.length) return { embeds: [embed('warn', 'ما فيه جلسة شغالة')] };

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

    await logToDiscord(env, 'warn', '🔧 /exec', [{ name: 'الأمر', value: '```\n' + cmd.slice(0, 900) + '\n```' }, { name: 'ID', value: payload.id, inline: true }]);
    return { embeds: [embed('ok', 'تم إرسال الأمر', 'النتيجة تظهر بقناة ryder-notify خلال ثواني. (الجلسة لازم تكون مشغّلة مع remote_exec.)')] };
  },
};

// ------------------------------------------------------------------ interaction plumbing
async function editOriginal(env, token, payload) {
  const res = await fetch(`${DISCORD_API}/webhooks/${env.APP_ID}/${token}/messages/@original`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ allowed_mentions: { parse: [] }, ...payload }),
  });
  if (!res.ok) console.error(JSON.stringify({ level: 'error', msg: 'edit original failed', status: res.status }));
}

async function execute(i, env, name, opts) {
  const t0 = Date.now();
  const user = i.member?.user?.id ?? i.user?.id;
  let payload;
  let ok = true;
  let errorId;
  try {
    payload = await COMMANDS[name](i, env, opts);
  } catch (e) {
    ok = false;
    errorId = newId();
    console.error(JSON.stringify({ level: 'error', errorId, command: name, err: String(e), body: e.body }));
    payload = { embeds: [embed('err', 'صار خطأ', `${friendlyError(e)}\nمعرّف الخطأ: \`${errorId}\``)] };
  }
  await editOriginal(env, i.token, payload);
  const logged = { ...opts };
  delete logged.command; // the /exec command text is logged separately
  await audit(env, { command: name, user, options: logged, ok, ms: Date.now() - t0, errorId });
}

async function handleButton(i, env) {
  const user = i.member?.user?.id ?? i.user?.id;
  const id = i.data.custom_id;
  const t0 = Date.now();
  let payload;
  let ok = true;
  let errorId;
  try {
    if (id === 'stop:cancel') {
      payload = { embeds: [embed('info', 'تم الإلغاء', 'ما انوقفت أي جلسة.')], components: [] };
    } else if (id === 'stop:all') {
      const active = await activeRuns(env);
      if (!active.length) {
        payload = { embeds: [embed('info', 'ما فيه جلسة شغالة')], components: [] };
      } else {
        const results = await Promise.all(
          active.map(async (r) => {
            const res = await gh(env, `/repos/${env.REPO}/actions/runs/${r.id}/cancel`, { method: 'POST' });
            return `${res.status === 202 ? '✅' : '⚠️'} #${r.run_number} (${res.status})`;
          }),
        );
        payload = { embeds: [embed('ok', 'أرسلت أمر الإيقاف', results.join('\n') + '\nتأكد بـ /status بعد لحظات.')], components: [] };
      }
    } else {
      payload = { embeds: [embed('warn', 'زر غير معروف')], components: [] };
    }
  } catch (e) {
    ok = false;
    errorId = newId();
    console.error(JSON.stringify({ level: 'error', errorId, button: id, err: String(e) }));
    payload = { embeds: [embed('err', 'صار خطأ', `${friendlyError(e)}\nمعرّف الخطأ: \`${errorId}\``)], components: [] };
  }
  await editOriginal(env, i.token, payload);
  await audit(env, { action: id, user, ok, ms: Date.now() - t0, errorId });
}

async function handleInteraction(i, env, ctx) {
  if (i.type === 1) return json({ type: 1 }); // PING -> PONG

  const user = i.member?.user?.id ?? i.user?.id;
  if (i.guild_id !== env.GUILD_ID || user !== env.OWNER_ID) {
    ctx.waitUntil(audit(env, { command: i.data?.name, action: i.data?.custom_id, user, denied: true }));
    return ephemeral('⛔ غير مصرّح لك باستخدام هذا البوت.');
  }

  if (i.type === 2) {
    const name = i.data.name;
    if (!COMMANDS[name]) return ephemeral('أمر غير معروف.');
    const opts = Object.fromEntries((i.data.options || []).map((o) => [o.name, o.value]));
    ctx.waitUntil(execute(i, env, name, opts));
    return deferred();
  }

  if (i.type === 3) {
    ctx.waitUntil(handleButton(i, env));
    return deferredUpdate();
  }

  return ephemeral('نوع تفاعل غير مدعوم.');
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'GET') return new Response('ryder-bot ok', { status: 200 });
    if (request.method !== 'POST') return new Response('method not allowed', { status: 405 });
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
