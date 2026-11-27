// Ryder UI - the single presentation layer for every Discord message the project sends.
// Pure functions only (no Cloudflare / Node specific APIs), so the same file runs in the Worker and in the tests.
//
// Design language (Discord Components V2):
//   Container (accent colour = state)   title (# header), subtitle (-# subtext), lead paragraph
//   sections split by dividers          ### heading + key/value facts, bullet items, text or a code block
//   action row                          link buttons (everywhere) and interactive buttons (slash replies only)
//   footer (-# subtext)                 "Ryder . date"
// Every spec can also be rendered as a classic embed: that is the automatic fallback (UI_MODE = "classic").

export const SESSION_LIMIT_MIN = 355; // keep equal to timeout-minutes in main.yml
export const FLAG_V2 = 1 << 15; // IS_COMPONENTS_V2
export const FLAG_EPHEMERAL = 1 << 6;
export const COLORS = { ok: 0x23a55a, warn: 0xf0b232, err: 0xf23f43, info: 0x5865f2, idle: 0x80848e };

const RLM = '\u200F'; // right-to-left mark: keeps lines that start with Latin text aligned like the Arabic ones
const MAX_TEXT = 3900; // Discord allows 4000 characters of text display per message

// ------------------------------------------------------------------ small helpers
export const unix = (ms) => Math.floor(ms / 1000);
export const ts = (ms, style = 'R') => `<t:${unix(ms)}:${style}>`;
export const clip = (s, n) => {
  const t = String(s ?? '');
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
};
export const code = (s) => '`' + String(s ?? '').replace(/[`\r\n]+/g, ' ').trim() + '`';
export const block = (s, max = 2400) => {
  let t = String(s ?? '').replace(/```/g, "'''");
  if (t.length > max) t = '…' + t.slice(-(max - 1));
  return '```\n' + t + '\n```';
};

export function fmtDuration(ms) {
  const m = Math.max(0, Math.round(ms / 60000));
  const h = Math.floor(m / 60);
  if (!h) return `${m} د`;
  return m % 60 ? `${h} س ${m % 60} د` : `${h} س`;
}

export function bar(done, total, width = 10) {
  const n = total > 0 ? Math.round((Math.min(Math.max(done, 0), total) / total) * width) : 0;
  return '▰'.repeat(n) + '▱'.repeat(width - n);
}

const fact = (label, value) => `${RLM}**${label}** · ${value}`;
const li = (text) => `- ${RLM}${text}`;
const isUrl = (u) => typeof u === 'string' && /^https?:\/\/\S+$/.test(u) && u.length <= 512;

// ------------------------------------------------------------------ component builders
const textC = (content) => ({ type: 10, content });
const sepC = (divider = true, spacing = 1) => ({ type: 14, divider, spacing });
const rowC = (components) => ({ type: 1, components });
const withEmoji = (o, emoji) => (emoji ? { ...o, emoji: { name: emoji } } : o);

export const link = (label, url, emoji) => (isUrl(url) ? withEmoji({ type: 2, style: 5, label: clip(label, 80), url }, emoji) : null);
// style: 1 primary, 2 secondary, 3 success, 4 danger
export const button = (label, id, style = 2, emoji) => withEmoji({ type: 2, style, label: clip(label, 80), custom_id: clip(id, 100) }, emoji);

// ------------------------------------------------------------------ spec -> text
function sectionBody(s, codeMax) {
  const parts = [];
  if (s.facts?.length) parts.push(s.facts.filter(Boolean).map(([l, v]) => fact(l, v)).join('\n'));
  if (s.items?.length) parts.push(s.items.filter(Boolean).map(li).join('\n'));
  if (s.text) parts.push(s.text);
  if (s.code !== undefined && s.code !== null) parts.push(block(s.code, Math.min(s.codeMax ?? 2400, codeMax)));
  return parts.join('\n');
}
const sectionText = (s, codeMax = 2400) => [s.heading ? `### ${s.heading}` : '', sectionBody(s, codeMax)].filter(Boolean).join('\n');

// ------------------------------------------------------------------ Components V2 rendering
export function toV2(spec) {
  const now = spec.now ?? Date.now();
  const head = [`${spec.compact ? '##' : '#'} ${spec.title}`];
  if (spec.subtitle) head.push(`-# ${RLM}${spec.subtitle}`);
  if (spec.lead) head.push('', spec.lead);
  const foot = spec.footer === false ? null : `-# ${RLM}${spec.footer ?? 'Ryder'} · ${ts(now, 'f')}`;

  // code blocks get whatever text budget the rest of the card leaves over
  const fixed = [head.join('\n'), foot || '', ...(spec.sections || []).map((s) => sectionText({ ...s, code: undefined }))].join('').length;
  const codeMax = Math.max(300, MAX_TEXT - fixed - 120);

  const kids = [textC(head.join('\n'))];
  for (const s of spec.sections || []) {
    const t = sectionText(s, codeMax);
    if (t) kids.push(sepC(), textC(t));
  }
  const buttons = (spec.buttons || []).filter(Boolean);
  if (buttons.length) {
    kids.push(sepC(false));
    for (let i = 0; i < buttons.length && i < 10; i += 5) kids.push(rowC(buttons.slice(i, i + 5)));
  }
  if (foot) kids.push(sepC(false), textC(foot));
  hardFit(kids);
  return { flags: FLAG_V2, components: [{ type: 17, accent_color: COLORS[spec.kind] ?? COLORS.info, components: kids }] };
}

// last line of defence: never exceed Discord's text limit, never leave a code fence open
function hardFit(kids) {
  const texts = kids.filter((k) => k.type === 10);
  const total = () => texts.reduce((n, k) => n + k.content.length, 0);
  let over = total() - MAX_TEXT;
  while (over > 0) {
    const t = texts.reduce((a, b) => (b.content.length > a.content.length ? b : a));
    let c = t.content.slice(0, Math.max(40, t.content.length - over - 8)) + '…';
    if ((c.match(/```/g) || []).length % 2) c += '\n```';
    t.content = c;
    const next = total() - MAX_TEXT;
    if (next >= over) break;
    over = next;
  }
}

// ------------------------------------------------------------------ classic embed rendering (fallback)
export function toClassic(spec, { interactive = true } = {}) {
  const now = spec.now ?? Date.now();
  const desc = [spec.subtitle ? `*${spec.subtitle}*` : '', spec.lead || ''].filter(Boolean).join('\n\n');
  const fields = (spec.sections || []).slice(0, 24).map((s) => {
    const value = s.code !== undefined && s.code !== null ? block(s.code, 950) : sectionBody(s, 950);
    return { name: clip(s.heading || '\u200b', 256), value: clip(value || '\u200b', 1024), inline: false };
  });
  const buttons = (spec.buttons || []).filter(Boolean);
  if (!interactive) {
    const links = buttons.filter((b) => b.url).map((b) => `[${b.label}](${b.url})`);
    if (links.length) fields.push({ name: 'روابط', value: clip(links.join(' · '), 1024), inline: false });
  }
  const payload = {
    embeds: [
      {
        title: clip(spec.title, 256),
        description: clip(desc, 4000) || undefined,
        color: COLORS[spec.kind] ?? COLORS.info,
        fields,
        timestamp: new Date(now).toISOString(),
        footer: { text: spec.footer === false ? 'Ryder' : spec.footer ?? 'Ryder' },
      },
    ],
  };
  if (interactive && buttons.length) {
    payload.components = [];
    for (let i = 0; i < buttons.length && i < 10; i += 5) payload.components.push(rowC(buttons.slice(i, i + 5)));
  }
  return payload;
}

export const uiMode = (env) => (String(env?.UI_MODE || 'v2').toLowerCase() === 'classic' ? 'classic' : 'v2');
export const render = (spec, mode = 'v2') => (mode === 'classic' ? toClassic(spec) : toV2(spec));

// ------------------------------------------------------------------ webhook delivery (V2 first, classic embed fallback)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function postWebhook(url, spec, { mode = 'v2', username = 'Ryder', fetchImpl = fetch } = {}) {
  const send = async (body, params) => {
    const u = new URL(url);
    u.searchParams.set('wait', 'true');
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
    const init = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, allowed_mentions: { parse: [] }, ...body }) };
    let res = await fetchImpl(u.toString(), init);
    if (res.status === 429) {
      const info = await res.json().catch(() => ({}));
      await sleep(Math.min(5, Math.max(0, Number(info.retry_after) || 1)) * 1000);
      res = await fetchImpl(u.toString(), init);
    }
    return res;
  };

  if (mode === 'v2') {
    try {
      const res = await send(toV2(spec), { with_components: 'true' });
      if (res.ok) return { ok: true, status: res.status, via: 'v2' };
      console.error(JSON.stringify({ level: 'warn', msg: 'v2 webhook rejected, falling back to embed', status: res.status, body: (await res.text()).slice(0, 300) }));
    } catch (e) {
      console.error(JSON.stringify({ level: 'warn', msg: 'v2 webhook failed', err: String(e) }));
    }
  }
  try {
    const res = await send(toClassic(spec, { interactive: false }), {});
    if (!res.ok) console.error(JSON.stringify({ level: 'error', msg: 'embed webhook rejected', status: res.status, body: (await res.text()).slice(0, 300) }));
    return { ok: res.ok, status: res.status, via: 'classic' };
  } catch (e) {
    console.error(JSON.stringify({ level: 'error', msg: 'embed webhook failed', err: String(e) }));
    return { ok: false, status: 0, via: 'classic' };
  }
}

// ------------------------------------------------------------------ shared Arabic wording
export const PRESETS = { minimal: 'أساسي', dev: 'تطوير', 'security-lab': 'مختبر أمني' };
export const presetLabel = (p) => (PRESETS[p] ? `${PRESETS[p]} (${code(p)})` : code(p || 'minimal'));
export const filesAr = (n) => {
  const k = Math.max(0, Number(n) || 0);
  if (k === 0) return 'لا ملفات';
  if (k === 1) return 'ملف واحد';
  if (k === 2) return 'ملفان';
  return k <= 10 ? `${k} ملفات` : `${k} ملفاً`;
};
export const yesNo = (v) => (v === true || v === 'true' ? 'نعم' : 'لا');
export const statusAr = (s) => ({ queued: 'بالانتظار', waiting: 'بالانتظار', requested: 'بالانتظار', pending: 'بالانتظار', in_progress: 'قيد التشغيل' })[s] || s;

// ------------------------------------------------------------------ session events (sent by main.yml through POST /event)
const runBtn = (d) => [link('فتح سجل التشغيل', d.runUrl, '📄')];
const sub = (d, now) => [d.runNumber ? `الجلسة #${d.runNumber}` : '', ts(now, 'R')].filter(Boolean).join(' · ');
const safeHost = (s) => String(s ?? '').replace(/[^0-9A-Za-z.:_-]/g, '').slice(0, 120);

export function eventSpec(type, d = {}, now = Date.now()) {
  switch (type) {
    case 'preparing': {
      const again = Number(d.renewCount) > 0;
      return {
        kind: 'info',
        title: '⏳ جارٍ تجهيز الجلسة',
        subtitle: sub(d, now),
        lead: 'بدأ تجهيز بيئة Windows. ستصلك رسالة أخرى فور جاهزية الاتصال، وعادةً لا يستغرق ذلك سوى بضع دقائق.',
        sections: [
          { heading: 'مراحل التجهيز', text: `${bar(3, 5)} · 3 / 5\n✅ تجهيز النظام وإعدادات RDP\n✅ تثبيت البرامج والأدوات\n⏳ استرجاع الملفات\n⚪ ربط Tailscale\n⚪ جاهزية الاتصال` },
          { heading: 'التفاصيل', facts: [['الإعداد المسبق', presetLabel(d.preset)], ['نوع الجلسة', again ? `مجدَّدة تلقائياً (رقم ${d.renewCount})` : 'جلسة جديدة']] },
        ],
        buttons: runBtn(d),
        now,
      };
    }

    case 'ready': {
      const end = (Number(d.startedAt) || now) + SESSION_LIMIT_MIN * 60000;
      const ip = safeHost(d.ip);
      const pw = d.passwordMode === 'page' ? `صفحة داخل شبكة Tailscale فقط: ${code(d.passwordUrl)}` : `قيمة السر ${code('RDP_PASSWORD')} المحفوظ في المستودع`;
      const max = Number(d.maxRenewals) || 0;
      const renew = d.autoRenew === true || d.autoRenew === 'true' ? (max > 0 ? `مفعّل · استُخدم ${Number(d.renewCount) || 0} من ${max} تجديدات` : 'مفعّل بلا حدّ') : 'معطّل';
      const files = d.dropFiles !== undefined ? `Drop: ${filesAr(d.dropFiles)} · Work: ${d.work === 'restored' ? 'استُرجع' : 'لا توجد نسخة سابقة'}` : '';
      return {
        kind: 'ok',
        title: '🟢 الجلسة جاهزة للاتصال',
        subtitle: sub(d, now),
        lead: 'اتصل الآن عبر تطبيق **Windows App** أو أي عميل Remote Desktop باستخدام البيانات التالية.',
        sections: [
          { heading: 'بيانات الاتصال', facts: [['العنوان', code(ip)], ['الاسم', code(safeHost(d.name))], ['المستخدم', code(d.user || 'RDP')], ['كلمة المرور', pw]] },
          { heading: 'اتصال سريع', text: `من Windows، شغّل الأمر التالي في نافذة Run أو Terminal:\n\`\`\`\nmstsc /v:${ip}\n\`\`\`` },
          {
            heading: 'الجلسة',
            facts: [['تنتهي', `${ts(end, 'R')} (${ts(end, 't')})`], ['التجديد التلقائي', renew], ['الإعداد المسبق', presetLabel(d.preset)], files ? ['الملفات', files] : null],
          },
        ],
        buttons: runBtn(d),
        now,
      };
    }

    case 'time_warning': {
      const m = Number(d.minutes) || 0;
      const label = m === 2 ? 'دقيقتان' : m >= 3 && m <= 10 ? `${m} دقائق` : `${m} دقيقة`;
      const renewed = d.renewed === true || d.renewed === 'true';
      const backup = d.backup === true || d.backup === 'true';
      const items = renewed
        ? ['تسترجع الجلسة الجديدة آخر نسخة محفوظة من Work.', 'تُرفع ملفات Outbox كالمعتاد حتى لحظة الانتهاء.']
        : backup
          ? [`يُنسخ مجلد ${code('C:\\Work')} احتياطياً تلقائياً عند الإغلاق.`, 'تُرفع ملفات Outbox تلقائياً.']
          : ['النسخ الاحتياطي معطّل لأن السر FILES_PAT غير مضبوط، فاحفظ ملفاتك يدوياً.'];
      return {
        kind: m <= 2 ? 'err' : 'warn',
        title: `⏰ تبقّى ${label} على انتهاء الجلسة`,
        subtitle: sub(d, now),
        lead: renewed ? 'توشك هذه الجلسة على الانتهاء. تابع عملك في الجلسة الجديدة التي بدأت تلقائياً.' : 'احفظ عملك الآن، فالجلسة توشك على الانتهاء.',
        sections: [{ heading: 'ما يُحفظ تلقائياً', items }],
        buttons: runBtn(d),
        compact: true,
        now,
      };
    }

    case 'renew_started':
      return {
        kind: 'info',
        title: '🔁 بدأت جلسة جديدة تلقائياً',
        subtitle: sub(d, now),
        lead: 'بدأ تجهيز جلسة بديلة قبل انتهاء هذه الجلسة. ستصلك رسالة «الجلسة جاهزة» بعد دقائق، وعندها انتقل إليها.',
        sections: [
          { heading: 'رقم التجديد', text: `${RLM}${Number(d.next) || 1} من ${Number(d.max) > 0 ? Number(d.max) : 'بلا حدّ'}` },
          { heading: 'ما يجب أن تعرفه', items: [`لم تعد تغييرات ${code('C:\\Work')} في هذه الجلسة تُحفظ تلقائياً؛ حُفظت آخر نسخة قبل التجديد.`, 'تُرفع ملفات Outbox كالمعتاد حتى انتهاء هذه الجلسة.'] },
        ],
        buttons: runBtn(d),
        now,
      };

    case 'renew_limit':
      return {
        kind: 'warn',
        title: '⚠️ بلغتَ حدّ التجديد التلقائي',
        subtitle: sub(d, now),
        lead: `بلغ عدد التجديدات ${Number(d.count) || 0} من أصل ${Number(d.max) || 0}، ولن تُنشأ جلسة جديدة تلقائياً.`,
        sections: [{ heading: 'ماذا تفعل؟', items: [`أطلق ${code('/start')} لمتابعة العمل.`, `ارفع ${code('max_renewals')} أو اجعله ${code('0')} لإلغاء الحدّ.`] }],
        buttons: runBtn(d),
        compact: true,
        now,
      };

    case 'renew_failed':
      return {
        kind: 'err',
        title: '❌ تعذّر التجديد التلقائي',
        subtitle: sub(d, now),
        lead: `جرت ${Number(d.tries) || 3} محاولات دون نجاح، لذا ستنتهي الجلسة في موعدها المحدد.`,
        sections: [{ heading: 'الحل المقترح', items: [`تحقّق من أن الـ workflow يملك الصلاحية ${code('actions: write')}.`, `أو أطلق ${code('/start')} يدوياً قبل انتهاء الجلسة.`] }],
        buttons: runBtn(d),
        compact: true,
        now,
      };

    case 'backup_failed':
      return {
        kind: 'warn',
        title: '⚠️ تعذّر حفظ مجلد Work',
        subtitle: sub(d, now),
        lead: 'لم تُحفظ النسخة الاحتياطية الأخيرة. ستُعاد المحاولة تلقائياً بعد نحو 10 دقائق.',
        sections: [{ heading: 'تفاصيل الخطأ', code: d.error || 'غير معروف', codeMax: 1200 }],
        buttons: runBtn(d),
        compact: true,
        now,
      };

    case 'exec_started':
      return { kind: 'info', title: '🔧 جارٍ تنفيذ أمر', subtitle: sub(d, now), sections: [{ heading: 'الأمر', code: d.command || '', codeMax: 1500 }], compact: true, now };

    case 'exec_result': {
      const timedOut = d.timedOut === true || d.timedOut === 'true';
      return {
        kind: timedOut ? 'warn' : 'ok',
        title: timedOut ? '⏱️ انتهت مهلة الأمر' : '✅ اكتمل تنفيذ الأمر',
        subtitle: sub(d, now),
        sections: [{ heading: 'المخرجات', code: d.output || '(لا توجد مخرجات)', codeMax: 2400 }],
        compact: true,
        now,
      };
    }

    case 'ended': {
      const st = String(d.status || 'success');
      const renewed = d.renewed === true || d.renewed === 'true';
      const lead =
        st === 'cancelled'
          ? 'أُنهيت الجلسة بالإلغاء. يرجّح أنها بلغت حدّ GitHub (نحو 6 ساعات) أو أنك أوقفتها يدوياً.'
          : st === 'failure'
            ? 'انتهت الجلسة بخطأ. راجع سجل التشغيل لمعرفة السبب.'
            : 'انتهت الجلسة بنجاح.';
      const dur = Number(d.startedAt) > 0 ? fmtDuration(now - Number(d.startedAt)) : null;
      return {
        kind: st === 'failure' ? 'err' : st === 'cancelled' ? 'warn' : 'idle',
        title: '🔴 انتهت الجلسة',
        subtitle: sub(d, now),
        lead,
        sections: [
          {
            heading: 'الخلاصة',
            facts: [['النتيجة', { success: 'اكتملت', cancelled: 'أُلغيت', failure: 'انتهت بخطأ' }[st] || st], dur ? ['مدة الجلسة', dur] : null, ['الجلسة التالية', renewed ? 'بدأت تلقائياً وتتابع العمل من حيث توقّفت.' : `لا توجد؛ أطلق ${code('/start')} عند الحاجة.`]],
          },
        ],
        buttons: runBtn(d),
        now,
      };
    }

    default:
      return d.title ? { kind: 'info', title: clip(d.title, 200), lead: clip(d.text || '', 1500), now } : null;
  }
}

// ------------------------------------------------------------------ audit log entry (log channel)
export function auditSpec(e, now = Date.now()) {
  const denied = !!e.denied;
  const failed = e.ok === false;
  const name = e.command ? `/${e.command}` : e.action || 'غير معروف';
  const opts = Object.entries(e.options || {}).map(([k, v]) => `${k}=${v}`).join(' ');
  return {
    kind: denied ? 'warn' : failed ? 'err' : 'info',
    title: denied ? '⛔ محاولة غير مصرّح بها' : `${failed ? '❌' : '✅'} ${name}`,
    compact: true,
    sections: [
      {
        facts: [
          ['المنفّذ', `<@${e.user}> ${code(e.user)}`],
          ['النتيجة', denied ? 'مرفوض' : failed ? 'فشل' : 'نجح'],
          denied && name !== 'غير معروف' ? ['الأمر', code(name)] : null,
          e.ms !== undefined ? ['الزمن', `${e.ms} ms`] : null,
          opts ? ['الخيارات', code(clip(opts, 300))] : null,
          e.errorId ? ['معرّف الخطأ', code(e.errorId)] : null,
        ],
      },
      e.detail ? { heading: 'التفاصيل', code: e.detail, codeMax: 900 } : null,
    ].filter(Boolean),
    footer: 'Ryder · سجلّ التدقيق',
    now,
  };
}
