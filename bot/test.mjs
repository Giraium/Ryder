// Ryder bot tests - no network, no secrets. Run from the bot folder:  node --test test.mjs
//   1) every message the project can send is checked against Discord's documented limits (Components V2 and classic embeds)
//   2) the Worker runs end to end with real Ed25519 / HMAC signatures and a fake GitHub + Discord
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import * as ui from './ui.mjs';
import worker from './worker.js';

// ------------------------------------------------------------------ validators (limits from Discord's component reference)
const V2_CHILDREN = new Set([1, 9, 10, 12, 13, 14]); // allowed inside a Container
function walk(c, fn) {
  fn(c);
  for (const k of c.components || []) walk(k, fn);
}
function validateV2(p) {
  assert.equal(p.flags & ui.FLAG_V2, ui.FLAG_V2, 'IS_COMPONENTS_V2 flag missing');
  assert.ok(!('content' in p) && !('embeds' in p), 'content/embeds are not allowed with V2');
  assert.ok(Array.isArray(p.components) && p.components.length >= 1);
  let count = 0;
  let text = 0;
  for (const top of p.components) {
    assert.equal(top.type, 17, 'top level must be a Container');
    assert.ok(Number.isInteger(top.accent_color) && top.accent_color >= 0 && top.accent_color <= 0xffffff);
    for (const k of top.components) assert.ok(V2_CHILDREN.has(k.type), `bad container child type ${k.type}`);
    walk(top, (c) => {
      count++;
      if (c.type === 10) {
        assert.equal(typeof c.content, 'string');
        assert.ok(c.content.length > 0, 'empty text display');
        text += c.content.length;
      }
      if (c.type === 14) assert.ok([1, 2].includes(c.spacing ?? 1));
      if (c.type === 1) {
        assert.ok(c.components.length >= 1 && c.components.length <= 5, 'action row holds 1-5 buttons');
        assert.ok(c.components.every((b) => b.type === 2));
      }
      if (c.type === 2) {
        assert.ok(c.label && c.label.length <= 80, 'button label');
        if (c.style === 5) {
          assert.ok(/^https?:\/\//.test(c.url) && c.url.length <= 512, 'link button url');
          assert.ok(!('custom_id' in c), 'link button must not have custom_id');
        } else {
          assert.ok(c.custom_id && c.custom_id.length <= 100, 'custom_id');
          assert.ok(!('url' in c), 'interactive button must not have url');
          assert.ok([1, 2, 3, 4].includes(c.style));
        }
      }
    });
  }
  assert.ok(count <= 40, `too many components: ${count}`);
  assert.ok(text <= 4000, `text displays total ${text} > 4000`);
  return { count, text };
}
function validateEmbed(p) {
  assert.ok(Array.isArray(p.embeds) && p.embeds.length === 1);
  const e = p.embeds[0];
  assert.ok(e.title.length <= 256);
  assert.ok((e.description || '').length <= 4096);
  assert.ok((e.fields || []).length <= 25);
  let total = e.title.length + (e.description || '').length + (e.footer?.text.length || 0);
  for (const f of e.fields || []) {
    assert.ok(f.name.length >= 1 && f.name.length <= 256 && f.value.length >= 1 && f.value.length <= 1024, 'field limits');
    total += f.name.length + f.value.length;
  }
  assert.ok(total <= 6000, `embed total ${total} > 6000`);
}

// ------------------------------------------------------------------ sample data
const long = (n, ch = 'x') => ch.repeat(n);
const EVENTS = {
  preparing: { preset: 'security-lab', renewCount: 2, runUrl: 'https://github.com/o/r/actions/runs/1', runNumber: '12' },
  ready: { name: 'ryder.tail1234.ts.net', ip: '100.64.0.7', user: 'RDP', passwordMode: 'page', passwordUrl: 'http://100.64.0.7:8080/', runUrl: 'https://github.com/o/r/actions/runs/1', runNumber: '12', startedAt: Date.now() - 600000, preset: 'dev', autoRenew: true, renewCount: 1, maxRenewals: 8, dropFiles: 3, work: 'restored' },
  time_warning: { minutes: 10, renewed: false, backup: true, runUrl: 'https://github.com/o/r/actions/runs/1' },
  renew_started: { next: 2, max: 8, runUrl: 'https://github.com/o/r/actions/runs/1' },
  renew_limit: { count: 8, max: 8, runUrl: 'https://github.com/o/r/actions/runs/1' },
  renew_failed: { tries: 3, runUrl: 'https://github.com/o/r/actions/runs/1' },
  backup_failed: { error: 'gh: HTTP 403 ' + long(5000), runUrl: 'https://github.com/o/r/actions/runs/1' },
  exec_started: { command: 'Get-Process | Sort CPU -desc | select -first 5 ' + long(3000) },
  exec_result: { output: long(9000, 'ا\n'), timedOut: false },
  ended: { status: 'cancelled', renewed: true, startedAt: Date.now() - 5.5 * 3600000, runUrl: 'https://github.com/o/r/actions/runs/1', runNumber: '12' },
};

test('every session event renders a valid V2 card and a valid classic embed', () => {
  for (const [type, data] of Object.entries(EVENTS)) {
    const spec = ui.eventSpec(type, data, Date.now());
    assert.ok(spec, `no spec for ${type}`);
    validateV2(ui.toV2(spec));
    validateEmbed(ui.toClassic(spec));
    validateEmbed(ui.toClassic(spec, { interactive: false }));
  }
});

test('time warnings: Arabic plurals and urgency colour', () => {
  const t = (m) => ui.eventSpec('time_warning', { minutes: m }, 0);
  assert.match(t(10).title, /10 دقائق/);
  assert.match(t(5).title, /5 دقائق/);
  assert.match(t(2).title, /دقيقتان/);
  assert.equal(t(10).kind, 'warn');
  assert.equal(t(2).kind, 'err');
});

test('ready card never contains the password and carries the quick-connect command', () => {
  const spec = ui.eventSpec('ready', { ...EVENTS.ready, passwordMode: 'secret' }, Date.now());
  const all = JSON.stringify(ui.toV2(spec));
  assert.match(all, /mstsc \/v:100\.64\.0\.7/);
  assert.ok(!/password"?\s*:/i.test(all));
});

test('hostile values cannot break the code fence or smuggle markdown links', () => {
  const spec = ui.eventSpec('ready', { ...EVENTS.ready, ip: '1.2.3.4`\n```\n[x](http://evil)', name: 'a b`c' }, Date.now());
  const p = ui.toV2(spec);
  validateV2(p);
  const txt = JSON.stringify(p);
  assert.ok(!txt.includes('http://evil'), 'unsanitised value leaked');
});

test('oversized spec is trimmed to the 4000 character limit without an open code fence', () => {
  const spec = { kind: 'info', title: 'x', lead: long(1500), sections: [{ heading: 'a', text: long(1500) }, { heading: 'b', code: long(9000) }], now: 0 };
  const p = ui.toV2(spec);
  const { text } = validateV2(p);
  assert.ok(text <= 4000);
  for (const c of p.components[0].components.filter((k) => k.type === 10)) assert.equal((c.content.match(/```/g) || []).length % 2, 0);
});

test('audit entries render (ok, failed, denied)', () => {
  for (const e of [
    { command: 'start', user: '1', ok: true, ms: 120, options: { preset: 'dev' } },
    { command: 'status', user: '1', ok: false, ms: 80, errorId: 'ab12cd34' },
    { command: 'exec', user: '1', denied: true },
    { command: 'exec', user: '1', ok: true, options: { id: 'x' }, detail: 'Get-Date' },
  ]) {
    validateV2(ui.toV2(ui.auditSpec(e, Date.now())));
    validateEmbed(ui.toClassic(ui.auditSpec(e, Date.now())));
  }
});

test('helpers', () => {
  assert.equal(ui.fmtDuration(45 * 60000), '45 د');
  assert.equal(ui.fmtDuration(125 * 60000), '2 س 5 د');
  assert.equal(ui.fmtDuration(120 * 60000), '2 س');
  assert.equal(ui.bar(5, 10), '▰▰▰▰▰▱▱▱▱▱');
  assert.equal(ui.bar(99, 10), '▰'.repeat(10));
  assert.equal(ui.ts(1700000000999, 'R'), '<t:1700000000:R>');
  assert.equal(ui.link('x', 'javascript:alert(1)'), null);
  assert.equal(ui.link('x', 'https://' + long(600)), null);
});

// ------------------------------------------------------------------ the Worker, end to end
const NOW = Date.now();
const iso = (msAgo) => new Date(NOW - msAgo).toISOString();
const RUN = (over = {}) => ({ id: 777, run_number: 12, status: 'in_progress', conclusion: null, html_url: 'https://github.com/o/r/actions/runs/777', created_at: iso(3600000), run_started_at: iso(3600000), updated_at: iso(1000), ...over });
const DONE = RUN({ id: 700, run_number: 11, status: 'completed', conclusion: 'cancelled', updated_at: iso(7200000), run_started_at: iso(7200000 + 355 * 60000) });
// real step names from .github/workflows/main.yml (the Worker matches them by substring; a test below keeps them in sync)
const REAL_STEPS = ['Configure Core RDP Settings', 'Create RDP User', 'Tune display, quality and speed', 'Write helper library', 'Provision apps and dev environment', 'Restore files (Drop + Work)', 'Install Tailscale', 'Establish Tailscale Connection', 'Verify RDP Accessibility', 'Announce ready'];
const JOB = (stepsDone, maintain = false) => ({
  jobs: [
    {
      id: 9,
      status: 'in_progress',
      started_at: iso(3000000),
      steps: [
        ...REAL_STEPS.map((name, i) => ({ name, status: i < stepsDone ? 'completed' : i === stepsDone ? 'in_progress' : 'queued' })),
        { name: 'Maintain Connection + Watchdog', status: maintain ? 'in_progress' : 'queued' },
      ],
    },
  ],
});

let keys;
let env;
let calls;
let scenario;
const jsonRes = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json' } });

function installFetch() {
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    const method = init.method || 'GET';
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ url: u, method, body });
    if (u.startsWith('https://api.github.com')) {
      if (/\/workflows\/main\.yml\/runs/.test(u)) return jsonRes({ workflow_runs: scenario.runs });
      if (/\/runs\/\d+\/jobs/.test(u)) return jsonRes(scenario.jobs);
      if (/\/workflows\/main\.yml\/dispatches/.test(u)) return new Response(null, { status: scenario.dispatchStatus ?? 204 });
      if (/\/runs\/\d+\/cancel/.test(u)) return new Response('{}', { status: 202 });
      if (/\/jobs\/9\/logs/.test(u)) return new Response(null, { status: 302, headers: { location: 'https://logs.test/raw' } });
      if (/contents\/control\/cmd\.json/.test(u)) return method === 'GET' ? new Response('{}', { status: 404 }) : jsonRes({ ok: true }, 201);
    }
    if (u === 'https://logs.test/raw') return new Response('2026-11-26T08:00:00.0000000Z Starting\n2026-11-26T08:00:01.0000000Z token ghp_abcdefghijklmnopqrstuvwx and https://discord.com/api/webhooks/1/SECRETTOKEN here\n2026-11-26T08:00:02.0000000Z done');
    if (u.includes('/messages/@original')) return scenario.patchStatus?.(body) ? new Response('{"message":"bad"}', { status: scenario.patchStatus(body) }) : jsonRes({ id: 'm' });
    if (u.startsWith('https://discord.com/api/webhooks/')) {
      const withComponents = new URL(u).searchParams.get('with_components') === 'true';
      if (withComponents && scenario.rejectV2) return new Response('{"message":"Invalid Form Body"}', { status: 400 });
      return jsonRes({ id: 'w' });
    }
    return new Response('not mocked: ' + u, { status: 599 });
  };
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

async function signedRequest(interaction) {
  const body = JSON.stringify(interaction);
  const t = String(Math.floor(Date.now() / 1000));
  const sig = await crypto.subtle.sign('Ed25519', keys.privateKey, new TextEncoder().encode(t + body));
  return new Request('https://bot.test/', { method: 'POST', headers: { 'x-signature-ed25519': hex(sig), 'x-signature-timestamp': t }, body });
}

async function call(interaction, extraEnv = {}) {
  const pending = [];
  const res = await worker.fetch(await signedRequest(interaction), { ...env, ...extraEnv }, { waitUntil: (p) => pending.push(p) });
  const out = res.headers.get('content-type')?.includes('json') ? await res.json() : await res.text();
  await Promise.all(pending);
  return { status: res.status, out };
}

const cmd = (name, options = [], user = 'u1', guild = 'g1') => ({ type: 2, token: 'tok', guild_id: guild, member: { user: { id: user } }, data: { name, options } });
const click = (custom_id, user = 'u1') => ({ type: 3, token: 'tok', guild_id: 'g1', member: { user: { id: user } }, data: { custom_id } });
const patches = () => calls.filter((c) => c.method === 'PATCH' && c.url.includes('@original'));
const lastPatch = () => patches().at(-1).body;

test.beforeEach(async () => {
  if (!keys) keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pub = hex(await crypto.subtle.exportKey('raw', keys.publicKey));
  env = { APP_ID: '111', GUILD_ID: 'g1', OWNER_ID: 'u1', DISCORD_PUBLIC_KEY: pub, REPO: 'o/r', WORKFLOW: 'main.yml', REF: 'main', FILES_REPO: 'o/f', ENABLE_EXEC: 'false', GH_BOT_PAT: 'x', FILES_PAT: 'y', DISCORD_LOG_WEBHOOK: 'https://discord.com/api/webhooks/2/logtoken', DISCORD_NOTIFY_WEBHOOK: 'https://discord.com/api/webhooks/3/notifytoken' };
  calls = [];
  scenario = { runs: [RUN(), DONE], jobs: JOB(5) };
  installFetch();
});

test('PING and bad signatures', async () => {
  assert.deepEqual((await call({ type: 1 })).out, { type: 1 });
  const bad = await worker.fetch(new Request('https://bot.test/', { method: 'POST', headers: { 'x-signature-ed25519': '00', 'x-signature-timestamp': '1' }, body: '{}' }), env, { waitUntil() {} });
  assert.equal(bad.status, 401);
});

test('replies are PUBLIC by default (no ephemeral flag) and PUBLIC_REPLIES=false makes them private', async () => {
  const a = await call(cmd('help'));
  assert.deepEqual(a.out, { type: 5 });
  const b = await call(cmd('help'), { PUBLIC_REPLIES: 'false' });
  assert.deepEqual(b.out, { type: 5, data: { flags: 64 } });
});

test('refusals stay private: wrong user and wrong server', async () => {
  for (const c of [cmd('status', [], 'intruder'), cmd('status', [], 'u1', 'other-guild')]) {
    const r = await call(c);
    assert.equal(r.out.type, 4);
    assert.equal(r.out.data.flags & 64, 64, 'ephemeral');
    validateV2({ flags: r.out.data.flags & ~64, components: r.out.data.components });
  }
  assert.equal(patches().length, 0, 'an intruder must never reach GitHub');
});

test('every slash command produces a valid V2 card', async () => {
  for (const [name, options] of [['help', []], ['status', []], ['stop', []], ['history', []], ['logs', [{ name: 'lines', value: 20 }]], ['start', [{ name: 'preset', value: 'security-lab' }, { name: 'extra_tools', value: 'nmap,7zip' }]], ['exec', [{ name: 'command', value: 'Get-Date' }]]]) {
    calls = [];
    await call(cmd(name, options));
    assert.equal(patches().length, 1, `${name}: one edit`);
    validateV2(lastPatch());
  }
});

test('/status shows live progress, remaining time and the three buttons', async () => {
  scenario.jobs = JOB(5);
  await call(cmd('status'));
  const p = lastPatch();
  validateV2(p);
  const txt = JSON.stringify(p);
  assert.match(txt, /الجلسة #12 قيد التجهيز/);
  assert.match(txt, /استرجاع الملفات/);
  assert.match(txt, /5 \/ 11/);
  assert.match(txt, /status:refresh/);
  assert.match(txt, /stop:ask/);
  assert.match(txt, /<t:\d+:R>/);
  scenario.jobs = JOB(10, true);
  await call(cmd('status'));
  assert.match(JSON.stringify(lastPatch()), /جاهزة للاتصال/);
});

test('/status with no active session offers a one-tap start', async () => {
  scenario.runs = [DONE];
  await call(cmd('status'));
  const txt = JSON.stringify(lastPatch());
  assert.match(txt, /لا توجد جلسة جارية/);
  assert.match(txt, /start:quick/);
});

test('/start dispatches the workflow with the chosen inputs and shows a summary', async () => {
  scenario.runs = [DONE];
  await call(cmd('start', [{ name: 'preset', value: 'security-lab' }, { name: 'max_renewals', value: 3 }]));
  const d = calls.find((c) => c.url.endsWith('/dispatches'));
  assert.equal(d.body.inputs.preset, 'security-lab');
  assert.equal(d.body.inputs.max_renewals, '3');
  assert.equal(d.body.inputs.remote_exec, 'false');
  assert.match(JSON.stringify(lastPatch()), /أُرسل أمر التشغيل/);
});

test('/start refuses while a session is running, and rejects bad package names', async () => {
  await call(cmd('start'));
  assert.ok(!calls.some((c) => c.url.endsWith('/dispatches')));
  assert.match(JSON.stringify(lastPatch()), /توجد جلسة جارية/);
  scenario.runs = [DONE];
  calls = [];
  await call(cmd('start', [{ name: 'extra_tools', value: 'x; rm -rf /' }]));
  assert.ok(!calls.some((c) => c.url.endsWith('/dispatches')));
});

test('/start GitHub failure becomes a friendly error card with an error id', async () => {
  scenario.runs = [DONE];
  scenario.dispatchStatus = 422;
  await call(cmd('start'));
  const txt = JSON.stringify(lastPatch());
  assert.match(txt, /تعذّر تنفيذ الأمر/);
  assert.match(txt, /معرّف الخطأ [0-9a-f]{8}/);
});

test('/stop asks for confirmation, and only the confirm button cancels', async () => {
  await call(cmd('stop'));
  assert.ok(!calls.some((c) => c.url.endsWith('/cancel')));
  const txt = JSON.stringify(lastPatch());
  assert.match(txt, /stop:all/);
  assert.match(txt, /stop:cancel/);
  const r = await call(click('stop:all'));
  assert.deepEqual(r.out, { type: 6 });
  assert.equal(calls.filter((c) => c.url.endsWith('/runs/777/cancel')).length, 1);
  calls = [];
  await call(click('stop:cancel'));
  assert.ok(!calls.some((c) => c.url.endsWith('/cancel')));
});

test('buttons from an intruder are refused', async () => {
  const r = await call(click('stop:all', 'intruder'));
  assert.equal(r.out.data.flags & 64, 64);
  assert.ok(!calls.some((c) => c.url.endsWith('/cancel')));
});

test('/logs masks tokens and webhooks before they reach the channel', async () => {
  await call(cmd('logs'));
  const p = lastPatch();
  validateV2(p);
  const txt = JSON.stringify(p);
  assert.ok(!txt.includes('ghp_abcdefghijklmnopqrstuvwx'));
  assert.ok(!txt.includes('SECRETTOKEN'));
  assert.match(txt, /\[token\]/);
  assert.match(txt, /\[webhook\]/);
  assert.match(txt, /logs:20|logs:40/);
});

test('/history lists runs with statistics', async () => {
  await call(cmd('history'));
  const txt = JSON.stringify(lastPatch());
  assert.match(txt, /إحصاءات/);
  assert.match(txt, /#12/);
  assert.match(txt, /#11/);
});

test('/exec is disabled by default; when enabled the command text only goes to the log channel', async () => {
  await call(cmd('exec', [{ name: 'command', value: 'Get-Date' }]));
  assert.match(JSON.stringify(lastPatch()), /الأمر معطّل/);
  calls = [];
  await call(cmd('exec', [{ name: 'command', value: 'Get-Secret-Thing' }]), { ENABLE_EXEC: 'true' });
  const reply = JSON.stringify(lastPatch());
  assert.ok(!reply.includes('Get-Secret-Thing'), 'public reply must not echo the command');
  const logPost = calls.find((c) => c.url.startsWith('https://discord.com/api/webhooks/2/'));
  assert.ok(logPost && JSON.stringify(logPost.body).includes('Get-Secret-Thing'), 'log channel keeps the audit trail');
});

test('audit goes to the log channel as a V2 card (and falls back to an embed if rejected)', async () => {
  await call(cmd('help'));
  const post = calls.find((c) => c.url.startsWith('https://discord.com/api/webhooks/2/'));
  assert.ok(post.url.includes('with_components=true'));
  validateV2(post.body);
  calls = [];
  scenario.rejectV2 = true;
  await call(cmd('help'));
  const posts = calls.filter((c) => c.url.startsWith('https://discord.com/api/webhooks/2/'));
  assert.equal(posts.length, 2);
  assert.ok(posts[1].body.embeds);
});

test('if Discord rejects the V2 edit, the reply is retried as a classic embed', async () => {
  scenario.patchStatus = (b) => (b.flags & ui.FLAG_V2 ? 400 : 0);
  await call(cmd('help'));
  assert.equal(patches().length, 2);
  validateEmbed(lastPatch());
});

test('UI_MODE=classic never sends V2', async () => {
  await call(cmd('status'), { UI_MODE: 'classic' });
  const p = lastPatch();
  assert.ok(p.embeds && !p.flags);
  validateEmbed(p);
});

// ------------------------------------------------------------------ /event (workflow -> Worker)
function eventRequest(payload, { key = 'https://discord.com/api/webhooks/3/notifytoken', t = String(Math.floor(Date.now() / 1000)), tamper = false } = {}) {
  const body = JSON.stringify(payload);
  const sig = createHmac('sha256', key).update(`${t}.${body}`).digest('hex'); // same recipe as Send-Event in main.yml
  return new Request('https://bot.test/event', { method: 'POST', headers: { 'x-ryder-ts': t, 'x-ryder-sig': sig }, body: tamper ? body.replace('ready', 'ended') : body });
}

test('/event: a correctly signed event is rendered and posted to the notify webhook', async () => {
  const res = await worker.fetch(eventRequest({ type: 'ready', ...EVENTS.ready }), env, { waitUntil() {} });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, via: 'v2' });
  const post = calls.find((c) => c.url.startsWith('https://discord.com/api/webhooks/3/'));
  assert.ok(post.url.includes('with_components=true') && post.url.includes('wait=true'));
  validateV2(post.body);
  assert.match(JSON.stringify(post.body), /الجلسة جاهزة للاتصال/);
});

test('/event: bad signature, wrong key, stale timestamp, tampered body, unknown type, missing secret', async () => {
  const ctx = { waitUntil() {} };
  assert.equal((await worker.fetch(eventRequest({ type: 'ready' }, { key: 'wrong' }), env, ctx)).status, 401);
  assert.equal((await worker.fetch(eventRequest({ type: 'ready' }, { t: '1000' }), env, ctx)).status, 401);
  assert.equal((await worker.fetch(eventRequest({ type: 'ready' }, { tamper: true }), env, ctx)).status, 401);
  assert.equal((await worker.fetch(eventRequest({ type: 'nope' }), env, ctx)).status, 400);
  assert.equal((await worker.fetch(eventRequest({ type: 'ready' }), { ...env, DISCORD_NOTIFY_WEBHOOK: '' }, ctx)).status, 503);
  assert.equal(calls.filter((c) => c.url.startsWith('https://discord.com/api/webhooks/3/')).length, 0, 'nothing may be posted for rejected events');
});

test('/event: if Discord rejects V2 the same event is delivered as an embed', async () => {
  scenario.rejectV2 = true;
  const res = await worker.fetch(eventRequest({ type: 'ended', ...EVENTS.ended }), env, { waitUntil() {} });
  assert.deepEqual(await res.json(), { ok: true, via: 'classic' });
  const posts = calls.filter((c) => c.url.startsWith('https://discord.com/api/webhooks/3/'));
  assert.equal(posts.length, 2);
  validateEmbed(posts[1].body);
});

test('step names the Worker relies on still exist in main.yml', async () => {
  const { readFile } = await import('node:fs/promises');
  let yml;
  try {
    yml = await readFile(new URL('../.github/workflows/main.yml', import.meta.url), 'utf8');
  } catch {
    return; // running outside the repo: nothing to compare
  }
  for (const name of [...REAL_STEPS, 'Maintain Connection + Watchdog']) assert.ok(yml.includes(`- name: ${name}`), `main.yml has no step named "${name}" - update PHASES in worker.js`);
});
