// Chaos & regression checks for the Phase 1 security patches, run against the REAL handlers (in-memory Supabase):
//   F-09 emailed step-up when the authenticator is off, F-10 whole-file PDF scanning, F-11 server-side photo cleaning,
//   plus concurrent payment confirmation and the app-level legal hold guards.
// (The legal hold database triggers themselves live in Postgres; the fake database can't run them.)
// Run with: node --experimental-test-module-mocks scripts/check-chaos.mjs
import { mock } from 'node:test';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { createFakeSupabase } from './fake-supabase.mjs';

const db = createFakeSupabase();
mock.module('@supabase/supabase-js', { namedExports: { createClient: () => db } });
const stripeSessions = new Map();   // id -> { id, status, payment_status, amount_total, url }
let stripeCreated = 0;
mock.module('stripe', { defaultExport: class { constructor() { this.checkout = { sessions: {
    expire: async (id) => { const x = stripeSessions.get(id); if (x) x.status = 'expired'; return x || {}; },
    retrieve: async (id) => stripeSessions.get(id) || null,
    create: async (params) => {
        const id = `cs_test_new_${++stripeCreated}_abcdefgh`;
        const x = { id, status: 'open', payment_status: 'unpaid', amount_total: params.line_items?.[0]?.price_data?.unit_amount, url: `https://checkout.stripe.test/${id}` };
        stripeSessions.set(id, x); return x;
    },
} }; } } });
Object.assign(process.env, { SUPABASE_SERVICE_ROLE_KEY: 'test-service-role', APP_SECRET: 'test-app-secret', RESEND_API_KEY: 're_test_fake', STRIPE_SECRET_KEY: 'sk_test_fake' });
delete process.env.ADMIN_EMAILS;
delete process.env.VERCEL_ENV;

const emails = [];
globalThis.fetch = async (url, init) => {
    if (String(url).includes('resend.com')) emails.push(JSON.parse(init.body));
    return new Response('{}', { status: 200 });
};

const core = await import('../api/_lib/core.mjs');
const orders = await import('../api/_lib/orders.mjs');
const { stripPhotoMetadata } = await import('../api/_lib/photo-meta.mjs');
const { POST: adminPOST } = await import('../api/admin.mjs');
const { POST: trackPOST } = await import('../api/track.mjs');
const browser = { window: {}, TextDecoder, TextEncoder, DataView, Uint8Array, File, fetch: () => {} };
vm.runInNewContext(`${await readFile(new URL('../assets/js/nps.js', import.meta.url), 'utf8')}\nthis.NPS = NPS;`, browser);

let passed = 0;
const failures = [];
async function check(name, fn) {
    db.__reset(); emails.length = 0; stripeSessions.clear();
    try { await fn(); passed++; console.log(`PASS ${name}`); } catch (err) { failures.push(name); console.log(`FAIL ${name}\n     ${err.message}`); }
}
function expect(cond, msg) { if (!cond) throw new Error(msg); }

const ADMIN = 'nicksprocessservices@outlook.com';
const tables = () => db.__state.tables;
const post = (body, cookie) => new Request('https://site.test/api/admin', {
    method: 'POST', headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body),
});
const admin = (body, cookie) => adminPOST(post(body, cookie));
function session(token = 'A'.repeat(43)) {
    (tables().admin_sessions ||= []).push({ token_hash: core.sha256(token), email: ADMIN, expires_at: new Date(Date.now() + 864e5).toISOString(), last_seen_at: new Date().toISOString() });
    return `nps_admin=${token}`;
}
function seedOrder(over = {}) {
    const o = { id: randomUUID(), code: 'NP-123456', status: 'received', recipient_name: 'Sam', client_email: 'c@example.com', legal_hold: false,
        paid_at: null, stripe_session_id: null, amount_due_cents: 7500, created_at: new Date().toISOString(), ...over };
    (tables().orders ||= []).push(o);
    return o;
}
const stepUpCodeFromEmail = () => emails.map(e => /confirmation code: (\d{8})/.exec(e.subject)?.[1]).filter(Boolean).pop();

// --- F-09: emailed step-up when the authenticator app is off ---
await check('F-09 deleting a request with the authenticator off needs an emailed code, not just the session', async () => {
    const cookie = session(); const o = seedOrder();
    const res = await admin({ action: 'delete', id: o.id, confirm: o.code }, cookie);
    const body = await res.json();
    expect(res.status === 403 && body.requiresEmailStepUp === true, `${res.status} ${JSON.stringify(body)}`);
    expect(tables().orders.length === 1, 'order was deleted without a step-up');
});
await check('F-09 the emailed code confirms the action, then covers this session for 5 minutes only', async () => {
    const cookie = session(); const a = seedOrder(); const b = seedOrder({ code: 'NP-654321' }); const c = seedOrder({ code: 'NP-111111' });
    expect((await admin({ action: 'send-stepup-code' }, cookie)).status === 200, 'send-stepup-code failed');
    const code = stepUpCodeFromEmail();
    expect(code, 'no code emailed');
    expect((await admin({ action: 'delete', id: a.id, confirm: a.code, totp: code }, cookie)).status === 200, 'right code refused');
    expect((await admin({ action: 'delete', id: b.id, confirm: b.code }, cookie)).status === 200, 'second action inside 5 minutes refused');
    tables().admin_sessions[0].last_step_up_at = new Date(Date.now() - 6 * 60e3).toISOString();
    expect((await admin({ action: 'delete', id: c.id, confirm: c.code }, cookie)).status === 403, 'step-up still counted after 5 minutes');
});
await check('F-09 a step-up code allows 5 guesses and belongs to one session', async () => {
    const mine = session('A'.repeat(43)); const other = session('B'.repeat(43));
    const tryCode = (code, cookie) => admin({ action: 'passkey-remove', id: 'A'.repeat(20), totp: code }, cookie);   // 404 = step-up passed
    await admin({ action: 'send-stepup-code' }, mine);
    const code = stepUpCodeFromEmail();
    expect((await tryCode(code, other)).status === 403, 'code worked on another session');
    for (let i = 0; i < 5; i++) await tryCode('00000000', mine);
    const last = await tryCode(code, mine);
    expect(last.status === 403, `code still worked after 5 wrong guesses (${last.status})`);
    await admin({ action: 'send-stepup-code' }, mine);
    expect((await tryCode(stepUpCodeFromEmail(), mine)).status === 404, 'a fresh code did not work');
});
await check('F-09 a dashboard login code cannot stand in for a step-up code', async () => {
    const cookie = session(); const o = seedOrder();
    (tables().admin_codes ||= []).push({ id: randomUUID(), email: ADMIN, code_hash: core.sha256(`${ADMIN}:12345678`), used: false, attempts: 0,
        expires_at: new Date(Date.now() + 6e5).toISOString(), created_at: new Date().toISOString() });
    expect((await admin({ action: 'delete', id: o.id, confirm: o.code, totp: '12345678' }, cookie)).status === 403, 'login code accepted as step-up');
});
await check('F-09 recovery codes, authenticator setup, passkey removal and legal-hold unlock all ask for the emailed step-up', async () => {
    const cookie = session(); const o = seedOrder({ legal_hold: true, status: 'served' });
    for (const body of [{ action: 'generate-recovery-codes' }, { action: 'totp-setup' }, { action: 'passkey-remove', id: 'A'.repeat(20) },
        { action: 'unlock-legal-hold', id: o.id, hold: false, confirm: o.code }]) {
        const res = await admin(body, cookie);
        const j = await res.json();
        expect(res.status === 403 && j.requiresEmailStepUp, `${body.action}: ${res.status} ${JSON.stringify(j)}`);
    }
    expect(tables().orders[0].legal_hold === true, 'legal hold unlocked without step-up');
});
await check('F-09 step-up codes are limited to 3 emails per 10 minutes', async () => {
    const cookie = session();
    const statuses = [];
    for (let i = 0; i < 4; i++) statuses.push((await admin({ action: 'send-stepup-code' }, cookie)).status);
    expect(statuses.join() === '200,200,200,429', statuses.join());
});

// --- F-10: whole-file PDF scanning ---
// The suspicious part sits in the middle, with padding on both sides, so it is outside the first and last 4 KB.
const pdf = (middle, pad = 0) => Buffer.concat([Buffer.from('%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n'),
    Buffer.alloc(pad, 0x41), Buffer.from(middle), Buffer.alloc(pad ? 50_000 : 0, 0x41), Buffer.from('\n%%EOF\n')]);
await check('F-10 a normal multi-page legal PDF is accepted', async () => {
    const pages = Array.from({ length: 40 }, (_, i) => `${i + 3} 0 obj << /Type /Page /Parent 2 0 R >> endobj\n`).join('');
    expect(core.verifyFileMagic(pdf(`2 0 obj << /Type /Pages /Count 40 >> endobj\n${pages}`, 300_000), 'summons.pdf'), 'valid PDF rejected');
});
await check('F-10 code, launch, embedded-file and form-submit actions are caught anywhere in the file, even past 100 KB', async () => {
    for (const token of ['/JavaScript', '/JS (app.alert(1))', '/Launch', '/RichMedia', '/EmbeddedFiles', '/EmbeddedFile', '/XFA', '/SubmitForm', '/ImportData']) {
        expect(!core.verifyFileMagic(pdf(`9 0 obj << /S ${token} >> endobj`, 150_000), 'x.pdf'), `${token} at 150 KB was accepted`);
    }
});
await check('F-10 names spelled with #xx escapes (/J#61vaScript) are decoded before checking', async () => {
    expect(!core.verifyFileMagic(pdf('<< /S /J#61vaScript /JS (x) >>', 120_000), 'x.pdf'), 'escaped /JavaScript accepted');
    expect(!core.verifyFileMagic(pdf('<< /S /#4C#61unch >>', 120_000), 'x.pdf'), 'escaped /Launch accepted');
});
await check('F-10 HTML/script buried deep inside a PDF is rejected', async () => {
    expect(!core.verifyFileMagic(pdf('<script>alert(1)</script>', 200_000), 'x.pdf'), 'buried <script> accepted');
    expect(!core.verifyFileMagic(pdf('<iframe src=x>', 500_000), 'x.pdf'), 'buried <iframe> accepted');
});
await check('F-10 similar but harmless names (/JSONData, /Launcher) are not mistaken for actions', async () => {
    expect(core.verifyFileMagic(pdf('<< /JSONData 1 /Launcher 2 >>', 120_000), 'x.pdf'), 'harmless name rejected');
});

// --- F-11: server-side photo cleaning ---
const GPS = 'GPS 37.9577N 121.2908W';
const be32 = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const le32 = (n) => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255];
const le16 = (n) => [n & 255, (n >>> 8) & 255];
const b = (...parts) => Buffer.concat(parts.map(p => (typeof p === 'string' ? Buffer.from(p, 'latin1') : Buffer.from(p))));
const jpeg = () => b([0xFF, 0xD8], [0xFF, 0xE1], [0, 2 + 6 + GPS.length], 'Exif\0\0', GPS, [0xFF, 0xDB, 0, 4, 1, 2], [0xFF, 0xDA, 0, 2], 'scan', [0xFF, 0xD9]);
const pngChunk = (type, data) => b(be32(data.length), type, data, [0, 0, 0, 0]);
const png = () => b([0x89], 'PNG\r\n\x1a\n', pngChunk('IHDR', Buffer.alloc(13, 1)), pngChunk('eXIf', GPS), pngChunk('IDAT', 'pixels'), pngChunk('IEND', ''));
const webp = () => {
    const parts = [b('VP8X', le32(10), [0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0]), b('VP8 ', le32(4), 'imag'), b('EXIF', le32(GPS.length), GPS)];
    const body = Buffer.concat(parts);
    return b('RIFF', le32(4 + body.length), 'WEBP', body);
};
// HEIC: ftyp box, then a little-endian TIFF block: IFD0 with one GPS pointer, GPS IFD with one ASCII entry (24 bytes).
const heic = () => {
    const tiff = b('II', [0x2A, 0], le32(8), le16(1), le16(0x8825), le16(4), le32(1), le32(26), le32(0),
        le16(1), le16(0x0002), le16(2), le32(GPS.length), le32(44), le32(0), GPS);
    return b(be32(16), 'ftypheic', [0, 0, 0, 0], 'Exif\0\0', tiff, 'mdat-image-data');
};
const FIXTURES = { 'photo.jpg': jpeg, 'photo.png': png, 'photo.webp': webp, 'photo.heic': heic };
const TYPES = { 'photo.jpg': 'image/jpeg', 'photo.png': 'image/png', 'photo.webp': 'image/webp', 'photo.heic': 'image/heic' };

await check('F-11 the server removes GPS from JPEG, PNG, WebP and HEIC, the same way the browser does', async () => {
    for (const [name, make] of Object.entries(FIXTURES)) {
        const raw = make();
        expect(core.verifyFileMagic(raw, name), `${name} fixture is not a valid file`);
        const clean = stripPhotoMetadata(raw, name);
        expect(clean && !clean.toString('latin1').includes(GPS), `${name}: GPS still present`);
        const fromBrowser = browser.NPS.stripPhotoBytes(new Uint8Array(raw), TYPES[name]);
        expect(Buffer.compare(Buffer.from(fromBrowser), clean) === 0, `${name}: server and browser cleaning differ`);
        expect(stripPhotoMetadata(clean, name) === null, `${name}: cleaning a clean photo changed it again`);
    }
});
await check('F-11 a photo uploaded straight to storage with GPS is cleaned, the stored copy replaced, and the fingerprint taken of the clean file', async () => {
    const o = seedOrder();
    for (const [name, make] of Object.entries(FIXTURES)) {
        const id = randomUUID(); const path = `${o.id}/${id}-${name}`;
        (tables().order_files ||= []).push({ id, order_id: o.id, storage_path: path, filename: name, kind: 'document', uploaded: false });
        db.__state.storage.set(path, new Uint8Array(make()));
        const r = await core.confirmUploads(o.id, [id]);
        const stored = Buffer.from(db.__state.storage.get(path));
        expect(r.files.length === 1, `${name}: not confirmed (${JSON.stringify(r)})`);
        expect(!stored.toString('latin1').includes(GPS), `${name}: GPS still in storage`);
        expect(r.files[0].sha256 === core.sha256(stored), `${name}: fingerprint is not of the cleaned file`);
    }
});
await check('F-11 if the cleaned copy cannot be written, the photo stays unconfirmed (retried later), never accepted with GPS', async () => {
    const o = seedOrder(); const id = randomUUID(); const path = `${o.id}/${id}-photo.jpg`;
    (tables().order_files ||= []).push({ id, order_id: o.id, storage_path: path, filename: 'photo.jpg', kind: 'document', uploaded: false });
    db.__state.storage.set(path, new Uint8Array(jpeg()));
    const bucket = db.storage.from();
    bucket.failUpdate = true;
    try {
        const r = await core.confirmUploads(o.id, [id]);
        expect(r.files.length === 0 && r.stillChecking === 1 && tables().order_files[0].uploaded === false, JSON.stringify(r));
    } finally { bucket.failUpdate = false; }
});

// --- Concurrency and legal hold ---
await check('CH1 webhook and client return confirming payment at the same time write exactly one "Payment received"', async () => {
    const o = seedOrder({ status: 'awaiting_payment', stripe_session_id: 'cs_test_chaos_123' });
    const results = await Promise.all(Array.from({ length: 8 }, () => orders.markPaid(o.id, 7500, 'cs_test_chaos_123')));
    const events = (tables().order_events || []).filter(e => e.order_id === o.id && e.kind === 'payment');
    expect(results.filter(Boolean).length === 1 && events.length === 1, `${results.filter(Boolean).length} wins, ${events.length} payment events`);
    const { data } = await db.rpc('verify_order_chain', { p_order: o.id });
    expect(data[0].ok === true, 'chain check failed');
});
await check('CH2 a served order under legal hold cannot be deleted or moved back to "Action required"', async () => {
    const cookie = session(); const o = seedOrder({ status: 'served', legal_hold: true });
    expect((await admin({ action: 'delete', id: o.id, confirm: o.code }, cookie)).status === 423, 'delete allowed under legal hold');
    const back = await admin({ action: 'update', id: o.id, status: 'action_required', actionNote: 'x' }, cookie);
    expect(back.status === 423 || back.status === 400, `status rollback allowed (${back.status})`);
    expect(tables().orders[0].status === 'served', 'status changed');
});

await check('CH3 when the database refuses the 26th file (order_files_cap), the request gets a clear 400 and no upload links', async () => {
    const o = seedOrder();
    const realFrom = db.from;
    db.from = (t) => t === 'order_files'
        ? { select: () => ({ eq: async () => ({ count: 20, error: null }) }),
            insert: () => ({ select: async () => ({ data: null, error: { code: 'P0001', message: 'order_files_cap: at most 25 files per request' } }) }) }
        : realFrom(t);
    try {
        await core.prepareUploads(o.id, 'client_document', [{ name: 'a.pdf', size: 10, type: 'application/pdf' }]);
        throw new Error('no error thrown');
    } catch (err) {
        expect(err instanceof core.HttpError && err.status === 400 && /at most 25 files/.test(err.message), err.message);
    } finally { db.from = realFrom; }
});
await check('CH4 a batch of uploads is created in one insert and every file gets its own upload link', async () => {
    const o = seedOrder();
    const out = await core.prepareUploads(o.id, 'client_document', [1, 2, 3].map(i => ({ name: `f${i}.pdf`, size: 10, type: 'application/pdf' })));
    expect(out.length === 3 && new Set(out.map(x => x.fileId)).size === 3 && out.every(x => x.fileId && x.uploadUrl), JSON.stringify(out));
});

// --- Milestone 2: page counts, client audit log, fresh payment links, bulk close, safe-walk ---
const TOKEN = 'T'.repeat(32);
const track = (body, ip = '203.0.113.7') => trackPOST(new Request('https://site.test/api/track', {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-real-ip': ip, 'user-agent': 'ChaosBrowser/1.0' }, body: JSON.stringify({ t: TOKEN, ...body }),
}));
const audit = () => tables().client_audit_logs || [];
const pdfPages = (n, { inline = true, countOnly = false } = {}) => Buffer.from('%PDF-1.7\n' +
    `2 0 obj << /Type /Pages /Count ${n} /Kids [] >> endobj\n` +
    (countOnly ? '' : Array.from({ length: inline ? n : 0 }, (_, i) => `${i + 3} 0 obj << /Type /Page /Parent 2 0 R >> endobj\n`).join('')) + '%%EOF\n');

await check('M2 PDF pages are counted from /Type /Page objects or the /Pages /Count, never from /Pages itself', async () => {
    expect(core.countPdfPages(pdfPages(40)) === 40, `inline: ${core.countPdfPages(pdfPages(40))}`);
    expect(core.countPdfPages(pdfPages(212, { countOnly: true })) === 212, 'count-only PDF');
    expect(core.countPdfPages(Buffer.from('%PDF-1.7\n<< /Type /ObjStm >> stream\n...compressed...\nendstream %%EOF')) === null, 'unknown should be null');
    expect(core.countPdfPages(Buffer.from('%PDF-1.7 << /Type /P#61ge >> << /Type /Pages /Count 1 >>')) === 1, 'escaped name');
});
await check('M2 printing fee: first 100 pages free, then 15 cents a page', async () => {
    expect(core.printingFeeCents(80) === 0 && core.printingFeeCents(100) === 0 && core.printingFeeCents(250) === 2250 && core.printingFeeCents(null) === 0, 'fee math');
});
await check('M2 confirming a PDF upload saves its page count', async () => {
    const o = seedOrder(); const id = randomUUID(); const path = `${o.id}/${id}.pdf`;
    (tables().order_files ||= []).push({ id, order_id: o.id, storage_path: path, filename: 'filing.pdf', kind: 'client_document', uploaded: false });
    db.__state.storage.set(path, new Uint8Array(pdfPages(130)));
    const r = await core.confirmUploads(o.id, [id]);
    expect(r.files[0].page_count === 130 && tables().order_files[0].page_count === 130, JSON.stringify(r.files[0]));
});
await check('M2 client audit log: unlocked view (once per 15 min), download with fingerprint, hashed IP, browser name', async () => {
    const o = seedOrder({ track_token: TOKEN, doc_lock: true });
    const unlockToken = core.signToken('track-unlock-v1', `${o.id}|${TOKEN}`, 3600);
    const fid = randomUUID();
    (tables().order_files ||= []).push({ id: fid, order_id: o.id, storage_path: `${o.id}/p.pdf`, filename: 'proof.pdf', kind: 'proof', uploaded: true, sha256: 'a'.repeat(64) });
    for (let i = 0; i < 3; i++) await track({ action: 'view', unlockToken });
    await track({ action: 'view' });   // locked view: not logged
    const dl = await track({ action: 'download', fileId: fid, unlockToken });
    expect(dl.status === 200, `download ${dl.status}`);
    const views = audit().filter(l => l.action === 'view_unlocked'), dls = audit().filter(l => l.action === 'download');
    expect(views.length === 1, `${views.length} view rows`);
    expect(dls.length === 1 && dls[0].detail.includes('a'.repeat(64)) && dls[0].ip_hash === core.sha256('203.0.113.7') && dls[0].user_agent === 'ChaosBrowser/1.0', JSON.stringify(dls[0]));
    expect(audit().every(l => !JSON.stringify(l).includes('203.0.113.7')), 'raw IP stored');
});
await check('M2 a payment confirmed by webhook and client together is logged once in the client audit log', async () => {
    const o = seedOrder({ status: 'awaiting_payment', stripe_session_id: 'cs_test_chaos_123' });
    await Promise.all(Array.from({ length: 6 }, () => orders.markPaid(o.id, 7500, 'cs_test_chaos_123')));
    const rows = audit().filter(l => l.action === 'payment_confirmed');
    expect(rows.length === 1 && rows[0].order_code === o.code && rows[0].detail.includes('cs_test_chaos_123'), JSON.stringify(rows));
});
await check('M2 if the audit table is missing, the client action still works', async () => {
    const o = seedOrder({ track_token: TOKEN });
    const fid = randomUUID();
    (tables().order_files ||= []).push({ id: fid, order_id: o.id, storage_path: `${o.id}/p.pdf`, filename: 'p.pdf', kind: 'proof', uploaded: true });
    const realFrom = db.from;
    db.from = (t) => t === 'client_audit_logs' ? { insert: async () => ({ error: { code: 'PGRST205', message: 'schema cache' } }) } : realFrom(t);
    try { expect((await track({ action: 'download', fileId: fid })).status === 200, 'download failed'); } finally { db.from = realFrom; }
});

const seedSession = (id, over = {}) => { stripeSessions.set(id, { id, status: 'expired', payment_status: 'unpaid', amount_total: 7500, url: `https://checkout.stripe.test/${id}`, ...over }); return id; };
await check('M2 an expired payment link is replaced by a new one for the same amount (client and Nick)', async () => {
    const o = seedOrder({ track_token: TOKEN, status: 'awaiting_payment', stripe_session_id: seedSession('cs_test_old_abcdefgh'), payment_url: 'https://old' });
    const res = await track({ action: 'refresh-payment-link' });
    const body = await res.json();
    expect(res.status === 200 && body.fresh === true && body.paymentUrl.includes('cs_test_new_'), `${res.status} ${JSON.stringify(body).slice(0, 200)}`);
    expect(stripeSessions.get(tables().orders[0].stripe_session_id).amount_total === 7500, 'amount changed');
    expect(tables().orders[0].amount_due_cents === 7500 && audit().some(l => l.action === 'payment_link_refreshed'), 'not recorded');
    stripeSessions.get(tables().orders[0].stripe_session_id).status = 'expired';
    const adminRes = await admin({ action: 'refresh-payment-link', id: o.id }, session());
    expect(adminRes.status === 200 && (await adminRes.json()).fresh === true && emails.some(e => /your payment link/.test(e.subject)), 'admin refresh failed');
});
await check('M2 a link that is still open is reused (no second payable link), and a paid one is recorded, not re-billed', async () => {
    seedOrder({ track_token: TOKEN, status: 'awaiting_payment', stripe_session_id: seedSession('cs_test_open_abcdefgh', { status: 'open' }) });
    const open = await (await track({ action: 'refresh-payment-link' })).json();
    expect(open.fresh === false && open.paymentUrl.includes('cs_test_open_') && stripeCreated >= 0 && stripeSessions.size === 1, JSON.stringify(open).slice(0, 160));
    db.__reset(); stripeSessions.clear();
    seedOrder({ track_token: TOKEN, status: 'awaiting_payment', stripe_session_id: seedSession('cs_test_paid_abcdefgh', { status: 'complete', payment_status: 'paid' }) });
    const paid = await track({ action: 'refresh-payment-link' });
    expect(paid.status === 409 && tables().orders[0].paid_at, `paid: ${paid.status}`);
});
await check('M2 no fresh link without an amount due, after payment, or more than 6 times an hour', async () => {
    seedOrder({ track_token: TOKEN, amount_due_cents: null });
    expect((await track({ action: 'refresh-payment-link' })).status === 409, 'no amount');
    db.__reset();
    seedOrder({ track_token: TOKEN, status: 'paid', paid_at: new Date().toISOString() });
    expect((await track({ action: 'refresh-payment-link' })).status === 409, 'already paid');
    db.__reset(); stripeSessions.clear();
    seedOrder({ track_token: TOKEN, status: 'awaiting_payment', stripe_session_id: seedSession('cs_test_x_abcdefgh') });
    const statuses = [];
    for (let i = 0; i < 7; i++) {
        statuses.push((await track({ action: 'refresh-payment-link' }, `198.51.100.${i}`)).status);
        stripeSessions.get(tables().orders[0].stripe_session_id).status = 'expired';
    }
    expect(statuses.slice(0, 6).every(x => x === 200) && statuses[6] === 429, statuses.join());
});
await check('M2 bulk close closes only served or cancelled requests and reports the rest', async () => {
    const cookie = session();
    const a = seedOrder({ status: 'served', legal_hold: true }), b = seedOrder({ code: 'NP-222222', status: 'cancelled' }), c = seedOrder({ code: 'NP-333333', status: 'attempting' });
    const res = await admin({ action: 'bulk-close', ids: [a.id, b.id, c.id, 'not-a-uuid'] }, cookie);
    const body = await res.json();
    expect(res.status === 200 && body.closed.length === 2 && body.skipped.join() === 'NP-333333', JSON.stringify(body));
    expect(tables().orders.map(o => o.status).join() === 'closed,closed,attempting', tables().orders.map(o => o.status).join());
    expect((await admin({ action: 'bulk-close', ids: [] }, cookie)).status === 400, 'empty list accepted');
    expect((await admin({ action: 'bulk-close', ids: [a.id] })).status === 401, 'no session accepted');
});
await check('M2 safe-walk alert emails the job code, address and time, and needs a session', async () => {
    const o = seedOrder({ address: '12 Main St', city: 'Stockton', zip: '95202' });
    expect((await admin({ action: 'safe-walk-alert', id: o.id })).status === 401, 'no session accepted');
    const res = await admin({ action: 'safe-walk-alert', id: o.id, minutes: 15 }, session());
    const mail = emails.find(e => /safe-walk/.test(e.subject));
    expect(res.status === 200 && mail && JSON.stringify(mail).includes('12 Main St') && JSON.stringify(mail).includes(o.code), JSON.stringify(mail || {}).slice(0, 200));
    expect((tables().admin_audit_logs || []).some(l => l.action === 'safe_walk_alert'), 'not audited');
});

// --- Milestone 3 server pieces: client messages, "Client replied", evidence pack, receipt privacy ---
await check('M3 a client can message Nick on any open request; Nick is emailed, it is logged, and the list shows "Client replied"', async () => {
    const o = seedOrder({ track_token: TOKEN, status: 'attempting' });
    (tables().order_events ||= []).push({ id: randomUUID(), order_id: o.id, kind: 'attempt', title: 'Attempt: No answer', created_at: new Date(Date.now() - 6e4).toISOString(), client_visible: true });
    const res = await track({ action: 'message', message: 'Try after 6pm, he works days.' });
    expect(res.status === 200, `message ${res.status} ${await res.clone().text()}`);
    const ev = tables().order_events.find(e => e.title === 'You sent a message');
    expect(ev && ev.kind === 'action_response' && /after 1 attempt/.test(ev.detail), JSON.stringify(ev));
    expect(tables().orders[0].status === 'attempting', 'status changed');
    expect(emails.some(e => /new message from/.test(e.subject)) && audit().some(l => l.action === 'reply'), 'not emailed or not logged');
    const list = await (await admin({ action: 'list' }, session())).json();
    expect(list.orders.find(x => x.id === o.id).client_replied === true, 'no Client replied badge');
});
await check('M3 messages are refused on finished or locked requests and when empty', async () => {
    seedOrder({ track_token: TOKEN, status: 'served' });
    expect((await track({ action: 'message', message: 'hi' })).status === 409, 'finished request accepted a message');
    db.__reset();
    seedOrder({ track_token: TOKEN, status: 'paid', doc_lock: true });
    expect((await track({ action: 'message', message: 'hi' })).status === 403, 'locked request accepted a message');
    db.__reset();
    seedOrder({ track_token: TOKEN, status: 'paid' });
    expect((await track({ action: 'message', message: '   ' })).status === 400, 'empty message accepted');
});
await check('M3 evidence pack: attestation, payment, attempts, file fingerprints, seal and client activity', async () => {
    const o = seedOrder({ status: 'served', paid_at: new Date().toISOString(), stripe_session_id: 'cs_test_chaos_123', case_number: 'STK-CV-1', court: 'San Joaquin' });
    const ev = (kind, title) => ({ id: randomUUID(), order_id: o.id, kind, title, detail: null, client_visible: true, created_at: new Date().toISOString() });
    (tables().order_events ||= []).push(ev('attestation', 'Client legal attestation & Terms sealed'), ev('payment', 'Payment received: $75.00'), ev('attempt', 'Attempt: Served'));
    (tables().order_files ||= []).push({ id: randomUUID(), order_id: o.id, kind: 'proof', filename: 'pos.pdf', uploaded: true, sha256: 'b'.repeat(64), created_at: new Date().toISOString() });
    (tables().client_audit_logs ||= []).push({ order_id: o.id, action: 'download', detail: 'pos.pdf', created_at: new Date().toISOString() });
    const res = await admin({ action: 'evidence-pack', id: o.id }, session());
    const p = await res.json();
    expect(res.status === 200 && p.attestation.length === 1 && p.payments.length === 1 && p.attempts.length === 1, JSON.stringify(p).slice(0, 200));
    expect(p.files[0].sha256 === 'b'.repeat(64) && p.order.stripe_session_id === 'cs_test_chaos_123' && p.timeline_seal && p.client_actions.length === 1, 'missing parts');
    expect(!('track_token' in p.order) && !JSON.stringify(p).includes(TOKEN), 'tracking token leaked into the pack');
    expect((await admin({ action: 'evidence-pack', id: o.id })).status === 401, 'no session accepted');
});
await check('M3 the itemized receipt appears only when paid and unlocked (it names the client and case)', async () => {
    const o = seedOrder({ track_token: TOKEN, status: 'paid', paid_at: new Date().toISOString(), doc_lock: true, tier: 'standard', addons: ['photo'], amount_due_cents: 9000, client_name: 'Pat Client', case_number: 'C-1' });
    const locked = await (await track({ action: 'view' })).json();
    expect(locked.receipt === null, 'receipt shown on a locked page');
    const unlockToken = core.signToken('track-unlock-v1', `${o.id}|${TOKEN}`, 3600);
    const open = await (await track({ action: 'view', unlockToken })).json();
    expect(open.receipt && open.receipt.clientName === 'Pat Client' && open.receipt.tierCents === 7500 && open.receipt.addons[0].cents === 1500 && open.receipt.totalCents === 9000, JSON.stringify(open.receipt));
});

await check('M4 "days since last update" counts the latest attempt, not just changes to the order row', async () => {
    const old = new Date(Date.now() - 6 * 864e5).toISOString(), recent = new Date(Date.now() - 3600e3).toISOString();
    const o = seedOrder({ status: 'attempting', updated_at: old, created_at: old });
    (tables().order_events ||= []).push({ id: randomUUID(), order_id: o.id, kind: 'attempt', title: 'Attempt: No answer', created_at: recent, client_visible: true });
    const list = await (await admin({ action: 'list' }, session())).json();
    expect(list.orders[0].last_activity_at === recent, JSON.stringify(list.orders[0].last_activity_at));
});
await check('M4 the dashboard is told who a safe-walk alert goes to, and the export includes client activity', async () => {
    const cookie = session();
    const me = await (await admin({ action: 'me' }, cookie)).json();
    expect(me.safeWalk && me.safeWalk.configured === false && me.safeWalk.recipients.includes(ADMIN), JSON.stringify(me.safeWalk));
    process.env.SAFE_WALK_EMAILS = 'Trusted@Example.com, not-an-email';
    try {
        const me2 = await (await admin({ action: 'me' }, cookie)).json();
        expect(me2.safeWalk.configured === true && me2.safeWalk.recipients.join() === 'trusted@example.com', JSON.stringify(me2.safeWalk));
    } finally { delete process.env.SAFE_WALK_EMAILS; }
    const o = seedOrder();
    (tables().client_audit_logs ||= []).push({ order_id: o.id, action: 'download', detail: 'x.pdf', created_at: new Date().toISOString() });
    const ex = await (await admin({ action: 'export', id: o.id }, cookie)).json();
    expect(Array.isArray(ex.client_activity) && ex.client_activity.length === 1, JSON.stringify(ex.client_activity));
});
await check('M4 scanning and page-counting a 25 MB PDF stays well inside the function time limit', async () => {
    const big = Buffer.concat([Buffer.from('%PDF-1.7\n<< /Type /Pages /Count 300 >>\n'), Buffer.alloc(25 * 1024 * 1024 - 64, 0x41), Buffer.from('\n%%EOF\n')]);
    const t = performance.now();
    const ok = core.verifyFileMagic(big, 'big.pdf'), pages = core.countPdfPages(big);
    const ms = performance.now() - t;
    console.log(`     25 MB PDF: checked in ${Math.round(ms)} ms (${pages} pages)`);
    expect(ok && pages === 300 && ms < 5000, `${ok} ${pages} ${Math.round(ms)} ms`);
});

console.log(`\n${passed} chaos & regression checks passed, ${failures.length} failed`);
if (failures.length) process.exit(1);
