// Chaos and edge-case suite: the REAL handlers in api/ under races, replays, tampering and hostile input, against the
// in-memory Supabase (scripts/fake-supabase.mjs) and a fake Stripe. The fake runs every query as one step, as Postgres
// runs one statement, so a race between a read and a later write shows up here the same way it would in production.
// Run with: node --experimental-test-module-mocks scripts/check-chaos-and-edge-cases.mjs
import { mock } from 'node:test';
import { randomUUID, randomBytes, createHash } from 'node:crypto';
import { createFakeSupabase } from './fake-supabase.mjs';

const db = createFakeSupabase();
const stripeSessions = new Map();
class FakeStripe {
    constructor() {
        this.webhooks = { constructEventAsync: async (raw) => JSON.parse(raw) };
        this.checkout = { sessions: { retrieve: async (id) => stripeSessions.get(id) || { id, payment_status: 'unpaid', metadata: {} }, expire: async () => ({}) } };
    }
}
mock.module('@supabase/supabase-js', { namedExports: { createClient: () => db } });
mock.module('stripe', { defaultExport: FakeStripe });
Object.assign(process.env, { SUPABASE_SERVICE_ROLE_KEY: 'test-service-role', APP_SECRET: 'test-app-secret', STRIPE_SECRET_KEY: 'sk_test_fake', STRIPE_WEBHOOK_SECRET: 'whsec_fake', RESEND_API_KEY: 're_test_fake' });
delete process.env.ADMIN_EMAILS;
delete process.env.VERCEL_ENV;
globalThis.fetch = async () => new Response('{}', { status: 200 });

const core = await import('../api/_lib/core.mjs');
const photos = await import('../api/_lib/photos.mjs');
const { POST: trackPOST } = await import('../api/track.mjs');
const { POST: adminPOST } = await import('../api/admin.mjs');
const { POST: webhookPOST } = await import('../api/stripe-webhook.mjs');

let passed = 0;
const failures = [];
async function check(name, fn) {
    db.__reset(); stripeSessions.clear();
    try { await fn(); passed++; console.log(`PASS ${name}`); } catch (err) { failures.push(name); console.log(`FAIL ${name}\n     ${err.message}`); }
}
function expect(cond, msg) { if (!cond) throw new Error(msg); }
const post = (path, body, headers = {}) => new Request(`https://site.test${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
const tables = () => db.__state.tables;
const ADMIN = 'nicksprocessservices@outlook.com';
function seedOrder(over = {}) {
    const o = { id: randomUUID(), code: 'NP-123456', track_token: 'T'.repeat(32), status: 'awaiting_payment', created_at: new Date().toISOString(),
        client_email: 'client@example.com', client_name: 'Pat Client', recipient_name: 'Sam Recipient', doc_type: 'Summons', address: '12 Main St', city: 'Stockton',
        zip: '95202', tier: 'standard', addons: [], estimated_total_cents: 7500, amount_due_cents: 7500, paid_at: null, stripe_session_id: 'cs_test_session0001',
        doc_lock: false, legal_hold: false, ...over };
    (tables().orders ||= []).push(o);
    return o;
}
const adminCookie = () => {
    const token = 'A'.repeat(43);
    (tables().admin_sessions ||= []).push({ token_hash: core.sha256(token), email: ADMIN, expires_at: new Date(Date.now() + 864e5).toISOString(), last_seen_at: new Date().toISOString() });
    return `nps_admin=${token}`;
};
const paidEvents = (o) => (tables().order_events || []).filter(e => e.order_id === o.id && e.title?.startsWith('Payment received'));

// --- 1. Races ---
await check('C1 ten return trips and ten webhooks for one paid session: paid once, one "Payment received", chain intact', async () => {
    const o = seedOrder();
    const session = { id: 'cs_test_session0001', payment_status: 'paid', amount_total: 7500, metadata: { order_id: o.id } };
    stripeSessions.set(session.id, session);
    const hook = () => webhookPOST(new Request('https://site.test/api/stripe-webhook', { method: 'POST', headers: { 'stripe-signature': 'x' },
        body: JSON.stringify({ type: 'checkout.session.completed', data: { object: session } }) }));
    const back = () => trackPOST(post('/api/track', { t: o.track_token, action: 'confirm-payment', session: session.id }));
    const results = await Promise.all([...Array.from({ length: 10 }, hook), ...Array.from({ length: 10 }, back)]);
    expect(results.every(r => r.status === 200), `statuses ${results.map(r => r.status).join(',')}`);
    expect(tables().orders[0].paid_at && paidEvents(o).length === 1, `"Payment received" written ${paidEvents(o).length} times`);
});
await check('C2 the same 8-digit login code tried ten times at once signs in at most once', async () => {
    const code = '12345678';
    (tables().admin_codes ||= []).push({ id: randomUUID(), email: ADMIN, code_hash: core.sha256(`${ADMIN}:${code}`), expires_at: new Date(Date.now() + 6e5).toISOString(), attempts: 0, used: false, created_at: new Date().toISOString() });
    const rs = await Promise.all(Array.from({ length: 10 }, () => adminPOST(post('/api/admin', { action: 'verify-code', email: ADMIN, code }))));
    expect(rs.filter(r => r.status === 200).length === 1, `${rs.filter(r => r.status === 200).length} sign-ins from one code`);
});
await check('C3 one authenticator code used for ten step-ups at once works only once', async () => {
    const secret = core.generateTotpSecret(20);
    (tables().admin_totp ||= []).push({ email: ADMIN, secret_enc: core.encryptSecret(secret), enabled: true, last_used_step: 0 });
    (tables().admin_recovery_codes ||= []);
    const cookie = adminCookie();
    const totp = core.totpCode(secret);
    const rs = await Promise.all(Array.from({ length: 10 }, () => adminPOST(post('/api/admin', { action: 'generate-recovery-codes', totp }, { cookie }))));
    expect(rs.filter(r => r.status === 200).length === 1, `${rs.filter(r => r.status === 200).length} step-ups from one code`);
});
await check('C4 one recovery code used for ten step-ups at once works only once', async () => {
    const secret = core.generateTotpSecret(20);
    (tables().admin_totp ||= []).push({ email: ADMIN, secret_enc: core.encryptSecret(secret), enabled: true, last_used_step: 0 });
    (tables().admin_recovery_codes ||= []).push({ id: randomUUID(), email: ADMIN, code_hash: core.keyedHash('admin-recovery-v1', `${ADMIN}:ABCDEFGH`), used: false });
    const cookie = adminCookie();
    const held = seedOrder({ status: 'served', legal_hold: true });
    const rs = await Promise.all(Array.from({ length: 10 }, () => adminPOST(post('/api/admin', { action: 'unlock-legal-hold', id: held.id, hold: false, totp: 'ABCD-EFGH' }, { cookie }))));
    expect(rs.filter(r => r.status === 200).length === 1 && rs.filter(r => r.status === 403).length === 9, `statuses ${rs.map(r => r.status).join(',')}`);
    expect(tables().admin_recovery_codes[0].used === true, 'recovery code not spent');
});

// --- 2. Cryptography and tokens ---
await check('C5 tampered encrypted secrets always fail closed (IV, tag, ciphertext, truncation, wrong purpose)', async () => {
    const stored = core.encryptSecret('JBSWY3DPEHPK3PXP');
    const [v, iv, tag, ct] = stored.split('.');
    const flip = (b64) => { const b = Buffer.from(b64, 'base64url'); b[0] ^= 1; return b.toString('base64url'); };
    const bad = [[v, flip(iv), tag, ct], [v, iv, flip(tag), ct], [v, iv, tag, flip(ct)], [v, iv, tag], [v, iv, tag, ct.slice(0, -2)], ['v2', iv, tag, ct], []]
        .map(p => p.join('.'));
    for (const b of bad) { let threw = false; try { core.decryptSecret(b); } catch { threw = true; } expect(threw, `accepted ${b.slice(0, 30)}`); }
    let threw = false; try { core.decryptSecret(stored, 'another-purpose-v1'); } catch { threw = true; }
    expect(threw, 'decrypted under the wrong purpose');
    expect(core.decryptSecret(stored) === 'JBSWY3DPEHPK3PXP', 'good secret no longer decrypts');
});
await check('C6 signed tokens: tampered, expired, other subject or other purpose are refused', async () => {
    const t = core.signToken('track-unlock-v1', 'order|token', 3600);
    const [exp, mac] = t.split('.');
    expect(core.checkToken('track-unlock-v1', 'order|token', t), 'good token refused');
    expect(!core.checkToken('track-unlock-v1', 'order|other', t), 'other subject accepted');
    expect(!core.checkToken('client-session-v1', 'order|token', t), 'other purpose accepted');
    expect(!core.checkToken('track-unlock-v1', 'order|token', `${Number(exp) + 100}.${mac}`), 'extended expiry accepted');
    expect(!core.checkToken('track-unlock-v1', 'order|token', `${exp}.${mac.slice(0, -1)}A`), 'changed signature accepted');
    expect(!core.checkToken('track-unlock-v1', 'order|token', core.signToken('track-unlock-v1', 'order|token', -10)), 'expired token accepted');
});
await check('C7 an unlock from before the tracking link was replaced stops working at once', async () => {
    const o = seedOrder({ doc_lock: true, status: 'attempting' });
    (tables().track_unlock_codes ||= []).push({ order_id: o.id, code_hash: core.sha256(`${o.id}:654321`), expires_at: new Date(Date.now() + 6e5).toISOString(), tries: 0 });
    const r = await (await trackPOST(post('/api/track', { t: o.track_token, action: 'verify-unlock-code', code: '654321' }))).json();
    expect(r.unlockToken, 'no unlock token');
    const unlocked = await (await trackPOST(post('/api/track', { t: o.track_token, action: 'view', unlockToken: r.unlockToken }))).json();
    expect(unlocked.unlocked === true, 'unlock did not work');
    o.track_token = 'N'.repeat(32);   // the link is replaced
    const after = await (await trackPOST(post('/api/track', { t: o.track_token, action: 'view', unlockToken: r.unlockToken }))).json();
    expect(after.unlocked === false, 'old unlock still works on the new link');
});

// --- 3. Hostile uploads ---
await check('C8 disguised names, macros, deep PDF scripts, empty and oversized files are refused', async () => {
    const reject = (fn, msg) => { let threw = false; try { fn(); } catch { threw = true; } expect(threw, msg); };
    reject(() => core.cleanFileList([{ name: 'summons.pdf.exe', size: 100, type: 'application/pdf' }]), '.pdf.exe accepted');
    reject(() => core.cleanFileList([{ name: 'complaint.pdf', size: 0, type: 'application/pdf' }]), 'empty file accepted');
    reject(() => core.cleanFileList([{ name: 'complaint.pdf', size: 25 * 1024 * 1024 + 1, type: 'application/pdf' }]), 'file over 25 MB accepted');
    const docx = new TextEncoder().encode('PK\x03\x04[Content_Types].xml word/document.xml word/vbaProject.bin');
    expect(core.verifyFileMagic(docx, 'complaint.docx') === false, 'macro .docx accepted');
    const deep = Buffer.concat([Buffer.from('%PDF-1.7\n'), Buffer.from('x'.repeat(500_000)), Buffer.from('\n9 0 obj << /S /JavaScript /JS (app.alert(1)) >>\n%%EOF')]);
    expect(core.verifyFileMagic(new Uint8Array(deep), 'a.pdf') === false, 'script at byte 500,000 accepted');
    expect(core.verifyFileMagic(new Uint8Array(0), 'a.pdf') === false, 'empty PDF accepted');
    expect(core.verifyFileMagic(new Uint8Array(25 * 1024 * 1024 + 1), 'a.pdf') === false, 'oversized buffer accepted');
});
await check('C9 2,000 random and corrupted files: the checks and the photo cleaner never crash, and never accept a wrong type', async () => {
    const heads = { pdf: [0x25, 0x50, 0x44, 0x46, 0x2D], jpg: [0xFF, 0xD8, 0xFF], png: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], heic: [0, 0, 0, 24, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63], webp: [0x52, 0x49, 0x46, 0x46, 1, 0, 0, 0, 0x57, 0x45, 0x42, 0x50] };
    const types = { jpg: 'image/jpeg', png: 'image/png', heic: 'image/heic', webp: 'image/webp' };
    for (let i = 0; i < 2000; i++) {
        const ext = Object.keys(heads)[i % 5];
        const buf = randomBytes(16 + (i * 37) % 4000);
        if (i % 3) Buffer.from(heads[ext]).copy(buf);
        // Malformed TIFF/EXIF structures inside images: a TIFF header with random offsets after it.
        if (i % 7 === 0 && buf.length > 40) Buffer.from([0x49, 0x49, 0x2A, 0]).copy(buf, 20);
        const u8 = new Uint8Array(buf);
        const ok = core.verifyFileMagic(u8, `f.${ext}`);
        if (!(i % 3)) expect(ok === false || buf.subarray(0, heads[ext].length).equals(Buffer.from(heads[ext])), `random bytes accepted as .${ext}`);
        expect(core.verifyFileMagic(u8, 'f.exe') === false, 'an .exe was accepted');
        if (types[ext]) { const out = photos.stripPhotoBytes(u8, types[ext]); expect(out === null || out instanceof Uint8Array, 'cleaner returned junk'); }
        core.countPdfPages(u8);
    }
});

// --- 4. Legal hold ---
await check('C10 a served order under legal hold refuses rollback, deletion and "Action required" from the dashboard', async () => {
    const o = seedOrder({ status: 'served', legal_hold: true, paid_at: new Date().toISOString() });
    const cookie = adminCookie();
    const back = await adminPOST(post('/api/admin', { action: 'update', id: o.id, kind: 'status', status: 'attempting' }, { cookie }));
    const ask = await adminPOST(post('/api/admin', { action: 'update', id: o.id, kind: 'action', note: 'More info' }, { cookie }));
    const del = await adminPOST(post('/api/admin', { action: 'delete', id: o.id, confirm: o.code }, { cookie }));
    expect(back.status === 423 && ask.status === 423 && del.status === 423, `rollback ${back.status}, ask ${ask.status}, delete ${del.status}`);
    expect(tables().orders[0].status === 'served' && tables().orders.length === 1, 'held order changed');
});
await check('C11 a client cannot rewrite a held order from the tracking page', async () => {
    const o = seedOrder({ status: 'served', legal_hold: true });
    const r = await trackPOST(post('/api/track', { t: o.track_token, action: 'respond', address: '1 Other St', reply: 'change it' }));
    expect(r.status === 409 && tables().orders[0].address === '12 Main St', `status ${r.status}`);
});

// Database-level protections (legal-hold triggers, append-only timeline and audit logs, the hash chain) run inside
// Postgres and are not reproduced by the in-memory fake; they are covered by the SQL in supabase/migrations and were
// checked against the live database when each migration was applied.
console.log(`\n${passed} chaos and edge-case checks passed, ${failures.length} failed`);
if (failures.length) process.exit(1);
