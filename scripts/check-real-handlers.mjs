// Regression tests that run the REAL handlers in api/ against an in-memory Supabase (scripts/fake-supabase.mjs) and a
// fake Stripe. The other suites mostly exercise scripts/mock-api.mjs, which is a separate copy of the logic.
// Run with: node --experimental-test-module-mocks scripts/check-real-handlers.mjs
import { mock } from 'node:test';
import { randomUUID } from 'node:crypto';
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

Object.assign(process.env, {
    SUPABASE_SERVICE_ROLE_KEY: 'test-service-role', APP_SECRET: 'test-app-secret', CRON_SECRET: 'test-cron',
    STRIPE_SECRET_KEY: 'sk_test_fake', STRIPE_WEBHOOK_SECRET: 'whsec_fake', RESEND_API_KEY: 're_test_fake',
});
delete process.env.ADMIN_EMAILS;
delete process.env.VERCEL_ENV;

const emails = [];
let resendUp = true;   // set to false to make Resend reject every email
globalThis.fetch = async (url, init) => {
    if (String(url).includes('resend.com')) {
        if (!resendUp) return new Response('{"message":"unavailable"}', { status: 503 });
        emails.push(JSON.parse(init.body));
    }
    return new Response('{}', { status: 200 });
};

const core = await import('../api/_lib/core.mjs');
const orders = await import('../api/_lib/orders.mjs');
const { POST: clientPOST } = await import('../api/client.mjs');
const { POST: trackPOST } = await import('../api/track.mjs');
const { POST: adminPOST } = await import('../api/admin.mjs');
const { POST: webhookPOST } = await import('../api/stripe-webhook.mjs');
const { GET: keepaliveGET } = await import('../api/keepalive.mjs');
const clients = await import('../api/_lib/clients.mjs');

let passed = 0;
const failures = [];
async function check(name, fn) {
    try {
        await fn();
        passed++;
        console.log(`PASS ${name}`);
    } catch (err) {
        failures.push(name);
        console.log(`FAIL ${name}\n     ${err.message}`);
    }
}
function expect(cond, msg) { if (!cond) throw new Error(msg); }

const post = (path, body, headers = {}) => new Request(`https://site.test${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
});
const tables = () => db.__state.tables;
const reset = () => { db.__reset(); stripeSessions.clear(); emails.length = 0; resendUp = true; };
const ADMIN = 'nicksprocessservices@outlook.com';
const CLIENT = 'client@example.com';
const PIN = '246810';

function seedOrder(over = {}) {
    const o = {
        id: randomUUID(), code: 'NP-123456', track_token: 'T'.repeat(32), status: 'received', created_at: new Date().toISOString(),
        client_email: CLIENT, client_name: 'Pat Client', client_phone: '209-555-0100', recipient_name: 'Sam Recipient',
        doc_type: 'Summons & Complaint', address: '12 Main St', unit: null, city: 'Stockton', zip: '95202', tier: 'standard',
        addons: [], estimated_total_cents: 7500, amount_due_cents: null, paid_at: null, stripe_session_id: null, payment_url: null,
        action_note: null, doc_lock: false, legal_hold: false, ...over,
    };
    (tables().orders ||= []).push(o);
    return o;
}
const setPin = (email, extra = {}) => (tables().client_security_settings ||= []).push({ email, pin_hash: core.hashPin(PIN), failed_tries: 0, locked_until: null, ...extra });
const pinRow = (email) => (tables().client_security_settings || []).find(r => r.email === email);
const events = (orderId) => (tables().order_events || []).filter(e => e.order_id === orderId);

// --- F-01: the PIN must also guard magic-link sign-in (the `session` action) ---
await check('F-01 magic-link sign-in asks for the PIN instead of setting a cookie', async () => {
    reset(); db.__addUser(CLIENT); setPin(CLIENT);
    const res = await clientPOST(post('/api/client', { action: 'session', access: db.__sessionFor(CLIENT), refresh: 'r' }));
    const body = await res.json();
    expect(!res.headers.get('set-cookie'), 'a session cookie was issued without the PIN');
    expect(body.requiresPin === true, `expected requiresPin, got ${JSON.stringify(body)}`);
});
await check('F-01 magic-link sign-in with a wrong PIN gets no cookie; the right PIN does', async () => {
    reset(); db.__addUser(CLIENT); setPin(CLIENT);
    const bad = await clientPOST(post('/api/client', { action: 'session', access: db.__sessionFor(CLIENT), refresh: 'r', pin: '000000' }));
    expect(!bad.headers.get('set-cookie'), 'cookie issued with a wrong PIN');
    const good = await clientPOST(post('/api/client', { action: 'session', access: db.__sessionFor(CLIENT), refresh: 'r', pin: PIN }));
    expect(good.status === 200 && good.headers.get('set-cookie'), `right PIN refused (${good.status})`);
});

await check('F-01 a hand-made cookie holding valid Supabase tokens is refused (no server signature)', async () => {
    reset(); db.__addUser(CLIENT); setPin(CLIENT);
    const forged = encodeURIComponent(JSON.stringify({ access: db.__sessionFor(CLIENT), refresh: 'r' }));
    const res = await clientPOST(post('/api/client', { action: 'list' }, { cookie: `nps_client=${forged}` }));
    expect(res.status === 401, `forged cookie accepted (${res.status})`);
});
await check('F-01 the cookie issued after sign-in (code + PIN) works for later requests', async () => {
    reset(); db.__addUser(CLIENT); setPin(CLIENT); db.__state.otp.set(CLIENT, '111111');
    const login = await clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '111111', pin: PIN }));
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const res = await clientPOST(post('/api/client', { action: 'list' }, { cookie }));
    expect(res.status === 200, `signed-in session refused (${res.status})`);
});

const cookieFor = (session, userId) => clients.clientCookie(new Request('https://site.test/api/client'), session, userId).split(';')[0];
await check('F-01 a signed cookie for one client is refused with another client\'s tokens', async () => {
    reset(); const a = db.__addUser(CLIENT); db.__addUser('other@example.com');
    const cookie = cookieFor({ access_token: db.__sessionFor('other@example.com'), refresh_token: 'r' }, a.id);
    const res = await clientPOST(post('/api/client', { action: 'list' }, { cookie }));
    expect(res.status === 401, `proof for client A accepted with client B's tokens (${res.status})`);
});
await check('F-01 an expired session is renewed only with a matching signed cookie', async () => {
    reset(); const a = db.__addUser(CLIENT); const b = db.__addUser('other@example.com');
    const ok = await clientPOST(post('/api/client', { action: 'list' }, { cookie: cookieFor({ access_token: 'expired', refresh_token: db.__refreshFor(CLIENT) }, a.id) }));
    expect(ok.status === 200 && /nps_client=/.test(ok.headers.get('set-cookie') || ''), `refresh with a matching proof failed (${ok.status})`);
    const bad = await clientPOST(post('/api/client', { action: 'list' }, { cookie: cookieFor({ access_token: 'expired', refresh_token: db.__refreshFor(CLIENT) }, b.id) }));
    expect(bad.status === 401, `refresh accepted a proof for another client (${bad.status})`);
});

// --- F-02: email code first, then PIN; no lockout or PIN oracle without the email code ---
await check('F-02 a wrong email code gives the same answer whether the PIN is right or wrong', async () => {
    reset(); db.__addUser(CLIENT); setPin(CLIENT); db.__state.otp.set(CLIENT, '111111');
    const a = await clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '999999', pin: '000000' }));
    const b = await clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '999999', pin: PIN }));
    const [ta, tb] = [await a.text(), await b.text()];
    expect(a.status === b.status && ta === tb, `responses differ: ${a.status} ${ta} vs ${b.status} ${tb}`);
});
await check('F-02 wrong PINs sent without a valid email code never lock the account', async () => {
    reset(); db.__addUser(CLIENT); setPin(CLIENT); db.__state.otp.set(CLIENT, '111111');
    for (let i = 0; i < 5; i++) await clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '999999', pin: '000000' }));
    expect(pinRow(CLIENT).failed_tries === 0 && !pinRow(CLIENT).locked_until, `counter moved: ${JSON.stringify(pinRow(CLIENT))}`);
});
await check('F-02 valid email code + wrong PIN: refused, counted, and the new session is revoked', async () => {
    reset(); db.__addUser(CLIENT); setPin(CLIENT); db.__state.otp.set(CLIENT, '111111');
    const res = await clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '111111', pin: '000000' }));
    expect(res.status === 401 && !res.headers.get('set-cookie'), `expected 401 without cookie, got ${res.status}`);
    expect(pinRow(CLIENT).failed_tries === 1, `failed_tries = ${pinRow(CLIENT).failed_tries}`);
    expect(db.__state.revoked.length === 1, 'the Supabase session created by the code was not revoked');
});
await check('F-02 an expired lockout starts a fresh count instead of re-locking on one mistake', async () => {
    reset(); db.__addUser(CLIENT); db.__state.otp.set(CLIENT, '111111');
    setPin(CLIENT, { failed_tries: 5, locked_until: new Date(Date.now() - 60e3).toISOString() });
    await clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '111111', pin: '000000' }));
    expect(pinRow(CLIENT).failed_tries === 1 && !pinRow(CLIENT).locked_until, `got ${JSON.stringify(pinRow(CLIENT))}`);
});
await check('F-02 valid email code + right PIN signs in and clears the counter', async () => {
    reset(); db.__addUser(CLIENT); db.__state.otp.set(CLIENT, '111111'); setPin(CLIENT, { failed_tries: 2 });
    const res = await clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '111111', pin: PIN }));
    expect(res.status === 200 && res.headers.get('set-cookie'), `sign-in failed (${res.status})`);
    expect(pinRow(CLIENT).failed_tries === 0, 'counter not cleared');
});

// --- F-03: PIN guesses on the tracking page are always counted, on a counter of their own ---
await check('F-03 five wrong PINs on a tracking page disable the PIN there (no emailed code requested)', async () => {
    reset(); setPin(CLIENT);
    const o = seedOrder({ doc_lock: true });
    for (let i = 0; i < 5; i++) await trackPOST(post('/api/track', { t: o.track_token, action: 'verify-unlock-code', code: '000000' }));
    const res = await trackPOST(post('/api/track', { t: o.track_token, action: 'verify-unlock-code', code: PIN }));
    expect(res.status === 401, `the right PIN still unlocked after 5 wrong guesses (${res.status})`);
});
await check('F-03 tracking-page guesses do not lock the client out of the portal', async () => {
    reset(); setPin(CLIENT);
    const o = seedOrder({ doc_lock: true });
    for (let i = 0; i < 5; i++) await trackPOST(post('/api/track', { t: o.track_token, action: 'verify-unlock-code', code: '000000' }));
    expect(pinRow(CLIENT).failed_tries === 0 && !pinRow(CLIENT).locked_until, `portal counter moved: ${JSON.stringify(pinRow(CLIENT))}`);
});
await check('F-03 the right PIN still unlocks normally', async () => {
    reset(); setPin(CLIENT);
    const o = seedOrder({ doc_lock: true });
    const res = await trackPOST(post('/api/track', { t: o.track_token, action: 'verify-unlock-code', code: PIN }));
    const body = await res.json();
    expect(res.status === 200 && body.unlockToken, `unlock failed (${res.status} ${JSON.stringify(body)})`);
});

// --- F-04: file checks fail closed ---
const PDF = new TextEncoder().encode('%PDF-1.7\n1 0 obj\n<<>>\nendobj\n');
function seedFile(o, over = {}) {
    const f = { id: randomUUID(), order_id: o.id, kind: 'client_document', storage_path: `orders/${o.id}/client/${randomUUID()}-a.pdf`,
        filename: 'a.pdf', size_bytes: PDF.length, content_type: 'application/pdf', uploaded: false, created_at: new Date().toISOString(), ...over };
    (tables().order_files ||= []).push(f);
    db.__state.storage.set(f.storage_path, PDF);
    return f;
}
const fileRow = (id) => (tables().order_files || []).find(f => f.id === id);
await check('F-04 a failed download leaves the file unconfirmed', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o);
    db.__state.failDownload.add(f.storage_path);
    const done = await core.confirmUploads(o.id, [f.id]);
    expect(done.length === 0 && fileRow(f.id)?.uploaded === false, `file accepted without inspection: ${JSON.stringify(fileRow(f.id))}`);
});
await check('F-04 a good file is still confirmed with its fingerprint', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o);
    const done = await core.confirmUploads(o.id, [f.id]);
    expect(done.length === 1 && fileRow(f.id).uploaded && /^[0-9a-f]{64}$/.test(fileRow(f.id).sha256 || ''), 'good file not confirmed');
});
const cron = () => keepaliveGET(new Request('https://site.test/api/keepalive', { headers: { authorization: 'Bearer test-cron' } }));
const dayOld = new Date(Date.now() - 2 * 864e5).toISOString();
await check('F-04 daily cleanup keeps a file row when storage cannot be reached', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o, { created_at: dayOld });
    db.__state.failExists.add(f.storage_path);
    await cron();
    expect(fileRow(f.id) && fileRow(f.id).uploaded === false, 'row deleted or confirmed after a storage error');
});
await check('F-04 daily cleanup still removes an upload that never reached storage', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o, { created_at: dayOld });
    db.__state.storage.delete(f.storage_path);
    await cron();
    expect(!fileRow(f.id), 'abandoned upload row was kept');
});
await check('F-04 files that keep failing cannot stop later uploads from being checked', async () => {
    reset(); const o = seedOrder();
    const old = new Date(Date.now() - 5 * 864e5).toISOString();
    for (let i = 0; i < 100; i++) db.__state.failDownload.add(seedFile(o, { created_at: old }).storage_path);
    const late = seedFile(o, { created_at: dayOld });
    const realNow = Date.now;
    try {
        for (let day = 0; day < 2 && !fileRow(late.id).uploaded; day++) {
            const t = realNow() + day * 864e5;
            Date.now = () => t;
            await cron();
        }
    } finally { Date.now = realNow; }
    expect(fileRow(late.id).uploaded === true, 'a later upload was never inspected within two daily runs');
});
await check('F-04 daily cleanup does not confirm a file it could not download', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o, { created_at: dayOld });
    db.__state.failDownload.add(f.storage_path);
    await cron();
    expect(fileRow(f.id) && fileRow(f.id).uploaded === false, `got ${JSON.stringify(fileRow(f.id))}`);
});

// --- F-05 / F-13: payments that can't be applied are flagged once; duplicates don't double-log ---
const webhook = (session) => webhookPOST(new Request('https://site.test/api/stripe-webhook', {
    method: 'POST', headers: { 'stripe-signature': 'fake' },
    body: JSON.stringify({ type: 'checkout.session.completed', data: { object: session } }),
}));
const reviewEvents = (o) => events(o.id).filter(e => e.kind === 'payment' && !e.client_visible);
await check('F-05 a paid, replaced payment link is flagged once for Nick (and emailed)', async () => {
    reset();
    const o = seedOrder({ status: 'awaiting_payment', amount_due_cents: 10000, stripe_session_id: 'cs_test_newlink123' });
    const s = { id: 'cs_test_oldlink123', payment_status: 'paid', amount_total: 10000, metadata: { order_id: o.id } };
    await webhook(s); await webhook(s);
    expect(!o.paid_at, 'order was marked paid from a replaced link');
    expect(reviewEvents(o).length === 1, `expected 1 private review entry, got ${reviewEvents(o).length}`);
    expect(emails.some(e => e.to.includes(ADMIN) && /review/i.test(e.subject)), 'Nick was not emailed');
});
await check('F-05 if the alert email fails, nothing is marked and Stripe is asked to retry', async () => {
    reset(); resendUp = false;
    const o = seedOrder({ status: 'awaiting_payment', amount_due_cents: 10000, stripe_session_id: 'cs_test_newlink123' });
    const s = { id: 'cs_test_oldlink123', payment_status: 'paid', amount_total: 10000, metadata: { order_id: o.id } };
    const first = await webhook(s);
    expect(first.status >= 500 && reviewEvents(o).length === 0, `status ${first.status}, review entries ${reviewEvents(o).length}`);
    resendUp = true;
    const retry = await webhook(s);
    expect(retry.status === 200 && reviewEvents(o).length === 1 && emails.some(e => /review/i.test(e.subject)), 'the retry did not alert Nick');
});
await check('F-05 an underpaid session is flagged, not applied', async () => {
    reset();
    const o = seedOrder({ status: 'awaiting_payment', amount_due_cents: 10000, stripe_session_id: 'cs_test_newlink123' });
    await webhook({ id: 'cs_test_newlink123', payment_status: 'paid', amount_total: 5000, metadata: { order_id: o.id } });
    expect(!o.paid_at && reviewEvents(o).length === 1, 'underpayment not flagged or applied anyway');
});
await check('F-05 a normal payment is applied and not flagged', async () => {
    reset();
    const o = seedOrder({ status: 'awaiting_payment', amount_due_cents: 10000, stripe_session_id: 'cs_test_newlink123' });
    const s = { id: 'cs_test_newlink123', payment_status: 'paid', amount_total: 10000, metadata: { order_id: o.id } };
    await webhook(s); await webhook(s);
    expect(o.paid_at && reviewEvents(o).length === 0, `paid=${o.paid_at} review=${reviewEvents(o).length}`);
});
await check('F-13 two payment confirmations at once add one "Payment received" entry', async () => {
    reset();
    const o = seedOrder({ status: 'awaiting_payment', amount_due_cents: 10000, stripe_session_id: 'cs_test_newlink123' });
    await Promise.all([orders.markPaid(o.id, 10000, 'cs_test_newlink123'), orders.markPaid(o.id, 10000, 'cs_test_newlink123')]);
    const n = events(o.id).filter(e => e.title.startsWith('Payment received')).length;
    expect(n === 1, `got ${n} entries`);
});

// --- F-06: a locked tracking page shows status only ---
function seedLocked() {
    const o = seedOrder({ doc_lock: true, status: 'action_required', action_note: 'Gate code 4321 did not work' });
    (tables().order_events ||= []).push({ id: randomUUID(), order_id: o.id, kind: 'action_response', title: 'You sent the requested information',
        detail: 'Access notes: gate 4321', client_visible: true, created_at: new Date().toISOString() });
    seedFile(o, { uploaded: true, filename: 'Lease agreement.pdf', sha256: 'a'.repeat(64) });
    return o;
}
function expectLocked(v) {
    expect(v.unlocked === false, 'view reports unlocked');
    expect(!v.address.includes('12 Main'), 'full address shown');
    expect(v.events.every(e => !e.detail), 'timeline details shown');
    expect(!v.actionNote, 'action note shown');
    expect(v.files.every(f => f.name !== 'Lease agreement.pdf' && !f.sha256), 'file names or fingerprints shown');
}
await check('F-06 locked view hides timeline details, the action note and file names', async () => {
    reset(); const o = seedLocked();
    expectLocked(await (await trackPOST(post('/api/track', { t: o.track_token, action: 'view' }))).json());
});
await check('F-06 confirm-payment on a locked page also returns the locked view', async () => {
    reset(); const o = seedLocked();
    expectLocked(await (await trackPOST(post('/api/track', { t: o.track_token, action: 'confirm-payment', session: 'cs_test_whatever123' }))).json());
});
await check('F-06 unlocking still shows everything', async () => {
    reset(); setPin(CLIENT); const o = seedLocked();
    const v = await (await trackPOST(post('/api/track', { t: o.track_token, action: 'verify-unlock-code', code: PIN }))).json();
    expect(v.unlocked && v.actionNote && v.events.some(e => e.detail) && v.files.some(f => f.name === 'Lease agreement.pdf'), 'unlocked view incomplete');
});

// --- F-07: the built-in admin list is Nick only ---
await check('F-07 default ADMIN_EMAILS is Nick only', async () => {
    expect(core.ADMIN_EMAILS.length === 1 && core.ADMIN_EMAILS[0] === ADMIN, `got ${core.ADMIN_EMAILS.join(', ')}`);
});

// --- F-08: the email code is checked before a second factor is spent ---
function seedAdmin2fa() {
    const secret = core.generateTotpSecret(20);
    (tables().admin_totp ||= []).push({ email: ADMIN, secret_enc: core.encryptSecret(secret), enabled: true, last_used_step: 0 });
    (tables().admin_recovery_codes ||= []).push({ id: randomUUID(), email: ADMIN, code_hash: core.keyedHash('admin-recovery-v1', `${ADMIN}:ABCDEFGH`), used: false });
    return secret;
}
const addAdminCode = (code) => (tables().admin_codes ||= []).push({ id: randomUUID(), email: ADMIN, code_hash: core.sha256(`${ADMIN}:${code}`),
    expires_at: new Date(Date.now() + 6e5).toISOString(), attempts: 0, used: false, created_at: new Date().toISOString() });
const adminLogin = (body) => adminPOST(post('/api/admin', { action: 'verify-code', email: ADMIN, ...body }));
await check('F-08 a mistyped email code does not use up a recovery code', async () => {
    reset(); seedAdmin2fa(); addAdminCode('12345678');
    const res = await adminLogin({ code: '87654321', totp: 'ABCD-EFGH' });
    expect(res.status === 401, `expected 401, got ${res.status}`);
    expect(tables().admin_recovery_codes[0].used === false, 'recovery code was spent');
});
await check('F-08 a wrong second factor gives the same answer as a wrong email code', async () => {
    reset(); seedAdmin2fa(); addAdminCode('12345678');
    const wrongEmail = await adminLogin({ code: '87654321', totp: '000000' });
    const wrongSecond = await adminLogin({ code: '12345678', totp: '000000' });
    const [a, b] = [await wrongEmail.text(), await wrongSecond.text()];
    expect(wrongEmail.status === 401 && wrongSecond.status === 401 && a === b, `differ: ${a} vs ${b}`);
});
await check('F-08 email code + authenticator code still signs in', async () => {
    reset(); const secret = seedAdmin2fa(); addAdminCode('12345678');
    const res = await adminLogin({ code: '12345678', totp: core.totpCode(secret) });
    expect(res.status === 200 && res.headers.get('set-cookie'), `sign-in failed (${res.status} ${await res.text()})`);
});

console.log(`\n${passed} real-handler checks passed, ${failures.length} failed`);
if (failures.length) process.exit(1);
