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
        this.checkout = { sessions: {
            retrieve: async (id) => stripeSessions.get(id) || { id, payment_status: 'unpaid', metadata: {} },
            expire: async () => ({}),
            create: async () => { const id = `cs_test_${randomUUID().replace(/-/g, '')}`; const ses = { id, url: `https://checkout.stripe.com/c/pay/${id}`, status: 'open', payment_status: 'unpaid' }; stripeSessions.set(id, ses); return ses; },
        } };
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
const { POST: feedbackPOST } = await import('../api/feedback.mjs');
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

await check('F-01 the cookie from a real sign-in renews once its access token expires', async () => {
    reset(); db.__addUser(CLIENT); db.__state.otp.set(CLIENT, '111111');
    const login = await clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '111111' }));
    const cookie = login.headers.get('set-cookie').split(';')[0];
    db.__state.sessions.clear();   // every access token has expired
    const res = await clientPOST(post('/api/client', { action: 'list' }, { cookie }));
    expect(res.status === 200 && /nps_client=/.test(res.headers.get('set-cookie') || ''), `renewal failed (${res.status})`);
});

await check('F-01 "sign out everywhere" ends every session of that client', async () => {
    reset(); db.__addUser(CLIENT); db.__state.otp.set(CLIENT, '111111');
    const first = (await clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '111111' }))).headers.get('set-cookie').split(';')[0];
    const second = (await clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '111111' }))).headers.get('set-cookie').split(';')[0];
    await clientPOST(post('/api/client', { action: 'logout-all' }, { cookie: first }));
    const res = await clientPOST(post('/api/client', { action: 'list' }, { cookie: second }));
    expect(res.status === 401 && db.__state.refreshTokens.size === 0, `other session still works (${res.status})`);
});


// --- Trusted devices (30 days) and login alerts ---
const cookieValue = (res, name) => (res.headers.get('set-cookie') || '').match(new RegExp(`${name}=([^;,]+)`))?.[1];
const codeLogin = (extra = {}, headers = {}) => { db.__state.otp.set(CLIENT, '111111'); return clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '111111', ...extra }, headers)); };
await check('Trusted devices: a remembered device skips the PIN next time, but still needs the email code', async () => {
    reset(); db.__addUser(CLIENT); setPin(CLIENT);
    const first = await codeLogin({ pin: PIN });
    const device = cookieValue(first, 'nps_device');
    expect(first.status === 200 && device, 'device was not remembered');
    const again = await codeLogin({}, { cookie: `nps_device=${device}` });
    expect(again.status === 200 && cookieValue(again, 'nps_client'), `trusted device was still asked for the PIN (${again.status})`);
    db.__state.otp.clear();
    const noCode = await clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '999999' }, { cookie: `nps_device=${device}` }));
    expect(noCode.status === 401, `trusted device signed in without an email code (${noCode.status})`);
});
await check('Trusted devices: an untrusted device is still asked for the PIN', async () => {
    reset(); db.__addUser(CLIENT); setPin(CLIENT);
    const res = await codeLogin({});
    expect(res.status === 200 && (await res.json()).requiresPin === true, 'PIN not requested on a new device');
});
await check('Trusted devices: a device remembered for one client does not work for another', async () => {
    reset(); db.__addUser(CLIENT); db.__addUser('other@example.com'); setPin(CLIENT); setPin('other@example.com');
    const first = await codeLogin({ pin: PIN });
    const device = cookieValue(first, 'nps_device');
    db.__state.otp.set('other@example.com', '111111');
    const res = await clientPOST(post('/api/client', { action: 'verify-code', email: 'other@example.com', code: '111111' }, { cookie: `nps_device=${device}` }));
    expect(res.status === 200 && (await res.json()).requiresPin === true, 'another client was let in by this device');
});
await check('Trusted devices: remember is optional and off when the client says no', async () => {
    reset(); db.__addUser(CLIENT); setPin(CLIENT);
    const res = await codeLogin({ pin: PIN, remember: false });
    expect(!cookieValue(res, 'nps_device') && (tables().client_trusted_devices || []).length === 0, 'device remembered without consent');
});
await check('Login alerts: a sign-in from a new device emails the client', async () => {
    reset(); db.__addUser(CLIENT);
    const res = await codeLogin({ remember: false }, { 'user-agent': 'Mozilla/5.0 (iPhone) Safari' });
    expect(res.status === 200, `sign-in failed (${res.status})`);
    expect(emails.some(e => e.to.includes(CLIENT) && /New sign-in to your account/.test(e.subject)), 'no login alert was sent');
});
await check('Login alerts: no alert for a trusted device', async () => {
    reset(); db.__addUser(CLIENT);
    const first = await codeLogin({});
    emails.length = 0;
    await codeLogin({}, { cookie: `nps_device=${cookieValue(first, 'nps_device')}` });
    expect(!emails.some(e => /New sign-in/.test(e.subject)), 'alert sent for a device the client already trusts');
});
await check('Trusted devices: "sign out all devices" forgets every remembered device', async () => {
    reset(); db.__addUser(CLIENT); setPin(CLIENT);
    const first = await codeLogin({ pin: PIN });
    const device = cookieValue(first, 'nps_device');
    const client = cookieValue(first, 'nps_client');
    await clientPOST(post('/api/client', { action: 'logout-all' }, { cookie: `nps_client=${client}` }));
    expect((tables().client_trusted_devices || []).length === 0, 'trusted devices survived sign out all');
    db.__state.otp.set(CLIENT, '111111');
    const after = await clientPOST(post('/api/client', { action: 'verify-code', email: CLIENT, code: '111111' }, { cookie: `nps_device=${device}` }));
    expect((await after.json()).requiresPin === true, 'old device still skipped the PIN');
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
    expect(db.__state.refreshTokens.size === 0, "the revoked session's refresh token still works");
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
    expect(done.files.length === 0 && done.stillChecking === 1 && fileRow(f.id)?.uploaded === false, `file accepted without inspection: ${JSON.stringify(fileRow(f.id))}`);
});
await check('F-04 a good file is still confirmed with its fingerprint', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o);
    const done = await core.confirmUploads(o.id, [f.id]);
    expect(done.files.length === 1 && done.stillChecking === 0 && fileRow(f.id).uploaded && /^[0-9a-f]{64}$/.test(fileRow(f.id).sha256 || ''), 'good file not confirmed');
});
await check('F-04 a file that never reached storage is counted as missing, not "still being checked"', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o);
    db.__state.storage.delete(f.storage_path);
    const r = await core.confirmUploads(o.id, [f.id]);
    expect(r.missing === 1 && r.stillChecking === 0 && r.files.length === 0, JSON.stringify(r));
});
const adminCookie = () => {
    const token = 'A'.repeat(43);
    (tables().admin_sessions ||= []).push({ token_hash: core.sha256(token), email: ADMIN, expires_at: new Date(Date.now() + 864e5).toISOString(), last_seen_at: new Date().toISOString() });
    return `nps_admin=${token}`;
};
await check('F-04 a proof upload with an unchecked file does not mark the order served or email the client', async () => {
    reset(); const o = seedOrder({ status: 'attempting' });
    const good = seedFile(o, { kind: 'proof' }); const slow = seedFile(o, { kind: 'proof' });
    db.__state.failDownload.add(slow.storage_path);
    const res = await adminPOST(post('/api/admin', { action: 'proof-finish', id: o.id, fileIds: [good.id, slow.id], markServed: true }, { cookie: adminCookie() }));
    expect(res.status === 503, `expected 503, got ${res.status}`);
    expect(o.status === 'attempting' && !o.legal_hold, `order changed: ${o.status}`);
    expect(!emails.some(e => e.to.includes(CLIENT)), 'the client was emailed');
    db.__state.failDownload.clear();
    const retry = await adminPOST(post('/api/admin', { action: 'proof-finish', id: o.id, fileIds: [good.id, slow.id], markServed: true }, { cookie: adminCookie() }));
    expect(retry.status === 200 && o.status === 'served' && emails.some(e => e.to.includes(CLIENT)), `retry failed (${retry.status})`);
});
await check('F-04 a proof file that fails the file check stops the order being marked served', async () => {
    reset(); const o = seedOrder({ status: 'attempting' });
    const good = seedFile(o, { kind: 'proof' }); const fake = seedFile(o, { kind: 'proof' });
    db.__state.storage.set(fake.storage_path, new TextEncoder().encode('<html><script>alert(1)</script></html>'));
    const res = await adminPOST(post('/api/admin', { action: 'proof-finish', id: o.id, fileIds: [good.id, fake.id], markServed: true }, { cookie: adminCookie() }));
    expect(res.status === 400 && o.status === 'attempting' && !emails.some(e => e.to.includes(CLIENT)), `status ${res.status}, order ${o.status}`);
    expect(!fileRow(fake.id), 'the disguised file was kept');
});
await check('P27 Nick sees his signed-in devices and can sign out another one, but not the one he is using', async () => {
    reset();
    const mine = adminCookie();
    const other = 'B'.repeat(43);
    tables().admin_sessions.push({ token_hash: core.sha256(other), email: ADMIN, expires_at: new Date(Date.now() + 864e5).toISOString(),
        last_seen_at: new Date().toISOString(), user_agent: 'Mozilla/5.0 (iPhone) Safari/604.1' });
    tables().admin_sessions.push({ token_hash: core.sha256('C'.repeat(43)), email: 'someone@else.test', expires_at: new Date(Date.now() + 864e5).toISOString(), last_seen_at: new Date().toISOString() });
    const list = await (await adminPOST(post('/api/admin', { action: 'sessions' }, { cookie: mine }))).json();
    expect(list.sessions.length === 2 && list.sessions.filter(s => s.current).length === 1, `got ${JSON.stringify(list.sessions)}`);
    const otherId = list.sessions.find(s => !s.current).id;
    const self = await adminPOST(post('/api/admin', { action: 'revoke-session', sessionId: list.sessions.find(s => s.current).id }, { cookie: mine }));
    expect(self.status === 400, `signing out the current device via the list was allowed (${self.status})`);
    const ok = await (await adminPOST(post('/api/admin', { action: 'revoke-session', sessionId: otherId }, { cookie: mine }))).json();
    expect(ok.sessions.length === 1 && ok.sessions[0].current, 'other device still listed');
    const gone = await adminPOST(post('/api/admin', { action: 'me' }, { cookie: `nps_admin=${other}` }));
    expect(gone.status === 401, `revoked device still signed in (${gone.status})`);
    expect(tables().admin_sessions.some(s => s.email === 'someone@else.test'), "another admin's session was touched");
});
await check('Option 2: a new request starts with the document lock on', async () => {
    reset();
    const { POST: requestPOST } = await import('../api/request.mjs');
    const res = await requestPOST(post('/api/request', { step: 'create', clientName: 'Lock Default', clientEmail: CLIENT, clientPhone: '209-555-0100', recipientName: 'Lock Target', docType: 'Other Legal Document', address: '1 Test Rd', city: 'Stockton', zip: '95202', tier: 'standard', addons: [], acceptTerms: true, files: [] }));
    const body = await res.json();
    expect(res.status === 200 && body.code, `create failed (${res.status} ${JSON.stringify(body)})`);
    const row = tables().orders.find(o => o.code === body.code);
    expect(row && row.doc_lock === true, `doc_lock = ${row?.doc_lock}`);
});
await check('F-04 the tracking page is told when a reply file is still being checked', async () => {
    reset(); const o = seedOrder({ status: 'received' }); const slow = seedFile(o, { kind: 'action_upload' });
    db.__state.failDownload.add(slow.storage_path);
    const v = await (await trackPOST(post('/api/track', { t: o.track_token, action: 'respond-finish', fileIds: [slow.id] }))).json();
    expect(v.filesStillChecking === 1 && v.filesMissing === 0, JSON.stringify({ c: v.filesStillChecking, m: v.filesMissing }));
});
await check('F-04 the new-request email says when uploads are still being checked', async () => {
    reset(); const o = seedOrder(); const good = seedFile(o); const slow = seedFile(o);
    db.__state.failDownload.add(slow.storage_path);
    const { POST: requestPOST } = await import('../api/request.mjs');
    const res = await requestPOST(post('/api/request', { step: 'finish', t: o.track_token, fileIds: [good.id, slow.id] }));
    const toNick = emails.find(e => e.to.includes(ADMIN) && /New request/.test(e.subject));
    expect(res.status === 200 && toNick && /1 document\(s\) attached\. 1 more could not be checked yet/.test(toNick.text), `email: ${toNick?.text}`);
});
await check('F-10 a PDF with a script action deep inside (past 4 KB) is refused', async () => {
    const pdf = new TextEncoder().encode(`%PDF-1.7\n${'x'.repeat(10000)}\n<< /S /JavaScript /JS (app.alert(1)) >>\n%%EOF`);
    expect(core.verifyFileMagic(pdf, 'a.pdf') === false, 'deep /JavaScript action accepted');
    expect(core.verifyFileMagic(new TextEncoder().encode(`%PDF-1.7\n${'x'.repeat(10000)}\n%%EOF`), 'a.pdf') === true, 'clean PDF refused');
});
await check('F-10 HTML appended to the end of a PNG is refused', async () => {
    const png = new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, ...new Uint8Array(9000)]);
    const tail = new TextEncoder().encode('<script>alert(1)</script>');
    expect(core.verifyFileMagic(new Uint8Array([...png, ...tail]), 'a.png') === false, 'PNG with appended script accepted');
    expect(core.verifyFileMagic(png, 'a.png') === true, 'clean PNG refused');
});
const cron = () => keepaliveGET(new Request('https://site.test/api/keepalive', { headers: { authorization: 'Bearer test-cron' } }));
const dayOld = new Date(Date.now() - 2 * 864e5).toISOString();
await check('F-04 daily cleanup keeps a file row when storage cannot be reached', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o, { created_at: dayOld });
    db.__state.failExists.add(f.storage_path);
    await cron();
    expect(fileRow(f.id) && fileRow(f.id).uploaded === false, 'row deleted or confirmed after a storage error');
});
await check('F-04 a "bucket not found" error is not taken as a missing upload', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o, { created_at: dayOld });
    db.__state.noBucket.add(f.storage_path);
    await cron();
    expect(fileRow(f.id) && fileRow(f.id).uploaded === false, 'row deleted after a bucket error');
});
await check('F-04 daily cleanup still removes an upload that never reached storage', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o, { created_at: dayOld });
    db.__state.storage.delete(f.storage_path);
    await cron();
    expect(!fileRow(f.id), 'abandoned upload row was kept');
});
await check('F-04 files that keep failing cannot stop later uploads from being checked (1,000 stuck ahead)', async () => {
    reset(); const o = seedOrder();
    const old = new Date(Date.now() - 5 * 864e5).toISOString();
    for (let i = 0; i < 1000; i++) db.__state.failDownload.add(seedFile(o, { created_at: old }).storage_path);
    const late = seedFile(o, { created_at: dayOld });
    const realNow = Date.now;
    try {
        for (let day = 0; day < 11 && !fileRow(late.id).uploaded; day++) {
            const t = realNow() + day * 864e5;
            Date.now = () => t;
            await cron();
        }
    } finally { Date.now = realNow; }
    expect(fileRow(late.id).uploaded === true, 'a later upload was never inspected within ceil(1001 / 100) = 11 daily runs');
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
await check('F-05 with no Resend key, sendEmail reports that nothing was sent', async () => {
    const key = process.env.RESEND_API_KEY;
    delete process.env.RESEND_API_KEY;
    const log = console.log; console.log = () => {};
    try { expect(await orders.sendEmail({ to: ADMIN, subject: 'x', heading: 'x', lines: [] }) === false, 'reported as sent'); }
    finally { process.env.RESEND_API_KEY = key; console.log = log; }
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
await check('P27 a very long browser name never breaks Nick\'s sign-in', async () => {
    reset(); addAdminCode('12345678');
    const res = await adminPOST(post('/api/admin', { action: 'verify-code', email: ADMIN, code: '12345678' }, { 'user-agent': 'Mozilla/5.0 '.repeat(30) }));
    expect(res.status === 200 && res.headers.get('set-cookie'), `sign-in failed (${res.status} ${await res.text()})`);
    expect(tables().admin_sessions[0].user_agent.length <= 200, 'browser name not shortened');
});
await check('F-08 email code + authenticator code still signs in', async () => {
    reset(); const secret = seedAdmin2fa(); addAdminCode('12345678');
    const res = await adminLogin({ code: '12345678', totp: core.totpCode(secret) });
    expect(res.status === 200 && res.headers.get('set-cookie'), `sign-in failed (${res.status} ${await res.text()})`);
});

await check('R1 a recovery code (XXXX-XXXX) works where the dashboard asks for the authenticator code, once only', async () => {
    reset(); seedAdmin2fa();
    const first = await adminPOST(post('/api/admin', { action: 'generate-recovery-codes', totp: 'abcd-efgh' }, { cookie: adminCookie() }));
    expect(first.status === 200 && (await first.json()).codes.length === 8, `recovery code refused (${first.status})`);
    reset(); seedAdmin2fa();
    tables().admin_recovery_codes[0].used = true;
    const reused = await adminPOST(post('/api/admin', { action: 'generate-recovery-codes', totp: 'ABCD-EFGH' }, { cookie: adminCookie() }));
    expect(reused.status === 403, `used recovery code accepted (${reused.status})`);
});
await check('R2 an authenticator set up under a different APP_SECRET gives a clear message, not a server error', async () => {
    reset(); seedAdmin2fa(); addAdminCode('12345678');
    tables().admin_totp[0].secret_enc = core.encryptSecret('JBSWY3DPEHPK3PXP').replace(/\.([^.]+)$/, '.AAAA$1');
    const res = await adminLogin({ code: '12345678', totp: '123456' });
    const body = await res.json();
    expect(res.status === 409 && /different copy of this site/.test(body.error), `${res.status} ${JSON.stringify(body)}`);
});

// --- F-10: the whole file is scanned, wherever the payload sits ---
const bigPdf = (middle) => {
    const pad = 'stream\n' + 'A'.repeat(1_500_000) + '\nendstream\n';
    return new TextEncoder().encode(`%PDF-1.7\n${pad}${middle}\n${pad}%%EOF`);
};
await check('F-10 PDF actions buried in the middle of a 3 MB file are refused', async () => {
    for (const bad of ['/Launch', '/EmbeddedFiles', '/EmbeddedFile', '/RichMedia', '/SubmitForm', '/ImportData', '/GoToE', '/J#61vaScript', '/#4A#53']) {
        expect(core.verifyFileMagic(bigPdf(`<< /S ${bad} >>`), 'a.pdf') === false, `${bad} accepted`);
    }
    expect(core.verifyFileMagic(bigPdf('<< /S /URI /URI (https://example.com) >> /OpenAction << /S /GoTo >>'), 'a.pdf') === true, 'ordinary link/open action refused');
});
const pngChunk = (type, data) => { const d = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    return [(d.length >>> 24) & 255, (d.length >>> 16) & 255, (d.length >>> 8) & 255, d.length & 255, ...new TextEncoder().encode(type), ...d, 0, 0, 0, 0]; };
await check('F-10 a script hidden in a PNG text chunk in the middle of the file is refused', async () => {
    const sig = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    const idat = pngChunk('IDAT', new Uint8Array(500_000));
    const png = (text) => new Uint8Array([...sig, ...pngChunk('IHDR', new Uint8Array(13)), ...idat, ...pngChunk('tEXt', `Comment\0${text}`), ...idat, ...pngChunk('IEND', '')]);
    expect(core.verifyFileMagic(png('<script>alert(1)</script>'), 'a.png') === false, 'script in tEXt accepted');
    expect(core.verifyFileMagic(png('Taken at the front door'), 'a.png') === true, 'plain PNG text refused');
});
await check('F-10 real-looking PDFs with large compressed streams are never refused by chance (5 x 5 MB random data)', async () => {
    const { randomBytes } = await import('node:crypto');
    for (let i = 0; i < 5; i++) {
        const pdf = Buffer.concat([Buffer.from('%PDF-1.7\n1 0 obj << /Length 5242880 /Filter /FlateDecode >>\nstream\n'), randomBytes(5 * 1024 * 1024), Buffer.from('\nendstream\nendobj\n%%EOF')]);
        expect(core.verifyFileMagic(new Uint8Array(pdf), 'a.pdf') === true, `random stream data refused (try ${i + 1})`);
    }
});

// --- F-11: photos are cleaned on the server too, for uploads that skipped the site's page ---
const GPS = 'GPS 37.9577N 121.2908W';
const jpegSeg = (m, txt) => { const d = new TextEncoder().encode(txt); return [0xFF, m, ((d.length + 2) >> 8) & 255, (d.length + 2) & 255, ...d]; };
const gpsJpeg = new Uint8Array([0xFF, 0xD8, ...jpegSeg(0xE0, 'JFIF\0'), ...jpegSeg(0xE1, `Exif\0\0${GPS}`), 0xFF, 0xDA, 0, 4, 1, 2, 3, 4, 0xFF, 0xD9]);
const asText = (u8) => Buffer.from(u8).toString('latin1');
await check('F-11 a photo uploaded straight to storage loses its GPS before it is confirmed', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o, { filename: 'door.jpg', content_type: 'image/jpeg', storage_path: `orders/${o.id}/client/x-door.jpg` });
    db.__state.storage.set(f.storage_path, gpsJpeg);
    const r = await core.confirmUploads(o.id, [f.id]);
    const stored = db.__state.storage.get(f.storage_path);
    expect(r.files.length === 1 && fileRow(f.id).uploaded, 'photo not confirmed');
    expect(!asText(stored).includes('GPS') && asText(stored).includes('JFIF'), 'GPS still in the stored photo');
    expect(fileRow(f.id).sha256 === core.sha256(Buffer.from(stored)), 'fingerprint is not of the cleaned file');
});
await check('F-11 if the cleaned photo cannot be stored back, it is not confirmed (retried later)', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o, { filename: 'door.jpg', content_type: 'image/jpeg', storage_path: `orders/${o.id}/client/y-door.jpg` });
    db.__state.storage.set(f.storage_path, gpsJpeg); db.__state.failUpdate.add(f.storage_path);
    const r = await core.confirmUploads(o.id, [f.id]);
    expect(r.stillChecking === 1 && !fileRow(f.id).uploaded, 'confirmed with GPS still inside');
});

// --- Phase 2: field tools, evidence and payments ---
const adminAct = (body, cookie) => adminPOST(post('/api/admin', body, { cookie }));
const track = (o, body) => trackPOST(post('/api/track', { t: o.track_token, ...body }));
const evs = (o) => (tables().order_events || []).filter(e => e.order_id === o.id);
await check('P2 PDF pages are counted (page objects, or the page tree when pages are compressed)', async () => {
    const three = new TextEncoder().encode('%PDF-1.7\n1 0 obj << /Type /Pages /Kids [2 0 R 3 0 R 4 0 R] /Count 3 >>\n2 0 obj << /Type /Page >>\n3 0 obj << /Type /Page >>\n4 0 obj << /Type /Page >>\n%%EOF');
    expect(core.countPdfPages(three) === 3, `got ${core.countPdfPages(three)}`);
    const compressed = new TextEncoder().encode('%PDF-1.7\n1 0 obj << /Type /Pages /Kids [5 0 R] /Count 150 >>\n5 0 obj << /Type /ObjStm /N 150 >>\n%%EOF');
    expect(core.countPdfPages(compressed) === 150, `got ${core.countPdfPages(compressed)}`);
    expect(core.countPdfPages(new TextEncoder().encode('%PDF-1.7\n%%EOF')) === null, 'invented a page count');
    reset(); const o = seedOrder(); const f = seedFile(o); db.__state.storage.set(f.storage_path, three);
    await core.confirmUploads(o.id, [f.id]);
    expect(fileRow(f.id).page_count === 3, `stored ${fileRow(f.id).page_count}`);
});
await check('P2 each attempt is labelled with its time window, in California time', async () => {
    reset(); const o = seedOrder(); const cookie = adminCookie();
    const at = (h) => { const d = new Date(); d.setUTCHours(h + 8, 0, 0, 0); while (d > new Date()) d.setUTCDate(d.getUTCDate() - 1); return d.toISOString(); };   // PST = UTC-8 (PDT shifts it by 1h; 9am/9pm stay put)
    for (const [h, w] of [[9, 'morning'], [21, 'night']]) {
        const r = await adminAct({ action: 'update', id: o.id, kind: 'attempt', outcome: 'No answer', at: at(h) }, cookie);
        expect(r.status === 200, `attempt ${r.status}`);
        expect(evs(o).some(e => e.title === `Attempt (${w}): No answer`), `no ${w} label: ${evs(o).map(e => e.title).join(' | ')}`);
    }
    const bad = await adminAct({ action: 'update', id: o.id, kind: 'attempt', outcome: 'No answer', at: new Date(Date.now() + 864e5).toISOString() }, cookie);
    expect(bad.status === 400, `future attempt accepted (${bad.status})`);
});
await check('P2 bulk close closes only served or cancelled jobs', async () => {
    reset(); const cookie = adminCookie();
    const a = seedOrder({ status: 'served', legal_hold: true }), b = seedOrder({ status: 'cancelled', code: 'NP-222222' }), c = seedOrder({ status: 'attempting', code: 'NP-333333' });
    const r = await (await adminAct({ action: 'bulk-close', ids: [a.id, b.id, c.id] }, cookie)).json();
    const st = (o) => tables().orders.find(x => x.id === o.id).status;
    expect(st(a) === 'closed' && st(b) === 'closed' && st(c) === 'attempting', `${st(a)} ${st(b)} ${st(c)}`);
    expect(r.closed.length === 2 && r.skipped === 1, JSON.stringify(r));
});
await check('P2 the tracking page logs views (once an hour), unlocks, downloads and replies for the evidence pack', async () => {
    reset(); const o = seedOrder(); const f = seedFile(o); f.uploaded = true; f.sha256 = 'a'.repeat(64);
    await track(o, { action: 'view' }); await track(o, { action: 'view' }); await track(o, { action: 'view' });
    await track(o, { action: 'download', fileId: f.id });
    const log = tables().client_audit_logs || [];
    expect(log.filter(l => l.action === 'view').length === 1, `views logged: ${log.filter(l => l.action === 'view').length}`);
    expect(log.some(l => l.action === 'download' && l.detail === 'a.pdf') && log.every(l => /^[0-9a-f]{64}$/.test(l.ip_hash)), 'download not logged, or IP not hashed');
    const pack = await (await adminAct({ action: 'evidence-pack', id: o.id }, adminCookie())).json();
    expect(pack.client_activity.length === 2 && pack.files[0].sha256 === 'a'.repeat(64) && pack.timeline_seal && pack.order.code === o.code, JSON.stringify(pack).slice(0, 300));
});
await check('P2 clients can send a note on any open request; it flags "Client replied" and leaves the status alone', async () => {
    reset(); const o = seedOrder({ status: 'attempting' });
    const r = await track(o, { action: 'respond', reply: 'They work nights, try after 8 PM.' });
    expect(r.status === 200, `note refused (${r.status} ${await r.clone().text()})`);
    expect(tables().orders[0].status === 'attempting', 'status changed');
    expect(evs(o).some(e => e.kind === 'action_response' && e.title === 'You sent Nick a note'), 'no note entry');
    expect((tables().client_audit_logs || []).some(l => l.action === 'reply'), 'reply not logged');
    const list = await (await adminAct({ action: 'list' }, adminCookie())).json();
    expect(list.orders[0].client_replied === true, 'no Client replied flag');
    const addr = await track(o, { action: 'respond', address: '9 Other St' });
    expect(addr.status === 409 && tables().orders[0].address === '12 Main St', 'address changed without Nick asking');
});
await check('P2 a finished or locked request does not take notes', async () => {
    reset(); const served = seedOrder({ status: 'served', legal_hold: true });
    expect((await track(served, { action: 'respond', reply: 'hi' })).status === 409, 'served request took a note');
    reset(); const locked = seedOrder({ status: 'attempting', doc_lock: true });
    expect((await track(locked, { action: 'respond', reply: 'hi' })).status === 403, 'locked request took a note');
});
await check('P2 the list shows when Nick last contacted the client', async () => {
    reset(); const o = seedOrder({ status: 'attempting' });
    await adminAct({ action: 'update', id: o.id, kind: 'note', note: 'Private', clientVisible: false }, adminCookie());
    let l = await (await adminAct({ action: 'list' }, adminCookie())).json();
    expect(l.orders[0].last_contact_at === null, 'a private note counted as contact');
    await adminAct({ action: 'update', id: o.id, kind: 'attempt', outcome: 'No answer' }, adminCookie());
    l = await (await adminAct({ action: 'list' }, adminCookie())).json();
    expect(typeof l.orders[0].last_contact_at === 'string', 'visible attempt not counted');
});
await check('P2 only Nick\'s own entries count as contact, and his shared note clears "Client replied"', async () => {
    reset(); const o = seedOrder({ status: 'attempting' });
    (tables().order_events ||= []).push({ id: randomUUID(), order_id: o.id, kind: 'note', title: '2 files added by you', client_visible: true, created_at: new Date().toISOString() });
    let l = await (await adminAct({ action: 'list' }, adminCookie())).json();
    expect(l.orders[0].last_contact_at === null, 'a client upload counted as Nick contacting the client');
    await track(o, { action: 'respond', reply: 'Any news?' });
    l = await (await adminAct({ action: 'list' }, adminCookie())).json();
    expect(l.orders[0].client_replied === true, 'reply not flagged');
    await new Promise(r => setTimeout(r, 5));
    await adminAct({ action: 'update', id: o.id, kind: 'note', note: 'Trying again tonight.', clientVisible: true }, adminCookie());
    l = await (await adminAct({ action: 'list' }, adminCookie())).json();
    expect(l.orders[0].client_replied === false && l.orders[0].last_contact_at, 'Nick\'s shared note did not clear the flag');
});
await check('P2 an expired, unpaid payment link can be renewed from the tracking page; a live one cannot', async () => {
    reset(); const o = seedOrder({ status: 'awaiting_payment', amount_due_cents: 9000, stripe_session_id: 'cs_test_oldsession1', payment_url: 'https://checkout.stripe.com/c/pay/cs_test_oldsession1' });
    stripeSessions.set('cs_test_oldsession1', { id: 'cs_test_oldsession1', status: 'open', payment_status: 'unpaid', metadata: { order_id: o.id } });
    expect((await track(o, { action: 'renew-payment' })).status === 409, 'renewed a link that still works');
    stripeSessions.get('cs_test_oldsession1').status = 'expired';
    const r = await (await track(o, { action: 'renew-payment' })).json();
    expect(tables().orders[0].stripe_session_id !== 'cs_test_oldsession1' && /^https:\/\/checkout\.stripe\.com\//.test(r.payUrl || ''), `not renewed: ${JSON.stringify(r).slice(0, 200)}`);
});
await check('P2 the receipt appears once paid, and never on a locked page', async () => {
    reset(); const paid = seedOrder({ paid_at: new Date().toISOString(), amount_due_cents: 9000, status: 'paid', case_number: 'CV-1', court: 'LA Superior' });
    const v = await (await track(paid, { action: 'view' })).json();
    expect(v.receipt?.amountPaid === '$90.00' && v.receipt.caseNumber === 'CV-1', JSON.stringify(v.receipt));
    reset(); const locked = seedOrder({ paid_at: new Date().toISOString(), amount_due_cents: 9000, status: 'paid', doc_lock: true });
    expect((await (await track(locked, { action: 'view' })).json()).receipt === null, 'receipt shown on a locked page');
});

async function expectReject(fn, msg) { let threw = false; try { await fn(); } catch { threw = true; } if (!threw) throw new Error(msg); }
// --- Phase 3: field tools, Safe-Walk, digest, firms ---
const firms = await import('../api/_lib/firms.mjs');
const safewalkMod = await import('../api/_lib/safewalk.mjs');
await check('P3 a substituted-service mailing and a stakeout are recorded on the timeline', async () => {
    reset(); const o = seedOrder({ status: 'attempting' }); const cookie = adminCookie();
    const m = await adminAct({ action: 'update', id: o.id, kind: 'mailing', date: new Date().toISOString().slice(0, 10), city: 'Stockton' }, cookie);
    expect(m.status === 200 && evs(o).some(e => e.title === 'Substituted service: follow-up mailing sent' && /Stockton/.test(e.detail)), `mailing ${m.status}`);
    const end = new Date(), start = new Date(end - 75 * 60e3);
    const st = await adminAct({ action: 'update', id: o.id, kind: 'stakeout', start: start.toISOString(), end: end.toISOString() }, cookie);
    expect(st.status === 200 && evs(o).some(e => e.title === 'Stakeout: 75 min' && /15 min past the first hour/.test(e.detail)), `stakeout ${st.status}`);
    const bad = await adminAct({ action: 'update', id: o.id, kind: 'stakeout', start: end.toISOString(), end: start.toISOString() }, cookie);
    expect(bad.status === 400, 'backwards stakeout accepted');
});
await check('P3 expenses are private, totalled per job, and exported as CSV that spreadsheets cannot run', async () => {
    reset(); const o = seedOrder(); const cookie = adminCookie();
    await adminAct({ action: 'expense-add', id: o.id, miles: '12.4', fees: '8', label: 'Parking' }, cookie);
    const r = await (await adminAct({ action: 'expense-add', id: o.id, miles: 3, fees: '', label: '=HYPERLINK("x")' }, cookie)).json();
    expect(r.miles === 15.4 && r.feesCents === 800, JSON.stringify(r));
    expect(!evs(o).some(e => /Parking/.test(e.detail || '')), 'expense leaked onto the timeline');
    const csv = (await (await adminAct({ action: 'expenses-csv' }, cookie)).json()).csv;
    expect(/NP-123456/.test(csv) && /Total,,,15\.4,8\.00/.test(csv) && csv.includes(`"'=HYPERLINK`), csv);
    expect((await adminAct({ action: 'expense-add', id: o.id, miles: 0, fees: 0 }, cookie)).status === 400, 'empty expense accepted');
});
await check('P3 Safe-Walk alerts the emergency contact once when the timer runs out, and not after "I\'m safe"', async () => {
    reset(); seedAdmin2fa(); const o = seedOrder(); const cookie = adminCookie();
    (tables().admin_settings ||= []).push({ email: ADMIN, emergency_email: 'family@example.com' });
    const st = await adminAct({ action: 'safewalk-start', minutes: 15, id: o.id }, cookie);
    expect(st.status === 200, `start ${st.status}`);
    tables().safe_walks[0].due_at = new Date(Date.now() - 1000).toISOString();
    emails.length = 0;
    const [a, b] = await Promise.all([safewalkMod.alertOverdueWalks(), safewalkMod.alertOverdueWalks()]);
    const toContact = emails.filter(e => e.to.includes('family@example.com'));
    expect(a + b === 1 && toContact.length === 1 && /12 Main St/.test(JSON.stringify(toContact[0])), `alerts: ${a}+${b}, contact emails ${toContact.length}`);
    expect(await safewalkMod.alertOverdueWalks() === 0, 'alerted twice');
    reset(); seedAdmin2fa(); const c2 = adminCookie();
    (tables().admin_settings ||= []).push({ email: ADMIN, emergency_email: 'family@example.com' });
    await adminAct({ action: 'safewalk-start', minutes: 15 }, c2);
    await adminAct({ action: 'safewalk-safe' }, c2);
    tables().safe_walks[0].due_at = new Date(Date.now() - 1000).toISOString();
    expect(await safewalkMod.alertOverdueWalks() === 0, 'alerted after check-in');
});
await check('P3 Safe-Walk retries when the alert email fails, and changing the contact needs a step-up', async () => {
    reset(); const cookie = adminCookie();
    (tables().admin_settings ||= []).push({ email: ADMIN, emergency_email: 'family@example.com' });
    await adminAct({ action: 'safewalk-start', minutes: 5 }, cookie);
    tables().safe_walks[0].due_at = new Date(Date.now() - 1000).toISOString();
    resendUp = false;
    expect(await safewalkMod.alertOverdueWalks() === 0 && tables().safe_walks[0].alerted_at === null, 'a failed alert was marked as sent');
    resendUp = true;
    expect(await safewalkMod.alertOverdueWalks() === 1, 'no retry after the email came back');
    const change = await adminAct({ action: 'safewalk-contact', contact: 'attacker@example.com' }, cookie);
    expect(change.status === 403 && tables().admin_settings[0].emergency_email === 'family@example.com', `contact changed without step-up (${change.status})`);
});
await check('P3 a client on the daily summary gets no status emails, then one digest', async () => {
    reset(); const o = seedOrder(); const cookie = adminCookie();
    (tables().client_preferences ||= []).push({ email: CLIENT, notify_mode: 'daily' });
    emails.length = 0;
    await adminAct({ action: 'update', id: o.id, kind: 'status', status: 'attempting', notify: true }, cookie);
    expect(!emails.some(e => e.to.includes(CLIENT)), 'status email sent to a daily-summary client');
    const sent = await orders.sendDailyDigests('https://site.test');
    expect(sent === 1 && emails.some(e => e.to.includes(CLIENT) && /daily update/i.test(e.subject)), `digests ${sent}`);
});
await check('P3 removing a departing staff member ends their access and replaces their open links, in one step', async () => {
    reset();
    const firmId = await firms.createFirm('Vance & Ortiz LLP', 'boss@firm.example');
    await firms.addMember(firmId, 'boss@firm.example', CLIENT, 'paralegal');
    const open = seedOrder({ firm_id: firmId, status: 'attempting' }), done = seedOrder({ firm_id: firmId, status: 'served', code: 'NP-222222', track_token: 'S'.repeat(32) });
    (tables().client_trusted_devices ||= []).push({ token_hash: 'a'.repeat(64), email: CLIENT });
    (tables().webauthn_credentials ||= []).push({ credential_id: 'cred-xxxxxxxxxxxxxxxx', owner_kind: 'client', owner_email: CLIENT });
    const access = db.__sessionFor(CLIENT);
    const oldToken = open.track_token;
    await expectReject(() => firms.removeMember(post('/x', {}), firmId, CLIENT, 'boss@firm.example'), 'a paralegal removed the admin');
    emails.length = 0;
    const r = await firms.removeMember(post('/x', {}), firmId, 'boss@firm.example', CLIENT);
    expect(r.linksReplaced.join() === 'NP-123456', JSON.stringify(r));
    expect(open.track_token !== oldToken && done.track_token === 'S'.repeat(32), 'wrong links replaced');
    expect(!tables().client_trusted_devices.length && !tables().webauthn_credentials.length && !db.__state.sessions.has(access), 'devices, passkeys or sessions survived');
    expect(await firms.memberRole(firmId, CLIENT) === null, 'still a member');
    expect(emails.some(e => e.to.includes('boss@firm.example') && JSON.stringify(e).includes(open.track_token)), 'admin not sent the new link');
    await expectReject(() => firms.removeMember(post('/x', {}), firmId, 'boss@firm.example', 'boss@firm.example'), 'the last admin was removed');
});

// --- Surveys: client feedback and Nick's own answers ---
const feedback = (body, ip = '9.9.9.9') => feedbackPOST(post('/api/feedback', body, { 'x-real-ip': ip }));
const surveyRows = () => tables().survey_responses || [];
await check('S1 a client\'s answers are saved only with permission, and only real questions are kept', async () => {
    reset();
    const no = await feedback({ answers: { c01: 'Landlord' }, consent: false });
    expect(no.status === 400 && !surveyRows().length, `saved without permission (${no.status})`);
    const ok = await feedback({ answers: { c01: 'Landlord', c19: 'Fast and clear', n01: 'sneaky', zz: 'x', c20: 42, c02: '  ', c99: 'no such question', c00: 'x' }, consent: true, name: 'Pat', email: 'PAT@example.com' });
    expect(ok.status === 200 && surveyRows().length === 1, `not saved (${ok.status})`);
    const row = surveyRows()[0];
    expect(JSON.stringify(Object.keys(row.answers)) === '["c01","c19"]' && row.contact_email === 'pat@example.com', JSON.stringify(row));
    expect(row.ip_hash === core.keyedHash('survey-ip-v1', '9.9.9.9') && row.ip_hash !== core.sha256('9.9.9.9'), 'address not stored as a keyed hash');
    expect((await feedback({ answers: {}, consent: true })).status === 400, 'empty answers accepted');
});
await check('S4 thirty long answers fit in one request; oversized answers get a clear message, not a database error', async () => {
    reset();
    const long = Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`c${String(i + 1).padStart(2, '0')}`, 'word '.repeat(700)]));
    const r = await feedback({ answers: long, consent: true });
    expect(r.status === 200 && Object.keys(surveyRows()[0].answers).length === 30, `long answers refused (${r.status})`);
    const huge = Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`c${String(i + 1).padStart(2, '0')}`, '€'.repeat(2000)]));
    const big = await feedback({ answers: huge, consent: true }, '8.8.8.8');
    expect(big.status === 400 && /too long/.test((await big.json()).error), `oversized answers: ${big.status}`);
});
await check('S5 client answers come back a page at a time, with Nick\'s own answers separate', async () => {
    reset(); const cookie = adminCookie();
    for (let i = 0; i < 105; i++) (tables().survey_responses ||= []).push({ id: randomUUID(), form: 'client-v1', answers: { c30: `#${i}` }, consent: true, created_at: new Date(Date.now() - i * 1000).toISOString() });
    await adminAct({ action: 'survey-save', answers: { n01: 'mine' }, consent: true }, cookie);
    const p1 = await (await adminAct({ action: 'survey-list' }, cookie)).json();
    expect(p1.responses.length === 100 && p1.more === true && p1.mine?.answers.n01 === 'mine', `page 1: ${p1.responses.length}, more ${p1.more}`);
    const p2 = await (await adminAct({ action: 'survey-list', before: p1.responses.at(-1).created_at }, cookie)).json();
    const ids = new Set([...p1.responses, ...p2.responses].map(r => r.id));
    expect(p2.more === false && ids.size === 106, `pages overlap or miss rows: ${ids.size}`);
});
await check('S6 a page of very long answers stays under Vercel\'s 4.5 MB response limit, and paging still reaches every row', async () => {
    reset(); const cookie = adminCookie();
    const big = Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`c${String(i + 1).padStart(2, '0')}`, 'x'.repeat(4000)]));   // about 120 KB each
    for (let i = 0; i < 60; i++) (tables().survey_responses ||= []).push({ id: randomUUID(), form: 'client-v1', answers: big, consent: true, created_at: new Date(Date.now() - i * 1000).toISOString() });
    const seen = new Set(); let before, pages = 0, more = true;
    while (more) {
        const res = await adminAct({ action: 'survey-list', ...(before ? { before } : {}) }, cookie);
        const text = await res.text();
        expect(Buffer.byteLength(text) < 4.5 * 1024 * 1024, `page ${pages + 1} is ${Buffer.byteLength(text)} bytes`);
        const r = JSON.parse(text);
        r.responses.forEach(x => seen.add(x.id)); before = r.responses.at(-1)?.created_at; more = r.more; pages++;
        expect(pages < 20, 'paging never ends');
    }
    expect(seen.size === 60 && pages > 1, `${seen.size} rows over ${pages} pages`);
});
await check('S2 the feedback form traps bots, is rate limited, and refuses other sites', async () => {
    reset();
    expect((await feedback({ answers: { c01: 'x' }, consent: true, website: 'spam' })).status === 200 && !surveyRows().length, 'bot answer saved');
    let last; for (let i = 0; i < 6; i++) last = await feedback({ answers: { c30: `hi ${i}` }, consent: true }, '7.7.7.7');
    expect(last.status === 429 && surveyRows().length === 5, `rate limit: ${last.status}, ${surveyRows().length} saved`);
    const cross = await feedbackPOST(post('/api/feedback', { answers: { c01: 'x' }, consent: true }, { origin: 'https://evil.example' }));
    expect(cross.status === 403, `cross-site post accepted (${cross.status})`);
});
await check('S3 Nick has one set of answers he can update; reading answers needs his login', async () => {
    reset(); const cookie = adminCookie();
    await adminAct({ action: 'survey-save', answers: { n01: 'Up at 6', n02: 'Phone', c01: 'no' }, consent: true, replace: true }, cookie);
    await adminAct({ action: 'survey-save', answers: { n01: 'Up at 6, coffee first', n25: 'Route planning' }, consent: true, replace: true, cleared: ['n02'] }, cookie);
    await adminAct({ action: 'survey-save', answers: { n30: 'Second batch' }, consent: true }, cookie);   // a later batch adds to the set
    const mine = surveyRows().filter(r => r.form === 'nick-v1');
    expect(mine.length === 1 && mine[0].answers.n25 === 'Route planning' && mine[0].answers.n30 === 'Second batch' && !mine[0].answers.n02 && !mine[0].answers.c01, JSON.stringify(mine));
    expect((await adminAct({ action: 'survey-save', answers: { n01: 'x' }, consent: false }, cookie)).status === 400, 'saved without permission');
    await feedback({ answers: { c19: 'Great' }, consent: true });
    const list = await (await adminAct({ action: 'survey-list' }, cookie)).json();
    expect(list.responses.length === 2 && list.me === ADMIN, `list has ${list.responses.length}, me ${list.me}`);
    expect((await adminPOST(post('/api/admin', { action: 'survey-list' }))).status === 401, 'answers readable without login');
});

// --- F-09: with two-step off, sensitive actions need an emailed step-up code, not just the session cookie ---
async function emailedStepUp(cookie) {
    emails.length = 0;
    const res = await adminAct({ action: 'stepup-send-code' }, cookie);
    expect(res.status === 200, `stepup-send-code ${res.status}`);
    return /step-up code: (\d{8})/.exec(emails.at(-1)?.subject || '')?.[1];
}
await check('F-09 with two-step off, minting recovery codes needs an emailed step-up code', async () => {
    reset(); const cookie = adminCookie();
    const bare = await adminAct({ action: 'generate-recovery-codes' }, cookie);
    expect(bare.status === 403, `session alone was enough (${bare.status})`);
    const code = await emailedStepUp(cookie);
    expect(code, 'no step-up code emailed');
    const ok = await adminAct({ action: 'generate-recovery-codes', totp: code }, cookie);
    expect(ok.status === 200, `right code refused (${ok.status})`);
    const again = await adminAct({ action: 'generate-recovery-codes', totp: code }, cookie);
    expect(again.status === 403, `step-up code worked twice (${again.status})`);
});
await check('F-09 with two-step off, a stolen session cannot enrol its own authenticator', async () => {
    reset(); const cookie = adminCookie();
    const res = await adminAct({ action: 'totp-setup' }, cookie);
    expect(res.status === 403 && !(tables().admin_totp || []).length, `authenticator setup started without a step-up (${res.status})`);
    const code = await emailedStepUp(cookie);
    expect((await adminAct({ action: 'totp-setup', totp: code }, cookie)).status === 200, 'setup refused with a valid step-up');
});
await check('F-09 with two-step off, unlocking legal hold needs the step-up code (typing the reference is not enough)', async () => {
    reset(); const cookie = adminCookie(); const o = seedOrder({ legal_hold: true, status: 'served' });
    const res = await adminAct({ action: 'unlock-legal-hold', id: o.id, hold: false, confirm: o.code }, cookie);
    expect(res.status === 403 && tables().orders[0].legal_hold === true, `hold unlocked without step-up (${res.status})`);
});
await check('F-09 a step-up code is not a login code, and a login code is not a step-up code', async () => {
    reset(); const cookie = adminCookie();
    const code = await emailedStepUp(cookie);
    const login = await adminPOST(post('/api/admin', { action: 'verify-code', email: ADMIN, code }));
    expect(login.status === 401, `step-up code signed in (${login.status})`);
    reset(); const c2 = adminCookie(); addAdminCode('12345678');
    const use = await adminAct({ action: 'generate-recovery-codes', totp: '12345678' }, c2);
    expect(use.status === 403, `login code accepted as step-up (${use.status})`);
});
await check('F-09 with the authenticator on, an emailed step-up code cannot be requested', async () => {
    reset(); seedAdmin2fa();
    const res = await adminAct({ action: 'stepup-send-code' }, adminCookie());
    expect(res.status === 400, `step-up email sent while authenticator is on (${res.status})`);
});


// --- Ported from the field-tools branch: database file cap, byte-sized request limit, portal receipts and proof files ---
await check('PORT-1 when the database refuses the 26th file (order_files_cap), the request gets a clear 400', async () => {
    reset(); const o = seedOrder();
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
await check('PORT-2 a batch of uploads is created in one insert and every file gets its own upload link', async () => {
    reset(); const o = seedOrder();
    const out = await core.prepareUploads(o.id, 'client_document', [1, 2, 3].map(i => ({ name: `f${i}.pdf`, size: 10, type: 'application/pdf' })));
    expect(out.length === 3 && new Set(out.map(x => x.fileId)).size === 3 && out.every(x => x.fileId && x.uploadUrl), JSON.stringify(out));
});
await check('PORT-3 the 64 KB request limit counts bytes, so multi-byte text cannot carry three times as much', async () => {
    const body = JSON.stringify({ action: 'view', note: '\u20ac'.repeat(30000) });   // 30,000 characters, about 90 KB
    const res = await trackPOST(new Request('https://site.test/api/track', { method: 'POST', headers: { 'content-type': 'application/json' }, body }));
    expect(res.status === 413, `got ${res.status}`);
});
await check('PORT-4 portal receipt and proof links stay inside the client\'s own requests', async () => {
    reset(); db.__addUser(CLIENT);
    const mine = seedOrder({ paid_at: new Date().toISOString(), amount_due_cents: 7500 });
    const theirs = seedOrder({ id: randomUUID(), code: 'NP-654321', client_email: 'other@example.com', paid_at: new Date().toISOString(), track_token: 'U'.repeat(32) });
    (tables().order_files ||= []).push(
        { id: randomUUID(), order_id: mine.id, kind: 'proof', filename: 'mine.pdf', storage_path: 'p/mine.pdf', uploaded: true, sha256: 'c'.repeat(64) },
        { id: randomUUID(), order_id: theirs.id, kind: 'proof', filename: 'theirs.pdf', storage_path: 'p/theirs.pdf', uploaded: true, sha256: 'd'.repeat(64) });
    const login = await codeLogin({ remember: false });
    const cookie = `nps_client=${cookieValue(login, 'nps_client')}`;
    const links = await (await clientPOST(post('/api/client', { action: 'proof-links' }, { cookie }))).json();
    expect(links.files.length === 1 && links.files[0].name === 'mine.pdf' && links.files[0].sha256 === 'c'.repeat(64), JSON.stringify(links));
    expect((tables().client_audit_logs || []).some(l => l.order_id === mine.id && l.action === 'download'), 'portal download not logged');
    const r = await clientPOST(post('/api/client', { action: 'receipt', code: 'NP-123456' }, { cookie }));
    expect(r.status === 200 && (await r.json()).receipt?.code === 'NP-123456', `own receipt ${r.status}`);
    expect((await clientPOST(post('/api/client', { action: 'receipt', code: 'NP-654321' }, { cookie }))).status === 404, 'another client\'s receipt was returned');
});

console.log(`\n${passed} real-handler checks passed, ${failures.length} failed`);
if (failures.length) process.exit(1);
