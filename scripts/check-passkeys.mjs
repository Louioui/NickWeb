// Passkey stress tests: the REAL handlers in api/ against the in-memory Supabase and a software passkey
// (scripts/soft-authenticator.mjs). Covers adding, signing in, removing, and the ways an attacker would try to cheat:
// replays, races, wrong site, missing Face ID / fingerprint, copied passkeys, someone else's passkey, stolen cookies.
// Run with: node --experimental-test-module-mocks scripts/check-passkeys.mjs
import { mock } from 'node:test';
import { randomUUID } from 'node:crypto';
import { createFakeSupabase } from './fake-supabase.mjs';
import { createAuthenticator } from './soft-authenticator.mjs';

const db = createFakeSupabase();
mock.module('@supabase/supabase-js', { namedExports: { createClient: () => db } });
mock.module('stripe', { defaultExport: class {} });
Object.assign(process.env, { SUPABASE_SERVICE_ROLE_KEY: 'test-service-role', APP_SECRET: 'test-app-secret', RESEND_API_KEY: 're_test_fake' });
delete process.env.ADMIN_EMAILS;
delete process.env.VERCEL_ENV;
delete process.env.RP_ID;
delete process.env.RP_ORIGINS;

const emails = [];
globalThis.fetch = async (url, init) => {
    if (String(url).includes('resend.com')) emails.push(JSON.parse(init.body));
    return new Response('{}', { status: 200 });
};

const core = await import('../api/_lib/core.mjs');
const { POST: clientPOST } = await import('../api/client.mjs');
const { POST: adminPOST } = await import('../api/admin.mjs');

let passed = 0;
const failures = [];
async function check(name, fn) {
    reset();
    try { await fn(); passed++; console.log(`PASS ${name}`); } catch (err) { failures.push(name); console.log(`FAIL ${name}\n     ${err.message}`); }
}
function expect(cond, msg) { if (!cond) throw new Error(msg); }

const SITE = 'https://site.test';
const RP = { rpId: 'site.test', origin: SITE };
const CLIENT = 'client@example.com';
const OTHER = 'other@example.com';
const ADMIN = 'nicksprocessservices@outlook.com';
const PIN = '246810';
const tables = () => db.__state.tables;
const creds = () => tables().webauthn_credentials || [];
function reset() { db.__reset(); emails.length = 0; db.__addUser(CLIENT); db.__addUser(OTHER); }

const post = (path, body, cookie = '') => new Request(`${SITE}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': 'TestBrowser/1.0', ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body),
});
const cookieValue = (res, name) => (res.headers.get('set-cookie') || '').match(new RegExp(`${name}=([^;,]*)`))?.[1];
const jar = (...pairs) => pairs.filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join('; ');
const client = (body, cookie) => clientPOST(post('/api/client', body, cookie));
const admin = (body, cookie) => adminPOST(post('/api/admin', body, cookie));

// A real sign-in with an email code (and PIN if set), so the session cookie carries a genuine "just signed in" proof.
async function signIn(addr = CLIENT, extra = {}) {
    db.__state.otp.set(addr, '111111');
    const res = await client({ action: 'verify-code', email: addr, code: '111111', remember: false, ...extra });
    const c = cookieValue(res, 'nps_client');
    if (!c) throw new Error(`sign-in failed (${res.status})`);
    return `nps_client=${c}`;
}
// The same signed-in session, but as it would look long after sign-in: no "just signed in" proof.
function staleCookie(session) {
    const v = JSON.parse(decodeURIComponent(session.slice('nps_client='.length)));
    delete v.fresh;
    return `nps_client=${encodeURIComponent(JSON.stringify(v))}`;
}
const setPin = (addr) => (tables().client_security_settings ||= []).push({ email: addr, pin_hash: core.hashPin(PIN), failed_tries: 0, locked_until: null });

async function addClientPasskey(session, auth = createAuthenticator(RP), extra = {}) {
    const o = await client({ action: 'passkey-register-options', ...extra }, session);
    const ob = await o.json();
    if (o.status !== 200) throw new Error(`options ${o.status} ${ob.error || ''}`);
    const pk = cookieValue(o, 'nps_pk_client');
    const v = await client({ action: 'passkey-register-verify', response: auth.register(ob.options), label: 'Test phone' }, `${session}; nps_pk_client=${pk}`);
    if (v.status !== 200) throw new Error(`verify ${v.status} ${(await v.json()).error || ''}`);
    return auth;
}
async function loginOptions(kind = 'client') {
    const res = await (kind === 'admin' ? admin : client)({ action: 'passkey-login-options' });
    return { options: (await res.json()).options, cookie: `nps_pk_${kind}=${cookieValue(res, `nps_pk_${kind}`)}`, status: res.status };
}
async function passkeyLogin(auth, opts = {}, kind = 'client') {
    const o = await loginOptions(kind);
    return (kind === 'admin' ? admin : client)({ action: 'passkey-login-verify', response: auth.login(o.options, opts) }, o.cookie);
}

// --- Adding a passkey ---
await check('PK01 a client who just signed in can add a passkey; only its public key is stored', async () => {
    const auth = await addClientPasskey(await signIn());
    expect(creds().length === 1 && creds()[0].owner_email === CLIENT && creds()[0].owner_kind === 'client', JSON.stringify(creds()));
    expect(creds()[0].credential_id === auth.id && creds()[0].public_key.length > 50, 'credential not saved');
    expect(emails.some(e => /passkey was added/i.test(e.subject)), 'no alert email for the new passkey');
});
await check('PK02 the passkey list never includes public keys or counters', async () => {
    const session = await signIn();
    await addClientPasskey(session);
    const list = await (await client({ action: 'passkeys' }, session)).json();
    const s = JSON.stringify(list);
    expect(list.passkeys.length === 1 && list.passkeys[0].label === 'Test phone', s);
    expect(!/public_key|publicKey|counter/.test(s) && !s.includes(creds()[0].public_key), `leaks key material: ${s}`);
});
await check('PK03 without a PIN, an old session (stolen cookie) cannot add a passkey', async () => {
    const res = await client({ action: 'passkey-register-options' }, staleCookie(await signIn()));
    expect(res.status === 403 && creds().length === 0 && !(tables().webauthn_challenges || []).length, `got ${res.status}`);
});
await check('PK04 renewing the session does not make an old cookie look freshly signed in', async () => {
    const session = staleCookie(await signIn());
    const v = JSON.parse(decodeURIComponent(session.slice('nps_client='.length)));
    db.__state.sessions.delete(v.access);   // access token expired -> the server renews the session
    const res = await client({ action: 'me' }, session);
    const renewed = cookieValue(res, 'nps_client');
    expect(res.status === 200 && renewed, `renewal failed (${res.status})`);
    expect(!JSON.parse(decodeURIComponent(renewed)).fresh, 'renewal minted a new "just signed in" proof');
    const add = await client({ action: 'passkey-register-options' }, `nps_client=${renewed}`);
    expect(add.status === 403, `renewed stale cookie could add a passkey (${add.status})`);
});
await check('PK05 with a PIN, adding a passkey needs the PIN, and wrong PINs count toward the lockout', async () => {
    setPin(CLIENT);
    const session = await signIn(CLIENT, { pin: PIN });
    const none = await client({ action: 'passkey-register-options' }, session);
    const wrong = await client({ action: 'passkey-register-options', pin: '000000' }, session);
    expect(none.status === 403 && wrong.status === 403, `${none.status} ${wrong.status}`);
    expect(tables().client_security_settings[0].failed_tries === 2, `failed_tries ${tables().client_security_settings[0].failed_tries}`);
    await addClientPasskey(session, undefined, { pin: PIN });
    expect(creds().length === 1, 'right PIN did not allow adding');
});
await check('PK06 a passkey made without Face ID / fingerprint / device PIN is refused', async () => {
    const session = await signIn();
    const o = await client({ action: 'passkey-register-options' }, session);
    const { options } = await o.json();
    const res = await client({ action: 'passkey-register-verify', response: createAuthenticator(RP).register(options, { uv: false }) }, `${session}; nps_pk_client=${cookieValue(o, 'nps_pk_client')}`);
    expect(res.status === 400 && creds().length === 0, `got ${res.status}`);
});
await check('PK07 a passkey made for another site (phishing page) is refused', async () => {
    const session = await signIn();
    for (const bad of [{ origin: 'https://site.test.evil.example' }, { rpId: 'evil.example' }]) {
        const o = await client({ action: 'passkey-register-options' }, session);
        const { options } = await o.json();
        const res = await client({ action: 'passkey-register-verify', response: createAuthenticator(RP).register(options, bad) }, `${session}; nps_pk_client=${cookieValue(o, 'nps_pk_client')}`);
        expect(res.status === 400, `${JSON.stringify(bad)} accepted (${res.status})`);
    }
    expect(creds().length === 0, 'saved a credential');
});
await check("PK08 one client's registration challenge cannot be used for another client's account", async () => {
    const mine = await signIn(CLIENT);
    const theirs = await signIn(OTHER);
    const o = await client({ action: 'passkey-register-options' }, mine);
    const { options } = await o.json();
    const res = await client({ action: 'passkey-register-verify', response: createAuthenticator(RP).register(options) }, `${theirs}; nps_pk_client=${cookieValue(o, 'nps_pk_client')}`);
    expect(res.status === 400 && creds().length === 0, `got ${res.status}`);
});
await check('PK09 a registration answer cannot be replayed, and the same passkey cannot be saved twice', async () => {
    const session = await signIn();
    const o = await client({ action: 'passkey-register-options' }, session);
    const { options } = await o.json();
    const cookie = `${session}; nps_pk_client=${cookieValue(o, 'nps_pk_client')}`;
    const auth = createAuthenticator(RP);
    const answer = auth.register(options);
    const first = await client({ action: 'passkey-register-verify', response: answer }, cookie);
    const replay = await client({ action: 'passkey-register-verify', response: answer }, cookie);
    expect(first.status === 200 && replay.status === 400, `${first.status} ${replay.status}`);
    const o2 = await client({ action: 'passkey-register-options' }, session);
    const o2b = await o2.json();
    expect(o2b.options.excludeCredentials.some(c => c.id === auth.id), 'existing passkey not excluded');
    const dup = await client({ action: 'passkey-register-verify', response: auth.register(o2b.options) }, `${session}; nps_pk_client=${cookieValue(o2, 'nps_pk_client')}`);
    expect(dup.status === 409 && creds().length === 1, `duplicate: ${dup.status}, ${creds().length} saved`);
});
await check('PK10 at most 10 passkeys per account', async () => {
    const session = await signIn();
    await addClientPasskey(session);
    for (let i = 0; i < 9; i++) (tables().webauthn_credentials).push({ ...creds()[0], credential_id: `seeded-credential-${i}-xxxxxxxx` });
    const res = await client({ action: 'passkey-register-options' }, session);
    expect(res.status === 400 && creds().length === 10, `got ${res.status}, ${creds().length}`);
});

// --- Signing in with a passkey ---
await check('PK11 a passkey signs the client in, skips the PIN, and a new device gets a login alert', async () => {
    setPin(CLIENT);
    const auth = await addClientPasskey(await signIn(CLIENT, { pin: PIN }), undefined, { pin: PIN });
    emails.length = 0;
    const res = await passkeyLogin(auth);
    const c = cookieValue(res, 'nps_client');
    expect(res.status === 200 && c, `got ${res.status} ${await res.clone().text()}`);
    const me = await (await client({ action: 'me' }, `nps_client=${c}`)).json();
    expect(me.profile?.email === CLIENT, JSON.stringify(me));
    expect(emails.some(e => e.to === CLIENT || e.to?.[0] === CLIENT), 'no login alert');
    expect(creds()[0].last_used_at, 'last_used_at not recorded');
});
await check('PK12 the account comes from the passkey, never from an email the browser sends', async () => {
    const auth = await addClientPasskey(await signIn(CLIENT));
    const o = await loginOptions();
    const res = await client({ action: 'passkey-login-verify', email: OTHER, response: auth.login(o.options) }, o.cookie);
    const c = cookieValue(res, 'nps_client');
    const me = await (await client({ action: 'me' }, `nps_client=${c}`)).json();
    expect(me.profile?.email === CLIENT, `signed in as ${me.profile?.email}`);
});
await check('PK13 a sign-in answer cannot be replayed', async () => {
    const auth = await addClientPasskey(await signIn());
    const o = await loginOptions();
    const answer = auth.login(o.options);
    const first = await client({ action: 'passkey-login-verify', response: answer }, o.cookie);
    const replay = await client({ action: 'passkey-login-verify', response: answer }, o.cookie);
    expect(first.status === 200 && replay.status === 400 && !cookieValue(replay, 'nps_client'), `${first.status} ${replay.status}`);
});
await check('PK14 ten parallel sign-ins with one challenge: exactly one wins', async () => {
    const auth = await addClientPasskey(await signIn());
    const o = await loginOptions();
    const answer = auth.login(o.options);
    const results = await Promise.all(Array.from({ length: 10 }, () => client({ action: 'passkey-login-verify', response: answer }, o.cookie)));
    const wins = results.filter(r => r.status === 200).length;
    expect(wins === 1, `${wins} sign-ins succeeded`);
});
await check('PK15 a challenge from another browser, a made-up one, or an expired one does not work', async () => {
    const auth = await addClientPasskey(await signIn());
    const o = await loginOptions();
    const none = await client({ action: 'passkey-login-verify', response: auth.login(o.options) });
    const madeUp = await client({ action: 'passkey-login-verify', response: auth.login(o.options) }, `nps_pk_client=${randomUUID()}`);
    const o2 = await loginOptions();
    tables().webauthn_challenges.forEach(c => { c.expires_at = new Date(Date.now() - 1000).toISOString(); });
    const expired = await client({ action: 'passkey-login-verify', response: auth.login(o2.options) }, o2.cookie);
    expect([none, madeUp, expired].every(r => r.status === 400), `${none.status} ${madeUp.status} ${expired.status}`);
});
await check("PK16 a signed answer to a different challenge than this browser's is refused", async () => {
    const auth = await addClientPasskey(await signIn());
    const mine = await loginOptions();
    const other = await loginOptions();
    const res = await client({ action: 'passkey-login-verify', response: auth.login(other.options) }, mine.cookie);
    expect(res.status === 401, `got ${res.status}`);
});
await check('PK17 wrong site, missing Face ID / fingerprint, or a forged signature cannot sign in', async () => {
    const auth = await addClientPasskey(await signIn());
    for (const bad of [{ origin: 'https://evil.example' }, { rpId: 'evil.example' }, { uv: false }, { badSignature: true }]) {
        const res = await passkeyLogin(auth, bad);
        expect(res.status === 401 && !cookieValue(res, 'nps_client'), `${JSON.stringify(bad)} -> ${res.status}`);
    }
});
await check('PK18 a passkey that never registered here cannot sign in', async () => {
    await addClientPasskey(await signIn());
    const res = await passkeyLogin(createAuthenticator(RP));
    expect(res.status === 401, `got ${res.status}`);
});
await check('PK19 a copied passkey (counter going backwards) is refused; counters only move forward', async () => {
    const auth = await addClientPasskey(await signIn());
    auth.counter = 5;
    expect((await passkeyLogin(auth)).status === 200, 'first counted sign-in failed');   // counter 6
    expect(creds()[0].counter === 6, `stored counter ${creds()[0].counter}`);
    const res = await passkeyLogin(auth, { count: 3 });
    expect(res.status === 401 && creds()[0].counter === 6, `got ${res.status}, counter ${creds()[0].counter}`);
});
await check('PK20 synced passkeys that always report counter 0 keep working', async () => {
    const auth = await addClientPasskey(await signIn());
    for (let i = 0; i < 3; i++) expect((await passkeyLogin(auth, { count: 0 })).status === 200, `sign-in ${i + 1} failed`);
});
await check('PK21 a client passkey cannot open Nick\'s dashboard', async () => {
    const auth = await addClientPasskey(await signIn());
    creds()[0].owner_email = ADMIN;   // even if it somehow carried Nick's address
    const res = await passkeyLogin(auth, {}, 'admin');
    expect(res.status === 401 && !cookieValue(res, 'nps_admin'), `got ${res.status}`);
});
await check('PK22 removing a passkey stops it working; nobody can remove another client\'s passkey', async () => {
    const mine = await signIn(CLIENT);
    const auth = await addClientPasskey(mine);
    const theirs = await signIn(OTHER);
    const steal = await client({ action: 'passkey-remove', id: auth.id }, theirs);
    expect(steal.status === 404 && creds().length === 1, `other client: ${steal.status}`);
    const stale = await client({ action: 'passkey-remove', id: auth.id }, staleCookie(mine));
    expect(stale.status === 403 && creds().length === 1, `stale cookie removed it: ${stale.status}`);
    const ok = await client({ action: 'passkey-remove', id: auth.id }, mine);
    expect(ok.status === 200 && creds().length === 0, `remove: ${ok.status}`);
    expect((await passkeyLogin(auth)).status === 401, 'removed passkey still signs in');
});
await check('PK23 sign-in options are rate limited per network address', async () => {
    let last;
    for (let i = 0; i < 31; i++) last = await client({ action: 'passkey-login-options' });
    expect(last.status === 429, `31st request: ${last.status}`);
});
await check('PK24 junk answers are refused cleanly (no crash, no session)', async () => {
    await addClientPasskey(await signIn());
    const o = await loginOptions();
    for (const junk of [null, 'x', 42, {}, { id: '../../etc' }, { id: 'A'.repeat(2000) }, { id: creds()[0].credential_id }, { id: creds()[0].credential_id, response: {} }]) {
        const res = await client({ action: 'passkey-login-verify', response: junk }, o.cookie);
        expect([400, 401].includes(res.status) && !cookieValue(res, 'nps_client'), `${JSON.stringify(junk)?.slice(0, 40)} -> ${res.status}`);
    }
});
await check('PK25 before the database tables exist, passkeys say "not available" and email sign-in still works', async () => {
    const realFrom = db.from;
    db.from = (t) => (t.startsWith('webauthn_') || t === 'client_trusted_devices')
        ? { insert: () => ({ select: () => ({ single: async () => ({ data: null, error: { code: 'PGRST205', message: "Could not find the table in the schema cache" } }) }), then: (r) => r({ data: null, error: { code: 'PGRST205', message: 'schema cache' } }) }),
            delete: () => ({ lt: () => Promise.resolve({ data: null, error: { code: 'PGRST205' } }) }) }
        : realFrom(t);
    try {
        const res = await client({ action: 'passkey-login-options' });
        expect(res.status === 503, `options: ${res.status}`);
        db.__state.otp.set(CLIENT, '111111');
        const login = await client({ action: 'verify-code', email: CLIENT, code: '111111' });   // remember on by default
        expect(login.status === 200 && cookieValue(login, 'nps_client'), `email sign-in broke: ${login.status}`);
    } finally { db.from = realFrom; }
});

await check("PK33 a deleted client's old passkey cannot bring the account back", async () => {
    const auth = await addClientPasskey(await signIn());
    expect(creds()[0].owner_user_id === db.__state.users.get(CLIENT).id, 'user id not stored with the passkey');
    db.__state.users.delete(CLIENT);   // Nick deletes the account in Supabase
    const res = await passkeyLogin(auth);
    expect(res.status === 401 && !cookieValue(res, 'nps_client'), `got ${res.status}`);
    expect(!db.__state.users.has(CLIENT), 'the sign-in recreated the deleted account');
    expect(creds().length === 0, 'the orphaned passkey was not removed');
});
await check('PK34 a passkey sign-in alert says to remove unknown passkeys (signing out alone would not stop them)', async () => {
    const auth = await addClientPasskey(await signIn());
    emails.length = 0;
    await passkeyLogin(auth);
    expect(emails.some(e => /remove any passkey/i.test(e.text)), JSON.stringify(emails.map(e => e.text)));
});

// --- Nick's dashboard ---
const adminCookie = () => {
    const token = 'A'.repeat(43);
    (tables().admin_sessions ||= []).push({ token_hash: core.sha256(token), email: ADMIN, expires_at: new Date(Date.now() + 864e5).toISOString(), last_seen_at: new Date().toISOString() });
    return `nps_admin=${token}`;
};
function seedTotp() {
    const secret = core.generateTotpSecret(20);
    (tables().admin_totp ||= []).push({ email: ADMIN, secret_enc: core.encryptSecret(secret), enabled: true, last_used_step: 0 });
    return secret;
}
async function addAdminPasskey(session, secret) {
    const o = await admin({ action: 'passkey-register-options', totp: core.totpCode(secret) }, session);
    const ob = await o.json();
    if (o.status !== 200) throw new Error(`options ${o.status} ${ob.error}`);
    const auth = createAuthenticator(RP);
    const v = await admin({ action: 'passkey-register-verify', response: auth.register(ob.options), label: 'iPhone' }, `${session}; nps_pk_admin=${cookieValue(o, 'nps_pk_admin')}`);
    if (v.status !== 200) throw new Error(`verify ${v.status}`);
    return auth;
}
await check('PK26 Nick cannot add a passkey until the authenticator app is on', async () => {
    const res = await admin({ action: 'passkey-register-options' }, adminCookie());
    expect(res.status === 400 && !(tables().webauthn_challenges || []).length, `got ${res.status}`);
});
await check('PK27 adding a dashboard passkey needs a current authenticator code', async () => {
    seedTotp();
    const session = adminCookie();
    const none = await admin({ action: 'passkey-register-options' }, session);
    const wrong = await admin({ action: 'passkey-register-options', totp: '000000' }, session);
    expect(none.status === 403 && wrong.status === 403, `${none.status} ${wrong.status}`);
});
await check('PK28 a dashboard passkey signs Nick in, with an audit entry and an alert', async () => {
    const secret = seedTotp();
    const auth = await addAdminPasskey(adminCookie(), secret);
    expect(creds()[0].owner_kind === 'admin' && creds()[0].owner_email === ADMIN, JSON.stringify(creds()[0]));
    tables().admin_sessions = [];
    emails.length = 0;
    const res = await passkeyLogin(auth, {}, 'admin');
    const token = cookieValue(res, 'nps_admin');
    expect(res.status === 200 && token, `got ${res.status}`);
    expect((await admin({ action: 'me' }, `nps_admin=${token}`)).status === 200, 'session does not work');
    expect((tables().admin_audit_logs || []).some(l => l.action === 'login_success' && /passkey/.test(l.detail)), 'no audit entry');
    expect(emails.some(e => /passkey/.test(JSON.stringify(e))), 'no alert');
});
await check('PK29 a dashboard passkey for an address that is not an admin is refused', async () => {
    const secret = seedTotp();
    const auth = await addAdminPasskey(adminCookie(), secret);
    creds()[0].owner_email = 'former-admin@example.com';
    const res = await passkeyLogin(auth, {}, 'admin');
    expect(res.status === 401 && !cookieValue(res, 'nps_admin'), `got ${res.status}`);
});
await check('PK30 a dashboard passkey cannot sign in to the client portal', async () => {
    const secret = seedTotp();
    const auth = await addAdminPasskey(adminCookie(), secret);
    const res = await passkeyLogin(auth, {}, 'client');
    expect(res.status === 401 && !cookieValue(res, 'nps_client'), `got ${res.status}`);
});
await check('PK31 a client challenge cookie does not work on the dashboard and the other way round', async () => {
    const secret = seedTotp();
    const auth = await addAdminPasskey(adminCookie(), secret);
    const o = await loginOptions('client');
    const res = await admin({ action: 'passkey-login-verify', response: auth.login(o.options) }, o.cookie.replace('nps_pk_client', 'nps_pk_admin'));
    expect(res.status === 400, `got ${res.status}`);
});
await check('PK32 removing a dashboard passkey needs the authenticator code', async () => {
    const secret = seedTotp();
    const session = adminCookie();
    const auth = await addAdminPasskey(session, secret);
    tables().admin_totp[0].last_used_step = 0;
    const none = await admin({ action: 'passkey-remove', id: auth.id }, session);
    expect(none.status === 403 && creds().length === 1, `without code: ${none.status}`);
    const ok = await admin({ action: 'passkey-remove', id: auth.id, totp: core.totpCode(secret, Date.now() + 30e3) }, session);
    expect(ok.status === 200 && creds().length === 0, `with code: ${ok.status} ${await ok.clone().text()}`);
});

console.log(`\n${passed} passkey checks passed, ${failures.length} failed`);
if (failures.length) process.exit(1);
