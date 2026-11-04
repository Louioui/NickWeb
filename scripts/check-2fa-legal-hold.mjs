// Attacks on two-step sign-in, legal hold, the document lock and the record seal. Run: npm test
// Uses the mock API (same rules as api/*.mjs) plus the real server helpers in api/_lib/core.mjs.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { handleMockApi, MOCK_ADMIN_CODE, MOCK_CLIENT_CODE, totpCode } from './mock-api.mjs';
import { encryptSecret, decryptSecret, hashPin, verifyPin, signToken, checkToken, verifyTotp, keyedHash } from '../api/_lib/core.mjs';

let passed = 0;
const check = (name, cond) => { assert.ok(cond, name); passed++; };
const call = async (endpoint, body, cookie = '') => {
    const res = await handleMockApi(endpoint, new Request(`http://localhost/api/${endpoint}`, {
        method: 'POST', headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body),
    }));
    let data = {};
    try { data = await res.clone().json(); } catch { /* not JSON */ }
    return { status: res.status, data, cookie: (res.headers.get('set-cookie') || '').split(';')[0] };
};
const NICK = 'nicksprocessservices@outlook.com';
// Each authenticator code works once, so between uses the test moves the clock to the next 30-second step,
// the way Nick would wait for his app to show a new code.
const realNow = Date.now;
let clockSteps = 0;
Date.now = () => realNow() + clockSteps * 30000;
const nextStep = () => { clockSteps++; };
const nowCode = (secret) => totpCode(secret, Date.now());

// --- Server helpers (real code) ---
const enc = encryptSecret('JBSWY3DPEHPK3PXP');
check('authenticator secret is encrypted, not stored as-is', !enc.includes('JBSWY3DPEHPK3PXP') && decryptSecret(enc) === 'JBSWY3DPEHPK3PXP');
const parts = enc.split('.'); parts[3] = (parts[3][0] === 'A' ? 'B' : 'A') + parts[3].slice(1);
check('a tampered encrypted secret is refused', (() => { try { decryptSecret(parts.join('.')); return false; } catch { return true; } })());
const pinHash = hashPin('482913');
check('PIN stored as salted scrypt', /^scrypt\$16384\$/.test(pinHash) && hashPin('482913') !== pinHash);
check('right PIN accepted, wrong PIN refused', verifyPin('482913', pinHash) && !verifyPin('482914', pinHash) && !verifyPin('', pinHash));
check('signed unlock token works for its subject only', checkToken('track-unlock-v1', 'a|b', signToken('track-unlock-v1', 'a|b', 60)) && !checkToken('track-unlock-v1', 'a|c', signToken('track-unlock-v1', 'a|b', 60)));
check('expired unlock token refused', !checkToken('track-unlock-v1', 'a|b', signToken('track-unlock-v1', 'a|b', -1)));
check('forged unlock token refused', !checkToken('track-unlock-v1', 'a|b', `9999999999.${'A'.repeat(43)}`));
check('recovery-code hash is keyed (not plain SHA-256)', keyedHash('admin-recovery-v1', 'x') !== keyedHash('other', 'x'));
check('authenticator: RFC 6238 test vector', totpCode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59000) === '287082');
check('authenticator: wrong code gives no step', verifyTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '000000') === 0);

// --- Two-step sign-in for Nick ---
await call('admin', { action: 'send-code', email: NICK });
let login = await call('admin', { action: 'verify-code', email: NICK, code: MOCK_ADMIN_CODE });
check('email-code login works before 2FA is on', login.status === 200 && login.cookie.startsWith('nps_admin='));
let nick = login.cookie;
check('F-09: turning two-step on with only a session is refused', (await call('admin', { action: 'totp-setup' }, nick)).status === 403);
await call('admin', { action: 'stepup-send-code' }, nick);
const setup = await call('admin', { action: 'totp-setup', totp: '87654321' }, nick);
check('setup returns a scannable otpauth link', setup.status === 200 && /^otpauth:\/\/totp\//.test(setup.data.otpauthUrl));
const secret = setup.data.secret;
check('wrong confirmation code does not turn 2FA on', (await call('admin', { action: 'totp-enable', totp: '000000' }, nick)).status === 400);
check('valid confirmation code turns 2FA on', (await call('admin', { action: 'totp-enable', totp: nowCode(secret) }, nick)).data.totpEnabled === true);

await call('admin', { action: 'send-code', email: NICK });
const needs2 = await call('admin', { action: 'verify-code', email: NICK, code: MOCK_ADMIN_CODE });
check('email code alone is no longer enough', needs2.data.requiresTwoFactor === true && !needs2.cookie.startsWith('nps_admin=x'));
nextStep();
const c1 = nowCode(secret);
login = await call('admin', { action: 'verify-code', email: NICK, code: MOCK_ADMIN_CODE, totp: c1 });
check('email code + authenticator code signs in', login.status === 200 && login.cookie.length > 20);
nick = login.cookie;
await call('admin', { action: 'send-code', email: NICK });
check('the same authenticator code cannot be replayed', (await call('admin', { action: 'verify-code', email: NICK, code: MOCK_ADMIN_CODE, totp: c1 })).status === 401);

// Changing the authenticator: needs the current one, and keeps it working until the new one is confirmed.
check('changing the authenticator without a current code is refused', (await call('admin', { action: 'totp-setup' }, nick)).status === 403);
nextStep();
const change = await call('admin', { action: 'totp-setup', totp: nowCode(secret) }, nick);
check('changing with a current code starts a pending setup', change.status === 200 && change.data.secret !== secret);
check('2FA stays on during a pending change', (await call('admin', { action: 'me' }, nick)).data.totpEnabled === true);
check('disabling 2FA without a code is refused', (await call('admin', { action: 'totp-disable' }, nick)).status === 403);

// Recovery codes: with 2FA on they replace the authenticator, never the email code.
await call('admin', { action: 'send-code', email: NICK });
nextStep();
const gen = await call('admin', { action: 'generate-recovery-codes', totp: nowCode(change.data.secret) }, nick);
check('creating recovery codes needs a step-up code', gen.status === 403);
// The pending change was never confirmed, so the old authenticator is still the one that counts.
nextStep();
const gen2 = await call('admin', { action: 'generate-recovery-codes', totp: nowCode(secret) }, nick);
check('recovery codes created with a valid step-up code', gen2.status === 200 && gen2.data.codes.length === 8);
const rc = gen2.data.codes[0];
await call('admin', { action: 'send-code', email: NICK });
check('a recovery code alone cannot sign in while 2FA is on', (await call('admin', { action: 'verify-code', email: NICK, code: rc })).status === 401);
await call('admin', { action: 'send-code', email: NICK });
check('email code + recovery code signs in (lost phone)', (await call('admin', { action: 'verify-code', email: NICK, code: MOCK_ADMIN_CODE, totp: rc })).status === 200);
await call('admin', { action: 'send-code', email: NICK });
check('a recovery code works only once', (await call('admin', { action: 'verify-code', email: NICK, code: MOCK_ADMIN_CODE, totp: rc })).status === 401);

// --- Legal hold ---
await call('admin', { action: 'send-code', email: NICK });
nick = (await call('admin', { action: 'verify-code', email: NICK, code: MOCK_ADMIN_CODE, totp: gen2.data.codes[1] })).cookie;
const created = await call('request', { step: 'create', clientName: 'Hold Test', clientEmail: 'hold.test@example.com', clientPhone: '7145550199',
    recipientName: 'Held Person', docType: 'Summons & Complaint', address: '1 Main St', city: 'Long Beach', zip: '90802',
    tier: 'standard', addons: [], acceptTerms: true, files: [] });
check('test order created', created.status === 200 && created.data.token);
const held = (await call('admin', { action: 'list' }, nick)).data.orders.find(o => o.code === created.data.code);
const served = await call('admin', { action: 'update', id: held.id, kind: 'status', status: 'served' }, nick);
check('serving an order puts it under legal hold', served.data.order.legal_hold === true);
check('held order cannot be deleted, even with the old "unlockLegalHold" flag', (await call('admin', { action: 'delete', id: held.id, confirm: held.code, unlockLegalHold: true }, nick)).status === 423);
check('held order status cannot be rolled back, even with the flag', (await call('admin', { action: 'update', id: held.id, kind: 'status', status: 'received', unlockLegalHold: true }, nick)).status === 423);
check('held order can still be closed', (await call('admin', { action: 'update', id: held.id, kind: 'status', status: 'closed' }, nick)).status === 200);
check('unlocking without a step-up code is refused', (await call('admin', { action: 'unlock-legal-hold', id: held.id, hold: false }, nick)).status === 403);
nextStep();
const unlocked = await call('admin', { action: 'unlock-legal-hold', id: held.id, hold: false, totp: nowCode(secret) }, nick);
check('unlocking with a fresh authenticator code works', unlocked.status === 200 && unlocked.data.order.legal_hold === false);
check('the record seal verifies', unlocked.data.order.integrity_seal.verified === true && /^[0-9a-f]{64}$/.test(unlocked.data.order.integrity_seal.head));

// Work that must still be possible on a served (held) order. The mock refuses exactly what the database trigger refuses,
// so these would fail here if the app tried a write the real database won't accept.
const relock = await call('admin', { action: 'unlock-legal-hold', id: held.id, hold: true }, nick);
check('legal hold can be turned back on', relock.data.order.legal_hold === true);
const billLater = await call('admin', { action: 'payment-link', id: held.id, amount: '75', description: 'Standard' }, nick);
check('a payment link can be sent after serving', billLater.status === 200 && billLater.data.order.status !== 'awaiting_payment' && billLater.data.order.legal_hold === true);
const heldView = (await call('track', { t: created.data.token, action: 'view' })).data;
check('the client sees the Pay button on a served order', !!heldView.payUrl);
const sessionId = new URL(billLater.data.order.payment_url, 'http://x').searchParams.get('s');
const paidLater = await call('track', { t: created.data.token, action: 'confirm-payment', session: sessionId });
check('a payment after serving is recorded and the order stays served/closed', paidLater.status === 200 && !!paidLater.data.paidAt && !['paid', 'awaiting_payment'].includes(paidLater.data.status));
check('asking the client a question on a held order gives a clear refusal, not an error', (await call('admin', { action: 'update', id: held.id, kind: 'action', note: 'Which unit?' }, nick)).status === 423);
const extraProof = await call('admin', { action: 'proof-upload', id: held.id, files: [{ name: 'second-proof.pdf', size: 10, type: 'application/pdf' }] }, nick);
check('a second proof can be added to a held order', extraProof.status === 200 && extraProof.data.uploads.length === 1);

// --- Document lock on the client's tracking page ---
const created2 = await call('request', { step: 'create', clientName: 'Lock Test', clientEmail: 'lock.test@example.com', clientPhone: '7145550199',
    recipientName: 'Locked Person', docType: 'Summons & Complaint', address: '42 Ocean Blvd', city: 'Long Beach', zip: '90802',
    tier: 'standard', addons: [], acceptTerms: true, files: [] });
const lockOrder = (await call('admin', { action: 'list' }, nick)).data.orders.find(o => o.code === created2.data.code);
await call('admin', { action: 'toggle-doc-lock', id: lockOrder.id, locked: true }, nick);
await call('admin', { action: 'update', id: lockOrder.id, kind: 'action', note: 'Which unit?' }, nick);
const t = created2.data.token;
const lockedView = (await call('track', { t, action: 'view' })).data;
check('locked page hides the street number', lockedView.unlocked === false && !lockedView.address.includes('42'));
check('locked page cannot change the address', (await call('track', { t, action: 'respond', unit: 'Apt 1' })).status === 403);
check('forged unlock token is refused', (await call('track', { t, action: 'respond', unit: 'Apt 1', unlockToken: `9999999999.${'A'.repeat(43)}` })).status === 403);
await call('track', { t, action: 'send-unlock-code' });
const unlock = await call('track', { t, action: 'verify-unlock-code', code: MOCK_CLIENT_CODE });
check('emailed code unlocks the page', unlock.status === 200 && /^\d{10}\.[\w-]{43}$/.test(unlock.data.unlockToken));
check('unlocked page can answer "Action required"', (await call('track', { t, action: 'respond', unit: 'Apt 1', unlockToken: unlock.data.unlockToken })).status === 200);
// Downloads are recorded privately in the sealed timeline (chain of custody), and the seal still verifies.
const servedId = (await call('admin', { action: 'list' }, nick)).data.orders.find(o => o.status === 'served').id;
// Orders start locked; Nick unlocks this one first (that adds its own timeline entry, so it happens before the snapshot).
await call('admin', { action: 'toggle-doc-lock', id: servedId, locked: false }, nick);   // orders start locked; Nick unlocks this one
const servedDetail = (await call('admin', { action: 'get', id: servedId }, nick)).data;
const dl = await call('track', { t: servedDetail.order.track_token, action: 'download', fileId: servedDetail.files[0].id });
const afterDl = (await call('admin', { action: 'get', id: servedId }, nick)).data;
check('client download works and returns the file fingerprint', dl.status === 200 && dl.data.url);
check('client download is logged privately in the timeline', afterDl.events.some(e => e.title === 'Document downloaded from tracking page' && e.client_visible === false));
check('the seal still verifies after new entries', afterDl.order.integrity_seal.verified === true && afterDl.order.integrity_seal.entries === servedDetail.order.integrity_seal.entries + 1);
await call('admin', { action: 'rotate-token', id: lockOrder.id }, nick);
check('after the link is replaced, the old link stops working', (await call('track', { t, action: 'view' })).status === 404);

// --- Code checks that must hold in the real server code ---
const src = (await Promise.all(['api/admin.mjs', 'api/track.mjs', 'api/client.mjs', 'api/_lib/core.mjs', 'api/_lib/clients.mjs', 'api/_lib/orders.mjs']
    .map(f => readFile(new URL(`../${f}`, import.meta.url), 'utf8')))).join('\n');
check('no browser-identifier session binding left', !/uaFingerprint/.test(src));
check('no recomputed (non-stored) seal left', !/computeChainSeal/.test(src));
check('legal hold never trusts a request flag', !/body\.unlockLegalHold/.test(src));
check('no plain SHA-256 PIN hashes left', !/sha256\(`\$\{[a-zA-Z.]+\}:\$\{(pin|code)\}`\)/.test(src.replace(/admin_codes[\s\S]{0,200}/g, '')) || /verifyPin/.test(src));
check('authenticator lookups fail closed', !/getAdminTotp[\s\S]{0,300}catch \{ return null; \}/.test(src));

// --- The shared browser script must actually run (a syntax check alone missed a deleted helper once) ---
const npsSrc = await readFile(new URL('../assets/js/nps.js', import.meta.url), 'utf8');
const NPS = new Function('window', 'document', 'navigator', 'location', 'BroadcastChannel', `${npsSrc}; return NPS;`)({}, {}, {}, {}, undefined);
for (const fn of ['esc', 'post', 'get', 'fileMeta', 'checkFiles', 'uploadAll', 'verifyFileSha256', 'printChainOfCustody', 'money', 'fmtDate', 'fmtSize']) {
    check(`assets/js/nps.js exports ${fn}`, typeof NPS[fn] === 'function');
}
check('browser helpers work', NPS.money(14000) === '$140.00' && NPS.esc('<b>') === '&lt;b&gt;');
const pages = await Promise.all(['admin.html', 'track.html', 'assets/js/admin.js', 'assets/js/track.js'].map(f => readFile(new URL(`../${f}`, import.meta.url), 'utf8')));
check('no page ships unverifiable security claims', !/TLS 1\.3|Zero-Trust|court-certified|tamper-proof|HMAC-SHA256|device-bound/i.test(pages.join('') + npsSrc));

console.log(`${passed} two-step, legal hold, document lock and seal checks passed`);
