// Account boundaries in the isolated mock plus the production identity/cookie helpers. No network or live data.
import assert from 'node:assert/strict';
import { handleMockApi, handleMockRoute } from './mock-api.mjs';
import { verifiedClient, clientCookie, savedClientSession, clientProfile } from '../api/_lib/clients.mjs';
let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`PASS ${name}`); };
const call = async (body, cookie = '', endpoint = 'client') => handleMockApi(endpoint, new Request(`http://localhost/api/${endpoint}`, { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify(body) }));
function zipJson(bytes) {
    for (let at = 0; bytes.readUInt32LE(at) === 0x04034b50;) {
        const size = bytes.readUInt32LE(at + 18), nameSize = bytes.readUInt16LE(at + 26), extraSize = bytes.readUInt16LE(at + 28);
        const name = bytes.subarray(at + 30, at + 30 + nameSize).toString();
        const begin = at + 30 + nameSize + extraSize;
        if (name === 'evidence.json') return JSON.parse(bytes.subarray(begin, begin + size).toString());
        at = begin + size;
    }
    throw new Error('JSON missing from ZIP');
}
const signup = async addr => {
    assert.equal((await call({ action:'send-code', intent:'signup', email:addr, name:'Demo Client', firm:'Test Firm' })).status,200);
    const response = await call({ action:'verify-code', email:addr, code:'123456' });
    assert.equal(response.status,200);
    return response.headers.get('set-cookie').split(';')[0];
};
check('unverified identities are refused', () => assert.throws(() => verifiedClient({id:'a', email:'x@example.com'}), /verify/));
check('anonymous identities are refused', () => assert.throws(() => verifiedClient({id:'a', email_confirmed_at:'now'}), /verify/));
check('profile email cannot come from editable metadata', () => assert.equal(clientProfile({email:'right@example.com',user_metadata:{email:'wrong@example.com',role:'admin'}}).email,'right@example.com'));
const cookie = clientCookie(new Request('https://example.com/api/client'), {access_token:'access-test',refresh_token:'refresh-test'}, 'user-test');
check('HTTPS client cookie is HttpOnly, Secure, strict and scoped', () => { for(const flag of ['HttpOnly','Secure','SameSite=Strict','Path=/api/client'])assert.ok(cookie.includes(flag)); });
check('server can parse its session cookie (with its signed proof)', () => { const s = savedClientSession(new Request('https://example.com/api/client',{headers:{cookie:cookie.split(';')[0]}})); assert.equal(s.access,'access-test'); assert.equal(s.refresh,'refresh-test'); assert.match(s.proof,/^\d{10}\.[A-Za-z0-9_-]{43}$/); });
check('oversized session cookies are rejected', () => assert.throws(() => clientCookie(new Request('https://example.com'),{access_token:'x'.repeat(5000),refresh_token:'y'},'user-test'),/completed/));
check('malformed cookies fail closed', () => assert.equal(savedClientSession(new Request('https://example.com',{headers:{cookie:'nps_client=%7Binvalid'}})),null));
assert.equal((await call({action:'list'})).status,401);passed++;
await call({action:'send-code',intent:'signup',email:'fresh@example.com',name:'Fresh'});
assert.equal((await call({action:'verify-code',email:'fresh@example.com',code:'000000'})).status,401);passed++;
const a=await signup('paralegal@example.com');
const all=await (await call({action:'list'},a)).json();
check('verified sample email sees its five requests',()=>assert.equal(all.orders.length,5));
const expiredOrder = all.orders.find(o => o.code === 'NP-403182');
const expiredToken = new URL(expiredOrder.trackUrl, 'http://localhost').hash.slice(3);
const expiredView = await (await call({ action: 'view', t: expiredToken }, '', 'track')).json();
check('expired payment link is withheld from tracking view', () => {
    assert.equal(expiredView.paymentExpired, true);
    assert.equal(expiredView.payUrl, null);
    assert.equal(expiredView.canRenewPayment, true);
});
const renewedView = await (await call({ action: 'renew-payment-link', t: expiredToken }, '', 'track')).json();
check('client renews expired mock link for the same amount', () => {
    assert.equal(renewedView.amountDue, '$175.00');
    assert.match(renewedView.payUrl, /^\/__mock-pay/);
    assert.equal(renewedView.paymentExpired, false);
});
assert.equal((await call({ action: 'renew-payment-link', t: expiredToken }, '', 'track')).status, 409);
passed++; console.log('PASS active link cannot be renewed again');
const b=await signup('unrelated@example.com');
const empty=await (await call({action:'list',email:'paralegal@example.com',userId:'another-client'},b)).json();
check('a different client cannot override ownership using body fields',()=>assert.equal(empty.orders.length,0));
check('client list never returns internal notes or raw user records',()=>assert.ok(all.orders.every(o=>!('events' in o)&&!('client_email' in o)&&!('instructions' in o))));
assert.equal((await call({action:'me'},b,'admin')).status,401);passed++;
console.log('PASS client session cannot log into staff API');
await call({action:'logout'},b);
assert.equal((await call({action:'list'},b)).status,401);passed++;
console.log('PASS sign-out invalidates demo client session');
const stillA=await call({action:'list'},a);assert.equal(stillA.status,200);passed++;
console.log('PASS signing out one client leaves another independent session valid');

// Verify devteam@partnershipwithmedia-dev.com support (client + admin), backup recovery codes, logout-all, and SHA-256 proof fingerprints
await call({ action: 'send-code', intent: 'login', email: 'devteam@partnershipwithmedia-dev.com' });
const devClientRes = await call({ action: 'verify-code', email: 'devteam@partnershipwithmedia-dev.com', code: '123456' });
check('devteam@partnershipwithmedia-dev.com is pre-seeded for client login', () => assert.equal(devClientRes.status, 200));

const devAdminLogin1 = await call({ action: 'verify-code', email: 'devteam@partnershipwithmedia-dev.com', code: '12345678' }, '', 'admin');
const devAdminLogin2 = await call({ action: 'verify-code', email: 'devteam@partnershipwithmedia-dev.com', code: '12345678' }, '', 'admin');
check('devteam@partnershipwithmedia-dev.com can log into admin dashboard', () => assert.equal(devAdminLogin1.status, 200));
const devAdminCookie1 = devAdminLogin1.headers.get('set-cookie').split(';')[0];
const devAdminCookie2 = devAdminLogin2.headers.get('set-cookie').split(';')[0];

const bareGen = await call({ action: 'generate-recovery-codes' }, devAdminCookie1, 'admin');
check('F-09: minting recovery codes with only a session is refused', () => assert.equal(bareGen.status, 403));
await call({ action: 'stepup-send-code' }, devAdminCookie1, 'admin');
const genRes = await (await call({ action: 'generate-recovery-codes', totp: '87654321' }, devAdminCookie1, 'admin')).json();
check('admin can generate 8 single-use backup recovery codes', () => {
    assert.equal(genRes.codes.length, 8);
    assert.equal(genRes.remaining, 8);
    assert.ok(genRes.codes.every(c => /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(c)));
});

const firstRecovery = genRes.codes[0];
const recLogin = await call({ action: 'verify-code', email: 'devteam@partnershipwithmedia-dev.com', code: firstRecovery }, '', 'admin');
check('unused backup recovery code logs in admin and decrements remaining count', async () => {
    assert.equal(recLogin.status, 200);
});
const meAfterRec = await (await call({ action: 'me' }, devAdminCookie1, 'admin')).json();
check('recoveryRemaining decrements from 8 to 7 after using one code', () => assert.equal(meAfterRec.recoveryRemaining, 7));

const reuseRec = await call({ action: 'verify-code', email: 'devteam@partnershipwithmedia-dev.com', code: firstRecovery }, '', 'admin');
check('used backup recovery code is rejected on reuse', () => assert.equal(reuseRec.status, 401));

await call({ action: 'logout-all' }, devAdminCookie1, 'admin');
const afterLogoutAll1 = await call({ action: 'me' }, devAdminCookie1, 'admin');
const afterLogoutAll2 = await call({ action: 'me' }, devAdminCookie2, 'admin');
check('logout-all invalidates all active admin sessions for that admin', () => {
    assert.equal(afterLogoutAll1.status, 401);
    assert.equal(afterLogoutAll2.status, 401);
});

const nickLogin = await call({ action: 'verify-code', email: 'nicksprocessservices@outlook.com', code: '12345678' }, '', 'admin');
const nickCookie = nickLogin.headers.get('set-cookie').split(';')[0];
const brokenLink = await (await call({ action: 'list' }, nickCookie, 'admin')).json();
const paymentJob = brokenLink.orders.find(o => o.code === 'NP-403182');
const firstLink = await (await call({ action: 'get', id: paymentJob.id }, nickCookie, 'admin')).json();
const replacedLink = await call({ action: 'payment-link', id: paymentJob.id, amount: '175.00' }, nickCookie, 'admin');
assert.equal(replacedLink.status, 200);
const afterReplace = await (await call({ action: 'get', id: paymentJob.id }, nickCookie, 'admin')).json();
assert.notEqual(firstLink.order.stripe_session_id, afterReplace.order.stripe_session_id);
assert.equal((await handleMockRoute(new Request(`http://localhost${firstLink.order.payment_url}`))).status, 410);
passed++; console.log('PASS mock payment link replacement invalidates the old session');
const listData = await (await call({ action: 'list' }, nickCookie, 'admin')).json();
// Last contact is Nick's newest entry the client can see (list_order_activity), or null when he hasn't updated the
// client yet (the dashboard shows that in red). It is never before the request was made.
check('mock active jobs carry Nick\'s last client contact (or null before his first update)', () => {
    const active = listData.orders.filter(o => !['served', 'closed', 'cancelled'].includes(o.status));
    assert.ok(active.every(o => 'last_contact_at' in o && (o.last_contact_at === null ||
        (Number.isFinite(Date.parse(o.last_contact_at)) && o.last_contact_at >= o.created_at))));
    assert.ok(active.some(o => o.last_contact_at !== null), 'no active demo job shows a contact date');
});
const servedOrder = listData.orders.find(o => o.code === 'NP-894771');
const detailData = await (await call({ action: 'get', id: servedOrder.id }, nickCookie, 'admin')).json();
check('mock admin printing summary counts client PDFs but excludes proof', () => {
    assert.equal(detailData.printing.pages, 1);
    assert.equal(detailData.printing.pdfs, 1);
    assert.equal(detailData.printing.feeCents, 0);
    assert.equal(detailData.printing.complete, true);
});
const accountReceipt = await (await call({ action: 'receipt', code: servedOrder.code }, a)).json();
check('mock receipt is itemized and uses the recorded captured amount', () => {
    assert.equal(accountReceipt.receipt.amountPaidCents, 14000);
    assert.equal(accountReceipt.receipt.items.reduce((sum, item) => sum + item.cents, 0), 14000);
    assert.equal(detailData.order.receipt.amountPaidCents, 14000);
});
const otherReceiptCookie = await signup('receipt-other@example.com');
assert.equal((await call({ action: 'receipt', code: servedOrder.code }, otherReceiptCookie)).status, 404);
passed++; console.log('PASS mock receipt cannot be fetched by another client');
const proofFile = detailData.files.find(f => f.kind === 'proof');
check('Proof of Service has a verified 64-char SHA-256 chain-of-custody fingerprint in admin view', () => {
    assert.ok(proofFile && /^[0-9a-f]{64}$/.test(proofFile.sha256));
});
// Orders start with the document lock on, so Nick turns it off for this order before reading the client's view.
await call({ action: 'toggle-doc-lock', id: servedOrder.id, locked: false }, nickCookie, 'admin');
const trackData = await (await call({ action: 'view', t: detailData.order.track_token }, '', 'track')).json();
check('Proof of Service exposes matching SHA-256 fingerprint on client tracking view', () => {
    const clientProof = trackData.files.find(f => f.kind === 'proof');
    assert.equal(clientProof?.sha256, proofFile.sha256);
});
await call({ action: 'download', t: detailData.order.track_token, fileId: proofFile.id }, '', 'track');
const mockPackResponse = await call({ action: 'dispute-pack', id: servedOrder.id }, nickCookie, 'admin');
const mockPack = zipJson(Buffer.from(await mockPackResponse.arrayBuffer()));
check('mock dispute pack includes verified file and client download evidence', () => {
    assert.equal(mockPackResponse.headers.get('content-type'), 'application/zip');
    assert.equal(mockPack.files.find(f => f.kind === 'proof')?.sha256, proofFile.sha256);
    // client_audit_logs (20261030061450) names the downloaded file; it has no file id column.
    assert.ok(mockPack.downloads.some(d => d.filename === proofFile.filename));
    assert.ok(mockPack.client_activity.some(a => a.action === 'download' && a.detail === proofFile.filename));
    assert.equal(mockPack.chain.verified, true);
    assert.ok(mockPack.attestation?.created_at && mockPack.payment.stripe_session_id);
    assert.equal(mockPack.order.track_token, undefined);
});
const finishBody = { step: 'finish', t: detailData.order.track_token, fileIds: [] };
assert.equal((await call(finishBody, '', 'request')).status, 200);
assert.equal((await call(finishBody, '', 'request')).status, 200);
const afterFinish = await (await call({ action: 'get', id: servedOrder.id }, nickCookie, 'admin')).json();
check('mock request finish records one confirmation when retried', () => {
    assert.equal(afterFinish.events.filter(e => e.title === 'Confirmation emailed').length, 1);
});
const fieldJob = listData.orders.find(o => o.code === 'NP-517309');
const attemptWhen = new Date(Date.now() - 3600e3).toISOString();
const recorded = await call({ action: 'update', id: fieldJob.id, kind: 'attempt', outcome: 'No answer', when: attemptWhen }, nickCookie, 'admin');
const rejected = await call({ action: 'update', id: fieldJob.id, kind: 'attempt', outcome: 'No answer', when: 'yesterday' }, nickCookie, 'admin');
const attemptDetail = await (await call({ action: 'get', id: fieldJob.id }, nickCookie, 'admin')).json();
check('mock attempt stores ISO time and rejects ambiguous time', () => {
    assert.equal(recorded.status, 200);
    assert.equal(rejected.status, 400);
    assert.ok(attemptDetail.events.some(e => e.kind === 'attempt' && e.detail?.startsWith(`Attempted at: ${attemptWhen}`)));
});

console.log(`${passed} client account checks passed`);
