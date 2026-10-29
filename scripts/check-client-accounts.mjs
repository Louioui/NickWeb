// Account boundaries in the isolated mock plus the production identity/cookie helpers. No network or live data.
import assert from 'node:assert/strict';
import { handleMockApi } from './mock-api.mjs';
import { verifiedClient, clientCookie, savedClientSession, clientProfile } from '../api/_lib/clients.mjs';
let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`PASS ${name}`); };
const call = async (body, cookie = '', endpoint = 'client') => handleMockApi(endpoint, new Request(`http://localhost/api/${endpoint}`, { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify(body) }));
const signup = async addr => {
    assert.equal((await call({ action:'send-code', intent:'signup', email:addr, name:'Demo Client', firm:'Test Firm' })).status,200);
    const response = await call({ action:'verify-code', email:addr, code:'123456' });
    assert.equal(response.status,200);
    return response.headers.get('set-cookie').split(';')[0];
};
check('unverified identities are refused', () => assert.throws(() => verifiedClient({id:'a', email:'x@example.com'}), /verify/));
check('anonymous identities are refused', () => assert.throws(() => verifiedClient({id:'a', email_confirmed_at:'now'}), /verify/));
check('profile email cannot come from editable metadata', () => assert.equal(clientProfile({email:'right@example.com',user_metadata:{email:'wrong@example.com',role:'admin'}}).email,'right@example.com'));
const cookie = clientCookie(new Request('https://example.com/api/client'), {access_token:'access-test',refresh_token:'refresh-test'});
check('HTTPS client cookie is HttpOnly, Secure, strict and scoped', () => { for(const flag of ['HttpOnly','Secure','SameSite=Strict','Path=/api/client'])assert.ok(cookie.includes(flag)); });
check('server can parse its session cookie', () => assert.deepEqual(savedClientSession(new Request('https://example.com/api/client',{headers:{cookie:cookie.split(';')[0]}})),{access:'access-test',refresh:'refresh-test'}));
check('oversized session cookies are rejected', () => assert.throws(() => clientCookie(new Request('https://example.com'),{access_token:'x'.repeat(5000),refresh_token:'y'}),/completed/));
check('malformed cookies fail closed', () => assert.equal(savedClientSession(new Request('https://example.com',{headers:{cookie:'nps_client=%7Binvalid'}})),null));
assert.equal((await call({action:'list'})).status,401);passed++;
await call({action:'send-code',intent:'signup',email:'fresh@example.com',name:'Fresh'});
assert.equal((await call({action:'verify-code',email:'fresh@example.com',code:'000000'})).status,401);passed++;
const a=await signup('paralegal@example.com');
const all=await (await call({action:'list'},a)).json();
check('verified sample email sees its five requests',()=>assert.equal(all.orders.length,5));
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

const genRes = await (await call({ action: 'generate-recovery-codes' }, devAdminCookie1, 'admin')).json();
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
const listData = await (await call({ action: 'list' }, nickCookie, 'admin')).json();
const servedOrder = listData.orders.find(o => o.code === 'NP-894771');
const detailData = await (await call({ action: 'get', id: servedOrder.id }, nickCookie, 'admin')).json();
const proofFile = detailData.files.find(f => f.kind === 'proof');
check('Proof of Service has a verified 64-char SHA-256 chain-of-custody fingerprint in admin view', () => {
    assert.ok(proofFile && /^[0-9a-f]{64}$/.test(proofFile.sha256));
});
const trackData = await (await call({ action: 'view', t: detailData.order.track_token }, '', 'track')).json();
check('Proof of Service exposes matching SHA-256 fingerprint on client tracking view', () => {
    const clientProof = trackData.files.find(f => f.kind === 'proof');
    assert.equal(clientProof?.sha256, proofFile.sha256);
});

console.log(`${passed} client account checks passed`);
