// Edge-case checks for the server's input handling (prices, files, text, email, cookies, request bodies). Run: npm test
const root = new URL('..', import.meta.url).href.replace(/\/$/, '');
const { estimate, clean, cleanTrackToken } = await import(root + '/api/_lib/orders.mjs');
const { cleanFileList, text, longText, email, phone, cleanOrderCode, cleanDate, getCookie, readJson, uuid, uuidList, ADMIN_EMAILS } = await import(root + '/api/_lib/core.mjs');
let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log('FAIL', name); };
const throws = (name, fn, re) => { try { fn(); ok(name, false); } catch (e) { ok(name, !re || re.test(e.message)); } };
const throwsAsync = async (name, fn, re) => { try { await fn(); ok(name, false); } catch (e) { ok(name, !re || re.test(e.message)); } };

// Prices
ok('normal estimate', estimate('expedited', ['photo', 'video']).cents === 12500 + 1500 + 5000);
ok('duplicate add-ons counted once', estimate('standard', ['photo', 'photo']).cents === 9000);
ok('prototype names ignored', estimate('standard', ['constructor', '__proto__', 'toString', 'hasOwnProperty']).cents === 7500);
ok('non-string add-ons ignored', estimate('standard', [{}, 5, null, ['photo']]).cents === 7500);
ok('add-ons not an array', estimate('standard', 'photo').cents === 7500);
for (const t of ['constructor', '__proto__', '', null, 42, ['standard'], 'STANDARD']) throws(`bad tier ${JSON.stringify(t)}`, () => estimate(t, []), /tier/);
ok('price is always a whole number', Number.isInteger(estimate('sameday', Object.keys({ photo: 1, photos: 1, video: 1, mail: 1, stakeout: 1, coordinated: 1 })).cents));

// Files
ok('pdf ok', cleanFileList([{ name: 'a.pdf', size: 10, type: 'application/pdf' }])[0].type === 'application/pdf');
ok('HEIC with no type ok', cleanFileList([{ name: 'IMG.HEIC', size: 10, type: '' }])[0].type === 'image/heic');
ok('type comes from extension', cleanFileList([{ name: 'a.png', size: 10, type: 'application/pdf' }])[0].type === 'image/png');
throws('html disguised as pdf', () => cleanFileList([{ name: 'notes.html', size: 10, type: 'application/pdf' }]), /only PDF/);
throws('old .doc (macros)', () => cleanFileList([{ name: 'a.doc', size: 10, type: 'application/msword' }]), /only PDF/);
ok('.docx ok', cleanFileList([{ name: 'a.docx', size: 10 }]).length === 1);
throws('exe', () => cleanFileList([{ name: 'x.exe', size: 10, type: 'application/x-msdownload' }]), /only PDF/);
throws('no extension', () => cleanFileList([{ name: 'pdf', size: 10, type: 'application/pdf' }]), /only PDF/);
throws('double extension', () => cleanFileList([{ name: 'x.pdf.exe', size: 10 }]), /only PDF/);
throws('26 MB', () => cleanFileList([{ name: 'a.pdf', size: 26 * 1024 * 1024 }]), /25 MB/);
throws('0 bytes', () => cleanFileList([{ name: 'a.pdf', size: 0 }]), /25 MB/);
throws('negative size', () => cleanFileList([{ name: 'a.pdf', size: -5 }]), /25 MB/);
throws('size as text', () => cleanFileList([{ name: 'a.pdf', size: 'big' }]), /25 MB/);
throws('11 files', () => cleanFileList(Array.from({ length: 11 }, () => ({ name: 'a.pdf', size: 1 }))), /at most 10/);
throws('missing name', () => cleanFileList([{ size: 1 }]), /File name/);
throws('200-char name', () => cleanFileList([{ name: 'a'.repeat(200) + '.pdf', size: 1 }]), /too long/);
ok('not a list -> no files', cleanFileList('a.pdf').length === 0 && cleanFileList(null).length === 0);

// Text and email
ok('whitespace collapsed', text('  a \n\t b  ') === 'a b');
ok('non-string -> empty', text({ toString: () => 'x' }) === null && text(['a']) === null);
throws('too long', () => text('x'.repeat(201)), /too long/);
throws('required', () => text('   ', { required: true, label: 'Name' }), /Name is required/);
ok('email lower-cased', email(' Maria@Example.COM ') === 'maria@example.com');
for (const e of ['a@b', 'a b@c.com', '@x.com', 'a@.c', '', 'a@b.c']) throws(`bad email ${e}`, () => email(e), /valid email|required/);

// Cookies and bodies
const req = (cookie) => new Request('http://x/', { headers: { cookie } });
ok('cookie read', getCookie(req('a=1; nps_admin=abc'), 'nps_admin') === 'abc');
ok('malformed cookie -> logged out', getCookie(req('nps_admin=%E0%A4%A'), 'nps_admin') === null);
ok('similar name not matched', getCookie(req('xnps_admin=abc'), 'nps_admin') === null);
const post = (body, headers = {}) => new Request('https://www.nicksprocessservices.dev/api/x', { method: 'POST', body,
    headers: { 'content-type': 'application/json', origin: 'https://www.nicksprocessservices.dev', ...headers } });
await throwsAsync('70 KB body', () => readJson(post('x'.repeat(70000))), /too large/);
await throwsAsync('broken JSON', () => readJson(post('{"a":')), /Invalid/);
ok('empty body', JSON.stringify(await readJson(post(''))) === '{}');
ok('same-site JSON accepted', (await readJson(post('{"a":1}'))).a === 1);
ok('no Origin header (server-to-server) accepted', (await readJson(post('{"a":1}', { origin: '' }))).a === 1);
await throwsAsync('form post from another site (text/plain)', () => readJson(post('{"a":1}', { 'content-type': 'text/plain' })), /Invalid/);
await throwsAsync('JSON sent from another site', () => readJson(post('{"a":1}', { origin: 'https://evil.example' })), /Invalid/);
await throwsAsync('look-alike origin', () => readJson(post('{"a":1}', { origin: 'https://www.nicksprocessservices.dev.evil.example' })), /Invalid/);
await throwsAsync('http instead of https origin', () => readJson(post('{"a":1}', { origin: 'http://www.nicksprocessservices.dev' })), /Invalid/);

// Email text: scam links removed, normal details kept
const scrubbed = (s) => !/evil|scam|bit\.ly|pay-now/i.test(clean(s));
for (const s of ['Visit https://evil.example/pay now', 'go to www.scam-site.com', 'pay at scam-site.com/invoice', 'bit.ly/3xYz',
                 'EVIL.COM', 'login at pay-now.net?x=1', 'Jordan (scam.dev)', 'http://192.168.0.1/evil'])
    ok(`link removed: ${s}`, scrubbed(s) || clean(s).includes('[link removed]'));
for (const s of ['refund at court-fees.help', 'case.ai/pay', 'see justice.law', 'pay.page', 'x.pro', 'xn--80ak6aa92e.com', 'login.microsoftonline.support/x',
                 'claim at nick-process.services', 'click here: EVIL.LOL', 'scam.example.museum'])
    ok(`any ending removed: ${s}`, clean(s).includes('[link removed]'));
ok('initials kept', clean('J.R.R. Tolkien and A.B. Smith') === 'J.R.R. Tolkien and A.B. Smith');
ok('money kept', clean('Total due: $140.00 (Standard $75.00 + $15.50)') === 'Total due: $140.00 (Standard $75.00 + $15.50)');
ok('time kept', clean('Tried 6:30 p.m. and 7 a.m.') === 'Tried 6:30 p.m. and 7 a.m.');
ok('reference kept', clean('Reference: NP-482913 · Case 24STFL01234') === 'Reference: NP-482913 · Case 24STFL01234');
ok('email address kept', clean('maria@example.com · (714) 555-0199') === 'maria@example.com · (714) 555-0199');
ok('names kept', clean('J.R. Smith, Vance & Ortiz LLP') === 'J.R. Smith, Vance & Ortiz LLP');
ok('address kept', clean('2250 E Ocean Blvd, Apt 7B, Long Beach 90803') === '2250 E Ocean Blvd, Apt 7B, Long Beach 90803');
ok('long text cut', clean('x'.repeat(5000)).length === 600);

// Ids
ok('uuid accepted', uuid('4c190c16-ccb0-40c6-9c81-da1842658d52') === '4c190c16-ccb0-40c6-9c81-da1842658d52');
for (const v of ['', 'abc', "4c190c16-ccb0-40c6-9c81-da1842658d52' or 1=1", { id: 1 }, null, '4c190c16ccb040c69c81da1842658d52'])
    throws(`bad id ${JSON.stringify(v)}`, () => uuid(v), /not found/);
ok('id list keeps only real ids', uuidList(['4c190c16-ccb0-40c6-9c81-da1842658d52', 'x),id.neq.0', 5, null]).length === 1);
ok('id list from non-list', uuidList('x').length === 0);
ok('default ADMIN_EMAILS is Nick only (anyone else must be listed in the ADMIN_EMAILS env var)',
    ADMIN_EMAILS.length === 1 && ADMIN_EMAILS[0] === 'nicksprocessservices@outlook.com');

// Hardened SQLi / PostgREST / control-char / prototype-pollution checks
for (const badEmail of [
    "admin'--@evil.com",
    'user"quote@evil.com',
    "a@b.com' OR '1'='1",
    'user,id.eq.1@evil.com',
    'user(1)@evil.com',
    'user;drop@evil.com',
    '.leading@evil.com',
    'trailing.@evil.com',
    'double..dot@evil.com',
    'user@-bad.com',
    'user@bad-.com',
    'user@bad..com',
]) throws(`SQLi/malformed email rejected: ${badEmail}`, () => email(badEmail), /valid email/);
ok('plus-tagged email accepted', email('devteam+test@partnershipwithmedia-dev.com') === 'devteam+test@partnershipwithmedia-dev.com');

ok('valid US phone accepted', phone('(562) 555-0144 ext 12') === '(562) 555-0144 ext 12');
for (const badPhone of [
    "2099226817' OR 1=1--",
    '5625550144; DROP TABLE orders',
    '<script>1234567890</script>',
    '12345',
    '12345678901234567',
]) throws(`SQLi/bad phone rejected: ${badPhone}`, () => phone(badPhone), /phone number/);

ok('valid calendar date accepted', cleanDate('2026-10-29') === '2026-10-29');
ok('leap year date accepted', cleanDate('2028-02-29') === '2028-02-29');
ok('empty date -> null', cleanDate('') === null && cleanDate(null) === null);
for (const badDate of ['9999-99-99', '2026-02-29', '2026-02-31', '2026-13-01', '2026-00-10', '1800-01-01', "2026-10-29' OR '1'='1"])
    throws(`invalid date rejected: ${badDate}`, () => cleanDate(badDate), /valid deadline date/);

ok('valid order code normalized', cleanOrderCode('np-649025') === 'NP-649025' && cleanOrderCode('649025') === 'NP-649025');
for (const badCode of ['NP-12345', 'NP-1234567', "NP-123456' OR 1=1", 'NP-ABCDEF', ''])
    throws(`bad order code rejected: ${badCode}`, () => cleanOrderCode(badCode), /reference number/i);

ok('valid track token accepted', cleanTrackToken('AbCdEfGhIjKlMnOpQrStUvWxYz012345') === 'AbCdEfGhIjKlMnOpQrStUvWxYz012345');
for (const badTok of ['short', "AbCdEfGhIjKlMnOpQrSt' OR '1'='1", 'aaaa,id.neq.00000000000000', '../etc/passwd/123456789012', 'a'.repeat(65)])
    throws(`bad track token rejected: ${badTok}`, () => cleanTrackToken(badTok), /tracking link/);

ok('NUL bytes and bidi override stripped from text', text('Hello\u0000\u0007\u202EWorld') === 'HelloWorld');
ok('NUL bytes and bidi override stripped from longText', longText('Line 1\u0000\u202E\nLine 2') === 'Line 1\nLine 2');

for (const badFile of [
    { name: '../secret.pdf', size: 100 },
    { name: 'sub/secret.pdf', size: 100 },
    { name: '..\\secret.pdf', size: 100 },
    { name: 'invoice.php.pdf', size: 100 },
    { name: 'malware.exe.pdf', size: 100 },
    { name: 'xss.svg.pdf', size: 100 },
    { name: 'payload.html.jpg', size: 100 },
    { name: 'script.js.png', size: 100 },
    { name: 'valid.pdf', size: 100.5 },
]) throws(`bad file rejected: ${badFile.name} (${badFile.size})`, () => cleanFileList([badFile]), /only PDF|25 MB/i);

const polluted = await readJson(post('{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}},"nested":{"__proto__":{"x":1}},"ok":1}'));
ok('prototype pollution keys stripped from JSON', polluted.ok === 1 && !({}).polluted && !Object.hasOwn(polluted, '__proto__') && !Object.hasOwn(polluted, 'constructor'));
for (const badRoot of ['null', '[]', '[1,2,3]', '"hello"', '42', 'true'])
    await throwsAsync(`non-object JSON root rejected: ${badRoot}`, () => readJson(post(badRoot)), /Invalid/);

ok('cookie with NUL byte rejected', getCookie(req('nps_admin=abc%00def'), 'nps_admin') === null);
ok('oversized cookie header rejected', getCookie(req('nps_admin=' + 'a'.repeat(9000)), 'nps_admin') === null);

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
