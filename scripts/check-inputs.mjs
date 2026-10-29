// Edge-case checks for the server's input handling (prices, files, text, email, cookies, request bodies). Run: npm test
const root = new URL('..', import.meta.url).href.replace(/\/$/, '');
const { estimate, clean } = await import(root + '/api/_lib/orders.mjs');
const { cleanFileList, text, email, getCookie, readJson, uuid, uuidList } = await import(root + '/api/_lib/core.mjs');
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

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
