// Checks the browser field helpers (assets/js/field-tools.js) in Node, and that the private pages keep a strict
// Content Security Policy: no inline scripts and no inline event handlers.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const ctx = { URL };
vm.runInNewContext(`${await readFile(new URL('../assets/js/field-tools.js', import.meta.url), 'utf8')}\nthis.NPSField = NPSField;`, ctx);
const F = ctx.NPSField;

let passed = 0;
const same = (a, b) => assert.equal(JSON.stringify(a), JSON.stringify(b));   // values from the VM sandbox are another realm
const check = (name, fn) => { fn(); passed++; console.log(`PASS ${name}`); };
const NOW = new Date(2026, 9, 30, 10, 0);   // Oct 30 2026, 10:00 local
const day = (offset) => { const d = new Date(NOW); d.setDate(d.getDate() + offset); return d.toISOString().slice(0, 10).replace(/^(\d{4}-\d{2}-\d{2}).*/, (_, x) => x); };
const localDay = (offset) => { const d = new Date(NOW); d.setDate(d.getDate() + offset); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
void day;

check('urgency: overdue (any tier), due today, rush/expedited within 48h; standard in 2 days is not urgent; finished jobs never', () => {
    assert.equal(F.urgency({ status: 'attempting', tier: 'standard', deadline: localDay(-1) }, NOW), 'overdue');
    assert.equal(F.urgency({ status: 'paid', tier: 'standard', deadline: localDay(0) }, NOW), 'today');
    assert.equal(F.urgency({ status: 'paid', tier: 'sameday', deadline: localDay(2) }, NOW), 'due48');
    assert.equal(F.urgency({ status: 'paid', tier: 'expedited', deadline: localDay(1) }, NOW), 'due48');
    assert.equal(F.urgency({ status: 'paid', tier: 'standard', deadline: localDay(2) }, NOW), null);
    assert.equal(F.urgency({ status: 'served', tier: 'sameday', deadline: localDay(-3) }, NOW), null);
    assert.equal(F.urgency({ status: 'paid', tier: 'sameday', deadline: 'not-a-date' }, NOW), null);
});
check('priority sort pins overdue, then due today, then rush within 48h, then nearest deadline', () => {
    const list = [
        { code: 'later', status: 'paid', tier: 'standard', deadline: localDay(9) },
        { code: 'rush', status: 'paid', tier: 'sameday', deadline: localDay(2) },
        { code: 'none', status: 'paid', tier: 'standard', deadline: null },
        { code: 'today', status: 'paid', tier: 'standard', deadline: localDay(0) },
        { code: 'late', status: 'attempting', tier: 'standard', deadline: localDay(-2) },
    ];
    same(F.prioritySort(list, NOW).map(o => o.code), ['late', 'today', 'rush', 'later', 'none']);
});
check('days since last update', () => {
    assert.equal(F.daysSince(new Date(NOW.getTime() - 3.5 * 864e5).toISOString(), NOW.getTime()), 3);
    assert.equal(F.daysSince(null), null);
});
check('attempt windows use the typed attempt time, else the logged time', () => {
    const ev = (detail, hour) => ({ kind: 'attempt', title: 'Attempt: No answer', detail, created_at: new Date(2026, 9, 29, hour, 5).toISOString() });
    const w = F.attemptWindows([ev('Oct 29, 7:30 PM · lights on', 9), ev('', 8), { kind: 'note', title: 'x', created_at: new Date(2026, 9, 29, 14).toISOString() }]);
    same(w.map(x => [x.key, x.done]), [['morning', true], ['evening', false], ['night', true]]);
    assert.equal(F.windowFor(F.attemptHour(ev('Oct 29, 12:15 PM', 1))), 'evening');
    assert.equal(F.windowFor(F.attemptHour(ev('Oct 29, 12:15 AM', 20))), 'morning');
    assert.equal(F.needsWindows('standard') && F.needsWindows('expedited') && !F.needsWindows('sameday'), true);
});
check('substituted service: reminder until a mailing is logged after the latest co-resident attempt', () => {
    const sub = { kind: 'attempt', title: 'Attempt: Left with co-resident', created_at: '2026-10-29T10:00:00Z' };
    const mail = { kind: 'note', title: 'Update from Nick', detail: 'Follow-up copy mailed (First-Class) on 10/29/2026 from Stockton.', created_at: '2026-10-29T12:00:00Z' };
    assert.equal(F.needsSubServiceMailing([sub]), true);
    assert.equal(F.needsSubServiceMailing([sub, mail]), false);
    assert.equal(F.needsSubServiceMailing([mail, { ...sub, created_at: '2026-10-30T10:00:00Z' }]), true);
    assert.equal(F.needsSubServiceMailing([{ kind: 'attempt', title: 'Attempt: No answer', created_at: 'x' }]), false);
});
check('route: at most 9 stops, last is the destination, the rest are waypoints, addresses are URL-encoded', () => {
    const stops = Array.from({ length: 12 }, (_, i) => `${i + 1} Main St #2, Stockton & Co`);
    const u = new URL(F.routeUrl(stops));
    assert.equal(u.origin + u.pathname, 'https://www.google.com/maps/dir/');
    assert.equal(u.searchParams.get('destination'), '9 Main St #2, Stockton & Co');
    assert.equal(u.searchParams.get('waypoints').split('|').length, 8);
    assert.equal(F.routeUrl([]), null);
    assert.ok(!F.routeUrl(['1 A St']).includes('waypoints'));
});
check('printing fee: first 100 pages free, then 15 cents', () => {
    assert.equal(F.printingFeeCents(100), 0);
    assert.equal(F.printingFeeCents(101), 15);
    assert.equal(F.printingFeeCents(250), 2250);
});
check('"what happens next" covers every status and the tier timing', () => {
    for (const s of ['received', 'action_required', 'awaiting_payment', 'paid', 'accepted', 'attempting', 'served', 'closed', 'cancelled']) assert.ok(F.nextStep({ status: s, tier: 'standard' }));
    assert.match(F.nextStep({ status: 'paid', tier: 'expedited' }), /within 48 hours of receiving/);
    assert.match(F.nextStep({ status: 'paid', tier: 'sameday' }), /within 24 hours of receiving/);
    assert.doesNotMatch(F.nextStep({ status: 'paid', tier: 'standard' }), /within/);   // the public page promises no first-attempt time
    assert.match(F.nextStep({ status: 'awaiting_payment', tier: 'standard' }), /Waiting for payment/);
});
check('printouts escape everything they show (no HTML from names, notes or file names)', () => {
    const evil = '<img src=x onerror=alert(1)>';
    const o = { code: 'NP-123456', recipient_name: evil, address: evil, city: 'S', zip: '1', case_number: evil, court: evil, client_name: evil, doc_type: evil };
    const events = [{ kind: 'attempt', title: `Attempt: ${evil}`, detail: evil, created_at: '2026-10-29T10:00:00Z' }];
    const pack = { order: { ...o, client_email: evil, addons: [evil] }, attestation: [{ title: evil, detail: evil, created_at: 'x' }], payments: [], attempts: events,
        files: [{ filename: evil, kind: 'proof', sha256: evil }], timeline_seal: { verified: true, head: evil }, client_actions: [{ action: 'download', detail: evil, user_agent: evil, ip_hash: 'a'.repeat(64), created_at: 'x' }] };
    for (const html of [F.diligenceHtml(o, events), F.pos010Html(o, events), F.evidenceHtml(pack),
        F.receiptHtml({ code: 'NP-1', clientName: evil, tierName: evil, tierCents: 7500, addons: [{ name: evil, cents: 1 }], totalCents: 7501 })]) {
        assert.ok(!html.includes('<img'), 'unescaped HTML in a printout');
        assert.ok(!/\son\w+\s*=/.test(html.replace(/&lt;img[^]*?&gt;/g, '')), 'inline handler in a printout');
    }
});
check('receipt itemizes tier, add-ons and printing, and shows any difference to the total as its own line', () => {
    const html = F.receiptHtml({ code: 'NP-123456', paidAt: '2026-10-30T10:00:00Z', clientName: 'Pat', tierName: 'Standard Service', tierCents: 7500,
        addons: [{ name: 'Basic Photo Proof', cents: 1500 }], printingPages: 120, printingFeeCents: 300, totalCents: 10000 });
    assert.match(html, /Standard Service[^]*\$75\.00/);
    assert.match(html, /Printing: 120 pages[^]*\$3\.00/);
    assert.match(html, /Other charges as quoted[^]*\$7\.00/);
    assert.match(html, /Total paid[^]*\$100\.00/);
});
check('CSV export quotes every cell and neutralizes spreadsheet formulas', () => {
    const csv = F.ordersCsv([{ code: 'NP-1', label: 'Paid', recipient: '=HYPERLINK("http://evil")', document: 'Summons, "A"', reference: '+1', amount: '$1' }]);
    const line = csv.split('\r\n')[1];
    assert.ok(line.includes(`"'=HYPERLINK(""http://evil"")"`), line);
    assert.ok(line.includes('"Summons, ""A"""') && line.includes(`"'+1"`), line);
});

// --- Strict CSP: no inline scripts or handlers on the private pages ---
for (const page of ['admin.html', 'track.html', 'account.html', 'demo.html']) {
    const html = (await readFile(new URL(`../${page}`, import.meta.url), 'utf8')).replace(/<style[^]*?<\/style>/gi, '');
    check(`${page}: no inline <script> and no on…= handlers`, () => {
        for (const m of html.matchAll(/<script\b([^>]*)>([^]*?)<\/script>/gi)) assert.ok(/\bsrc=/.test(m[1]) && !m[2].trim(), `inline script in ${page}`);
        assert.ok(!/<[a-z][^>]*\son[a-z]+\s*=/i.test(html), `inline handler in ${page}`);
    });
}

{
    const admin = await readFile(new URL('../admin.html', import.meta.url), 'utf8');
    const sw = await readFile(new URL('../sw.js', import.meta.url), 'utf8');
    const srcs = [...admin.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map(m => '/' + m[1].replace(/^\//, ''));
    check('admin.html scripts are all listed in sw.js SHELL_ASSETS', () => { for (const src of srcs) assert.ok(sw.includes(`'${src}'`), `${src} missing from sw.js`); });
}

console.log(`\n${passed} field tool & CSP checks passed`);
