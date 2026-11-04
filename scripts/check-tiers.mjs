// Checks the three package builds from scripts/build-tiers.mjs (it runs the build first).
// Aura must be the live page byte for byte; Origin and Nexus must hold no private platform code and no dead buttons;
// Nexus keeps the motion layer and its reduced-motion branch; Origin has none of it.
// Run with: node scripts/check-tiers.mjs
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
execFileSync(process.execPath, [join(ROOT, 'scripts/build-tiers.mjs')], { stdio: 'ignore' });
const read = (tier) => readFileSync(join(ROOT, 'dist', tier, 'index.html'), 'utf8');
const source = readFileSync(join(ROOT, 'index.html'), 'utf8');
const pages = { origin: read('origin'), nexus: read('nexus'), aura: read('aura') };

let passed = 0;
const failures = [];
function check(name, fn) {
    try { fn(); passed++; console.log(`PASS ${name}`); }
    catch (err) { failures.push(name); console.log(`FAIL ${name}\n     ${err.message}`); }
}
function expect(cond, msg) { if (!cond) throw new Error(msg); }

// Private platform markers: anything that would call the server, show order tracking or link to a private page.
const PRIVATE = ['/api/', 'NPS.post', 'NPS.uploadAll', 'stripe', 'supabase', 'service-request-form', 'lookupOrder', 'openTrackModal',
    'track-modal', 'confirm-modal', 'handleOrderSubmit', 'admin.html', 'account.html', 'track.html', 'href="#checkout"'];

check('Aura is the live index.html, byte for byte', () => expect(pages.aura === source, 'dist/aura/index.html differs from index.html'));
check('Aura still carries the platform and the motion layer', () => {
    for (const s of ['/api/request', 'openTrackModal', 'initLuxuryVisuals', 'geometry-canvas']) expect(pages.aura.includes(s), `missing ${s}`);
});
for (const tier of ['origin', 'nexus']) {
    const html = pages[tier];
    check(`${tier}: no private platform code or links`, () => {
        // Scanned without the shared compiled CSS, which has selectors for every page. The privacy policy is included,
        // so it can't name services (Stripe, Supabase) this package doesn't use.
        const code = html.replace(/<style>[\s\S]*?<\/style>/, '');
        const found = PRIVATE.filter(s => code.toLowerCase().includes(s.toLowerCase()));
        expect(!found.length, `found ${found.join(', ')}`);
    });
    check(`${tier}: the privacy policy matches a site with no online forms or payments`, () => {
        const policy = html.slice(html.indexOf("titleEl.textContent = 'Privacy Policy"), html.indexOf("titleEl.textContent = 'Terms of Service'"));
        for (const s of ['Supabase', 'Resend', 'Stripe', 'uploaded documents', 'tracking page']) expect(!policy.includes(s), `policy still mentions ${s}`);
        expect(policy.includes('collects nothing from you online'), 'policy does not say the site collects nothing online');
    });
    check(`${tier}: no api/ folder or private pages in the package`, () => {
        for (const f of ['api', 'admin.html', 'account.html', 'track.html', 'sw.js']) expect(!existsSync(join(ROOT, 'dist', tier, f)), `${f} shipped`);
    });
    check(`${tier}: ships the site's security headers and nothing server-side`, () => {
        const config = JSON.parse(readFileSync(join(ROOT, 'dist', tier, 'vercel.json'), 'utf8'));
        expect(JSON.stringify(Object.keys(config)) === '["headers"]', `unexpected config keys: ${Object.keys(config)}`);
        const site = config.headers.find(h => h.source === '/(.*)');
        const keys = new Set((site?.headers || []).map(h => h.key));
        for (const k of ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security', 'Referrer-Policy', 'Permissions-Policy']) expect(keys.has(k), `missing ${k}`);
        const csp = site.headers.find(h => h.key === 'Content-Security-Policy').value;
        expect(/connect-src 'self';/.test(csp) && !/supabase/i.test(csp) && /frame-ancestors 'self'/.test(csp), `CSP: ${csp}`);
    });
    check(`${tier}: every inline handler calls a function the page defines`, () => {
        const called = new Set([...html.matchAll(/\bon(?:click|submit|change|input)="(?:event\.preventDefault\(\);\s*)?([A-Za-z_$][\w$]*)\(/g)].map(m => m[1]));
        const missing = [...called].filter(fn => !new RegExp(`function ${fn}\\b`).test(html));
        expect(!missing.length, `undefined: ${missing.join(', ')}`);
    });
    check(`${tier}: every in-page link points at an element that exists`, () => {
        const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));
        const dead = [...new Set([...html.matchAll(/href="#([A-Za-z][\w-]*)"/g)].map(m => m[1]))].filter(id => !ids.has(id));
        expect(!dead.length, `dead links: #${dead.join(', #')}`);
    });
    check(`${tier}: the contact section offers call, text and email`, () => {
        for (const s of ['id="contact"', 'href="tel:+12099226817"', 'href="sms:+12099226817"', 'href="mailto:nicksprocessservices@outlook.com"']) expect(html.includes(s), `missing ${s}`);
    });
    check(`${tier}: the contact section only uses classes the page's CSS defines`, () => {
        const section = html.slice(html.indexOf('<section id="contact"'), html.indexOf('</section>', html.indexOf('<section id="contact"')));
        const css = html.slice(html.indexOf('<style>'), html.indexOf('</style>'));
        const classes = new Set([...section.matchAll(/class="([^"]+)"/g)].flatMap(m => m[1].split(/\s+/)).filter(c => !c.startsWith('fa-')));
        const esc = (c) => c.replace(/[:\[\]./!]/g, m => '\\' + m);
        const missing = [...classes].filter(c => !css.includes('.' + esc(c)));
        expect(!missing.length, `no CSS for: ${missing.join(', ')}`);
    });
}
check('Nexus keeps the motion layer and its reduced-motion branch', () => {
    for (const s of ['initLuxuryVisuals', 'geometry-canvas', "matchMedia('(prefers-reduced-motion: reduce)')", '.logo-lockup']) expect(pages.nexus.includes(s), `missing ${s}`);
});
check('Origin is static: no motion layer, canvas or sprite animation', () => {
    const code = pages.origin.replace(/<style>[\s\S]*?<\/style>/, '');
    for (const s of ['initLuxuryVisuals', '<canvas', 'is-run-visible', "'reveal-item'"]) expect(!code.includes(s), `found ${s}`);
    // CSS-only animations (hero rise, gold shimmer, tagline shine) need the static override too.
    expect(pages.origin.includes('<style id="origin-static">*,:after,:before{animation:none!important}</style>'), 'CSS animations are not switched off');
    expect(!pages.nexus.includes('origin-static'), 'Nexus lost its CSS animations');
});

console.log(`\n${passed} package checks passed, ${failures.length} failed`);
if (failures.length) process.exit(1);
