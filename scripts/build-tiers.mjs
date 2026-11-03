// Builds the three website packages into dist/ (gitignored; never deployed by Vercel):
//   dist/aura/    Origin + Nexus + the private platform. The live site, byte for byte.
//   dist/nexus/   Origin plus the motion layer (rosette canvas, parallax, scroll reveal, running-logo sprite).
//   dist/origin/  The public landing page alone: services, coverage, pricing, reviews, FAQ, and a call / text / email contact.
// Origin and Nexus get no api/ folder and no private pages, and nothing in them calls /api/. Every cut is anchored on
// exact text from index.html and must match exactly once, so if the page changes under it the build fails loudly
// instead of shipping a half-stripped page. scripts/check-tiers.mjs checks the output.
// Run with: node scripts/build-tiers.mjs
import { readFileSync, writeFileSync, mkdirSync, rmSync, cpSync, existsSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(ROOT, 'dist');
const source = readFileSync(join(ROOT, 'index.html'), 'utf8');

function count(html, needle) {
    let n = 0;
    for (let i = html.indexOf(needle); i !== -1; i = html.indexOf(needle, i + needle.length)) n++;
    return n;
}
function once(html, needle, label) {
    const n = count(html, needle);
    if (n !== 1) throw new Error(`${label}: expected the anchor once in index.html, found it ${n} times`);
    return html.indexOf(needle);
}
// Removes everything from `start` up to (but not including) `end`, or replaces it with `insert`.
// With `through`, the end anchor is removed too.
function cut(html, start, end, label, insert = '', through = false) {
    const a = once(html, start, `${label} (start)`);
    const b = html.indexOf(end, a + start.length);
    if (b === -1) throw new Error(`${label}: end anchor not found after the start`);
    return html.slice(0, a) + insert + html.slice(through ? b + end.length : b);
}
function replace(html, from, to, label) {
    once(html, from, label);
    return html.replace(from, () => to);
}
function replaceAll(html, from, to, label) {
    if (!count(html, from)) throw new Error(`${label}: anchor not found`);
    return html.split(from).join(to);
}

// The contact section that takes the place of the online request form. Only classes the page already uses, so the
// compiled CSS covers it.
const CONTACT = `<!-- Contact: call, text or email Nick. No form and no server: the package includes no private platform. -->
    <section id="contact" class="py-24 lg:py-32 rule-t">
        <div class="max-w-7xl mx-auto px-6">
            <div class="max-w-3xl mb-14">
                <p class="eyebrow mb-5">Request service</p>
                <h2 class="section-title mb-5">Contact Nick to Start a Serve</h2>
                <p class="lede">Call, text or email Nick with the person to be served, the address and your deadline. He confirms the details, the final price and the timing with you directly.</p>
            </div>
            <div class="flex flex-wrap gap-4">
                <a href="tel:+12099226817" class="btn btn-pine"><i class="fa-solid fa-phone-volume" aria-hidden="true"></i> Call (209) 922-6817</a>
                <a href="sms:+12099226817" class="btn btn-outline"><i class="fa-solid fa-comment-sms" aria-hidden="true"></i> Text Nick</a>
                <a href="mailto:nicksprocessservices@outlook.com" class="btn btn-outline"><i class="fa-solid fa-envelope" aria-hidden="true"></i> Email Nick</a>
            </div>
        </div>
    </section>

    `;

// Origin and Nexus: take out the private platform (online request form, order tracking, client account check).
function withoutPlatform(html) {
    // Header, mobile menu, hero and footer "Track" buttons.
    html = cut(html, `<button type="button" onclick="openTrackModal()" class="hidden sm:inline-flex hover:text-accent transition-colors items-center gap-1.5 font-medium">`,
        `<a href="tel:+12099226817"`, 'top-bar track button');
    html = html.replace(/\s*<span[^>]*aria-hidden="true">&#9670;<\/span>(\s*<a href="tel:\+12099226817")/, '$1');
    html = html.replace(/\n[^\n]*<button type="button" onclick="openTrackModal\(\)"[^\n]*>Track (Order|Existing Serve)<\/button>/g, '');
    html = cut(html, '<!-- Track an existing serve -->', '\n                </div>\n            </div>\n        </div>\n    </section>', 'hero track block');
    html = html.replace(/\n[^\n]*<li><button type="button" onclick="openTrackModal\(\)"[^\n]*<\/li>/, '');
    // The online request form becomes the contact section; every link to it follows.
    html = cut(html, '<!-- Checkout / Service Request Section', '\n    </section>\n', 'request form section', CONTACT.trimEnd() + '\n', true);
    html = replaceAll(html, 'href="#checkout"', 'href="#contact"', '#checkout links');
    // Track and confirmation dialogs (the legal dialog stays).
    html = cut(html, '<div id="track-modal"', '<div id="legal-modal"', 'track and confirm dialogs');
    // Script: pricing calculator and file upload feed the request form; the plan buttons now go to the contact section.
    html = cut(html, '        // --- Pricing Plan & Add-on Calculator', '        // --- Accessible Modal Management',
        'pricing calculator and uploads',
        "        // --- Pricing: choosing a plan goes to the contact section ---\n" +
        "        document.querySelectorAll('#pricing [data-plan]').forEach(btn => {\n" +
        "            btn.addEventListener('click', () => document.getElementById('contact').scrollIntoView({ behavior: 'smooth' }));\n" +
        "        });\n\n");
    html = replace(html, "const MODAL_IDS = ['track-modal', 'confirm-modal', 'legal-modal'];", "const MODAL_IDS = ['legal-modal'];", 'modal list');
    html = cut(html, '        // --- Track Existing Serve', '        // --- Legal Modals ---', 'tracking, account check and request wizard');
    html = replace(html, '                closeTrackModal();\n                closeConfirmModal();\n', '', 'Escape handler');
    // Privacy policy: without the platform the site collects nothing online, so the parts about online requests,
    // uploads, the database, emails and card payments are replaced with what is true for these packages.
    html = cut(html, '<p><strong>What we collect:</strong>', '<p><strong>Cookies and tracking:</strong>', 'privacy policy', PUBLIC_PRIVACY);
    return html;
}

const PUBLIC_PRIVACY = `<p><strong>What we collect:</strong> This website has no forms and collects nothing from you online. When you call, text, or email Nick, we receive what you choose to share: your name, firm, email and phone; your case details; the name, address and description of the person to be served; and any documents you send.</p>
                    <p><strong>How it's used:</strong> Only to carry out and keep a record of the service you request. We never sell it or share it for advertising.</p>
                    <p><strong>Storage:</strong> Information you send by phone, text or email is kept in Nick's own business records and email account, and documents are opened only by Nick.</p>
                    <p><strong>Service providers:</strong> The site is hosted by Vercel, which receives your IP address when you visit, like any website host. The coverage map shows map images from OpenStreetMap, which also receives your IP address when those images load. Links to Nick's Google reviews open Google's own site. Payment is arranged directly with Nick after he confirms your request, for example by Zelle.</p>
                    `;

// Origin: also take out the motion layer, so the page is static (content was never hidden without it: the reveal
// script is what adds the hidden state).
function withoutMotion(html) {
    html = cut(html, '        // Start each logo only after its sprite loads', '        // --- Helpers ---', 'running-logo sprite');
    html = cut(html, '        // --- Luxury Visual Choreography', '        // --- Dev Live-Server False-Reload Guard ---', 'motion layer');
    html = replace(html, '<canvas id="geometry-canvas" aria-hidden="true"></canvas>', '', 'rosette canvas');
    // The CSS-only effects (hero rise, gold shimmer, tagline shine, step pulses) run without any script, so they are
    // switched off the way the page already does for visitors who ask for reduced motion. Hover transitions stay.
    html = replace(html, '<!-- site-css:end', '<style id="origin-static">*,:after,:before{animation:none!important}</style>\n    <!-- site-css:end', 'static override');
    return html;
}

const nexus = withoutPlatform(source);
const origin = withoutMotion(nexus);

// Static files each package may ship. Origin and Nexus get an allowlist; Aura is the whole deployable site.
const PUBLIC_FILES = ['assets/fonts', 'assets/vendor', 'assets/js/nps.js', 'assets/logo-base.svg', 'assets/logo-base.webp',
    'assets/logo-man-run.webp', 'assets/logo.webp', 'assets/icon-180.png', 'assets/icon-192.png', 'assets/icon-512.png',
    'assets/icon-512-maskable.png', 'LICENSE'];
const AURA_EXCLUDE = new Set(['.git', '.github', '.claude', 'node_modules', 'dist', 'docs', 'scripts', 'src', 'build', 'supabase',
    '.DS_Store', '.gitignore', 'package.json', 'package-lock.json', 'tailwind.config.js', 'demo.html']);

rmSync(DIST, { recursive: true, force: true });
for (const [tier, html] of [['origin', origin], ['nexus', nexus]]) {
    const out = join(DIST, tier);
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, 'index.html'), html);
    for (const f of PUBLIC_FILES) {
        if (existsSync(join(ROOT, f))) { mkdirSync(dirname(join(out, f)), { recursive: true }); cpSync(join(ROOT, f), join(out, f), { recursive: true }); }
    }
}
for (const entry of readdirSync(ROOT)) {
    if (!AURA_EXCLUDE.has(entry)) cpSync(join(ROOT, entry), join(DIST, 'aura', entry), { recursive: true });
}
console.log(`Built dist/origin (${origin.length} B), dist/nexus (${nexus.length} B), dist/aura (${source.length} B, unchanged)`);
