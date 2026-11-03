// Produces intentionally static Origin or Nexus delivery artifacts. Aura is the full repository/deployment and must
// be released through its normal server, database migration, and security-verification workflow.
// Usage: node scripts/build-package.mjs origin|nexus /absolute/empty/output-directory
import { cp, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageName = String(process.argv[2] || '').toLowerCase();
const out = path.resolve(process.argv[3] || '');
if (!['origin', 'nexus'].includes(packageName)) throw new Error('Choose package "origin" or "nexus". Aura is released from the secured application project.');
if (!out || !path.isAbsolute(out) || out === root) throw new Error('Choose a separate absolute output directory.');
await mkdir(out, { recursive: true });
if ((await readdir(out)).length) throw new Error('Package output directory must be empty.');

const template = await readFile(path.join(root, 'templates/package-landing.html'), 'utf8');
const nexus = packageName === 'nexus';
const nexusStyle = nexus ? `
    .nexus-reveal{animation:nexus-rise .7s cubic-bezier(.16,1,.3,1) both}.grid .nexus-reveal:nth-child(2){animation-delay:.1s}.grid .nexus-reveal:nth-child(3){animation-delay:.2s}@keyframes nexus-rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}.card{transition:transform .25s ease,box-shadow .25s ease}.card:hover{transform:translateY(-5px);box-shadow:0 22px 40px -26px rgba(8,43,30,.55)}
` : '';
const html = template.replaceAll('{{TITLE}}', nexus ? "Nick's Process Services | Nexus" : "Nick's Process Services")
    .replace('{{NEXUS_STYLE}}', nexusStyle).replaceAll('{{YEAR}}', String(new Date().getFullYear()));
await writeFile(path.join(out, 'index.html'), html);
await mkdir(path.join(out, 'assets', 'fonts'), { recursive: true });
for (const font of ['librecaslondisplay-400.woff2', 'montserrat-var.woff2']) {
    await cp(path.join(root, 'assets', 'fonts', font), path.join(out, 'assets', 'fonts', font));
}
await cp(path.join(root, 'assets', 'logo-base.svg'), path.join(out, 'assets', 'logo-base.svg'));
await writeFile(path.join(out, 'vercel.json'), JSON.stringify({
    framework: null,
    buildCommand: null,
    outputDirectory: '.',
    headers: [{ source: '/(.*)', headers: [
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        { key: 'Content-Security-Policy', value: "default-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'self'" },
        { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
    ] }],
}, null, 2));
console.log(`Built ${packageName} static package at ${out}. No API handlers, private pages, server code, credentials, payments, or client portal are included.`);
