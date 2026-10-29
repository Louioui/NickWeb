// Package a static, browser-only preview. No API handlers, secrets or real integrations are shipped.
// Usage: node scripts/build-demo.mjs /absolute/output/directory
import { readFile, writeFile, mkdir, cp, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.resolve(process.argv[2] || path.join(root, 'build/demo'));
if (out === root || !path.isAbsolute(out)) throw new Error('Choose a separate demo output directory.');
await mkdir(out, { recursive: true });
if ((await readdir(out)).length) throw new Error('Demo output directory must be empty.');
await cp(path.join(root, 'assets'), path.join(out, 'assets'), { recursive: true });
await cp(path.join(root, 'manifest.webmanifest'), path.join(out, 'manifest.webmanifest'));
await cp(path.join(root, 'sw.js'), path.join(out, 'sw.js'));
const orders = await readFile(path.join(root, 'api/_lib/orders.mjs'), 'utf8');
const rules = orders.slice(orders.indexOf('export const TIERS'), orders.indexOf('export async function orderByToken')).replaceAll('export ', '');
let mock = await readFile(path.join(root, 'scripts/mock-api.mjs'), 'utf8');
mock = mock.replace(/^import .*;\n/gm, '').replaceAll('export ', '');
// Browser Responses hide Set-Cookie, so keep the simulated session in a demo-only header.
mock = mock.replace("'content-type': 'application/json', ...headers", "'content-type': 'application/json', 'x-demo-session': headers['set-cookie'] || '', ...headers");
// Demo emails are deliberately suppressed; they never reach a mail provider or the console.
mock = mock.replace(/^const email = .*;$/m, 'const email = () => {};').replace(/^.*console\.log\(`\[mock\].*$/m, '');
const template = await readFile(path.join(root, 'scripts/demo-browser-runtime.js'), 'utf8');
const runtime = template.replace('/* BUSINESS_RULES */', () => rules).replace('/* MOCK_API */', () => mock);
new Function(runtime); // Fail before deploying if source composition produced invalid JavaScript.
await writeFile(path.join(out, 'assets/demo-runtime.js'), runtime);
for (const page of ['index.html', 'admin.html', 'track.html', 'account.html']) {
    const html = await readFile(path.join(root, page), 'utf8');
    await writeFile(path.join(out, page), html.replace('</head>', '<script src="/assets/demo-runtime.js"></script>\n</head>'));
}
const shell = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${title}</title><script src="/assets/demo-runtime.js"></script></head><body style="margin:0;background:#f4f6f0;color:#10221a;font-family:system-ui,sans-serif"><main style="max-width:850px;margin:30px auto;padding:24px">${body}</main></body></html>`;
await writeFile(path.join(out, 'demo.html'), shell('Demo workspace | Nick’s Process Services', '<div id="demo-hub" aria-live="polite">Loading sample requests…</div>'));
await writeFile(path.join(out, 'demo-checkout.html'), shell('Simulated checkout | Nick’s Process Services', '<div id="demo-checkout" aria-live="polite">Loading simulated checkout…</div>'));
const csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data: blob: https://tile.openstreetmap.org https://*.tile.openstreetmap.org; connect-src 'self'; manifest-src 'self'; worker-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'self'";
await writeFile(path.join(out, 'vercel.json'), JSON.stringify({ framework: null, buildCommand: null, outputDirectory: '.', redirects: [{ source: '/__mock', destination: '/demo.html', permanent: false }], headers: [{ source: '/(.*)', headers: [{ key: 'X-Robots-Tag', value: 'noindex, nofollow' }, { key: 'Cache-Control', value: 'no-store' }, { key: 'Referrer-Policy', value: 'no-referrer' }, { key: 'X-Content-Type-Options', value: 'nosniff' }, { key: 'Content-Security-Policy', value: csp }] }] }, null, 2));
console.log(`Static demo packaged at ${out}. No API functions, credentials, emails or charges.`);
