// Package artifact regression test. It proves the $550/$2,800 static deliverables cannot accidentally contain the
// $4,500 Aura platform merely because a UI control was hidden.
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
const run = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tmp = await mkdtemp(path.join(os.tmpdir(), 'nickweb-packages-'));
const forbiddenNames = new Set(['api', 'admin.html', 'account.html', 'track.html', 'supabase', 'scripts', 'node_modules']);
const forbiddenText = [/\/api\//i, /supabase/i, /stripe/i, /service_role/i, /private tracking/i, /client portal/i, /checkout/i,
  /track\.html/i, /admin\.html/i, /account\.html/i, /APP_SECRET/, /RESEND/i, /webhook/i, /passkey/i, /sourceMappingURL/i];
try {
  for (const name of ['origin', 'nexus']) {
    const out = path.join(tmp, name);
    await run(process.execPath, ['scripts/build-package.mjs', name, out], { cwd: root });
    const rootNames = new Set(await readdir(out));
    for (const forbidden of forbiddenNames) assert(!rootNames.has(forbidden), `${name} artifact exposes forbidden path ${forbidden}`);
    const html = await readFile(path.join(out, 'index.html'), 'utf8');
    for (const pattern of forbiddenText) assert(!pattern.test(html), `${name} landing page includes forbidden content ${pattern}`);
    const config = await readFile(path.join(out, 'vercel.json'), 'utf8');
    assert(/connect-src 'none'/.test(config), `${name} artifact permits network connections`);
    assert(!/script-src/.test(config), `${name} artifact permits JavaScript execution without an explicit need`);
    if (name === 'origin') assert(!/nexus-rise/.test(html), 'Origin includes Nexus animation code');
    if (name === 'nexus') assert(/nexus-rise/.test(html) && /prefers-reduced-motion/.test(html), 'Nexus interaction or reduced-motion support missing');
    console.log(`PASS ${name}: static package excludes Aura code and has its expected visual scope`);
  }
  // A relative or in-repo output path would write the deliverable among the Aura source, so both must be refused.
  for (const bad of ['relative-out', path.join(root, 'package-out')]) {
    const refused = await run(process.execPath, ['scripts/build-package.mjs', 'origin', bad], { cwd: root }).then(() => false, () => true);
    assert(refused, `build-package accepted unsafe output directory ${bad}`);
    await rm(path.resolve(root, bad), { recursive: true, force: true });
  }
  console.log('PASS build-package refuses relative and in-repository output directories');
} finally { await rm(tmp, { recursive: true, force: true }); }
