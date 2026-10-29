#!/usr/bin/env node
// Copies the compiled stylesheet (build/site.css) into each page, between the site-css markers.
// Inlining means the page styles correctly in every viewing mode (hosted, file://, and the app's static previews)
// and removes a render-blocking request. Fonts and the logo stay as real files under assets/.
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const PAGES = ['index.html', 'track.html', 'admin.html', 'account.html'];
const css = fs.readFileSync(path.join(root, 'build', 'site.css'), 'utf8').trim();
if (css.includes('</style')) throw new Error('Compiled CSS contains "</style"; refusing to inline it.');

const pattern = /(<!-- site-css:start[^>]*-->)[\s\S]*?(<!-- site-css:end -->)/;
for (const page of PAGES) {
    const htmlPath = path.join(root, page);
    const html = fs.readFileSync(htmlPath, 'utf8');
    if (!pattern.test(html)) throw new Error(`site-css markers not found in ${page}`);
    const out = html.replace(pattern, (_m, start, end) => `${start}\n    <style>${css}</style>\n    ${end}`);
    if (out !== html) {
        fs.writeFileSync(htmlPath, out);
        console.log(`Inlined ${css.length.toLocaleString()} bytes of CSS into ${page}`);
    } else {
        console.log(`CSS in ${page} is already up to date`);
    }
}
