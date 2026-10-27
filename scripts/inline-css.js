#!/usr/bin/env node
// Copies the compiled stylesheet (build/site.css) into index.html, between the site-css markers.
// Inlining means the page styles correctly in every viewing mode (hosted, file://, and the app's static previews)
// and removes a render-blocking request. Fonts and the logo stay as real files under assets/.
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const htmlPath = path.join(root, 'index.html');
const cssPath = path.join(root, 'build', 'site.css');

const html = fs.readFileSync(htmlPath, 'utf8');
const css = fs.readFileSync(cssPath, 'utf8').trim();
if (css.includes('</style')) throw new Error('Compiled CSS contains "</style"; refusing to inline it.');

const pattern = /(<!-- site-css:start[^>]*-->)[\s\S]*?(<!-- site-css:end -->)/;
if (!pattern.test(html)) throw new Error('site-css markers not found in index.html');

const out = html.replace(pattern, (_m, start, end) => `${start}\n    <style>${css}</style>\n    ${end}`);
if (out !== html) {
    fs.writeFileSync(htmlPath, out);
    console.log(`Inlined ${css.length.toLocaleString()} bytes of CSS into index.html`);
} else {
    console.log(`CSS in index.html is already up to date (${css.length.toLocaleString()} bytes)`);
}
