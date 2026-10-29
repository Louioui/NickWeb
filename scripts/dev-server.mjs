// Local test server: serves the site's static files and runs /api/<name>.mjs handlers the way Vercel does
// (exported GET/POST functions that take a Request and return a Response). Reads secrets from .env.local.
// Usage: node scripts/dev-server.mjs [port]
import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const port = Number(process.argv[2]) || 8765;

const envFile = path.join(root, '.env.local');
if (existsSync(envFile)) {
    for (const line of readFileSync(envFile, 'utf8').split('\n')) {
        const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
        if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
}

const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.mjs': 'text/javascript',
    '.svg': 'image/svg+xml', '.webp': 'image/webp', '.png': 'image/png', '.jpg': 'image/jpeg', '.woff2': 'font/woff2', '.json': 'application/json' };

http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${port}`);
    try {
        if (url.pathname.startsWith('/api/')) {
            const name = url.pathname.slice(5).replace(/[^\w-]/g, '');
            const file = path.join(root, 'api', `${name}.mjs`);
            if (!name || name.startsWith('_') || !existsSync(file)) { res.writeHead(404); return res.end('Not found'); }
            const mod = await import(pathToFileURL(file).href + `?v=${(await stat(file)).mtimeMs}`);
            const fn = mod[req.method];
            if (!fn) { res.writeHead(405); return res.end('Method not allowed'); }
            const chunks = [];
            for await (const c of req) chunks.push(c);
            const request = new Request(url, { method: req.method, headers: req.headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks) });
            const response = await fn(request);
            const headers = {};
            response.headers.forEach((v, k) => { headers[k] = v; });
            res.writeHead(response.status, headers);
            return res.end(Buffer.from(await response.arrayBuffer()));
        }
        let rel = decodeURIComponent(url.pathname);
        if (rel.endsWith('/')) rel += 'index.html';
        const file = path.join(root, rel);
        if (!file.startsWith(root) || rel.includes('/.') || rel.startsWith('/node_modules') || rel.startsWith('/api')) { res.writeHead(404); return res.end(); }
        const body = await readFile(file);
        res.writeHead(200, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream' });
        res.end(body);
    } catch (err) {
        if (err.code === 'ENOENT') { res.writeHead(404); return res.end('Not found'); }
        console.error(err);
        res.writeHead(500); res.end('Server error');
    }
}).listen(port, () => console.log(`Dev server on http://localhost:${port}`));
