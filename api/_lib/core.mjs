// Shared server code for the /api functions: database client, HTTP helpers, tokens, rate limits.
// Files under api/_lib are not deployed as their own endpoints (Vercel skips paths starting with "_").
import { createClient } from '@supabase/supabase-js';
import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

export const SUPABASE_URL = process.env.SUPABASE_URL || 'https://wlbmtcrgftermdtwnbgb.supabase.co';
export const BUCKET = 'case-files';
export const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'nicksprocessservices@outlook.com,devteam@partnershipwithmedia-dev.com')
    .split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
export const IS_PROD = process.env.VERCEL_ENV === 'production';

let client = null;
// Service-role client: bypasses row-level security, so it must only ever run on the server.
export function db() {
    if (!client) {
        const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
        if (!key) {
            console.error('SUPABASE_SERVICE_ROLE_KEY is not set (Vercel env vars, or .env.local when testing locally).');
            throw new HttpError(503, 'Online requests are temporarily unavailable. Please call or text Nick at (209) 922-6817.');
        }
        client = createClient(SUPABASE_URL, key, { auth: { persistSession: false, autoRefreshToken: false } });
    }
    return client;
}

export class HttpError extends Error {
    constructor(status, message) { super(message); this.status = status; }
}

export function json(data, status = 200, headers = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
    });
}

// Wraps a handler so thrown HttpErrors become clean JSON and anything else is logged and hidden.
export function handle(fn) {
    return async (request) => {
        try {
            return await fn(request);
        } catch (err) {
            if (err instanceof HttpError) return json({ error: err.message }, err.status);
            console.error(err);
            return json({ error: 'Something went wrong on our end. Please try again or call (209) 922-6817.' }, 500);
        }
    };
}

// Every API call from the site is a same-site JSON POST. Refusing anything else stops other websites from sending
// requests through a visitor's browser (a second lock next to the login cookie's SameSite=Strict).
export async function readJson(request, maxBytes = 64 * 1024) {
    if (!(request.headers.get('content-type') || '').toLowerCase().startsWith('application/json')) throw new HttpError(415, 'Invalid request.');
    const origin = request.headers.get('origin');
    if (origin && origin !== new URL(request.url).origin) throw new HttpError(403, 'Invalid request.');
    const text = await request.text();
    if (text.length > maxBytes) throw new HttpError(413, 'Request is too large.');
    let parsed;
    try {
        parsed = text ? JSON.parse(text, (k, v) => (k === '__proto__' || k === 'constructor' || k === 'prototype') ? undefined : v) : {};
    } catch {
        throw new HttpError(400, 'Invalid request.');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new HttpError(400, 'Invalid request.');
    return parsed;
}

// Vercel sets x-real-ip itself; the first x-forwarded-for entry is only a fallback for local testing.
export function clientIp(request) {
    return request.headers.get('x-real-ip') || (request.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'local';
}

// Links in emails always point at the real domain in production, whatever address the request came in on.
export function siteOrigin(request) {
    return process.env.SITE_URL || (IS_PROD ? 'https://nicksprocessservices.dev' : new URL(request.url).origin);
}

export function getCookie(request, name) {
    const raw = request.headers.get('cookie') || '';
    if (raw.length > 8192) return null;
    for (const part of raw.split(';')) {
        const [k, ...v] = part.trim().split('=');
        if (k === name) {
            try {
                const decoded = decodeURIComponent(v.join('='));
                if (/[\u0000-\u001F\u007F]/.test(decoded)) return null;
                return decoded;
            } catch { return null; }   // malformed cookie: treat as logged out
        }
    }
    return null;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Ids from the browser must look like ours before they reach a database query.
export function uuid(value, label = 'Item') {
    if (typeof value !== 'string' || !UUID_RE.test(value)) throw new HttpError(404, `${label} not found.`);
    return value;
}
export const uuidList = (list) => (Array.isArray(list) ? list : []).filter(v => typeof v === 'string' && UUID_RE.test(v));

export const sha256 = (s) => createHash('sha256').update(s).digest('hex');
export function timingSafeMatch(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || !a || !b) return false;
    const ha = createHash('sha256').update(a).digest();
    const hb = createHash('sha256').update(b).digest();
    return timingSafeEqual(ha, hb);
}
export const randomToken = (bytes = 24) => randomBytes(bytes).toString('base64url');   // 24 bytes = 192 bits
export const orderCode = () => 'NP-' + String(randomInt(100000, 1000000));

// Throws 429 once a bucket passes `max` hits in its window (counted atomically in the database).
export async function rateLimit(bucket, max, windowSeconds) {
    const { data, error } = await db().rpc('hit_rate_limit', { p_bucket: bucket, p_window_seconds: windowSeconds });
    if (error) throw error;
    if (data > max) throw new HttpError(429, 'Too many attempts. Please wait a few minutes and try again.');
}

// --- Input cleaning ---
// Strip NUL bytes, ASCII control chars, and Unicode bidirectional override chars (which could crash Postgres UTF-8 or spoof extensions).
const CTRL_INLINE_RE = /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g;
const CTRL_MULTILINE_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g;

export function text(value, { max = 200, required = false, label = 'This field' } = {}) {
    const s = typeof value === 'string' ? value.replace(/[\r\n\t]+/g, ' ').replace(CTRL_INLINE_RE, '').trim().replace(/\s+/g, ' ') : '';
    if (required && !s) throw new HttpError(400, `${label} is required.`);
    if (s.length > max) throw new HttpError(400, `${label} is too long.`);
    return s || null;
}
export function longText(value, { max = 2000, label = 'This field' } = {}) {
    const s = typeof value === 'string' ? value.replace(/\r\n?/g, '\n').replace(CTRL_MULTILINE_RE, '').trim() : '';
    if (s.length > max) throw new HttpError(400, `${label} is too long.`);
    return s || null;
}
// Strict RFC-safe email validator: forbids quotes, parens, commas, semicolons, backslashes, and SQL/PostgREST operators.
const EMAIL_RE = /^[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
export function email(value) {
    const s = text(value, { max: 200, required: true, label: 'Email' }).toLowerCase();
    const local = s.split('@')[0] || '';
    if (!EMAIL_RE.test(s) || /^\.|\.$|\.\./.test(local)) throw new HttpError(400, 'Please enter a valid email address.');
    return s;
}
const PHONE_RE = /^[0-9+().\-\s]{10,28}(?:\s*(?:ext\.?|x)\s*\d{1,6})?$/i;
export function phone(value, { label = 'Phone number' } = {}) {
    const s = text(value, { max: 40, required: true, label });
    const digits = s.replace(/\D/g, '');
    if (!PHONE_RE.test(s) || digits.length < 10 || digits.length > 15) {
        throw new HttpError(400, 'Please enter a valid phone number with area code.');
    }
    return s;
}
export function cleanOrderCode(value) {
    const raw = (text(value, { max: 20, required: true, label: 'Reference number' }) || '').toUpperCase().replace(/^(NP)?-?/, 'NP-');
    if (!/^NP-\d{6}$/.test(raw)) throw new HttpError(400, 'Please enter a valid 6-digit reference number (e.g. NP-482913).');
    return raw;
}
export function cleanDate(value, { label = 'Deadline' } = {}) {
    if (value === null || value === undefined || value === '') return null;
    const s = typeof value === 'string' ? value.trim() : '';
    if (!s) return null;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) throw new HttpError(400, `Please enter a valid ${label.toLowerCase()} date.`);
    const d = new Date(s + 'T00:00:00Z');
    if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== s || d.getUTCFullYear() < 2020 || d.getUTCFullYear() > 2100) {
        throw new HttpError(400, `Please enter a valid ${label.toLowerCase()} date.`);
    }
    return s;
}

// --- Files ---
export const MAX_FILE_BYTES = 25 * 1024 * 1024;
export const MAX_FILES = 10;
export const MAX_ORDER_FILES = 25;
const ALLOWED_TYPES = new Set([
    // No old-style .doc: it can carry macro viruses. .docx can't.
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'image/jpeg', 'image/png', 'image/heic', 'image/heif', 'image/webp',
]);
const TYPE_BY_EXT = { pdf: 'application/pdf', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', heic: 'image/heic', heif: 'image/heif', webp: 'image/webp' };
const DANGEROUS_EXT_RE = /\.(?:php\d?|phtml|phar|exe|dll|bat|cmd|sh|bash|zsh|ps1|vbs|scr|msi|com|jar|py|pl|rb|cgi|asp|aspx|jsp|jspx|html?|xhtml|shtml|svg|xml|js|mjs|cjs|wasm|hta)\./i;

export function cleanFileList(files) {
    if (!Array.isArray(files)) return [];
    if (files.length > MAX_FILES) throw new HttpError(400, `Please attach at most ${MAX_FILES} files.`);
    return files.map(f => {
        const name = text(f?.name, { max: 180, required: true, label: 'File name' });
        if (/[/\\<>:"'|?*;`$]|\.\./.test(name) || DANGEROUS_EXT_RE.test(name)) {
            throw new HttpError(400, `${name}: only PDF, Word (.docx), JPG, PNG or HEIC files can be uploaded.`);
        }
        // The type comes from the extension, never from what the browser claims, so "notes.html" labeled as a PDF is refused.
        const ext = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
        const type = TYPE_BY_EXT[ext];
        if (!type || !ALLOWED_TYPES.has(type)) throw new HttpError(400, `${name}: only PDF, Word (.docx), JPG, PNG or HEIC files can be uploaded.`);
        const size = Number(f?.size);
        if (!Number.isSafeInteger(size) || size <= 0 || size > MAX_FILE_BYTES) throw new HttpError(400, `${name} is larger than 25 MB.`);
        return { name, type, size };
    });
}

// Creates file rows plus one-time upload links; the browser then uploads straight to private storage.
export async function prepareUploads(orderId, kind, files) {
    if (!files.length) return [];
    const { count, error: cErr } = await db().from('order_files').select('id', { count: 'exact', head: true }).eq('order_id', orderId);
    if (cErr) throw cErr;
    if ((count || 0) + files.length > MAX_ORDER_FILES) {
        throw new HttpError(400, `Each request can have at most ${MAX_ORDER_FILES} files total.`);
    }
    const folder = { client_document: 'client', proof: 'proof', action_upload: 'action' }[kind];
    const out = [];
    for (const f of files) {
        const safe = f.name.replace(/[^\w.\-]+/g, '_').slice(-120);
        const path = `orders/${orderId}/${folder}/${randomToken(8)}-${safe}`;
        const { data: row, error } = await db().from('order_files').insert({
            order_id: orderId, kind, storage_path: path, filename: f.name, size_bytes: f.size, content_type: f.type,
        }).select('id').single();
        if (error) throw error;
        const { data: signed, error: sErr } = await db().storage.from(BUCKET).createSignedUploadUrl(path);
        if (sErr) throw sErr;
        out.push({ fileId: row.id, name: f.name, uploadUrl: signed.signedUrl });
    }
    return out;
}

// Verifies that actual uploaded file bytes match the expected binary signature (magic bytes) of the file extension
// and rejects polyglot files that embed HTML/script tags, executable PDF actions, or macro-enabled/disguised ZIPs.
const POLYGLOT_SCRIPT_RE = /<\s*(?:script|!doctype\s+html|html|iframe|svg|object|embed)\b|(?:javascript|vbscript)\s*:|\bon(?:load|error)\s*=/i;
const PDF_DANGEROUS_ACTION_RE = /\/(?:JavaScript|JS|Launch)\b/;
const DOCX_MACRO_OR_EXEC_RE = /(?:vbaProject\.bin|vbaData\.xml|activeX\/activeX|\.(?:exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|scr|msi|com|hta|jar|sh)(?:[\x00-\x20"'<>\/\\]|$))/i;

export function verifyFileMagic(bytes, filename) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4 || bytes.length > MAX_FILE_BYTES) return false;
    const ext = typeof filename === 'string' && filename.includes('.') ? filename.split('.').pop().toLowerCase() : '';
    const headLen = Math.min(bytes.length, 4096);
    let head = '';
    for (let i = 0; i < headLen; i++) head += String.fromCharCode(bytes[i]);
    if (POLYGLOT_SCRIPT_RE.test(head)) return false;

    if (ext === 'pdf') {
        // %PDF- and no embedded Acrobat JavaScript / Launch actions
        if (PDF_DANGEROUS_ACTION_RE.test(head)) return false;
        return bytes.length >= 5 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46 && bytes[4] === 0x2D;
    }
    if (ext === 'docx') {
        // PK\x03\x04 (ZIP container used by OpenXML .docx) + OpenXML structure + no VBA macros or executables
        if (bytes[0] !== 0x50 || bytes[1] !== 0x4B || bytes[2] !== 0x03 || bytes[3] !== 0x04) return false;
        const scanLen = Math.min(bytes.length, 65536);
        let zipScan = head;
        for (let i = headLen; i < scanLen; i++) zipScan += String.fromCharCode(bytes[i]);
        if (bytes.length > scanLen) {
            const tailStart = Math.max(scanLen, bytes.length - 65536);
            for (let i = tailStart; i < bytes.length; i++) zipScan += String.fromCharCode(bytes[i]);
        }
        if (!zipScan.includes('[Content_Types].xml') && !zipScan.includes('word/')) return false;
        if (DOCX_MACRO_OR_EXEC_RE.test(zipScan)) return false;
        return true;
    }
    if (ext === 'jpg' || ext === 'jpeg') {
        // JPEG SOI + marker: FF D8 FF
        return bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF;
    }
    if (ext === 'png') {
        // 89 50 4E 47 0D 0A 1A 0A
        return bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47 &&
            bytes[4] === 0x0D && bytes[5] === 0x0A && bytes[6] === 0x1A && bytes[7] === 0x0A;
    }
    if (ext === 'webp') {
        // RIFF....WEBP
        return bytes.length >= 12 && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
            bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50;
    }
    if (ext === 'heic' || ext === 'heif') {
        // ISO Base Media File Format: ....ftyp<brand>
        if (bytes.length < 12 || bytes[4] !== 0x66 || bytes[5] !== 0x74 || bytes[6] !== 0x79 || bytes[7] !== 0x70) return false;
        const brand = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]);
        return /^(?:heic|heix|hevc|hevx|heim|heis|hevm|hevs|mif1|msf1)$/.test(brand);
    }
    return false;
}

// Marks files uploaded only if the object really exists in storage, passes magic-byte inspection, and records a SHA-256 fingerprint.
export async function confirmUploads(orderId, fileIds) {
    const ids = uuidList(fileIds).slice(0, MAX_FILES);
    if (!ids.length) return [];
    const { data: rows, error } = await db().from('order_files').select('id, storage_path, filename, kind')
        .eq('order_id', orderId).in('id', ids);
    if (error) throw error;
    const done = [];
    for (const r of rows) {
        const { data: exists } = await db().storage.from(BUCKET).exists(r.storage_path);
        if (exists) {
            let fileHash = null;
            let validMagic = true;
            try {
                const { data: blob } = await db().storage.from(BUCKET).download(r.storage_path);
                if (blob) {
                    const buf = Buffer.from(await blob.arrayBuffer());
                    if (!verifyFileMagic(buf, r.filename)) validMagic = false;
                    else fileHash = sha256(buf);
                }
            } catch { /* non-fatal if storage download cannot compute hash */ }
            if (!validMagic) {
                await db().storage.from(BUCKET).remove([r.storage_path]).catch(() => {});
                await db().from('order_files').delete().eq('id', r.id);
                continue;
            }
            const patch = fileHash ? { uploaded: true, sha256: fileHash } : { uploaded: true };
            const { error: uErr } = await db().from('order_files').update(patch).eq('id', r.id);
            if (uErr && fileHash) await db().from('order_files').update({ uploaded: true }).eq('id', r.id);
            done.push({ ...r, sha256: fileHash });
        }
    }
    return done;
}

export async function signedDownload(path, filename) {
    const { data, error } = await db().storage.from(BUCKET).createSignedUrl(path, 300, { download: filename });
    if (error) throw error;
    return data.signedUrl;
}

export async function addEvent(orderId, kind, title, detail = null, clientVisible = true) {
    const { error } = await db().from('order_events').insert({ order_id: orderId, kind, title, detail, client_visible: clientVisible });
    if (error) throw error;
}
