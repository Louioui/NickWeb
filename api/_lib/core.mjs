// Shared server code for the /api functions: database client, HTTP helpers, tokens, rate limits.
// Files under api/_lib are not deployed as their own endpoints (Vercel skips paths starting with "_").
import { createClient } from '@supabase/supabase-js';
import { stripPhotoBytes, photoType } from './photos.mjs';
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, randomInt, scryptSync, timingSafeEqual } from 'node:crypto';

export const SUPABASE_URL = process.env.SUPABASE_URL || 'https://wlbmtcrgftermdtwnbgb.supabase.co';
export const BUCKET = 'case-files';
// Who can sign into the dashboard and gets new-request emails. Without the env var it is Nick alone; anyone else
// (such as the developers) must be listed in ADMIN_EMAILS on purpose, per environment.
export const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'nicksprocessservices@outlook.com')
    .split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
export const IS_PROD = process.env.VERCEL_ENV === 'production';
if (IS_PROD && !process.env.ADMIN_EMAILS) console.warn('ADMIN_EMAILS is not set in production; only the built-in owner address can sign in.');

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

// --- Server-side secrets ---
// One server-only root secret, APP_SECRET, is stretched into separate keys per purpose with HKDF, so a key for one job
// can never be replayed for another. None of these keys is ever stored in the database, so a copy of the database alone
// cannot decrypt authenticator secrets, crack recovery codes or forge unlock tokens.
// APP_SECRET must be its own value (never the Supabase key: rotating that after a breach would make Nick's authenticator
// secret undecryptable and lock him out), and the same in Preview and Production, which share one database.
// Only the local mock (no database key at all) may use a built-in development value.
const appKeys = new Map();
export function appKey(purpose) {
    if (!appKeys.has(purpose)) {
        const root = process.env.APP_SECRET || (process.env.SUPABASE_SERVICE_ROLE_KEY ? '' : 'local-dev-only-secret');
        if (!root) {
            console.error('APP_SECRET is not set. Add a long random value in Vercel (Preview and Production) and in .env.local.');
            throw new HttpError(503, 'Online requests are temporarily unavailable. Please call or text Nick at (209) 922-6817.');
        }
        appKeys.set(purpose, Buffer.from(hkdfSync('sha256', root, 'nps-app-keys-v1', purpose, 32)));
    }
    return appKeys.get(purpose);
}

// AES-256-GCM, stored as "v1.<iv>.<tag>.<ciphertext>" (base64url). Tampered ciphertext fails to decrypt.
export function encryptSecret(plain, purpose = 'totp-secret-v1') {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', appKey(purpose), iv);
    const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
    return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), ct.toString('base64url')].join('.');
}
export function decryptSecret(stored, purpose = 'totp-secret-v1') {
    const [v, iv, tag, ct] = String(stored || '').split('.');
    if (v !== 'v1' || !iv || !tag || !ct) throw new HttpError(500, 'Stored secret is unreadable.');
    const decipher = createDecipheriv('aes-256-gcm', appKey(purpose), Buffer.from(iv, 'base64url'));
    decipher.setAuthTag(Buffer.from(tag, 'base64url'));
    return Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]).toString('utf8');
}

// Keyed hash for short codes (recovery codes). Unlike a plain SHA-256, it can't be brute-forced from a database copy.
export const keyedHash = (purpose, value) => createHmac('sha256', appKey(purpose)).update(String(value)).digest('hex');

// Short numeric PINs need a deliberately slow hash with a per-record salt: a million possibilities is nothing for SHA-256.
const SCRYPT_N = 16384;
export function hashPin(pin) {
    const salt = randomBytes(16);
    const hash = scryptSync(String(pin), salt, 32, { N: SCRYPT_N, r: 8, p: 1 });
    return `scrypt$${SCRYPT_N}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}
export function verifyPin(pin, stored) {
    const [scheme, n, salt, hash] = String(stored || '').split('$');
    if (scheme !== 'scrypt' || !salt || !hash || !/^\d{6}$/.test(String(pin || ''))) return false;
    const expected = Buffer.from(hash, 'base64url');
    const actual = scryptSync(String(pin), Buffer.from(salt, 'base64url'), expected.length, { N: Number(n), r: 8, p: 1 });
    return expected.length === actual.length && timingSafeEqual(expected, actual);
}

// Expiring signed token: "<expiry seconds>.<HMAC>" over a purpose and a subject. Nothing to store, nothing to look up.
export function signToken(purpose, subject, ttlSeconds) {
    const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
    return `${exp}.${createHmac('sha256', appKey(purpose)).update(`${subject}|${exp}`).digest('base64url')}`;
}
export function checkToken(purpose, subject, token) {
    const m = /^(\d{10})\.([A-Za-z0-9_-]{43})$/.exec(String(token || ''));
    if (!m || Number(m[1]) < Date.now() / 1000) return false;
    const expected = createHmac('sha256', appKey(purpose)).update(`${subject}|${m[1]}`).digest('base64url');
    return timingSafeMatch(expected, m[2]);
}

// --- RFC 6238 TOTP (Authenticator App 2-Step Verification) ---
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function generateTotpSecret(bytes = 20) {
    const buf = randomBytes(bytes);
    let bits = 0, val = 0, out = '';
    for (const byte of buf) {
        val = (val << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            out += BASE32_ALPHABET[(val >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) out += BASE32_ALPHABET[(val << (5 - bits)) & 31];
    return out;
}
function decodeBase32(secret) {
    const clean = String(secret || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
    let bits = 0, val = 0;
    const out = [];
    for (let i = 0; i < clean.length; i++) {
        const idx = BASE32_ALPHABET.indexOf(clean[i]);
        if (idx < 0) continue;
        val = (val << 5) | idx;
        bits += 5;
        if (bits >= 8) {
            out.push((val >>> (bits - 8)) & 0xFF);
            bits -= 8;
        }
    }
    return Buffer.from(out);
}
export function totpCode(secret, timeMs = Date.now(), stepOffset = 0) {
    const key = decodeBase32(secret);
    if (!key.length) return '';
    const counter = Math.floor(timeMs / 30000) + stepOffset;
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(counter));
    const hmac = createHmac('sha1', key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code = ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    return String(code % 1000000).padStart(6, '0');
}
// Returns the matched 30-second step (so the caller can mark it used, which blocks replay), or 0 for no match.
// Accepts one step either side of now to allow for a phone clock that is slightly off.
export function verifyTotp(secret, inputCode, timeMs = Date.now()) {
    const clean = String(inputCode || '').replace(/\s+/g, '');
    if (!/^\d{6}$/.test(clean) || !secret) return 0;
    let matched = 0;
    for (const offset of [-1, 0, 1]) {
        if (timingSafeMatch(totpCode(secret, timeMs, offset), clean)) matched = Math.floor(timeMs / 30000) + offset;
    }
    return matched;
}

// Counts one hit in a bucket's fixed window (atomically in the database) and returns the window's total.
export async function hitRateLimit(bucket, windowSeconds) {
    const { data, error } = await db().rpc('hit_rate_limit', { p_bucket: bucket, p_window_seconds: windowSeconds });
    if (error) throw error;
    return data;
}

// Throws 429 once a bucket passes `max` hits in its window.
export async function rateLimit(bucket, max, windowSeconds) {
    if (await hitRateLimit(bucket, windowSeconds) > max) throw new HttpError(429, 'Too many attempts. Please wait a few minutes and try again.');
}

// Reads a bucket's hits in the current window without adding one (same window start as hit_rate_limit in SQL).
// ">= start" rather than "= start", so the match never depends on how the timestamp is formatted.
export async function peekRateLimit(bucket, windowSeconds) {
    const windowStart = new Date(Math.floor(Date.now() / 1000 / windowSeconds) * windowSeconds * 1000).toISOString();
    const { data, error } = await db().from('rate_limits').select('hits').eq('bucket', bucket).gte('window_start', windowStart);
    if (error) throw error;
    return (data || []).reduce((n, r) => n + (r.hits || 0), 0);
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
// PDF actions that run code, open programs, carry hidden files or send data out. Ordinary links, page actions and
// forms are allowed. XFA forms are not refused: some official court forms use them.
const PDF_DANGEROUS_ACTION_RE = /\/(?:JavaScript|JS|Launch|EmbeddedFiles?|RichMedia|SubmitForm|ImportData|GoToE)\b/;
// PDF names may hide letters as #xx (e.g. /J#61vaScript is /JavaScript), so they are decoded before matching.
const decodePdfNames = (s) => s.replace(/\/[^\s\/<>\[\]()%{}]*#[0-9A-Fa-f]{2}[^\s\/<>\[\]()%{}]*/g,
    (name) => name.replace(/#([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))));
const DOCX_MACRO_OR_EXEC_RE = /(?:vbaProject\.bin|vbaData\.xml|activeX\/activeX|\.(?:exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|scr|msi|com|hta|jar|sh)(?:[\x00-\x20"'<>\/\\]|$))/i;

export function verifyFileMagic(bytes, filename) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4 || bytes.length > MAX_FILE_BYTES) return false;
    const ext = typeof filename === 'string' && filename.includes('.') ? filename.split('.').pop().toLowerCase() : '';
    const headLen = Math.min(bytes.length, 4096);
    let head = '';
    for (let i = 0; i < headLen; i++) head += String.fromCharCode(bytes[i]);
    // Hidden HTML or script can sit anywhere in a file (start, middle or appended at the end), so the whole file is checked.
    const whole = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('latin1');
    if (POLYGLOT_SCRIPT_RE.test(whole)) return false;

    if (ext === 'pdf') {
        // %PDF- and no Acrobat JavaScript / Launch actions anywhere in the file (not just its first 4 KB). Actions hidden
        // inside compressed object streams can't be seen this way; this is a filter, not a full PDF parser.
        if (PDF_DANGEROUS_ACTION_RE.test(whole) || PDF_DANGEROUS_ACTION_RE.test(decodePdfNames(whole))) return false;
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
        // 89 50 4E 47 0D 0A 1A 0A (and IHDR chunk header at bytes 12..15 when >= 16 bytes)
        if (bytes.length < 8 || bytes[0] !== 0x89 || bytes[1] !== 0x50 || bytes[2] !== 0x4E || bytes[3] !== 0x47 ||
            bytes[4] !== 0x0D || bytes[5] !== 0x0A || bytes[6] !== 0x1A || bytes[7] !== 0x0A) return false;
        if (bytes.length >= 16 && (bytes[12] !== 0x49 || bytes[13] !== 0x48 || bytes[14] !== 0x44 || bytes[15] !== 0x52)) return false;
        return true;
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

// True only when storage positively says the object isn't there. A bad key, a missing bucket or anything unclear is not
// "missing" (exists() can't tell these apart: its HEAD request has no error body and it reports every 400/404 as absent).
function isMissingObject(err) {
    const code = String(err?.code ?? '');
    const message = String(err?.message ?? '');
    if (/bucket/i.test(`${code} ${message}`)) return false;
    return String(err?.statusCode ?? '') === '404' || /^(NoSuchKey|not_found)$/i.test(code) || /object not found/i.test(message);
}

// Reads a stored upload and checks it. Returns { state: 'ok', sha256 }, 'bad' (the bytes are not what the name claims),
// 'missing' (storage confirms it never arrived), or 'unknown' (anything else: retried later, never deleted). Like the rest
// of supabase-js, these calls report failures as { error } instead of throwing, so each one is checked.
// Page count of a PDF, for the printing fee. Counts page objects, and also reads the page tree's /Count (which stays
// visible when pages sit in compressed object streams). Returns null when neither can be found.
export function countPdfPages(bytes) {
    const s = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('latin1');
    const objects = (s.match(/\/Type\s*\/Page(?![s\w])/g) || []).length;
    let tree = 0;
    for (const m of s.matchAll(/<<(?:(?!<<|>>)[\s\S]){0,400}?\/Type\s*\/Pages\b(?:(?!<<|>>)[\s\S]){0,400}?>>/g)) {
        const c = /\/Count\s+(\d{1,6})/.exec(m[0]);
        if (c) tree = Math.max(tree, Number(c[1]));
    }
    const pages = Math.max(objects, tree);
    return pages > 0 && pages <= 100000 ? pages : null;
}

export async function inspectStoredFile(path, filename) {
    try {
        const { data: info, error: iErr } = await db().storage.from(BUCKET).info(path);
        if (iErr) return { state: isMissingObject(iErr) ? 'missing' : 'unknown' };
        if (!info) return { state: 'unknown' };
        const { data: blob, error: dErr } = await db().storage.from(BUCKET).download(path);
        if (dErr || !blob) return { state: 'unknown' };
        let buf = Buffer.from(await blob.arrayBuffer());
        if (!verifyFileMagic(buf, filename)) return { state: 'bad' };
        // Photos are cleaned again here (location and other hidden metadata), in case they were uploaded without the
        // site's page. A changed file is stored back first; if that fails, the file waits for the next check.
        const type = photoType(filename);
        const clean = type ? stripPhotoBytes(new Uint8Array(buf), type) : null;
        if (clean && !Buffer.from(clean).equals(buf)) {
            const { error: wErr } = await db().storage.from(BUCKET).update(path, Buffer.from(clean), { contentType: type, upsert: true });
            if (wErr) return { state: 'unknown' };
            buf = Buffer.from(clean);
            if (!verifyFileMagic(buf, filename)) return { state: 'bad' };
        }
        const pages = /\.pdf$/i.test(String(filename)) ? countPdfPages(buf) : null;
        return { state: 'ok', sha256: sha256(buf), pages };
    } catch {
        return { state: 'unknown' };
    }
}

// Marks files uploaded only if the object really exists in storage, passes magic-byte inspection, and records a SHA-256
// fingerprint. A disguised file is deleted; one that couldn't be read stays unconfirmed for the daily job to retry.
// Returns { files: the confirmed files, stillChecking: how many couldn't be read yet (retried later), missing: how many
// never reached storage, rejected: how many failed the file check and were deleted }, so callers can say what happened.
export async function confirmUploads(orderId, fileIds) {
    const ids = uuidList(fileIds).slice(0, MAX_FILES);
    if (!ids.length) return { files: [], stillChecking: 0, missing: 0, rejected: 0 };
    const { data: rows, error } = await db().from('order_files').select('id, storage_path, filename, kind')
        .eq('order_id', orderId).in('id', ids);
    if (error) throw error;
    const done = [];
    let stillChecking = 0;
    let missing = 0;
    let rejected = 0;
    for (const r of rows) {
        const check = await inspectStoredFile(r.storage_path, r.filename);
        if (check.state === 'bad') {
            await db().storage.from(BUCKET).remove([r.storage_path]).catch(() => {});
            await db().from('order_files').delete().eq('id', r.id);
            rejected++;
            continue;
        }
        if (check.state === 'missing') { missing++; continue; }
        if (check.state !== 'ok') { stillChecking++; continue; }
        let { error: uErr } = await db().from('order_files').update({ uploaded: true, sha256: check.sha256, page_count: check.pages ?? null }).eq('id', r.id);
        // Before the page_count column exists (migration not applied yet), confirm the file without it.
        if (uErr && /page_count/.test(uErr.message || '')) ({ error: uErr } = await db().from('order_files').update({ uploaded: true, sha256: check.sha256 }).eq('id', r.id));
        if (uErr) throw uErr;
        done.push({ ...r, sha256: check.sha256, page_count: check.pages ?? null });
    }
    return { files: done, stillChecking, missing, rejected };
}

export async function signedDownload(path, filename) {
    // 60-second ephemeral download token so leaked signed URLs expire almost immediately.
    const { data, error } = await db().storage.from(BUCKET).createSignedUrl(path, 60, { download: filename });
    if (error) throw error;
    return data.signedUrl;
}

export async function addEvent(orderId, kind, title, detail = null, clientVisible = true) {
    const { error } = await db().from('order_events').insert({ order_id: orderId, kind, title, detail, client_visible: clientVisible });
    if (error) throw error;
}
