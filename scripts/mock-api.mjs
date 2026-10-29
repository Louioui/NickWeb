// Local-only stand-in for the real API. scripts/dev-server.mjs uses it when SUPABASE_SERVICE_ROLE_KEY is not set, so the request
// form, tracking page and dashboard can be clicked through before any keys exist. Orders live in memory and reset on restart.
// It mirrors the behavior of api/*.mjs (same request and response shapes); it is never deployed.
import { randomBytes, randomInt, randomUUID } from 'node:crypto';
import { TIERS, ADDONS, STATUSES, estimate, money, cleanTrackToken } from '../api/_lib/orders.mjs';
import { generateTotpSecret, totpCode, verifyTotp, timingSafeMatch, hashPin, verifyPin, signToken, checkToken } from '../api/_lib/core.mjs';

export const MOCK_ADMIN_CODE = '12345678';
export const MOCK_CLIENT_CODE = '123456';
export { totpCode };
const ADMIN_EMAIL = 'nicksprocessservices@outlook.com';
const DEVTEAM_EMAIL = 'devteam@partnershipwithmedia-dev.com';
const MOCK_ADMIN_EMAILS = [ADMIN_EMAIL, DEVTEAM_EMAIL];
const RECOVERY_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

const orders = new Map();      // id -> order row
const events = [];             // { order_id, created_at, kind, title, detail, client_visible }
const files = new Map();       // id -> { id, order_id, kind, filename, size_bytes, content_type, sha256, uploaded, data, created_at }
const clients = new Map();
const clientSessions = new Map();
const clientCodes = new Map();
const clientSecurity = new Map(); // email -> { pin_hash, failed_tries, locked_until }
const trackPinFails = new Map();  // order id -> { window, count } (wrong PINs on the tracking page)
const trackUnlockCodes = new Map(); // order_id -> { code, tries, expires }
const sessions = new Set();
const sessionEmails = new Map();
const adminRecoveryCodes = new Map();
const adminTotpSecrets = new Map(); // email -> { secret, enabled }
const adminBurnFails = new Map();   // email -> count
const adminCodesBurned = new Set(); // email if active code was burned
const adminAuditLogs = [];
function auditAdmin(emailAddr, action, targetCode = null, detailText = null) {
    adminAuditLogs.unshift({ email: emailAddr, action, target_code: targetCode, detail: detailText, created_at: now() });
}

const SHA256_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];
function sha256Hex(input) {
    const bytes = typeof input === 'string' ? Uint8Array.from(input, c => c.charCodeAt(0) & 255) : new Uint8Array(input);
    const bitLen = bytes.length * 8;
    const padLen = ((bytes.length + 9 + 63) & ~63);
    const buf = new Uint8Array(padLen);
    buf.set(bytes);
    buf[bytes.length] = 0x80;
    const view = new DataView(buf.buffer);
    view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(padLen - 4, bitLen >>> 0, false);
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let i = 0; i < padLen; i += 64) {
        for (let t = 0; t < 16; t++) w[t] = view.getUint32(i + t * 4, false);
        for (let t = 16; t < 64; t++) {
            const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
            const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
            w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
        }
        let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (let t = 0; t < 64; t++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + SHA256_K[t] + w[t]) >>> 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;
            h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
        }
        h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }
    return [h0, h1, h2, h3, h4, h5, h6, h7].map(v => v.toString(16).padStart(8, '0')).join('');
}

const now = () => new Date().toISOString();
const token = () => randomBytes(24).toString('base64url');
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', ...headers } });
class MockError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const fail = (status, msg) => { throw new MockError(status, msg); };
const email = (to, subject, link) => console.log(`[mock email] To: ${to} | ${subject}${link ? ` | ${link}` : ''}`);

const UNSAFE_CHARS_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/g;
const EMAIL_RE = /^[a-z0-9._%+-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const PHONE_RE = /^[0-9+().\-\s]{10,28}(?:\s*(?:ext\.?|x)\s*\d{1,6})?$/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DANGEROUS_EXT_RE = /\.(?:exe|scr|bat|cmd|com|msi|ps1|vbs|js|mjs|cjs|html|htm|xhtml|svg|xml|php|phtml|sh|bash|zsh|py|rb|pl|jar|apk|dmg|iso|dll|so|dylib|lnk|htaccess|sql)(?:\.|$)/i;
const MOCK_FILE_TYPES = { pdf: 'application/pdf', jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', heic: 'image/heic', heif: 'image/heif', tif: 'image/tiff', tiff: 'image/tiff', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' };

function cleanText(v, max = 200, required = false, label = 'Field') {
    const s = typeof v === 'string' ? v.replace(UNSAFE_CHARS_RE, '').replace(/[\r\n\t]+/g, ' ').trim() : '';
    if (!s) { if (required) fail(400, `${label} is required.`); return null; }
    if (s.length > max) fail(400, `${label} is too long (max ${max} characters).`);
    return s;
}
function cleanLongText(v, max = 2000, label = 'Field') {
    const s = typeof v === 'string' ? v.replace(/\r\n/g, '\n').replace(UNSAFE_CHARS_RE, '').trim() : '';
    if (!s) return null;
    if (s.length > max) fail(400, `${label} is too long (max ${max} characters).`);
    return s;
}
function cleanEmail(v) {
    const s = cleanText(v, 160, true, 'Email').toLowerCase();
    const [local] = s.split('@');
    if (!EMAIL_RE.test(s) || !local || local.length > 64 || /^\.|\.$|\.\./.test(local)) fail(400, 'Please enter a valid email.');
    return s;
}
function cleanPhone(v) {
    const s = cleanText(v, 40, true, 'Phone number');
    const digits = s.replace(/\D/g, '');
    if (!PHONE_RE.test(s) || digits.length < 10 || digits.length > 15) fail(400, 'Please enter a phone number with area code.');
    return s;
}
function cleanDate(v) {
    if (v === null || v === undefined || v === '') return null;
    const s = typeof v === 'string' ? v.trim() : '';
    if (!s) return null;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) fail(400, 'Please enter a valid deadline date.');
    const d = new Date(s + 'T00:00:00Z');
    if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== s || d.getUTCFullYear() < 2020 || d.getUTCFullYear() > 2100) {
        fail(400, 'Please enter a valid deadline date.');
    }
    return s;
}
function cleanUuid(v, label = 'Record') {
    if (typeof v !== 'string' || !UUID_RE.test(v)) fail(404, `${label} not found.`);
    return v.toLowerCase();
}

// Mirrors the database trigger (seal_order_event): each entry is chained to the previous one with SHA-256 when written.
const chainPayload = (e) => JSON.stringify(['NPS-CHAIN-V1', e.order_id, e.seq, e.prev_hash || 'GENESIS', e.kind, e.title, e.detail || '', e.client_visible, e.created_at]);
function addEvent(orderId, kind, title, detail = null, clientVisible = true, at = now()) {
    const prior = events.filter(e => e.order_id === orderId).sort((a, b) => a.seq - b.seq).at(-1);
    const e = { id: randomUUID(), order_id: orderId, created_at: at, kind, title, detail, client_visible: clientVisible,
        seq: (prior?.seq || 0) + 1, prev_hash: prior?.chain_hash || null };
    e.chain_hash = sha256Hex(chainPayload(e));
    events.push(e);
}
// Mirrors verify_order_chain: recomputes the chain from the stored entries.
function orderSeal(orderId) {
    const list = events.filter(e => e.order_id === orderId).sort((a, b) => a.seq - b.seq);
    let prev = null, ok = true;
    list.forEach((e, i) => {
        if (e.seq !== i + 1 || (e.prev_hash || null) !== prev || e.chain_hash !== sha256Hex(chainPayload(e))) ok = false;
        prev = e.chain_hash;
    });
    return { verified: ok, head: prev, entries: list.length };
}

function orderByToken(t) {
    const safe = cleanTrackToken(t);
    const o = [...orders.values()].find(o => o.track_token === safe);
    if (!o) fail(404, 'This tracking link is not valid.');
    return o;
}

function maskMockAddress(o) {
    const street = String(o.address || '').replace(/^\s*\d+[A-Za-z0-9\-/]*/, '••••');
    return street + (o.city ? `, ${o.city}` : '') + (o.zip ? ` ${o.zip}` : '');
}

function clientView(o, { unlocked = false } = {}) {
    const visibleEvents = events.filter(e => e.order_id === o.id && e.client_visible).sort((a, b) => a.created_at.localeCompare(b.created_at))
        .map(({ created_at, kind, title, detail }) => ({ created_at, kind, title, detail }));
    const uploadedFiles = [...files.values()].filter(f => f.order_id === o.id && f.uploaded);
    const isLocked = !!o.doc_lock && !unlocked;
    const fullAddr = [o.address, o.unit].filter(Boolean).join(', ') + `, ${o.city} ${o.zip}`;
    const seal = orderSeal(o.id);
    return {
        code: o.code, status: o.status, statusLabel: STATUSES[o.status]?.label, statusText: STATUSES[o.status]?.client,
        createdAt: o.created_at,
        recipient: isLocked ? String(o.recipient_name || '').replace(/^(\S+)\s+.*$/, '$1 ••••') : o.recipient_name,
        docType: o.doc_type,
        address: isLocked ? maskMockAddress(o) : fullAddr,
        tier: TIERS[o.tier]?.name, addons: o.addons.map(k => ADDONS[k]?.name).filter(Boolean),
        estimate: money(o.estimated_total_cents),
        amountDue: o.amount_due_cents != null ? money(o.amount_due_cents) : null,
        payUrl: (o.status === 'awaiting_payment' || (o.legal_hold && !o.paid_at)) ? o.payment_url : null,
        // Same as api/_lib/orders.mjs: a locked view keeps status and dates, not what was said or sent.
        paidAt: o.paid_at, actionNote: o.status === 'action_required' && !isLocked ? o.action_note : null,
        docLock: !!o.doc_lock,
        unlocked: !isLocked,
        legalHold: !!o.legal_hold,
        integritySeal: seal,
        events: visibleEvents.map(e => (isLocked ? { ...e, detail: null } : e)),
        files: uploadedFiles.map(f => ({ id: f.id, kind: f.kind, name: isLocked ? (f.kind === 'proof' ? 'Proof of service (locked)' : 'Document (locked)') : f.filename,
            size: f.size_bytes, sha256: isLocked ? null : f.sha256 || null, at: f.created_at, locked: isLocked })),
    };
}

function adminDetail(o) {
    const evs = events.filter(e => e.order_id === o.id).sort((a, b) => a.created_at.localeCompare(b.created_at));
    const fls = [...files.values()].filter(f => f.order_id === o.id && f.uploaded).map(({ data, ...f }) => f);
    const seal = orderSeal(o.id);
    return {
        order: { ...o, legal_hold: !!o.legal_hold, doc_lock: !!o.doc_lock, integrity_seal: seal, tier_name: TIERS[o.tier]?.name, addon_names: o.addons.map(k => ADDONS[k]?.name).filter(Boolean) },
        events: evs,
        files: fls,
        integritySeal: seal,
        statuses: STATUSES,
    };
}

function prepareUploads(orderId, kind, list) {
    if (!Array.isArray(list) || !list.length) return [];
    if (list.length > 10) fail(400, 'Please attach at most 10 files.');
    const existingCount = [...files.values()].filter(f => f.order_id === orderId).length;
    if (existingCount + list.length > 25) fail(400, 'Each request can have at most 25 files total.');
    return list.map(f => {
        if (!f || typeof f !== 'object') fail(400, 'Invalid file entry.');
        const name = cleanText(f.name, 180, true, 'File name');
        if (/[/\\<>:"'|?*;`$]|\.\./.test(name)) fail(400, `${name}: invalid file name.`);
        const dot = name.lastIndexOf('.');
        const ext = dot > 0 ? name.slice(dot + 1).toLowerCase() : '';
        const type = MOCK_FILE_TYPES[ext];
        if (!type || DANGEROUS_EXT_RE.test(name)) fail(400, `${name}: only PDF, Word (.docx) and image files are accepted.`);
        const size = Number(f.size);
        if (!Number.isSafeInteger(size) || size <= 0 || size > 25 * 1024 * 1024) fail(400, `${name} must be under 25 MB.`);
        const id = randomUUID();
        files.set(id, { id, order_id: orderId, kind, filename: name, size_bytes: size, content_type: type, sha256: null, uploaded: false, data: null, created_at: now() });
        return { fileId: id, name, uploadUrl: `/__mock-upload/${id}` };
    });
}
const POLYGLOT_SCRIPT_RE = /<\s*(?:script|!doctype\s+html|html|iframe|svg|object|embed)\b|(?:javascript|vbscript)\s*:|\bon(?:load|error)\s*=/i;
const PDF_DANGEROUS_ACTION_RE = /\/(?:JavaScript|JS|Launch)\b/;
const DOCX_MACRO_OR_EXEC_RE = /(?:vbaProject\.bin|vbaData\.xml|activeX\/activeX|\.(?:exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|scr|msi|com|hta|jar|sh)(?:[\x00-\x20"'<>\/\\]|$))/i;
function verifyFileMagic(bytes, filename) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4 || bytes.length > 25 * 1024 * 1024) return false;
    const ext = typeof filename === 'string' && filename.includes('.') ? filename.split('.').pop().toLowerCase() : '';
    const headLen = Math.min(bytes.length, 4096);
    let head = '';
    for (let i = 0; i < headLen; i++) head += String.fromCharCode(bytes[i]);
    if (POLYGLOT_SCRIPT_RE.test(head)) return false;
    if (ext === 'pdf') {
        if (PDF_DANGEROUS_ACTION_RE.test(head)) return false;
        return bytes.length >= 5 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46 && bytes[4] === 0x2D;
    }
    if (ext === 'docx') {
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
        if (bytes.length > 4096) {
            let tail = '';
            for (let i = Math.max(0, bytes.length - 4096); i < bytes.length; i++) tail += String.fromCharCode(bytes[i]);
            if (POLYGLOT_SCRIPT_RE.test(tail)) return false;
        }
        return bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF;
    }
    if (ext === 'png') {
        if (bytes.length < 8 || bytes[0] !== 0x89 || bytes[1] !== 0x50 || bytes[2] !== 0x4E || bytes[3] !== 0x47 ||
            bytes[4] !== 0x0D || bytes[5] !== 0x0A || bytes[6] !== 0x1A || bytes[7] !== 0x0A) return false;
        if (bytes.length >= 16 && (bytes[12] !== 0x49 || bytes[13] !== 0x48 || bytes[14] !== 0x44 || bytes[15] !== 0x52)) return false;
        return true;
    }
    if (ext === 'webp') {
        return bytes.length >= 12 && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
            bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50;
    }
    if (ext === 'heic' || ext === 'heif') {
        if (bytes.length < 12 || bytes[4] !== 0x66 || bytes[5] !== 0x74 || bytes[6] !== 0x79 || bytes[7] !== 0x70) return false;
        const brand = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]);
        return /^(?:heic|heix|hevc|hevx|heim|heis|hevm|hevs|mif1|msf1)$/.test(brand);
    }
    return false;
}
function confirmUploads(orderId, ids) {
    const out = [];
    for (const id of (Array.isArray(ids) ? ids : []).filter(id => typeof id === 'string' && UUID_RE.test(id))) {
        const f = files.get(id.toLowerCase());
        if (!f || f.order_id !== orderId || !f.data) continue;
        if (!verifyFileMagic(f.data, f.filename)) {
            files.delete(f.id);
            continue;
        }
        f.uploaded = true;
        if (!f.sha256) f.sha256 = sha256Hex(f.data);
        out.push(f);
    }
    return out;
}

function markPaid(o, sessionId, amountCents = o?.amount_due_cents) {
    if (!o || o.paid_at) return false;
    if (typeof sessionId !== 'string' || !/^cs_[A-Za-z0-9_]{8,128}$/.test(sessionId)) return false;
    if (o.stripe_session_id && o.stripe_session_id !== sessionId) return false;
    const paidCents = Number(amountCents);
    if (!Number.isSafeInteger(paidCents) || paidCents <= 0) return false;
    if (o.amount_due_cents != null && paidCents < o.amount_due_cents) return false;
    // Same as api/_lib/orders.mjs: a held (served) order records the payment and keeps its status.
    updateOrder(o, { paid_at: now(), stripe_session_id: sessionId, ...(o.legal_hold ? {} : { status: 'paid' }) });
    addEvent(o.id, 'payment', `Payment received: ${money(paidCents)}`);
    return true;
}

// Mirrors the database trigger enforce_legal_hold: every order write in the mock goes through this, so a write the
// real database would refuse also fails here (as a 500, like an unhandled database error would).
const HELD_FIELDS = ['client_name', 'client_email', 'recipient_name', 'doc_type', 'address', 'unit', 'city', 'zip', 'case_number', 'court', 'served_at'];
function updateOrder(o, patch) {
    const next = { ...o, ...patch };
    if (o.legal_hold && next.legal_hold) {
        if (next.status !== o.status && !['served', 'closed'].includes(next.status)) fail(500, `Order ${o.code} is under legal hold; its status cannot be moved back.`);
        if (HELD_FIELDS.some(k => (next[k] ?? null) !== (o[k] ?? null))) fail(500, `Order ${o.code} is under legal hold; its record cannot be changed.`);
        if (o.paid_at && next.paid_at !== o.paid_at) fail(500, `Order ${o.code} is under legal hold; its recorded payment cannot be changed.`);
    }
    Object.assign(o, patch);
}

// --- Handlers, keyed by the api/<name>.mjs they stand in for ---
const DOC_TYPES = ['Summons & Complaint', 'Subpoena (Civil, Criminal, or Federal)', 'Writ of Garnishment', 'Small Claims Documents',
    'Eviction Notice', 'Divorce Papers', 'Child Custody & Support Order', 'Restraining Order', 'Order to Show Cause',
    'Debt Collection Notice', 'Other Legal Document'];

// Same signed, 12-hour unlock token as api/track.mjs.
const makeMockUnlockToken = (req, o) => signToken('track-unlock-v1', `${o.id}|${o.track_token}`, 12 * 3600);
const isMockUnlocked = (req, o, body) => !o.doc_lock || checkToken('track-unlock-v1', `${o.id}|${o.track_token}`, body?.unlockToken);

// Same rules as api/admin.mjs: a matched code consumes its 30-second step, so it can't be replayed.
function useMockTotp(adminEmail, secret, code) {
    const step = verifyTotp(secret, code);
    const row = adminTotpSecrets.get(adminEmail);
    if (!step || !row || step <= (row.last_used_step || 0)) return false;
    row.last_used_step = step;
    return true;
}
function requireMockStepUp(adminEmail, totpInput) {
    const row = adminTotpSecrets.get(adminEmail);
    if (!row?.enabled) return false;
    if (!useMockTotp(adminEmail, row.secret, totpInput)) fail(403, 'Enter the current 6-digit code from your authenticator app.');
    return true;
}

const handlers = {
    async client(req, body) {
        const action = body.action;
        if (action === 'send-code') {
            const addr = cleanEmail(body.email);
            const signup = body.intent === 'signup';
            const name = signup ? cleanText(body.name, 120, true, 'Full name') : '';
            const firm = signup ? (cleanText(body.firm, 160, false, 'Firm') || '') : '';
            clientCodes.set(addr, { intent: body.intent, name, firm, expires: Date.now() + 600000, attempts: 0 });
            return json({ ok: true, demo: true });
        }
        if (action === 'verify-code') {
            const addr = cleanEmail(body.email);
            const code = String(body.code || '').trim();
            if (!/^\d{6,8}$/.test(code)) fail(400, 'Enter the verification code from your email.');
            // Same order as api/client.mjs: ask for the PIN first, check the email code, and only then the PIN.
            const sec = clientSecurity.get(addr);
            const pin = String(body.pin || '').trim();
            if (sec?.pin_hash && !pin) return json({ ok: false, requiresPin: true, message: 'Enter your 6-digit Security PIN to complete 2-step sign-in.' }, 200);
            if (sec?.pin_hash && sec.locked_until > Date.now()) fail(429, 'Account temporarily locked after repeated wrong Security PINs. Please wait 15 minutes.');
            const pending = clientCodes.get(addr);
            if (!pending || pending.expires < Date.now() || pending.attempts >= 5) fail(401, 'That code is invalid or expired. Request another email.');
            pending.attempts++;
            if (code !== '123456') {
                if (pending.attempts >= 5) clientCodes.delete(addr);
                fail(401, 'That code is invalid or expired. Request another email.');
            }
            if (sec?.pin_hash) {
                if (!verifyPin(pin, sec.pin_hash)) {
                    if (sec.locked_until && sec.locked_until <= Date.now()) { sec.failed_tries = 0; sec.locked_until = 0; }
                    sec.failed_tries = (sec.failed_tries || 0) + 1;
                    if (sec.failed_tries >= 5) sec.locked_until = Date.now() + 15 * 60 * 1000;
                    clientCodes.delete(addr);   // the code is spent
                    fail(401, 'Wrong Security PIN. Request a new code and try again.');
                }
                sec.failed_tries = 0;
                sec.locked_until = 0;
            }
            if (!clients.has(addr)) {
                if (pending.intent !== 'signup') fail(401, 'That code is invalid or expired. Create an account first.');
                clients.set(addr, { name: pending.name, firm: pending.firm, email: addr });
            } else if (pending.intent === 'signup' && pending.name) {
                clients.set(addr, { name: pending.name, firm: pending.firm, email: addr });
            }
            clientCodes.delete(addr);
            const value = token();
            clientSessions.set(value, addr);
            return json({ ok: true }, 200, { 'set-cookie': `nps_client=${value}; Path=/api/client; HttpOnly; SameSite=Strict` });
        }
        const value = (req.headers.get('cookie') || '').match(/(?:^|;\s*)nps_client=([^;]+)/)?.[1];
        const verifiedEmail = value && /^[A-Za-z0-9_-]{16,160}$/.test(value) ? clientSessions.get(value) : null;
        if (action === 'logout') { if (value) clientSessions.delete(value); return json({ ok: true }, 200, { 'set-cookie': 'nps_client=; Path=/api/client; Max-Age=0' }); }
        if (action === 'logout-all') {
            if (verifiedEmail) {
                for (const [k, em] of [...clientSessions.entries()]) {
                    if (em === verifiedEmail) clientSessions.delete(k);
                }
            }
            return json({ ok: true }, 200, { 'set-cookie': 'nps_client=; Path=/api/client; Max-Age=0' });
        }
        if (!verifiedEmail || !clients.has(verifiedEmail)) fail(401, 'Please sign in to see your requests.');
        const baseProfile = clients.get(verifiedEmail);
        const sec = clientSecurity.get(verifiedEmail);
        const profile = { ...baseProfile, hasPin: !!sec?.pin_hash };
        if (action === 'me') return json({ profile });
        if (action === 'set-pin') {
            const pin = String(body.pin || '').trim();
            if (!/^\d{6}$/.test(pin)) fail(400, 'Please enter a 6-digit numeric Security PIN.');
            // Same as api/client.mjs: replacing a PIN needs the current one.
            if (sec?.pin_hash && !verifyPin(String(body.currentPin || '').trim(), sec.pin_hash)) fail(403, 'Enter your current 6-digit Security PIN to change it.');
            clientSecurity.set(verifiedEmail, { pin_hash: hashPin(pin), failed_tries: 0, locked_until: 0 });
            return json({ ok: true, hasPin: true });
        }
        if (action === 'disable-pin') {
            if (sec?.pin_hash) {
                const pin = String(body.pin || '').trim();
                if (!verifyPin(pin, sec.pin_hash)) fail(403, 'Enter your current 6-digit Security PIN to disable it.');
                clientSecurity.delete(verifiedEmail);
            }
            return json({ ok: true, hasPin: false });
        }
        if (action === 'rotate-token') {
            const code = (cleanText(body.code, 20, true, 'Reference number') || '').toUpperCase().replace(/^(NP)?-?/, 'NP-');
            const o = [...orders.values()].find(ord => ord.client_email.toLowerCase() === verifiedEmail && ord.code === code);
            if (!o) fail(404, 'Order not found.');
            o.track_token = randomBytes(32).toString('base64url');
            addEvent(o.id, 'note', 'Private tracking link rotated by client (previous link revoked)', null, true);
            return json({ ok: true, code: o.code, trackUrl: `/track.html#t=${encodeURIComponent(o.track_token)}` });
        }
        if (action === 'toggle-doc-lock') {
            const code = (cleanText(body.code, 20, true, 'Reference number') || '').toUpperCase().replace(/^(NP)?-?/, 'NP-');
            const o = [...orders.values()].find(ord => ord.client_email.toLowerCase() === verifiedEmail && ord.code === code);
            if (!o) fail(404, 'Order not found.');
            o.doc_lock = body.locked !== undefined ? !!body.locked : !o.doc_lock;
            addEvent(o.id, 'note', o.doc_lock ? '2-Step Document Protection enabled by client' : '2-Step Document Protection unlocked by client', null, true);
            return json({ ok: true, code: o.code, docLock: o.doc_lock });
        }
        if (action === 'request-purge') {
            const code = (cleanText(body.code, 20, true, 'Reference number') || '').toUpperCase().replace(/^(NP)?-?/, 'NP-');
            const o = [...orders.values()].find(ord => ord.client_email.toLowerCase() === verifiedEmail && ord.code === code);
            if (!o) fail(404, 'Order not found.');
            if (!['served', 'closed', 'cancelled'].includes(o.status)) {
                fail(400, 'Confidential retention purge can only be requested on completed or closed orders.');
            }
            addEvent(o.id, 'note', 'Client requested confidential document purge / retention seal', `Requested by verified account ${verifiedEmail}`, true);
            return json({ ok: true, code: o.code });
        }
        if (action === 'list') {
            const list = [...orders.values()].filter(o => o.client_email.toLowerCase() === verifiedEmail).sort((a,b) => b.created_at.localeCompare(a.created_at)).slice(0,100);
            return json({ profile, orders: list.map(o => ({ code: o.code, status: o.status, label: STATUSES[o.status].label, recipient: o.recipient_name, document: o.doc_type,
                service: TIERS[o.tier]?.name, created: o.created_at, amount: money(o.amount_due_cents ?? o.estimated_total_cents), paid: !!o.paid_at,
                docLock: !!o.doc_lock, legalHold: o.status === 'served' || !!o.legal_hold, trackUrl: `/track.html#t=${o.track_token}` })) });
        }
        fail(400, 'Unknown action.');
    },
    async request(req, body) {
        if (body.step === 'finish') {
            const o = orderByToken(body.t);
            const up = confirmUploads(o.id, body.fileIds);
            if (up.length) addEvent(o.id, 'note', `${up.length} document${up.length === 1 ? '' : 's'} uploaded`);
            email(o.client_email, `We received your request ${o.code}`, `/track.html#t=${o.track_token}`);
            email(ADMIN_EMAIL, `New request ${o.code}: ${o.recipient_name}`, `/admin.html#${o.id}`);
            return json({ ok: true });
        }
        if (body.website) return json({ ok: true, code: 'NP-000000', trackUrl: '/' });
        const clientName = cleanText(body.clientName, 120, true, 'Your name');
        const clientFirm = cleanText(body.clientFirm, 160, false, 'Firm');
        const clientEmail = cleanEmail(body.clientEmail);
        const clientPhone = cleanPhone(body.clientPhone);
        const recipientName = cleanText(body.recipientName, 160, true, 'Person to be served');
        const address = cleanText(body.address, 200, true, 'Street address');
        const unit = cleanText(body.unit, 40, false, 'Unit');
        const city = cleanText(body.city, 80, true, 'City');
        const zip = cleanText(body.zip, 10, true, 'ZIP code');
        if (!/^\d{5}(-\d{4})?$/.test(zip)) fail(400, 'Please enter a valid 5-digit ZIP code.');
        const deadline = cleanDate(body.deadline);
        const docType = DOC_TYPES.includes(body.docType) ? body.docType : 'Other Legal Document';
        if (body.acceptTerms !== true) fail(400, 'Please accept the Terms of Service to submit your request.');
        const { keys, cents } = estimate(body.tier, body.addons);
        const o = createOrder({
            client_name: clientName, client_firm: clientFirm, client_email: clientEmail, client_phone: clientPhone,
            case_number: cleanText(body.caseNumber, 80, false, 'Case number'),
            court: cleanText(body.court, 160, false, 'Court'),
            client_reference: cleanText(body.clientReference, 80, false, 'Client reference'),
            deadline,
            recipient_name: recipientName, doc_type: docType, address, unit, city, zip,
            access_notes: cleanLongText(body.accessNotes, 500, 'Gate code / access notes'),
            physical_notes: cleanLongText(body.physicalNotes, 1000, 'Description notes'),
            instructions: cleanLongText(body.instructions, 2000, 'Special instructions'),
            tier: body.tier, addons: keys, estimated_total_cents: cents,
        });
        addEvent(o.id, 'created', 'Request received', `${TIERS[o.tier].name} · estimate ${money(cents)}`);
        const submissionDigest = sha256Hex(`${o.code}|${clientEmail}|${recipientName}|${docType}|${address}|${unit || ''}|${city}|${zip}|${body.tier}|${deadline || 'none'}|TOS-ACCEPTED`).slice(0, 32);
        addEvent(o.id, 'attestation', 'Client legal attestation & Terms sealed', `Terms & Best-Efforts Service scope accepted · Deadline: ${deadline || 'Standard'} · Submission SHA-256: ${submissionDigest}`, true);
        return json({ ok: true, code: o.code, token: o.track_token, trackUrl: `/track.html#t=${o.track_token}`, uploads: prepareUploads(o.id, 'client_document', body.files) });
    },

    async track(req, body, url) {
        const o = orderByToken(body.t);
        const unlocked = isMockUnlocked(req, o, body);
        if (body.action === 'view') return json(clientView(o, { unlocked }));
        if (body.action === 'send-unlock-code') {
            trackUnlockCodes.set(o.id, { code: MOCK_CLIENT_CODE, tries: 0, expires: Date.now() + 600000 });
            const maskedEmail = o.client_email.replace(/^(..).*(@.*)$/, '$1•••$2');
            return json({ ok: true, maskedEmail });
        }
        if (body.action === 'verify-unlock-code') {
            const code = String(body.code || '').trim();
            if (!/^\d{6}$/.test(code)) fail(400, 'Please enter a 6-digit verification code or Security PIN.');
            // Same as api/track.mjs: wrong PINs here count on this order's own 15-minute counter, never the portal's lockout.
            const sec = clientSecurity.get(o.client_email.toLowerCase());
            const window = Math.floor(Date.now() / 900e3);
            const fails = trackPinFails.get(o.id);
            const pinFails = fails?.window === window ? fails.count : 0;
            const pinUsable = !!sec?.pin_hash && !(sec.locked_until > Date.now()) && pinFails < 5;
            let verified = pinUsable && verifyPin(code, sec.pin_hash);
            if (!verified) {
                const row = trackUnlockCodes.get(o.id);
                const codeOk = !!row && row.expires >= Date.now() && row.tries < 5 && code === row.code;
                if (!codeOk) {
                    if (pinUsable) trackPinFails.set(o.id, { window, count: pinFails + 1 });
                    if (row) { row.tries++; if (row.tries >= 5) trackUnlockCodes.delete(o.id); }
                    fail(401, 'That code or PIN is invalid or expired. Request a new code.');
                }
                trackUnlockCodes.delete(o.id);
                verified = true;
            }
            const unlockToken = makeMockUnlockToken(req, o);
            return json({ ok: true, unlockToken, ...clientView(o, { unlocked: true }) });
        }
        if (body.action === 'toggle-doc-lock') {
            if (o.doc_lock && !unlocked) fail(403, 'Unlock 2-Step Protection first before changing lock settings.');
            o.doc_lock = body.locked !== undefined ? !!body.locked : !o.doc_lock;
            addEvent(o.id, 'note', o.doc_lock ? '2-Step Document Protection enabled' : '2-Step Document Protection unlocked', null, true);
            const unlockToken = o.doc_lock ? makeMockUnlockToken(req, o) : null;
            return json({ ok: true, unlockToken, ...clientView(o, { unlocked: true }) });
        }
        if (body.action === 'rotate-token') {
            if (o.doc_lock && !unlocked) fail(403, 'Verify your 2-Step code before rotating this private link.');
            o.track_token = randomBytes(32).toString('base64url');
            addEvent(o.id, 'note', 'Private tracking link replaced', 'The previous link no longer works. A copy of the new link was emailed.', true);
            email(o.client_email, `${o.code}: your new private tracking link`, `/track.html#t=${o.track_token}`);
            return json({ ok: true, token: o.track_token, trackUrl: `/track.html#t=${encodeURIComponent(o.track_token)}` });
        }
        if (body.action === 'download') {
            if (o.doc_lock && !unlocked) {
                fail(403, '2-Step Document Protection is active. Verify your email code or Security PIN to download case documents.');
            }
            const fid = cleanUuid(body.fileId, 'File');
            const f = files.get(fid);
            if (!f || f.order_id !== o.id || !f.uploaded) fail(404, 'File not found.');
            addEvent(o.id, 'note', 'Document downloaded from tracking page', f.filename, false);   // same as api/track.mjs
            return json({ url: `/__mock-file/${f.id}`, sha256: f.sha256 || null, expiresInSeconds: 60 });
        }
        if (body.action === 'confirm-payment') {
            if (typeof body.session !== 'string' || !/^cs_[A-Za-z0-9_]{8,128}$/.test(body.session)) fail(400, 'Invalid payment session.');
            // Like api/track.mjs (which asks Stripe): the matching unpaid session counts, whatever the status. Held orders are billed while served.
            if (body.session === o.stripe_session_id && !o.paid_at) markPaid(o, body.session);
            return json(clientView(o, { unlocked }));
        }
        if (body.action === 'respond') {
            if (o.status !== 'action_required') fail(409, 'Nothing is needed from you right now.');
            if (o.doc_lock && !unlocked) fail(403, 'This request is locked. Enter the code we email you (or your Security PIN) to unlock it first.');
            const changes = {};
            const address = cleanText(body.address, 200, false, 'Street address');
            if (address) changes.address = address;
            const unit = cleanText(body.unit, 40, false, 'Unit');
            if (unit) changes.unit = unit;
            const city = cleanText(body.city, 80, false, 'City');
            if (city) changes.city = city;
            const zip = cleanText(body.zip, 10, false, 'ZIP code');
            if (zip) {
                if (!/^\d{5}(-\d{4})?$/.test(zip)) fail(400, 'Please enter a valid 5-digit ZIP code.');
                changes.zip = zip;
            }
            const access = cleanLongText(body.accessNotes, 500, 'Access notes');
            if (access) changes.access_notes = access;
            const reply = cleanLongText(body.reply, 2000, 'Your reply');
            const fileList = Array.isArray(body.files) ? body.files : [];
            if (!Object.keys(changes).length && !reply && !fileList.length) fail(400, 'Please add the missing information, a reply, or a file.');
            const uploads = prepareUploads(o.id, 'action_upload', fileList);
            updateOrder(o, { ...changes, status: 'received', action_note: null, updated_at: now() });
            const attemptCount = events.filter(e => e.order_id === o.id && e.kind === 'attempt').length;
            const amendDigest = sha256Hex(`${o.code}|${changes.address || ''}|${changes.unit || ''}|${changes.city || ''}|${changes.zip || ''}|${changes.access_notes || ''}|${reply || ''}`).slice(0, 16);
            const summary = [
                changes.address || changes.unit || changes.city || changes.zip ? 'Updated the service address' : null,
                changes.access_notes ? `Access notes: ${changes.access_notes}` : null,
                reply,
                `[Cutoff stamp: after ${attemptCount} attempt(s) · SHA-256: ${amendDigest}]`,
            ].filter(Boolean).join(' · ');
            addEvent(o.id, 'action_response', 'You sent the requested information', summary || null);
            return json({ ok: true, uploads });
        }
        if (body.action === 'respond-finish') {
            if (o.doc_lock && !unlocked) fail(403, 'This request is locked. Unlock it first.');
            if (o.status !== 'received') return json(clientView(o, { unlocked }));
            const up = confirmUploads(o.id, body.fileIds);
            if (up.length) addEvent(o.id, 'note', `${up.length} file${up.length === 1 ? '' : 's'} added by you`);
            const orderEvents = events.filter(e => e.order_id === o.id);
            const lastResponse = [...orderEvents].reverse().find(e => e.kind === 'action_response');
            const lastEmailed = [...orderEvents].reverse().find(e => e.title === 'Reply emailed');
            if (lastResponse && (!lastEmailed || lastEmailed.created_at < lastResponse.created_at)) {
                addEvent(o.id, 'note', 'Reply emailed', null, false);
                email(ADMIN_EMAIL, `${o.code}: client sent the information you asked for`, `/admin.html#${o.id}`);
            }
            return json(clientView(o, { unlocked }));
        }
        fail(400, 'Unknown action.');
    },

    async lookup(req, body) {
        const code = (cleanText(body.code, 20, true, 'Reference number') || '').toUpperCase().replace(/^(NP)?-?/, 'NP-');
        const addr = cleanEmail(body.email);
        const o = /^NP-\d{6}$/.test(code) ? [...orders.values()].find(o => o.code === code && o.client_email === addr) : null;
        if (o) email(o.client_email, `Your tracking link for ${o.code}`, `/track.html#t=${o.track_token}`);
        return json({ ok: true, message: 'If that reference number and email match a request, we just emailed you its private tracking link.' });
    },

    async admin(req, body) {
        const a = body.action;
        if (a === 'send-code') {
            const addr = cleanEmail(body.email);
            if (MOCK_ADMIN_EMAILS.includes(addr)) {
                adminCodesBurned.delete(addr);
                adminBurnFails.set(addr, 0);
                console.log(`[mock] dashboard login code for ${addr}: ${MOCK_ADMIN_CODE}`);
            }
            return json({ ok: true });
        }
        if (a === 'verify-code') {
            // Same rules as api/admin.mjs: with an authenticator on, email code + (authenticator code or recovery code);
            // without one, an email code, or a recovery code on its own.
            const addr = cleanEmail(body.email);
            if (!MOCK_ADMIN_EMAILS.includes(addr)) fail(401, 'That code is wrong or expired. Request a new one.');
            const raw = String(body.code || '').trim().toUpperCase();
            const digits = raw.replace(/\D/g, '');
            const isEmailCode = digits.length === 8 && raw.replace(/[\s-]+/g, '') === digits;
            const second = String(body.totp || '').trim().toUpperCase();
            const secondRecovery = second.replace(/[^A-Z0-9]/g, '');
            const totpRow = adminTotpSecrets.get(addr);
            if (totpRow?.enabled && isEmailCode && !second) {
                return json({ ok: false, requiresTwoFactor: true, message: 'Enter the 6-digit code from your authenticator app, or one of your recovery codes.' });
            }
            const codes = adminRecoveryCodes.get(addr);
            let ok = false;
            let method = 'email';
            if (isEmailCode && !adminCodesBurned.has(addr)) {
                let secondOk = !totpRow?.enabled;
                if (!secondOk && /^\d{6}$/.test(second.replace(/\s+/g, ''))) { secondOk = useMockTotp(addr, totpRow.secret, second); method = 'email+authenticator'; }
                else if (!secondOk && secondRecovery.length === 8 && codes?.has(secondRecovery)) { codes.delete(secondRecovery); secondOk = true; method = 'email+recovery'; }
                ok = secondOk && digits === MOCK_ADMIN_CODE;
            } else if (!totpRow?.enabled && !isEmailCode && codes?.has(raw.replace(/[^A-Z0-9]/g, ''))) {
                codes.delete(raw.replace(/[^A-Z0-9]/g, ''));
                ok = true;
                method = 'recovery';
            }
            if (!ok) {
                auditAdmin(addr, 'login_failed');
                const fails = (adminBurnFails.get(addr) || 0) + 1;
                adminBurnFails.set(addr, fails);
                if (fails >= 5) {
                    adminCodesBurned.add(addr);   // codes already sent stop working; a new send-code clears this
                    auditAdmin(addr, 'codes_burned', null, 'Pending login codes discarded after 5 failed attempts');
                }
                fail(401, 'That code is wrong or expired. Request a new one.');
            }
            adminBurnFails.set(addr, 0);
            const existingForAdmin = [...sessionEmails.entries()].filter(([, em]) => em === addr).map(([tok]) => tok);
            while (existingForAdmin.length >= 5) {
                const oldest = existingForAdmin.shift();
                sessions.delete(oldest);
                sessionEmails.delete(oldest);
            }
            const t = token();
            sessions.add(t);
            sessionEmails.set(t, addr);
            auditAdmin(addr, method.includes('recovery') ? 'login_recovery_code' : 'login_success', null, `Signed in with ${method}`);
            email(addr, method.includes('recovery') ? 'Security alert: recovery code used to sign in' : 'Security alert: new sign-in to your dashboard');
            return json({ ok: true, totpEnabled: !!totpRow?.enabled }, 200, { 'set-cookie': `nps_admin=${t}; Path=/api/admin; HttpOnly; SameSite=Strict` });
        }
        const cookie = (req.headers.get('cookie') || '').match(/(?:^|;\s*)nps_admin=([^;]+)/)?.[1];
        if (!cookie || !/^[A-Za-z0-9_-]{16,160}$/.test(cookie) || !sessions.has(cookie)) fail(401, 'Please log in.');
        const adminEmail = sessionEmails.get(cookie) || ADMIN_EMAIL;
        if (a === 'me') {
            const totpRow = adminTotpSecrets.get(adminEmail);
            const auditLogs = adminAuditLogs.filter(l => l.email === adminEmail).slice(0, 10).map(({ action, target_code, detail, created_at }) => ({ action, target_code, detail, created_at }));
            return json({ email: adminEmail, recoveryRemaining: adminRecoveryCodes.get(adminEmail)?.size || 0, totpEnabled: !!totpRow?.enabled, auditLogs });
        }
        if (a === 'logout') {
            sessions.delete(cookie);
            sessionEmails.delete(cookie);
            auditAdmin(adminEmail, 'logout');
            return json({ ok: true }, 200, { 'set-cookie': 'nps_admin=; Path=/api/admin; Max-Age=0' });
        }
        if (a === 'logout-all') {
            for (const [tok, em] of [...sessionEmails.entries()]) {
                if (em === adminEmail) { sessions.delete(tok); sessionEmails.delete(tok); }
            }
            sessions.delete(cookie);
            auditAdmin(adminEmail, 'logout_all');
            return json({ ok: true }, 200, { 'set-cookie': 'nps_admin=; Path=/api/admin; Max-Age=0' });
        }
        if (a === 'totp-setup') {
            // While one is on, changing it needs the current code, and the new secret waits as pending until confirmed.
            const row = adminTotpSecrets.get(adminEmail);
            if (row?.enabled) requireMockStepUp(adminEmail, body?.totp);
            const secret = generateTotpSecret(20);
            if (row?.enabled) row.pending = secret;
            else adminTotpSecrets.set(adminEmail, { secret, enabled: false, last_used_step: row?.last_used_step || 0 });
            auditAdmin(adminEmail, row?.enabled ? 'totp_change_started' : 'totp_setup_started');
            const label = encodeURIComponent(`Nick's Process Services:${adminEmail}`);
            return json({ ok: true, secret, otpauthUrl: `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent("Nick's Process Services")}&algorithm=SHA1&digits=6&period=30` });
        }
        if (a === 'totp-enable') {
            const row = adminTotpSecrets.get(adminEmail);
            const candidate = row?.pending || (!row?.enabled && row?.secret);
            if (!candidate) fail(400, 'Start authenticator setup first.');
            if (!useMockTotp(adminEmail, candidate, body.totp)) fail(400, "That code didn't match. Check that your phone's clock is set automatically, then try the newest code.");
            Object.assign(row, { secret: candidate, pending: null, enabled: true });
            auditAdmin(adminEmail, 'totp_enabled');
            return json({ ok: true, totpEnabled: true });
        }
        if (a === 'totp-disable') {
            const row = adminTotpSecrets.get(adminEmail);
            if (!row?.enabled) return json({ ok: true, totpEnabled: false });
            if (!useMockTotp(adminEmail, row.secret, body.totp)) fail(403, 'Enter the current 6-digit code from your authenticator app to turn two-step sign-in off.');
            Object.assign(row, { enabled: false, pending: null });
            auditAdmin(adminEmail, 'totp_disabled');
            return json({ ok: true, totpEnabled: false });
        }
        if (a === 'generate-recovery-codes') {
            requireMockStepUp(adminEmail, body?.totp);
            const set = new Set();
            const out = [];
            for (let i = 0; i < 8; i++) {
                let raw = '';
                for (let j = 0; j < 8; j++) raw += RECOVERY_ALPHABET[randomInt(0, RECOVERY_ALPHABET.length)];
                set.add(raw);
                out.push(`${raw.slice(0, 4)}-${raw.slice(4)}`);
            }
            adminRecoveryCodes.set(adminEmail, set);
            auditAdmin(adminEmail, 'generate_recovery_codes');
            return json({ codes: out, remaining: out.length });
        }
        if (a === 'list') {
            const kinds = ['action', 'status', 'attempt', 'payment', 'proof', 'action_response'];
            const list = [...orders.values()].sort((x, y) => y.created_at.localeCompare(x.created_at)).map(o => {
                const last = events.filter(e => e.order_id === o.id && kinds.includes(e.kind)).sort((a, b) => b.created_at.localeCompare(a.created_at))[0];
                return { ...o, client_replied: last?.kind === 'action_response' };
            });
            return json({ orders: list, statuses: STATUSES, tiers: TIERS });
        }
        if (a === 'file-url') {
            const fid = cleanUuid(body.fileId, 'File');
            const f = files.get(fid);
            if (!f?.uploaded) fail(404, 'File not found.');
            return json({ url: `/__mock-file/${f.id}` });
        }
        if (!['get', 'update', 'rotate-token', 'toggle-doc-lock', 'unlock-legal-hold', 'payment-link', 'export', 'delete', 'proof-upload', 'proof-finish'].includes(a)) fail(400, 'Unknown action.');
        const oid = cleanUuid(body.id, 'Order');
        const o = orders.get(oid);
        if (!o) fail(404, 'Order not found.');
        const trackUrl = `/track.html#t=${o.track_token}`;
        const note = cleanLongText(body.note, 2000, 'Note');
        if (a === 'get') return json(adminDetail(o));
        if (a === 'rotate-token') {
            o.track_token = randomBytes(32).toString('base64url');
            addEvent(o.id, 'note', 'Private tracking link replaced', 'The previous link no longer works. The new link was emailed to the client.', true);
            auditAdmin(adminEmail, 'rotate_track_token', o.code);
            email(o.client_email, `${o.code}: your new private tracking link`, `/track.html#t=${o.track_token}`);
            return json(adminDetail(o));
        }
        if (a === 'toggle-doc-lock') {
            o.doc_lock = body.locked !== undefined ? !!body.locked : !o.doc_lock;
            addEvent(o.id, 'note', o.doc_lock ? 'Document lock turned on' : 'Document lock turned off',
                o.doc_lock ? 'Viewing documents and full details on the tracking page now needs a code emailed to the client.' : null, true);
            auditAdmin(adminEmail, o.doc_lock ? 'doc_lock_enabled' : 'doc_lock_disabled', o.code);
            return json(adminDetail(o));
        }
        if (a === 'unlock-legal-hold') {
            // Same as api/admin.mjs: unlocking needs a fresh authenticator code, or the typed reference without one.
            const hold = !!body.hold;
            if (!hold) {
                const usedTotp = requireMockStepUp(adminEmail, body.totp);
                if (!usedTotp && String(body.confirm || '').trim().toUpperCase() !== o.code) fail(400, `Type ${o.code} to confirm unlocking legal hold.`);
            }
            o.legal_hold = hold;
            addEvent(o.id, 'note', hold ? 'Legal hold turned on' : 'Legal hold unlocked by Nick', null, false);
            auditAdmin(adminEmail, hold ? 'legal_hold_on' : 'legal_hold_unlocked', o.code);
            if (!hold) email(adminEmail, `Security alert: legal hold unlocked on ${o.code}`);
            return json(adminDetail(o));
        }
        if (a === 'update') {
            if (body.kind === 'status') {
                if (!STATUSES[body.status] || body.status === 'action_required') fail(400, 'Choose a status.');
                if (o.legal_hold && !['served', 'closed'].includes(body.status)) {
                    fail(423, 'This order is under legal hold, so its status can only move to Closed. Unlock legal hold first if it really needs to change.');
                }
                updateOrder(o, { status: body.status, ...(body.status === 'served' ? { served_at: now(), legal_hold: true } : {}) });
                addEvent(o.id, 'status', STATUSES[body.status].label, note, body.clientVisible !== false);
                if (body.notify) email(o.client_email, `${o.code}: ${STATUSES[body.status].label}`, trackUrl);
            } else if (body.kind === 'attempt') {
                const outcome = cleanText(body.outcome, 120, true, 'Outcome');
                const when = cleanText(body.when, 40, false, 'When');
                if (['received', 'paid', 'accepted'].includes(o.status)) updateOrder(o, { status: 'attempting' });
                addEvent(o.id, 'attempt', `Attempt: ${outcome}`, [when, note].filter(Boolean).join(' · '), body.clientVisible !== false);
            } else if (body.kind === 'note') {
                if (!note) fail(400, 'Write a note first.');
                addEvent(o.id, 'note', body.clientVisible ? 'Update from Nick' : 'Internal note', note, !!body.clientVisible);
            } else if (body.kind === 'action') {
                if (!note) fail(400, 'Tell the client what you need.');
                if (o.legal_hold) fail(423, 'This order is served and under legal hold, so it can’t go back to "Action required". Add a note the client can see, or contact them directly.');
                updateOrder(o, { status: 'action_required', action_note: note });
                addEvent(o.id, 'action', 'Action required', note);
                email(o.client_email, `${o.code}: Nick needs a little more information`, trackUrl);
            } else fail(400, 'Unknown update.');
            return json(adminDetail(o));
        }
        if (a === 'payment-link') {
            const cents = Math.round(Number(body.amount) * 100);
            if (!Number.isFinite(cents) || cents < 100 || cents > 1000000) fail(400, 'Enter an amount between $1 and $10,000.');
            if (o.paid_at) fail(409, 'This order is already paid.');
            const description = cleanText(body.description, 300, false, 'Description');
            const session = `cs_mock_${randomBytes(6).toString('hex')}`;
            updateOrder(o, { ...(o.legal_hold ? {} : { status: 'awaiting_payment' }), amount_due_cents: cents, stripe_session_id: session,
                payment_url: `/__mock-pay?t=${encodeURIComponent(o.track_token)}&s=${session}` });
            addEvent(o.id, 'payment', `Payment requested: ${money(cents)}`, description);
            auditAdmin(adminEmail, 'payment_link', o.code, money(cents));
            email(o.client_email, `${o.code}: confirmed, ${money(cents)} due to start service`, o.payment_url);
            return json(adminDetail(o));
        }
        if (a === 'export') {
            auditAdmin(adminEmail, 'export_order', o.code);
            const { order: detOrder, events: detEvents, files: detFiles, integritySeal } = adminDetail(o);
            const { track_token, payment_url, stripe_session_id, ...fields } = detOrder;
            return json({ exported_at: now(), integrity_seal: integritySeal, request: { ...fields, tier: TIERS[o.tier]?.name },
                timeline: detEvents.map(({ created_at, title, detail, client_visible }) => ({ created_at, title, detail, shown_to_client: client_visible })),
                files: detFiles.map(({ filename, kind, size_bytes, sha256, created_at }) => ({ filename, kind, size_bytes, sha256: sha256 || null, created_at })) });
        }
        if (a === 'delete') {
            if (o.legal_hold) fail(423, 'This order is under legal hold and cannot be deleted. Unlock legal hold first (that step is logged and emailed to you).');
            requireMockStepUp(adminEmail, body.totp);
            if (String(body.confirm || '').trim().toUpperCase() !== o.code) fail(400, `Type ${o.code} to confirm.`);
            let deletedFiles = 0;
            for (const [fid, f] of files) if (f.order_id === o.id) { files.delete(fid); deletedFiles++; }
            for (let i = events.length - 1; i >= 0; i--) if (events[i].order_id === o.id) events.splice(i, 1);
            orders.delete(o.id);
            auditAdmin(adminEmail, 'delete_order', o.code, `${deletedFiles} file(s) deleted`);
            return json({ ok: true, deleted: o.code });
        }
        if (a === 'proof-upload') {
            if (!Array.isArray(body.files) || !body.files.length) fail(400, 'Choose the proof of service file.');
            return json({ uploads: prepareUploads(o.id, 'proof', body.files) });
        }
        if (a === 'proof-finish') {
            const up = confirmUploads(o.id, body.fileIds);
            if (!up.length) fail(400, 'The upload did not finish. Please try again.');
            const detailText = up.map(f => f.sha256 ? `${f.filename} (SHA-256: ${f.sha256.slice(0, 12)}…)` : f.filename).join(', ');
            addEvent(o.id, 'proof', 'Proof of service uploaded', detailText);
            if (body.markServed && o.status !== 'served') { updateOrder(o, { status: 'served', served_at: now(), legal_hold: true }); addEvent(o.id, 'status', STATUSES.served.label); }
            email(o.client_email, `${o.code}: your proof of service is ready`, trackUrl);
            return json(adminDetail(o));
        }
        fail(400, 'Unknown action.');
    },
};

const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
function parseSafeJson(raw) {
    if (!raw) return {};
    if (raw.length > 65536) fail(413, 'Request too large.');
    let parsed;
    try {
        parsed = JSON.parse(raw, (k, v) => (PROTO_KEYS.has(k) ? undefined : v));
    } catch {
        fail(400, 'Invalid JSON.');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) fail(400, 'Invalid request.');
    return parsed;
}

export async function handleMockApi(name, req) {
    const handler = handlers[name];
    if (!handler) return null;
    try {
        const raw = req.method === 'GET' ? '' : await req.text();
        return await handler(req, parseSafeJson(raw), new URL(req.url));
    } catch (err) {
        if (err instanceof MockError || typeof err?.status === 'number') return json({ error: err.message }, err.status);
        if (err?.message === 'Please choose a service tier.') return json({ error: err.message }, 400);
        console.error(err);
        return json({ error: 'Something went wrong on our end.' }, 500);
    }
}

// --- Pages and endpoints that stand in for Supabase Storage and Stripe Checkout ---
export async function handleMockRoute(req) {
    const url = new URL(req.url);
    const [, route, id] = url.pathname.match(/^\/(__mock[\w-]*)\/?([\w-]*)/) || [];
    if (route === '__mock-upload' && req.method === 'PUT') {
        if (!UUID_RE.test(id)) return new Response('Unknown upload', { status: 404 });
        const f = files.get(id.toLowerCase());
        if (!f) return new Response('Unknown upload', { status: 404 });
        const part = (await req.formData()).get('');
        const buf = Buffer.from(await part.arrayBuffer());
        if (buf.length === 0 || buf.length > 25 * 1024 * 1024) return new Response('Invalid file size', { status: 400 });
        f.data = buf;
        return json({ Key: id });
    }
    if (route === '__mock-file') {
        const f = files.get(id);
        if (!f?.data) return new Response('Not found', { status: 404 });
        return new Response(f.data, { headers: { 'content-type': f.content_type || 'application/octet-stream',
            'content-disposition': `attachment; filename="${f.filename.replace(/"/g, '')}"` } });
    }
    if (route === '__mock-pay') {
        const o = [...orders.values()].find(o => o.track_token === url.searchParams.get('t'));
        if (!o) return new Response('Unknown order', { status: 404 });
        const back = `/track.html#t=${encodeURIComponent(o.track_token)}`;
        const paidBack = (s) => `/track.html?paid=${encodeURIComponent(s)}#t=${encodeURIComponent(o.track_token)}`;   // same shape as api/_lib/stripe.mjs
        return page(`Test checkout`, `
            <p style="color:#635bff;font-weight:700;letter-spacing:.04em;margin:0 0 6px">STRIPE CHECKOUT (LOCAL STAND-IN)</p>
            <h1 style="margin:0 0 4px;font-size:30px">${money(o.amount_due_cents)}</h1>
            <p style="color:#666;margin:0 0 24px">Nick's Process Services · ${o.code}</p>
            <p style="font-size:13px;color:#666;margin:0 0 24px">The real page is hosted by Stripe and takes card or Apple Pay. Nothing is charged here.</p>
            <a href="${paidBack(url.searchParams.get('s') || '')}" style="display:block;text-align:center;background:#635bff;color:#fff;padding:14px;border-radius:6px;text-decoration:none;font-weight:700">Pay ${money(o.amount_due_cents)}</a>
            <a href="${back}" style="display:block;text-align:center;margin-top:14px;color:#635bff;font-size:14px">Cancel and go back</a>`);
    }
    if (route === '__mock-split') {
        // The client's phone on the left, Nick's dashboard on the right. Both pages refresh themselves when the other acts.
        return new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Client + Nick, side by side</title>
<style>
  html, body { margin: 0; height: 100%; background: #1d2b24; font-family: -apple-system, Segoe UI, Arial, sans-serif; overflow: hidden; }
  #stage { position: absolute; top: 0; left: 0; display: flex; gap: 24px; padding: 16px; transform-origin: 0 0; }
  .col { display: flex; flex-direction: column; gap: 8px; }
  .label { color: #f6d9a0; font-size: 13px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; display: flex; justify-content: space-between; gap: 12px; }
  .label a { color: #9fc7b3; font-weight: 600; text-transform: none; letter-spacing: 0; text-decoration: none; }
  iframe { border: 0; background: #f4f6f0; border-radius: 10px; box-shadow: 0 20px 50px -20px #000; }
  #client { width: 390px; } #nick { width: 1100px; }
</style>
<div id="stage">
  <div class="col"><div class="label">Client's phone <a href="/#checkout" target="client">New request</a></div><iframe id="client" name="client" src="/#checkout"></iframe></div>
  <div class="col"><div class="label">Nick's dashboard <a href="/__mock" target="_blank">Sample orders</a></div><iframe id="nick" name="nick" src="/admin.html"></iframe></div>
</div>
<script>
  // Lay both screens out at real size, then shrink the whole stage to fit the window.
  const stage = document.getElementById('stage');
  function fit() {
    const h = 900;
    document.querySelectorAll('iframe').forEach(f => { f.style.height = h + 'px'; });
    const scale = Math.min(1, innerWidth / stage.scrollWidth, innerHeight / stage.scrollHeight);
    stage.style.transform = 'scale(' + scale + ')';
  }
  addEventListener('resize', fit); fit();
</script>`, { headers: { 'content-type': 'text/html; charset=utf-8' } });
    }
    if (route === '__mock-login') {
        const clientAddr = url.searchParams.get('client');
        const adminAddr = url.searchParams.get('admin');
        if (clientAddr) {
            if (!clients.has(clientAddr)) clients.set(clientAddr, { name: clientAddr === DEVTEAM_EMAIL ? 'Dev Team Tester' : 'Demo Client', firm: 'Partnership With Media', email: clientAddr });
            const t = token();
            clientSessions.set(t, clientAddr);
            return new Response(null, { status: 302, headers: { location: '/account.html', 'set-cookie': `nps_client=${t}; Path=/api/client; HttpOnly; SameSite=Strict` } });
        }
        if (adminAddr && MOCK_ADMIN_EMAILS.includes(adminAddr)) {
            const t = token();
            sessions.add(t);
            sessionEmails.set(t, adminAddr);
            return new Response(null, { status: 302, headers: { location: '/admin.html', 'set-cookie': `nps_admin=${t}; Path=/api/admin; HttpOnly; SameSite=Strict` } });
        }
        return new Response(null, { status: 302, headers: { location: '/__mock' } });
    }
    if (route === '__mock') {
        const sorted = [...orders.values()].sort((a, b) => b.created_at.localeCompare(a.created_at));
        const byCode = Object.fromEntries(sorted.map(o => [o.code, o]));
        const linkFor = code => byCode[code] ? `/track.html#t=${encodeURIComponent(byCode[code].track_token)}` : '/__mock';
        const rows = sorted.map(o => `
            <tr><td style="padding:10px 8px;border-bottom:1px solid #e3e8e5;font-weight:600">${o.code}</td><td style="padding:10px 8px;border-bottom:1px solid #e3e8e5">${STATUSES[o.status].label}</td><td style="padding:10px 8px;border-bottom:1px solid #e3e8e5">${escape(o.recipient_name)}</td>
            <td style="padding:10px 8px;border-bottom:1px solid #e3e8e5"><a href="/track.html#t=${encodeURIComponent(o.track_token)}" style="color:#0d422e;font-weight:600">Client tracking page</a> · <a href="/admin.html#${o.id}" style="color:#0d422e;font-weight:600">Nick’s view</a></td></tr>`).join('');
        const btn = 'display:inline-block;padding:9px 13px;margin:6px 6px 0 0;background:#0d422e;color:#f6e9cc;border:1px solid #0d422e;border-radius:3px;font-size:13px;font-weight:600;text-decoration:none';
        const btnAlt = 'display:inline-block;padding:9px 13px;margin:6px 6px 0 0;background:#fff;color:#0d422e;border:1px solid #0d422e;border-radius:3px;font-size:13px;font-weight:600;text-decoration:none';
        return page('Interactive Demo Hub | Nick’s Process Services', `
            <div style="display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:12px;margin-bottom:8px">
                <h1 style="margin:0;font-size:26px;color:#0d422e">Interactive Demo Hub</h1>
                <a href="/" style="color:#0d422e;font-weight:700;font-size:14px">Open Front Website &rarr;</a>
            </div>
            <p style="color:#42544b;margin:0 0 18px;font-size:14px;line-height:1.5">Try the complete client and staff workflow locally. No real emails or charges are sent while in demo mode.</p>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:18px">
                <div style="border:1px solid #d6ded8;border-radius:6px;padding:16px;background:#fafbf9">
                    <h2 style="margin:0 0 6px;font-size:17px;color:#0d422e">1. Try as a Client</h2>
                    <p style="margin:0 0 10px;font-size:13px;color:#555">One-click sign-in to the private client portal (manual code: <b>${MOCK_CLIENT_CODE}</b>).</p>
                    <a href="/__mock-login?client=paralegal%40example.com" style="${btn}">Sign in as Jordan Vance (5 requests)</a>
                    <a href="/__mock-login?client=${encodeURIComponent(DEVTEAM_EMAIL)}" style="${btnAlt}">Sign in as ${DEVTEAM_EMAIL}</a>
                    <p style="margin:10px 0 0;font-size:13px"><a href="/account.html" style="color:#0d422e">Manual Client Login</a> · <a href="/#checkout" style="color:#0d422e">New Service Request</a> · <a href="/__mock-split" style="color:#0d422e">Side-by-Side Split View</a></p>
                </div>
                <div style="border:1px solid #d6ded8;border-radius:6px;padding:16px;background:#fafbf9">
                    <h2 style="margin:0 0 6px;font-size:17px;color:#0d422e">2. Try as Nick (Staff Dashboard)</h2>
                    <p style="margin:0 0 10px;font-size:13px;color:#555">One-click sign-in to Nick’s dashboard (manual code: <b>${MOCK_ADMIN_CODE}</b> or backup code).</p>
                    <a href="/__mock-login?admin=${encodeURIComponent(ADMIN_EMAIL)}" style="${btn}">Open Dashboard as Nick</a>
                    <a href="/__mock-login?admin=${encodeURIComponent(DEVTEAM_EMAIL)}" style="${btnAlt}">Open as ${DEVTEAM_EMAIL}</a>
                    <p style="margin:10px 0 0;font-size:13px"><a href="/admin.html" style="color:#0d422e">Manual Staff Login Screen</a></p>
                </div>
            </div>
            <div style="border:1px solid #d8b46b;background:#fffbf0;border-radius:6px;padding:16px;margin-bottom:20px">
                <h2 style="margin:0 0 8px;font-size:16px;color:#0d422e">Guided 4-Step End-to-End Walkthrough</h2>
                <ol style="margin:0;padding-left:20px;font-size:13.5px;line-height:1.7;color:#2c3a33">
                    <li><b>Reply to an “Action required” request:</b> Open <a href="${linkFor('NP-649025')}" style="color:#0d422e;font-weight:600">NP-649025 (Dana Whitfield)</a>, add the apartment number, and click <i>Send to Nick</i>.</li>
                    <li><b>Complete a simulated payment:</b> Open <a href="${linkFor('NP-403182')}" style="color:#0d422e;font-weight:600">NP-403182 (Pacific Harbor Logistics LLC)</a>, click <i>Pay Securely</i>, and simulate the $175.00 payment.</li>
                    <li><b>Work the queue as Nick:</b> Click <i>Open Dashboard as Nick</i> above to see <i>Client replied</i> &amp; <i>Paid</i>, log an attempt, upload Proof of Service, or open <i>Security &amp; App</i> in the top bar.</li>
                    <li><b>Verify Proof of Service &amp; SHA-256 badge:</b> Open <a href="${linkFor('NP-894771')}" style="color:#0d422e;font-weight:600">NP-894771 (Alicia Moreno — Served)</a> to see the Proof of Service PDF and its verified SHA-256 chain-of-custody fingerprint.</li>
                </ol>
            </div>
            <h2 style="margin:0 0 8px;font-size:16px;color:#0d422e">Sample Service Requests</h2>
            <table style="border-collapse:collapse;font-size:14px;width:100%">${rows}</table>`, 820);
    }
    return null;
}

const escape = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const page = (title, body, width = 420) => new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<body style="margin:0;background:#f4f6f0;font-family:-apple-system,Segoe UI,Arial,sans-serif;color:#1a1a1a"><div style="max-width:${width}px;margin:48px auto;padding:28px;background:#fff;border:1px solid #ddd;border-radius:8px">${body}</div></body>`,
    { headers: { 'content-type': 'text/html; charset=utf-8' } });

// --- Sample orders, one in each state a client can see ---
function createOrder(fields, createdAt = now()) {
    const o = {
        id: randomUUID(), code: 'NP-' + randomInt(100000, 1000000), track_token: token(), status: 'received',
        created_at: createdAt, updated_at: createdAt, amount_due_cents: null, payment_url: null, stripe_session_id: null,
        paid_at: null, action_note: null, served_at: null, ...fields,
    };
    orders.set(o.id, o);
    return o;
}

function samplePdf(line) {
    const stream = `BT /F1 20 Tf 72 700 Td (${line.replace(/[()\\]/g, '')}) Tj ET`;
    const objs = ['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
        `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'];
    let out = '%PDF-1.4\n';
    const offsets = objs.map((o, i) => { const at = out.length; out += `${i + 1} 0 obj\n${o}\nendobj\n`; return at; });
    const xref = out.length;
    out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offsets.map(o => String(o).padStart(10, '0') + ' 00000 n \n').join('')}`;
    out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
    return Buffer.from(out, 'latin1');
}
function sampleFile(orderId, kind, filename, at) {
    const data = samplePdf(`Sample file: ${filename}`);
    const id = randomUUID();
    const sha256 = sha256Hex(data);
    files.set(id, { id, order_id: orderId, kind, filename, size_bytes: data.length, content_type: 'application/pdf', sha256, uploaded: true, data, created_at: at });
    return files.get(id);
}

(function seed() {
    clients.set('paralegal@example.com', { name: 'Jordan Vance', firm: 'Vance & Ortiz LLP', email: 'paralegal@example.com' });
    clients.set(DEVTEAM_EMAIL, { name: 'Dev Team Tester', firm: 'Partnership With Media', email: DEVTEAM_EMAIL });

    const ago = (h) => new Date(Date.now() - h * 3600e3).toISOString();
    const inDays = (d) => new Date(Date.now() + d * 864e5).toISOString().slice(0, 10);
    const base = { client_firm: 'Vance & Ortiz LLP', client_email: 'paralegal@example.com', client_phone: '(562) 555-0144', court: 'LA Superior Court, Long Beach',
        doc_type: 'Summons & Complaint', tier: 'expedited', addons: ['photo'], estimated_total_cents: 14000, city: 'Long Beach', zip: '90802' };
    const mk = (f, h) => createOrder({ ...base, case_number: '24LBCV0' + randomInt(1000, 9999), client_name: 'Jordan Vance', unit: null,
        access_notes: null, physical_notes: null, instructions: null, client_reference: null, deadline: null, ...f }, ago(h));

    const a = mk({ code: 'NP-218940', recipient_name: 'Marcus Reyes', address: '412 W Broadway', deadline: inDays(12) }, 2);
    addEvent(a.id, 'created', 'Request received', 'Expedited Service · estimate $140.00', true, ago(2));
    sampleFile(a.id, 'client_document', 'Summons-and-Complaint.pdf', ago(2));

    const b = mk({ code: 'NP-649025', recipient_name: 'Dana Whitfield', address: '1840 E 7th St', zip: '90813', status: 'action_required',
        action_note: 'The building has 24 units and the documents do not list an apartment number. Which unit does Dana live in? A gate code would help too.' }, 30);
    addEvent(b.id, 'created', 'Request received', 'Expedited Service · estimate $140.00', true, ago(30));
    addEvent(b.id, 'action', 'Action required', b.action_note, true, ago(5));

    const c = mk({ code: 'NP-403182', recipient_name: 'Pacific Harbor Logistics LLC', address: '21100 S Figueroa St', city: 'Carson', zip: '90745', doc_type: 'Subpoena (Civil, Criminal, or Federal)',
        tier: 'sameday', addons: [], estimated_total_cents: 17500, status: 'awaiting_payment', amount_due_cents: 17500, stripe_session_id: 'cs_mock_seed' }, 6);
    c.payment_url = `/__mock-pay?t=${encodeURIComponent(c.track_token)}&s=cs_mock_seed`;
    addEvent(c.id, 'created', 'Request received', 'Same-Day Rush Service · estimate $175.00', true, ago(6));
    addEvent(c.id, 'payment', 'Payment requested: $175.00', 'Same-Day Rush Service', true, ago(1));

    const d = mk({ code: 'NP-517309', recipient_name: 'Kevin Tran', address: '3300 Atlantic Ave', zip: '90807', status: 'attempting', amount_due_cents: 14000, paid_at: ago(40), deadline: inDays(3) }, 50);
    addEvent(d.id, 'created', 'Request received', 'Expedited Service · estimate $140.00', true, ago(50));
    addEvent(d.id, 'payment', 'Payment received: $140.00', null, true, ago(40));
    addEvent(d.id, 'attempt', 'Attempt: No answer', 'Lights on, car in driveway, no answer after 3 knocks.', true, ago(26));
    addEvent(d.id, 'note', 'Internal note', 'Neighbor says he leaves around 7:15am. Try early.', false, ago(25));
    addEvent(d.id, 'attempt', 'Attempt: Subject not home', 'Spoke with roommate, said he works evenings.', true, ago(4));

    const e = mk({ code: 'NP-894771', recipient_name: 'Alicia Moreno', address: '520 Pine Ave', status: 'served', amount_due_cents: 14000, paid_at: ago(100), served_at: ago(20), legal_hold: true }, 120);
    addEvent(e.id, 'created', 'Request received', 'Expedited Service · estimate $140.00', true, ago(120));
    addEvent(e.id, 'payment', 'Payment received: $140.00', null, true, ago(100));
    addEvent(e.id, 'attempt', 'Attempt: No answer', null, true, ago(70));
    addEvent(e.id, 'status', 'Served', 'Personally served at residence.', true, ago(20));
    sampleFile(e.id, 'client_document', 'Summons-and-Complaint.pdf', ago(120));
    const proof = sampleFile(e.id, 'proof', 'Proof-of-Service-Moreno.pdf', ago(19));
    addEvent(e.id, 'proof', 'Proof of service uploaded', `${proof.filename} (SHA-256: ${proof.sha256.slice(0, 12)}…)`, true, ago(19));
})();
