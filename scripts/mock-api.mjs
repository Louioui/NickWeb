// Local-only stand-in for the real API. scripts/dev-server.mjs uses it when SUPABASE_SERVICE_ROLE_KEY is not set, so the request
// form, tracking page and dashboard can be clicked through before any keys exist. Orders live in memory and reset on restart.
// It mirrors the behavior of api/*.mjs (same request and response shapes); it is never deployed.
import { randomBytes, randomInt, randomUUID } from 'node:crypto';
import { TIERS, ADDONS, STATUSES, estimate, money } from '../api/_lib/orders.mjs';

export const MOCK_ADMIN_CODE = '12345678';
export const MOCK_CLIENT_CODE = '123456';
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
const sessions = new Set();
const sessionEmails = new Map();
const adminRecoveryCodes = new Map();

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

function addEvent(orderId, kind, title, detail = null, clientVisible = true, at = now()) {
    events.push({ id: randomUUID(), order_id: orderId, created_at: at, kind, title, detail, client_visible: clientVisible });
}

function orderByToken(t) {
    const o = [...orders.values()].find(o => o.track_token === t);
    if (!o) fail(404, 'This tracking link is not valid.');
    return o;
}

function clientView(o) {
    return {
        code: o.code, status: o.status, statusLabel: STATUSES[o.status]?.label, statusText: STATUSES[o.status]?.client,
        createdAt: o.created_at, recipient: o.recipient_name, docType: o.doc_type,
        address: [o.address, o.unit].filter(Boolean).join(', ') + `, ${o.city} ${o.zip}`,
        tier: TIERS[o.tier]?.name, addons: o.addons.map(k => ADDONS[k]?.name).filter(Boolean),
        estimate: money(o.estimated_total_cents),
        amountDue: o.amount_due_cents != null ? money(o.amount_due_cents) : null,
        payUrl: o.status === 'awaiting_payment' ? o.payment_url : null,
        paidAt: o.paid_at, actionNote: o.status === 'action_required' ? o.action_note : null,
        events: events.filter(e => e.order_id === o.id && e.client_visible).sort((a, b) => a.created_at.localeCompare(b.created_at))
            .map(({ created_at, kind, title, detail }) => ({ created_at, kind, title, detail })),
        files: [...files.values()].filter(f => f.order_id === o.id && f.uploaded)
            .map(f => ({ id: f.id, kind: f.kind, name: f.filename, size: f.size_bytes, sha256: f.sha256 || null, at: f.created_at })),
    };
}

function adminDetail(o) {
    return {
        order: { ...o, tier_name: TIERS[o.tier]?.name, addon_names: o.addons.map(k => ADDONS[k]?.name).filter(Boolean) },
        events: events.filter(e => e.order_id === o.id).sort((a, b) => a.created_at.localeCompare(b.created_at)),
        files: [...files.values()].filter(f => f.order_id === o.id && f.uploaded).map(({ data, ...f }) => f),
        statuses: STATUSES,
    };
}

function prepareUploads(orderId, kind, list) {
    if (!Array.isArray(list)) return [];
    if (list.length > 10) fail(400, 'Please attach at most 10 files.');
    return list.map(f => {
        if (!(f?.size > 0) || f.size > 25 * 1024 * 1024) fail(400, `${f?.name} is larger than 25 MB.`);
        const id = randomUUID();
        files.set(id, { id, order_id: orderId, kind, filename: String(f.name), size_bytes: f.size, content_type: f.type, sha256: null, uploaded: false, data: null, created_at: now() });
        return { fileId: id, name: f.name, uploadUrl: `/__mock-upload/${id}` };
    });
}
function confirmUploads(orderId, ids) {
    return (Array.isArray(ids) ? ids : []).map(id => files.get(id))
        .filter(f => f && f.order_id === orderId && f.data).map(f => {
            f.uploaded = true;
            if (!f.sha256) f.sha256 = sha256Hex(f.data);
            return f;
        });
}

function markPaid(o, sessionId) {
    if (o.paid_at) return;
    Object.assign(o, { status: 'paid', paid_at: now(), stripe_session_id: sessionId });
    addEvent(o.id, 'payment', `Payment received: ${money(o.amount_due_cents)}`);
}

// --- Handlers, keyed by the api/<name>.mjs they stand in for ---
const handlers = {
    async client(req, body) {
        const addr = String(body.email || '').trim().toLowerCase();
        const action = body.action;
        if (action === 'send-code') {
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(addr)) fail(400, 'Please enter a valid email.');
            if (body.intent === 'signup' && !String(body.name || '').trim()) fail(400, 'Full name is required.');
            clientCodes.set(addr, { intent: body.intent, name: String(body.name || '').trim().slice(0,120), firm: String(body.firm || '').trim().slice(0,160), expires: Date.now() + 600000, attempts: 0 });
            return json({ ok: true, demo: true });
        }
        if (action === 'verify-code') {
            const pending = clientCodes.get(addr);
            if (!pending || pending.expires < Date.now() || pending.attempts >= 5) fail(401, 'That code is invalid or expired. Request another email.');
            pending.attempts++;
            if (String(body.code) !== '123456') fail(401, 'That code is invalid or expired. Request another email.');
            if (!clients.has(addr)) {
                if (pending.intent !== 'signup') fail(401, 'That code is invalid or expired. Create an account first.');
                clients.set(addr, { name: pending.name, firm: pending.firm, email: addr });
            } else if (pending.intent === 'signup' && pending.name) {
                clients.set(addr, { name: pending.name, firm: pending.firm, email: addr });
            }
            clientCodes.delete(addr);
            const value = token(); clientSessions.set(value, addr);
            return json({ ok: true }, 200, { 'set-cookie': `nps_client=${value}; Path=/api/client; HttpOnly; SameSite=Strict` });
        }
        const value = (req.headers.get('cookie') || '').match(/(?:^|;\s*)nps_client=([^;]+)/)?.[1];
        const verifiedEmail = clientSessions.get(value);
        if (action === 'logout') { clientSessions.delete(value); return json({ ok: true }, 200, { 'set-cookie': 'nps_client=; Path=/api/client; Max-Age=0' }); }
        if (!verifiedEmail || !clients.has(verifiedEmail)) fail(401, 'Please sign in to see your requests.');
        const profile = clients.get(verifiedEmail);
        if (action === 'me') return json({ profile });
        if (action === 'list') {
            const list = [...orders.values()].filter(o => o.client_email.toLowerCase() === verifiedEmail).sort((a,b) => b.created_at.localeCompare(a.created_at)).slice(0,100);
            return json({ profile, orders: list.map(o => ({ code: o.code, status: o.status, label: STATUSES[o.status].label, recipient: o.recipient_name, document: o.doc_type,
                service: TIERS[o.tier]?.name, created: o.created_at, amount: money(o.amount_due_cents ?? o.estimated_total_cents), paid: !!o.paid_at, trackUrl: `/track.html#t=${o.track_token}` })) });
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
        for (const [k, label] of [['clientName', 'Your name'], ['clientEmail', 'Email'], ['recipientName', 'Person to be served'], ['address', 'Street address'], ['city', 'City']]) {
            if (!String(body[k] || '').trim()) fail(400, `${label} is required.`);
        }
        if (String(body.clientPhone || '').replace(/\D/g, '').length < 10) fail(400, 'Please enter a phone number with area code.');
        if (!/^\d{5}(-\d{4})?$/.test(body.zip || '')) fail(400, 'Please enter a valid 5-digit ZIP code.');
        if (body.acceptTerms !== true) fail(400, 'Please accept the Terms of Service to submit your request.');
        const { keys, cents } = estimate(body.tier, body.addons);
        const o = createOrder({
            client_name: body.clientName, client_firm: body.clientFirm || null, client_email: body.clientEmail.toLowerCase(), client_phone: body.clientPhone,
            case_number: body.caseNumber || null, court: body.court || null, client_reference: body.clientReference || null, deadline: body.deadline || null,
            recipient_name: body.recipientName, doc_type: body.docType, address: body.address, unit: body.unit || null, city: body.city, zip: body.zip,
            access_notes: body.accessNotes || null, physical_notes: body.physicalNotes || null, instructions: body.instructions || null,
            tier: body.tier, addons: keys, estimated_total_cents: cents,
        });
        addEvent(o.id, 'created', 'Request received', `${TIERS[o.tier].name} · estimate ${money(cents)}`);
        return json({ ok: true, code: o.code, token: o.track_token, trackUrl: `/track.html#t=${o.track_token}`, uploads: prepareUploads(o.id, 'client_document', body.files) });
    },

    async track(req, body, url) {
        const o = orderByToken(body.t);
        if (body.action === 'view') return json(clientView(o));
        if (body.action === 'download') {
            const f = files.get(body.fileId);
            if (!f || f.order_id !== o.id || !f.uploaded) fail(404, 'File not found.');
            return json({ url: `/__mock-file/${f.id}` });
        }
        if (body.action === 'confirm-payment') {
            if (body.session === o.stripe_session_id && o.status === 'awaiting_payment') markPaid(o, body.session);
            return json(clientView(o));
        }
        if (body.action === 'respond') {
            if (o.status !== 'action_required') fail(409, 'Nothing is needed from you right now.');
            const changes = {};
            for (const [k, col] of [['address', 'address'], ['unit', 'unit'], ['city', 'city'], ['zip', 'zip'], ['accessNotes', 'access_notes']]) {
                const v = String(body[k] || '').trim();
                if (v) changes[col] = v;
            }
            if (changes.zip && !/^\d{5}(-\d{4})?$/.test(changes.zip)) fail(400, 'Please enter a valid 5-digit ZIP code.');
            const reply = String(body.reply || '').trim();
            const fileList = Array.isArray(body.files) ? body.files : [];
            if (!Object.keys(changes).length && !reply && !fileList.length) fail(400, 'Please add the missing information, a reply, or a file.');
            Object.assign(o, changes, { status: 'received', action_note: null, updated_at: now() });
            const summary = [changes.address || changes.unit || changes.city || changes.zip ? 'Updated the service address' : null,
                changes.access_notes ? `Access notes: ${changes.access_notes}` : null, reply].filter(Boolean).join(' · ');
            addEvent(o.id, 'action_response', 'You sent the requested information', summary || null);
            return json({ ok: true, uploads: prepareUploads(o.id, 'action_upload', fileList) });
        }
        if (body.action === 'respond-finish') {
            const up = confirmUploads(o.id, body.fileIds);
            if (up.length) addEvent(o.id, 'note', `${up.length} file${up.length === 1 ? '' : 's'} added by you`);
            email(ADMIN_EMAIL, `${o.code}: client sent the information you asked for`, `/admin.html#${o.id}`);
            return json(clientView(o));
        }
        fail(400, 'Unknown action.');
    },

    async lookup(req, body) {
        const code = String(body.code || '').toUpperCase().replace(/^(NP)?-?/, 'NP-');
        const o = [...orders.values()].find(o => o.code === code && o.client_email === String(body.email || '').trim().toLowerCase());
        if (o) email(o.client_email, `Your tracking link for ${o.code}`, `/track.html#t=${o.track_token}`);
        return json({ ok: true, message: 'If that reference number and email match a request, we just emailed you its private tracking link.' });
    },

    async admin(req, body) {
        const a = body.action;
        if (a === 'send-code') {
            const addr = String(body.email || '').trim().toLowerCase();
            if (MOCK_ADMIN_EMAILS.includes(addr)) console.log(`[mock] dashboard login code for ${addr}: ${MOCK_ADMIN_CODE}`);
            return json({ ok: true });
        }
        if (a === 'verify-code') {
            const addr = String(body.email || '').trim().toLowerCase();
            if (!MOCK_ADMIN_EMAILS.includes(addr)) fail(401, 'That code is wrong or expired. Request a new one.');
            const raw = String(body.code || '').trim().toUpperCase();
            const digits = raw.replace(/\D/g, '');
            const alnum = raw.replace(/[^A-Z0-9]/g, '');
            const codes = adminRecoveryCodes.get(addr);
            let ok = digits === MOCK_ADMIN_CODE && raw.replace(/\s+/g, '') === digits;
            if (!ok && alnum.length === 8 && codes && codes.has(alnum)) {
                codes.delete(alnum);
                ok = true;
            }
            if (!ok) fail(401, 'That code is wrong or expired. Request a new one.');
            const t = token();
            sessions.add(t);
            sessionEmails.set(t, addr);
            return json({ ok: true }, 200, { 'set-cookie': `nps_admin=${t}; Path=/api/admin; HttpOnly; SameSite=Strict` });
        }
        const cookie = (req.headers.get('cookie') || '').match(/(?:^|;\s*)nps_admin=([^;]+)/)?.[1];
        if (!cookie || !sessions.has(cookie)) fail(401, 'Please log in.');
        const adminEmail = sessionEmails.get(cookie) || ADMIN_EMAIL;
        if (a === 'me') return json({ email: adminEmail, recoveryRemaining: adminRecoveryCodes.get(adminEmail)?.size || 0 });
        if (a === 'logout') {
            sessions.delete(cookie);
            sessionEmails.delete(cookie);
            return json({ ok: true }, 200, { 'set-cookie': 'nps_admin=; Path=/api/admin; Max-Age=0' });
        }
        if (a === 'logout-all') {
            for (const [tok, em] of [...sessionEmails.entries()]) {
                if (em === adminEmail) { sessions.delete(tok); sessionEmails.delete(tok); }
            }
            sessions.delete(cookie);
            return json({ ok: true }, 200, { 'set-cookie': 'nps_admin=; Path=/api/admin; Max-Age=0' });
        }
        if (a === 'generate-recovery-codes') {
            const set = new Set();
            const out = [];
            for (let i = 0; i < 8; i++) {
                let raw = '';
                for (let j = 0; j < 8; j++) raw += RECOVERY_ALPHABET[randomInt(0, RECOVERY_ALPHABET.length)];
                set.add(raw);
                out.push(`${raw.slice(0, 4)}-${raw.slice(4)}`);
            }
            adminRecoveryCodes.set(adminEmail, set);
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
            const f = files.get(body.fileId);
            if (!f?.uploaded) fail(404, 'File not found.');
            return json({ url: `/__mock-file/${f.id}` });
        }
        const o = orders.get(body.id);
        if (!o) fail(404, 'Order not found.');
        const trackUrl = `/track.html#t=${o.track_token}`;
        const note = String(body.note || '').trim() || null;
        if (a === 'get') return json(adminDetail(o));
        if (a === 'update') {
            if (body.kind === 'status') {
                if (!STATUSES[body.status] || body.status === 'action_required') fail(400, 'Choose a status.');
                o.status = body.status;
                if (body.status === 'served') o.served_at = now();
                addEvent(o.id, 'status', STATUSES[body.status].label, note, body.clientVisible !== false);
                if (body.notify) email(o.client_email, `${o.code}: ${STATUSES[body.status].label}`, trackUrl);
            } else if (body.kind === 'attempt') {
                if (!body.outcome) fail(400, 'Outcome is required.');
                if (['received', 'paid', 'accepted'].includes(o.status)) o.status = 'attempting';
                const when = body.when || null;
                addEvent(o.id, 'attempt', `Attempt: ${body.outcome}`, [when, note].filter(Boolean).join(' · '), body.clientVisible !== false);
            } else if (body.kind === 'note') {
                if (!note) fail(400, 'Write a note first.');
                addEvent(o.id, 'note', body.clientVisible ? 'Update from Nick' : 'Internal note', note, !!body.clientVisible);
            } else if (body.kind === 'action') {
                if (!note) fail(400, 'Tell the client what you need.');
                Object.assign(o, { status: 'action_required', action_note: note });
                addEvent(o.id, 'action', 'Action required', note);
                email(o.client_email, `${o.code}: Nick needs a little more information`, trackUrl);
            } else fail(400, 'Unknown update.');
            return json(adminDetail(o));
        }
        if (a === 'payment-link') {
            const cents = Math.round(Number(body.amount) * 100);
            if (!Number.isFinite(cents) || cents < 100 || cents > 1000000) fail(400, 'Enter an amount between $1 and $10,000.');
            if (o.paid_at) fail(409, 'This order is already paid.');
            const session = `cs_mock_${randomBytes(6).toString('hex')}`;
            Object.assign(o, { status: 'awaiting_payment', amount_due_cents: cents, stripe_session_id: session,
                payment_url: `/__mock-pay?t=${encodeURIComponent(o.track_token)}&s=${session}` });
            addEvent(o.id, 'payment', `Payment requested: ${money(cents)}`, String(body.description || '').trim() || null);
            email(o.client_email, `${o.code}: confirmed, ${money(cents)} due to start service`, o.payment_url);
            return json(adminDetail(o));
        }
        if (a === 'export') {
            const { track_token, payment_url, stripe_session_id, ...fields } = o;
            return json({ exported_at: now(), request: { ...fields, tier: TIERS[o.tier]?.name },
                timeline: events.filter(e => e.order_id === o.id).map(({ created_at, title, detail, client_visible }) => ({ created_at, title, detail, shown_to_client: client_visible })),
                files: [...files.values()].filter(f => f.order_id === o.id && f.uploaded).map(({ filename, kind, size_bytes, sha256, created_at }) => ({ filename, kind, size_bytes, sha256: sha256 || null, created_at })) });
        }
        if (a === 'delete') {
            if (String(body.confirm || '').trim().toUpperCase() !== o.code) fail(400, `Type ${o.code} to confirm.`);
            for (const [fid, f] of files) if (f.order_id === o.id) files.delete(fid);
            for (let i = events.length - 1; i >= 0; i--) if (events[i].order_id === o.id) events.splice(i, 1);
            orders.delete(o.id);
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
            if (body.markServed) { Object.assign(o, { status: 'served', served_at: now() }); addEvent(o.id, 'status', STATUSES.served.label); }
            email(o.client_email, `${o.code}: your proof of service is ready`, trackUrl);
            return json(adminDetail(o));
        }
        fail(400, 'Unknown action.');
    },
};

export async function handleMockApi(name, req) {
    const handler = handlers[name];
    if (!handler) return null;
    try {
        const raw = req.method === 'GET' ? '' : await req.text();
        return await handler(req, raw ? JSON.parse(raw) : {}, new URL(req.url));
    } catch (err) {
        if (err instanceof MockError) return json({ error: err.message }, err.status);
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
        const f = files.get(id);
        if (!f) return new Response('Unknown upload', { status: 404 });
        const part = (await req.formData()).get('');
        f.data = Buffer.from(await part.arrayBuffer());
        f.content_type = part.type || f.content_type;
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
    if (route === '__mock') {
        const rows = [...orders.values()].sort((a, b) => b.created_at.localeCompare(a.created_at)).map(o => `
            <tr><td style="padding:8px 10px">${o.code}</td><td style="padding:8px 10px">${STATUSES[o.status].label}</td><td style="padding:8px 10px">${escape(o.recipient_name)}</td>
            <td style="padding:8px 10px"><a href="/track.html#t=${encodeURIComponent(o.track_token)}">Client tracking page</a></td>
            <td style="padding:8px 10px"><a href="/admin.html#${o.id}">Dashboard</a></td></tr>`).join('');
        return page('Local preview', `
            <h1 style="margin:0 0 6px;font-size:24px;color:#0d422e">Local preview with sample data</h1>
            <p style="color:#555;margin:0 0 18px;font-size:14px">No database keys are set, so the site is running on in-memory sample orders (they reset when the server restarts).
            Dashboard login: <b>${ADMIN_EMAIL}</b>, code <b>${MOCK_ADMIN_CODE}</b>. <a href="/#checkout">Submit a new request</a> or <a href="/__mock-split">see the client and Nick side by side</a>.</p>
            <table style="border-collapse:collapse;font-size:14px;width:100%">${rows}</table>`, 760);
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

    const e = mk({ code: 'NP-894771', recipient_name: 'Alicia Moreno', address: '520 Pine Ave', status: 'served', amount_due_cents: 14000, paid_at: ago(100), served_at: ago(20) }, 120);
    addEvent(e.id, 'created', 'Request received', 'Expedited Service · estimate $140.00', true, ago(120));
    addEvent(e.id, 'payment', 'Payment received: $140.00', null, true, ago(100));
    addEvent(e.id, 'attempt', 'Attempt: No answer', null, true, ago(70));
    addEvent(e.id, 'status', 'Served', 'Personally served at residence.', true, ago(20));
    sampleFile(e.id, 'client_document', 'Summons-and-Complaint.pdf', ago(120));
    const proof = sampleFile(e.id, 'proof', 'Proof-of-Service-Moreno.pdf', ago(19));
    addEvent(e.id, 'proof', 'Proof of service uploaded', `${proof.filename} (SHA-256: ${proof.sha256.slice(0, 12)}…)`, true, ago(19));
})();
