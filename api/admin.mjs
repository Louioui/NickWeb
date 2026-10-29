// POST /api/admin { action, ... } — Nick's dashboard. Everything except the two login steps needs his session cookie.
import { randomInt } from 'node:crypto';
import { db, handle, json, readJson, clientIp, siteOrigin, rateLimit, getCookie, text, longText, email,
         sha256, randomToken, cleanFileList, prepareUploads, confirmUploads, addEvent, signedDownload,
         HttpError, ADMIN_EMAILS, IS_PROD } from './_lib/core.mjs';
import { STATUSES, TIERS, ADDONS, money, sendEmail } from './_lib/orders.mjs';
import { createCheckout } from './_lib/stripe.mjs';

const COOKIE = 'nps_admin';
const SESSION_DAYS = 14;

export const POST = handle(async (request) => {
    const body = await readJson(request);
    const a = body.action;
    if (a === 'send-code') return sendCode(request, body);
    if (a === 'verify-code') return verifyCode(request, body);

    const admin = await requireAdmin(request);
    if (a === 'me') return json({ email: admin });
    if (a === 'logout') return logout(request);
    if (a === 'list') return list();
    if (a === 'get') return json(await detail(body.id));
    if (a === 'update') return update(request, body);
    if (a === 'payment-link') return paymentLink(request, body);
    if (a === 'proof-upload') return proofUpload(body);
    if (a === 'proof-finish') return proofFinish(request, body);
    if (a === 'file-url') return fileUrl(body);
    throw new HttpError(400, 'Unknown action.');
});

// --- Login: a 6-digit code emailed to an allowed address, then a session cookie ---
async function sendCode(request, body) {
    await rateLimit(`admin-code:${clientIp(request)}`, 5, 900);
    const addr = email(body.email);
    if (ADMIN_EMAILS.includes(addr)) {
        const code = String(randomInt(0, 1000000)).padStart(6, '0');
        await db().from('admin_codes').insert({ email: addr, code_hash: sha256(`${addr}:${code}`), expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString() });
        await sendEmail({
            to: addr,
            subject: `Your dashboard login code: ${code}`,
            heading: `Your login code is ${code}`,
            lines: ['Enter this code on the dashboard login page. It expires in 10 minutes.', "If you didn't try to log in, you can ignore this email."],
        });
        if (!IS_PROD && !process.env.RESEND_API_KEY) console.log(`[dev] admin login code for ${addr}: ${code}`);
    }
    return json({ ok: true });   // same answer for any email, so the allowed address isn't revealed
}

async function verifyCode(request, body) {
    await rateLimit(`admin-verify:${clientIp(request)}`, 10, 900);
    const addr = email(body.email);
    const code = String(body.code || '').replace(/\D/g, '');
    const { data: row } = await db().from('admin_codes').select('*').eq('email', addr).eq('used', false)
        .gt('expires_at', new Date().toISOString()).order('created_at', { ascending: false }).limit(1).maybeSingle();
    if (!row || row.attempts >= 5) throw new HttpError(401, 'That code is wrong or expired. Request a new one.');
    if (row.code_hash !== sha256(`${addr}:${code}`)) {
        await db().from('admin_codes').update({ attempts: row.attempts + 1 }).eq('id', row.id);
        throw new HttpError(401, 'That code is wrong or expired. Request a new one.');
    }
    await db().from('admin_codes').update({ used: true }).eq('id', row.id);
    const token = randomToken(32);
    await db().from('admin_sessions').insert({ token_hash: sha256(token), email: addr, expires_at: new Date(Date.now() + SESSION_DAYS * 864e5).toISOString() });
    const secure = new URL(request.url).protocol === 'https:' ? ' Secure;' : '';
    return json({ ok: true }, 200, { 'set-cookie': `${COOKIE}=${token}; Path=/api/admin; HttpOnly;${secure} SameSite=Strict; Max-Age=${SESSION_DAYS * 86400}` });
}

async function requireAdmin(request) {
    const token = getCookie(request, COOKIE);
    if (!token) throw new HttpError(401, 'Please log in.');
    const { data } = await db().from('admin_sessions').select('email, expires_at').eq('token_hash', sha256(token)).maybeSingle();
    if (!data || data.expires_at < new Date().toISOString() || !ADMIN_EMAILS.includes(data.email)) throw new HttpError(401, 'Please log in.');
    return data.email;
}

async function logout(request) {
    const token = getCookie(request, COOKIE);
    if (token) await db().from('admin_sessions').delete().eq('token_hash', sha256(token));
    return json({ ok: true }, 200, { 'set-cookie': `${COOKIE}=; Path=/api/admin; HttpOnly; SameSite=Strict; Max-Age=0` });
}

// --- Jobs ---
async function list() {
    const { data, error } = await db().from('orders')
        .select('id, code, status, created_at, updated_at, client_name, client_firm, recipient_name, city, zip, tier, deadline, estimated_total_cents, amount_due_cents, paid_at')
        .order('created_at', { ascending: false }).limit(500);
    if (error) throw error;
    return json({ orders: await withClientReplied(data), statuses: STATUSES, tiers: TIERS });
}

// A job "has a client reply" when the client's answer is newer than anything Nick has done on it since.
const NICK_KINDS = ['action', 'status', 'attempt', 'payment', 'proof'];
async function withClientReplied(list) {
    if (!list.length) return list;
    const { data: evs, error } = await db().from('order_events').select('order_id, kind')
        .in('order_id', list.map(o => o.id)).in('kind', [...NICK_KINDS, 'action_response'])
        .order('created_at', { ascending: false }).limit(5000);
    if (error) throw error;
    const latest = new Map();
    for (const e of evs) if (!latest.has(e.order_id)) latest.set(e.order_id, e.kind);
    return list.map(o => ({ ...o, client_replied: latest.get(o.id) === 'action_response' }));
}

async function getOrder(id) {
    if (typeof id !== 'string') throw new HttpError(400, 'Missing order.');
    const { data, error } = await db().from('orders').select('*').eq('id', id).maybeSingle();
    if (error) throw error;
    if (!data) throw new HttpError(404, 'Order not found.');
    return data;
}

async function detail(id) {
    const order = await getOrder(id);
    const [{ data: events }, { data: files }] = await Promise.all([
        db().from('order_events').select('*').eq('order_id', id).order('created_at', { ascending: true }),
        db().from('order_files').select('id, kind, filename, size_bytes, created_at, uploaded').eq('order_id', id).order('created_at'),
    ]);
    return {
        order: { ...order, tier_name: TIERS[order.tier]?.name, addon_names: (order.addons || []).map(k => ADDONS[k]?.name).filter(Boolean) },
        events, files: (files || []).filter(f => f.uploaded), statuses: STATUSES,
    };
}

// One endpoint for Nick's job actions: change status, log an attempt, add a note, or ask the client for info.
async function update(request, body) {
    const order = await getOrder(body.id);
    const kind = body.kind;
    const note = longText(body.note, { max: 2000, label: 'Note' });
    const trackUrl = `${siteOrigin(request)}/track.html?t=${order.track_token}`;

    if (kind === 'status') {
        if (!STATUSES[body.status] || body.status === 'action_required') throw new HttpError(400, 'Choose a status.');
        const patch = { status: body.status };
        if (body.status === 'served') patch.served_at = new Date().toISOString();
        await db().from('orders').update(patch).eq('id', order.id);
        await addEvent(order.id, 'status', STATUSES[body.status].label, note, body.clientVisible !== false);
        if (body.notify) await sendEmail({
            to: order.client_email, subject: `${order.code}: ${STATUSES[body.status].label}`,
            heading: STATUSES[body.status].label,
            lines: [STATUSES[body.status].client, ...(note ? [note] : [])],
            button: { label: 'Track your request', url: trackUrl },
        });
    } else if (kind === 'attempt') {
        const outcome = text(body.outcome, { max: 120, required: true, label: 'Outcome' });
        const when = text(body.when, { max: 40 });   // blank means "now", which the entry's own timestamp already shows
        if (['received', 'paid', 'accepted'].includes(order.status)) await db().from('orders').update({ status: 'attempting' }).eq('id', order.id);
        await addEvent(order.id, 'attempt', `Attempt: ${outcome}`, [when, note].filter(Boolean).join(' · '), body.clientVisible !== false);
    } else if (kind === 'note') {
        if (!note) throw new HttpError(400, 'Write a note first.');
        await addEvent(order.id, 'note', body.clientVisible ? 'Update from Nick' : 'Internal note', note, !!body.clientVisible);
    } else if (kind === 'action') {
        if (!note) throw new HttpError(400, 'Tell the client what you need.');
        await db().from('orders').update({ status: 'action_required', action_note: note }).eq('id', order.id);
        await addEvent(order.id, 'action', 'Action required', note);
        await sendEmail({
            to: order.client_email, subject: `${order.code}: Nick needs a little more information`,
            heading: 'Action required on your request',
            lines: [note, 'Open your tracking page to send the missing details or upload a file.'],
            button: { label: 'Send the information', url: trackUrl },
        });
    } else {
        throw new HttpError(400, 'Unknown update.');
    }
    return json(await detail(order.id));
}

async function paymentLink(request, body) {
    const order = await getOrder(body.id);
    const cents = Math.round(Number(body.amount) * 100);
    if (!Number.isFinite(cents) || cents < 100 || cents > 1000000) throw new HttpError(400, 'Enter an amount between $1 and $10,000.');
    if (order.paid_at) throw new HttpError(409, 'This order is already paid.');
    const description = text(body.description, { max: 300 });
    const origin = siteOrigin(request);
    const session = await createCheckout(order, cents, description, origin);
    await db().from('orders').update({ status: 'awaiting_payment', amount_due_cents: cents, payment_url: session.url, stripe_session_id: session.id }).eq('id', order.id);
    await addEvent(order.id, 'payment', `Payment requested: ${money(cents)}`, description);
    await sendEmail({
        to: order.client_email, subject: `${order.code}: confirmed, ${money(cents)} due to start service`,
        heading: 'Your request is confirmed',
        lines: [`Total due: ${money(cents)}${description ? ` (${description})` : ''}.`, 'Payment must be sent to effectuate service. Attempts begin once payment is received.', 'Pay securely by card or Apple Pay. The link works for 24 hours; ask Nick for a new one if it expires.'],
        button: { label: `Pay ${money(cents)}`, url: session.url },
    });
    return json(await detail(order.id));
}

async function proofUpload(body) {
    const order = await getOrder(body.id);
    const files = cleanFileList(body.files);
    if (!files.length) throw new HttpError(400, 'Choose the proof of service file.');
    return json({ uploads: await prepareUploads(order.id, 'proof', files) });
}

async function proofFinish(request, body) {
    const order = await getOrder(body.id);
    const uploaded = await confirmUploads(order.id, body.fileIds);
    if (!uploaded.length) throw new HttpError(400, 'The upload did not finish. Please try again.');
    await addEvent(order.id, 'proof', 'Proof of service uploaded', uploaded.map(u => u.filename).join(', '));
    if (body.markServed) {
        await db().from('orders').update({ status: 'served', served_at: new Date().toISOString() }).eq('id', order.id);
        await addEvent(order.id, 'status', STATUSES.served.label);
    }
    await sendEmail({
        to: order.client_email, subject: `${order.code}: your proof of service is ready`,
        heading: body.markServed ? 'Service complete' : 'New document on your request',
        lines: [body.markServed ? `${order.recipient_name} has been served.` : 'Nick added a document to your request.', 'Download it from your private tracking page.'],
        button: { label: 'Download proof of service', url: `${siteOrigin(request)}/track.html?t=${order.track_token}` },
    });
    return json(await detail(order.id));
}

async function fileUrl(body) {
    const { data, error } = await db().from('order_files').select('storage_path, filename').eq('id', body.fileId).eq('uploaded', true).maybeSingle();
    if (error) throw error;
    if (!data) throw new HttpError(404, 'File not found.');
    return json({ url: await signedDownload(data.storage_path, data.filename) });
}
