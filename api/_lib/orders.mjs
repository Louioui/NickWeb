// Business rules for service requests: prices, statuses, what clients may see, and emails.
import { db, addEvent, signedDownload, uuid, HttpError, IS_PROD, ADMIN_EMAILS } from './core.mjs';

// Same prices as the pricing section on the site (dollars there, cents here). Keep the two in step.
export const TIERS = {
    standard: { name: 'Standard Service', cents: 7500 },
    expedited: { name: 'Expedited Service', cents: 12500 },
    sameday: { name: 'Same-Day Rush Service', cents: 17500 },
};
export const ADDONS = {
    photo: { name: 'Basic Photo Proof', cents: 1500 },
    photos: { name: 'Detailed Photo Documentation', cents: 4000 },
    video: { name: 'Video Proof of Service', cents: 5000 },
    mail: { name: 'Service by Certified Mail', cents: 6500 },
    stakeout: { name: 'Standard Stakeout (Up to 1 Hour)', cents: 10000 },
    coordinated: { name: 'Coordinated Service', cents: 5000 },
};

// What each status means to the client. Order here is the normal path of a job.
export const STATUSES = {
    received: { label: 'Request received', client: "Nick has your request and will review it shortly." },
    action_required: { label: 'Action required', client: 'Nick needs a little more information before he can continue.' },
    awaiting_payment: { label: 'Awaiting payment', client: 'Your request is confirmed. Pay securely to start service.' },
    paid: { label: 'Paid', client: 'Payment received. Nick will schedule your service.' },
    accepted: { label: 'Accepted', client: 'Your service is scheduled and attempts will begin soon.' },
    attempting: { label: 'Service in progress', client: 'Nick is making service attempts.' },
    served: { label: 'Served', client: 'Service is complete. Your proof of service is ready below.' },
    closed: { label: 'Closed', client: 'This request is closed.' },
    cancelled: { label: 'Cancelled', client: 'This request was cancelled.' },
};

export const money = (cents) => '$' + (cents / 100).toFixed(2);

export function estimate(tier, addonKeys) {
    if (typeof tier !== 'string' || !Object.hasOwn(TIERS, tier)) throw new HttpError(400, 'Please choose a service tier.');
    const t = TIERS[tier];
    // hasOwn, not ADDONS[k]: "constructor" or "__proto__" would otherwise pass and turn the price into NaN.
    const keys = [...new Set((Array.isArray(addonKeys) ? addonKeys : []).filter(k => typeof k === 'string' && Object.hasOwn(ADDONS, k)))];
    return { keys, cents: t.cents + keys.reduce((s, k) => s + ADDONS[k].cents, 0) };
}

const TOKEN_RE = /^[A-Za-z0-9_-]{20,64}$/;
export function cleanTrackToken(token) {
    if (typeof token !== 'string' || !TOKEN_RE.test(token)) throw new HttpError(404, 'This tracking link is not valid.');
    return token;
}

export async function orderByToken(token) {
    const safeToken = cleanTrackToken(token);
    const { data, error } = await db().from('orders').select('*').eq('track_token', safeToken).maybeSingle();
    if (error) throw error;
    if (!data) throw new HttpError(404, 'This tracking link is not valid.');
    return data;
}

const isSafePaymentUrl = (u) => typeof u === 'string' && (/^https:\/\/checkout\.stripe\.com\//i.test(u) || u.startsWith('/__mock-pay'));

// The timeline's tamper-evident seal. Each entry was chained with SHA-256 by the database when it was written;
// verify_order_chain recomputes the chain from the stored rows, so any later edit shows up as verified = false.
export async function orderSeal(orderId) {
    const { data, error } = await db().rpc('verify_order_chain', { p_order: orderId });
    if (error) throw error;
    const row = Array.isArray(data) ? data[0] : data;
    return { verified: !!row?.ok, head: row?.head || null, entries: row?.entries || 0 };
}

// Masks street numbers and apartment/suite identifiers when 2-Step Case/Document Lock is active and unverified.
export function maskAddress(order) {
    const street = String(order.address || '').replace(/^\s*\d+[A-Za-z0-9\-/]*/, '••••');
    return street + (order.city ? `, ${order.city}` : '') + (order.zip ? ` ${order.zip}` : '');
}

// The client's view of an order: no internal notes, only client-visible events and files.
// Callers must say whether this browser has unlocked a document-locked order; anything unsure gets the locked view.
// A locked view keeps the status, dates and progress, but not what was said or sent: no timeline details (they can
// hold gate codes and address changes), no "Action required" note, no file names or fingerprints.
export async function clientView(order, { unlocked = false } = {}) {
    const [{ data: events }, fileRes] = await Promise.all([
        db().from('order_events').select('created_at, kind, title, detail').eq('order_id', order.id)
            .eq('client_visible', true).order('created_at', { ascending: true }),
        db().from('order_files').select('id, kind, filename, size_bytes, sha256, created_at').eq('order_id', order.id)
            .eq('uploaded', true).order('created_at', { ascending: true }),
    ]);
    let files = fileRes.data;
    if (fileRes.error) {
        const fallback = await db().from('order_files').select('id, kind, filename, size_bytes, created_at').eq('order_id', order.id)
            .eq('uploaded', true).order('created_at', { ascending: true });
        files = fallback.data;
    }
    const isLocked = !!order.doc_lock && !unlocked;
    const fullAddr = [order.address, order.unit].filter(Boolean).join(', ') + (order.city ? `, ${order.city}` : '') + ` ${order.zip}`;
    const seal = await orderSeal(order.id);
    return {
        code: order.code,
        status: order.status,
        statusLabel: STATUSES[order.status]?.label,
        statusText: STATUSES[order.status]?.client,
        createdAt: order.created_at,
        recipient: isLocked ? String(order.recipient_name || '').replace(/^(\S+)\s+.*$/, '$1 ••••') : order.recipient_name,
        docType: order.doc_type,
        address: isLocked ? maskAddress(order) : fullAddr,
        tier: TIERS[order.tier]?.name || order.tier,
        addons: (order.addons || []).map(k => ADDONS[k]?.name).filter(Boolean),
        estimate: money(order.estimated_total_cents),
        amountDue: order.amount_due_cents != null ? money(order.amount_due_cents) : null,
        // Held (served) orders keep their status when billed afterwards, so an unpaid link alone shows the Pay button.
        payUrl: (order.status === 'awaiting_payment' || (order.legal_hold && !order.paid_at)) && isSafePaymentUrl(order.payment_url) ? order.payment_url : null,
        paidAt: order.paid_at,
        actionNote: order.status === 'action_required' && !isLocked ? order.action_note : null,
        docLock: !!order.doc_lock,
        unlocked: !isLocked,
        legalHold: !!order.legal_hold,
        integritySeal: seal,
        events: (events || []).map(e => (isLocked ? { ...e, detail: null } : e)),
        files: (files || []).map(f => ({
            id: f.id,
            kind: f.kind,
            name: isLocked ? (f.kind === 'proof' ? 'Proof of service (locked)' : 'Document (locked)') : f.filename,
            size: f.size_bytes,
            sha256: isLocked ? null : f.sha256 || null,
            at: f.created_at,
            locked: isLocked,
        })),
    };
}

export async function fileForOrder(orderId, fileId) {
    uuid(orderId, 'Order');
    uuid(fileId, 'File');
    const { data, error } = await db().from('order_files').select('storage_path, filename')
        .eq('order_id', orderId).eq('id', fileId).eq('uploaded', true).maybeSingle();
    if (error) throw error;
    if (!data) throw new HttpError(404, 'File not found.');
    return signedDownload(data.storage_path, data.filename);
}

export function canMarkPaid(order, amountCents, sessionId) {
    if (!order || order.paid_at) return false;
    if (typeof sessionId !== 'string' || !/^cs_[A-Za-z0-9_]{8,128}$/.test(sessionId)) return false;
    if (order.stripe_session_id && order.stripe_session_id !== sessionId) return false;
    const paidCents = Number(amountCents);
    if (!Number.isSafeInteger(paidCents) || paidCents <= 0) return false;
    if (order.amount_due_cents != null && paidCents < order.amount_due_cents) return false;
    return true;
}

export async function markPaid(orderId, amountCents, sessionId) {
    uuid(orderId, 'Order');
    const { data: order, error } = await db().from('orders').select('id, status, paid_at, stripe_session_id, amount_due_cents, legal_hold').eq('id', orderId).maybeSingle();
    if (error) throw error;
    if (!canMarkPaid(order, amountCents, sessionId)) return false;
    // Paying after the job was served (Nick serves first for some clients): record the money, keep the status "Served".
    // The legal hold would refuse moving a served order back to "Paid", and the webhook would then fail for days.
    const patch = { paid_at: new Date().toISOString(), stripe_session_id: sessionId, ...(order.legal_hold ? {} : { status: 'paid' }) };
    // Only the call that actually flips paid_at writes the timeline entry, so the webhook and the client's return from
    // Stripe arriving together can't log the payment twice (timeline entries can never be removed).
    const { data: changed, error: uErr } = await db().from('orders').update(patch).eq('id', orderId).is('paid_at', null).select('id');
    if (uErr) throw uErr;
    if (!changed?.length) return false;
    await addEvent(orderId, 'payment', `Payment received: ${money(Number(amountCents))}`);
    return true;
}

// A paid Stripe session that markPaid would not apply: an older link Nick replaced, less than the amount due, or a
// second payment. The client was charged, so Nick gets a private timeline entry and an email, once per session, to
// check Stripe and refund or record it. Nothing is applied automatically.
export async function flagUnappliedPayment(orderId, amountCents, sessionId) {
    uuid(orderId, 'Order');
    if (typeof sessionId !== 'string' || !/^cs_[A-Za-z0-9_]{8,128}$/.test(sessionId)) return false;
    const { data: order, error } = await db().from('orders').select('id, code, paid_at, stripe_session_id, amount_due_cents').eq('id', orderId).maybeSingle();
    if (error) throw error;
    if (!order || (order.paid_at && order.stripe_session_id === sessionId)) return false;   // the normal paid case
    const { data: earlier, error: eErr } = await db().from('order_events').select('detail').eq('order_id', orderId).eq('kind', 'payment').eq('client_visible', false);
    if (eErr) throw eErr;
    if ((earlier || []).some(e => String(e.detail || '').includes(sessionId))) return false;   // already flagged
    const paid = money(Number(amountCents) || 0);
    const reason = order.paid_at ? 'the order was already paid'
        : order.stripe_session_id && order.stripe_session_id !== sessionId ? 'it was paid on a payment link that had been replaced'
        : 'it is less than the amount due';
    await addEvent(orderId, 'payment', 'Payment needs review', `Stripe payment ${sessionId} for ${paid} was not applied because ${reason}. Check it in Stripe, then refund it or record it.`, false);
    console.error(`Unapplied Stripe payment on ${order.code}: ${sessionId} (${paid}), ${reason}`);
    await Promise.all(ADMIN_EMAILS.map(to => sendEmail({
        to, subject: `${order.code}: a payment needs your review`,
        heading: 'A payment needs your review',
        lines: [`A card payment of ${paid} on ${order.code} was not applied to the order because ${reason}.`,
            'Open Stripe to check it, then refund it or record it. The order timeline has the details.'],
    })));
    return true;
}

// --- Email (Resend). Without RESEND_API_KEY the email is printed to the server log instead (local testing). ---
const FROM = process.env.EMAIL_FROM || "Nick's Process Services <updates@nicksprocessservices.dev>";
const REPLY_TO = 'nicksprocessservices@outlook.com';

// Names and notes typed on the site go into these emails. Web addresses in them are removed, so nobody can use the
// request form to send a scam link from Nick's real address (email apps would make it clickable). Our own links
// only ever travel in the button. Email addresses are left alone.
// Any "name.ending" counts (there are 1,500+ endings: .help, .law, .ai, xn--…), except inside an email address.
// Initials like "J.R." and amounts like "$1.50" don't match: an ending needs 2+ letters and can't be followed by a letter.
const LINKISH = /\b(?:https?:\/\/|www\.)\S+|(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:[a-z]{2,}|xn--[a-z0-9-]+)(?![a-z0-9-])(?:[:\/]\S*)?/gi;
export const clean = (s, max = 600) => String(s ?? '').replace(LINKISH, '[link removed]').slice(0, max);

export async function sendEmail({ to, subject: rawSubject, heading: rawHeading, lines: rawLines, button }) {
    const subject = clean(rawSubject, 160);
    const heading = clean(rawHeading, 160);
    const lines = rawLines.map(l => clean(l));
    const html = emailHtml(heading, lines, button);
    const textBody = [heading, '', ...lines, ...(button ? ['', `${button.label}: ${button.url}`] : []), '',
        "You're receiving this because a service request was made at nicksprocessservices.dev with this email address. It's about that request only; we don't send marketing emails."].join('\n');
    const key = process.env.RESEND_API_KEY;
    if (!key) {
        // Locally the email is printed so the flow can be tested. In production it would put login codes and client details in the logs.
        if (IS_PROD) console.error(`Email not sent (RESEND_API_KEY is not set): "${subject.replace(/\d{6}/g, '######')}"`);
        else console.log(`\n[email not sent: no RESEND_API_KEY]\nTo: ${to}\nSubject: ${subject}\n${textBody}\n`);
        return;
    }
    const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
        body: JSON.stringify({ from: FROM, to: [to], reply_to: REPLY_TO, subject, html, text: textBody }),
    });
    if (!res.ok) console.error('Resend error', res.status, await res.text());
}

export async function sendSecurityAlert(to, eventTitle, detailLines = []) {
    try {
        await sendEmail({
            to,
            subject: `Security alert: ${eventTitle} — Nick's Process Services`,
            heading: `Security Notice: ${eventTitle}`,
            lines: [
                ...detailLines,
                `Timestamp (UTC): ${new Date().toISOString()}`,
                'If you performed this action, no further steps are needed. If you do not recognize this activity, rotate your emergency recovery codes and sign out all active sessions immediately.',
            ],
        });
    } catch (err) {
        console.error('Security alert email error:', err);
    }
}

const escHtml = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function emailHtml(heading, lines, button) {
    return `<!doctype html><html><body style="margin:0;background:#f3efe6;font-family:Arial,Helvetica,sans-serif;color:#1c2a22">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:28px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-top:4px solid #efa833">
<tr><td style="background:#0d422e;padding:18px 28px;color:#f6d9a0;font-size:15px;font-weight:bold;letter-spacing:.06em">NICK'S PROCESS SERVICES</td></tr>
<tr><td style="padding:28px">
<h1 style="margin:0 0 16px;font-size:22px;color:#0d422e;font-weight:normal">${escHtml(heading)}</h1>
${lines.map(l => `<p style="margin:0 0 12px;font-size:15px;line-height:1.55">${escHtml(l)}</p>`).join('')}
${button ? `<p style="margin:24px 0 8px"><a href="${escHtml(button.url)}" style="display:inline-block;background:#0d422e;color:#ffffff;text-decoration:none;padding:13px 22px;font-size:14px;font-weight:bold;letter-spacing:.04em">${escHtml(button.label)}</a></p>` : ''}
</td></tr>
<tr><td style="padding:16px 28px;border-top:1px solid #e6e0d2;font-size:12px;color:#6b6b62">Questions? Call or text Nick at (209) 922-6817 or reply to this email.<br><br>You're receiving this because a service request was made at nicksprocessservices.dev with this email address. It's a message about that request only; we don't send marketing emails. If you didn't make this request, reply and let us know.</td></tr>
</table></td></tr></table></body></html>`;
}
