// Business rules for service requests: prices, statuses, what clients may see, and emails.
import { db, addEvent, signedDownload, uuid, HttpError, IS_PROD, ADMIN_EMAILS, clientIp, sha256, hitRateLimit } from './core.mjs';
import { createCheckout, checkoutExpiresAt, stripeClient } from './stripe.mjs';

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
export function attemptDetail(when, note) {
    if (!when) return note || null;
    if (typeof when !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(when) ||
        !Number.isFinite(Date.parse(when)) || new Date(when).toISOString() !== when ||
        Date.parse(when) > Date.now() + 5 * 60e3) {
        throw new HttpError(400, 'Enter a valid attempt time that is not in the future.');
    }
    return `Attempted at: ${when}${note ? ` · ${note}` : ''}`;
}

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

// Statuses on which the client can write to Nick from the tracking page: answering his question, or a note or file on
// any other open request. Finished requests (served, closed, cancelled) take no new notes; the client calls Nick.
export const CLIENT_NOTE_STATUSES = ['action_required', 'received', 'awaiting_payment', 'paid', 'accepted', 'attempting'];

// Only the amount captured from Stripe is suitable for a receipt. Older paid rows without that amount need review.
export function receiptForOrder(order) {
    if (!order?.paid_at || !Number.isSafeInteger(order.paid_amount_cents) || order.paid_amount_cents <= 0) return null;
    const tier = TIERS[order.tier];
    const items = tier ? [{ label: tier.name, cents: tier.cents }] : [];
    for (const key of order.addons || []) if (Object.hasOwn(ADDONS, key)) items.push({ label: ADDONS[key].name, cents: ADDONS[key].cents });
    const difference = order.paid_amount_cents - items.reduce((sum, item) => sum + item.cents, 0);
    if (difference) items.push({ label: 'Other charges or adjustments', cents: difference });
    return { code: order.code, caseNumber: order.case_number || null, court: order.court || null,
        clientReference: order.client_reference || null, clientName: order.client_name || null, clientFirm: order.client_firm || null,
        tier: tier?.name || order.tier || null, addons: (order.addons || []).map(k => ADDONS[k]?.name).filter(Boolean),
        paidAt: order.paid_at, amountPaidCents: order.paid_amount_cents, amountPaid: money(order.paid_amount_cents), items };
}

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

// Only real Stripe Checkout links are shown to clients; the local mock's /__mock-pay links never are in production.
const isSafePaymentUrl = (u) => typeof u === 'string' && (/^https:\/\/checkout\.stripe\.com\//i.test(u) || (!IS_PROD && u.startsWith('/__mock-pay')));

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
    const paymentExpired = !!order.payment_expires_at && !order.paid_at && Date.parse(order.payment_expires_at) <= Date.now();
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
        payUrl: !paymentExpired && (order.status === 'awaiting_payment' || (order.legal_hold && !order.paid_at)) && isSafePaymentUrl(order.payment_url) ? order.payment_url : null,
        paymentExpired,
        canRenewPayment: !order.paid_at && !!order.stripe_session_id && Number.isSafeInteger(order.amount_due_cents) && order.amount_due_cents > 0 &&
            (paymentExpired || !order.payment_expires_at),
        paidAt: order.paid_at,
        // Receipt details, once paid and unlocked (case details stay hidden on a locked page).
        receipt: isLocked ? null : receiptForOrder(order),
        canReply: !isLocked && CLIENT_NOTE_STATUSES.includes(order.status),
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
    const cents = Number(amountCents);
    if (!Number.isSafeInteger(cents) || cents <= 0 || typeof sessionId !== 'string' || !/^cs_[A-Za-z0-9_]{8,128}$/.test(sessionId)) return false;
    // The row lock and sealed event insert live in one Postgres transaction. If either fails, Stripe can retry safely.
    const { data, error } = await db().rpc('record_paid_order', { p_order: orderId, p_amount_cents: cents, p_session_id: sessionId });
    if (error) throw error;
    return !!data;
}

// Closes a Checkout session this request created but could not save on the order (another request or a payment got
// there first), so only one link can be paid. Never closes the session the order now holds: if Stripe ever returned the
// same session to two requests, that one is the live link.
export async function expireLosingSession(orderId, sessionId) {
    try {
        const { data: current } = await db().from('orders').select('stripe_session_id').eq('id', orderId).maybeSingle();
        if (current?.stripe_session_id === sessionId) return;
        await stripeClient().checkout.sessions.expire(sessionId);
    } catch (err) {
        console.error('Could not expire a losing payment link:', err?.message);
    }
}

export async function renewExpiredPaymentLink(order, origin) {
    if (order.paid_at) throw new HttpError(409, 'This order is already paid.');
    if (!Number.isSafeInteger(order.amount_due_cents) || order.amount_due_cents < 100 ||
        typeof order.stripe_session_id !== 'string' || !/^cs_[A-Za-z0-9_]{8,128}$/.test(order.stripe_session_id)) {
        throw new HttpError(409, 'There is no payment link to renew. Contact Nick.');
    }
    let old;
    try { old = await stripeClient().checkout.sessions.retrieve(order.stripe_session_id); }
    catch { throw new HttpError(503, 'Stripe could not check the current payment link. Try again shortly.'); }
    if (!old || old.id !== order.stripe_session_id || old.metadata?.order_id !== order.id ||
        old.amount_total !== order.amount_due_cents) {
        throw new HttpError(503, 'The current payment link could not be verified. Contact Nick.');
    }
    if (old.payment_status === 'paid') {
        await markPaid(order.id, old.amount_total, old.id);
        throw new HttpError(409, 'Your payment was already received. Refresh this page.');
    }
    if (old.status === 'open') {
        if (!Number.isSafeInteger(old.expires_at) || old.expires_at * 1000 > Date.now()) {
            throw new HttpError(409, 'The current payment link is still active.');
        }
        try { await stripeClient().checkout.sessions.expire(old.id); }
        catch { throw new HttpError(503, 'Stripe could not close the expired link. Try again shortly.'); }
    } else if (old.status !== 'expired') {
        throw new HttpError(409, 'A payment is still processing. Check again shortly.');
    }
    const session = await createCheckout(order, order.amount_due_cents, `Process service ${order.code}`, origin);
    let expiresAt;
    try { expiresAt = checkoutExpiresAt(session); }
    catch (err) { await stripeClient().checkout.sessions.expire(session.id).catch(() => {}); throw err; }
    const { data: saved, error } = await db().from('orders').update({
        stripe_session_id: session.id, payment_url: session.url, payment_expires_at: expiresAt,
    }).eq('id', order.id).eq('stripe_session_id', order.stripe_session_id).eq('amount_due_cents', order.amount_due_cents)
        .is('paid_at', null).select('id').maybeSingle();
    if (error || !saved) {
        await expireLosingSession(order.id, session.id);
        if (error) throw error;
        throw new HttpError(409, 'This payment link was already renewed. Refresh for the latest one.');
    }
    // The CAS above is the payment-link commit point. A later timeline or email failure must not make the caller
    // think renewal failed and retry a link that is already live; the client can use the returned link immediately.
    try { await addEvent(order.id, 'payment', `Payment link renewed: ${money(order.amount_due_cents)}`); }
    catch { console.error('Payment renewal timeline event failed', order.id); }
    try {
        await sendEmail({ to: order.client_email, subject: `${order.code}: your renewed payment link`,
            heading: 'Your payment link was renewed',
            lines: [`The previous link expired. The amount due is still ${money(order.amount_due_cents)}.`,
                'Use the new secure link below to pay. It expires in 24 hours.'],
            button: { label: `Pay ${money(order.amount_due_cents)}`, url: session.url } });
    } catch { console.error('Payment renewal email failed', order.id); }
    return session;
}

// A paid Stripe session that markPaid would not apply: an older link Nick replaced, less than the amount due, or a
// second payment. The client was charged, so Nick gets a private timeline entry and an email, once per session, to
// check Stripe and refund or record it. Nothing is applied automatically. The emails go out first and the timeline
// entry (which marks the session as handled) is written only if at least one was accepted; otherwise this throws, so the
// Stripe webhook answers with an error and Stripe delivers the event again later.
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
    console.error(`Unapplied Stripe payment on ${order.code}: ${sessionId} (${paid}), ${reason}`);
    const sent = await Promise.all(ADMIN_EMAILS.map(to => sendEmail({
        to, subject: `${order.code}: a payment needs your review`,
        heading: 'A payment needs your review',
        lines: [`A card payment of ${paid} on ${order.code} was not applied to the order because ${reason}.`,
            'Open Stripe to check it, then refund it or record it. The order timeline has the details.'],
    }).catch(() => false)));
    if (!sent.some(Boolean)) throw new Error(`Payment review alert for ${order.code} could not be emailed`);
    await addEvent(orderId, 'payment', 'Payment needs review', `Stripe payment ${sessionId} for ${paid} was not applied because ${reason}. Check it in Stripe, then refund it or record it.`, false);
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

// Returns whether the email was handed to Resend (callers that must know, like payment alerts, check it).
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
        return false;   // nothing was delivered, whatever was logged
    }
    const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
        body: JSON.stringify({ from: FROM, to: [to], reply_to: REPLY_TO, subject, html, text: textBody }),
    });
    if (!res.ok) console.error('Resend error', res.status, await res.text());
    return res.ok;
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

// A refund, a card dispute or an early fraud warning on an order's payment. The money moved (or may move) inside
// Stripe, so the order is never changed automatically: Nick gets a private timeline entry and an email, once per Stripe
// event, and decides what to do. The Stripe account is shared with another site, so only payments carrying one of these
// orders' ids get here. Like flagUnappliedPayment, the entry is written only after an email was accepted; otherwise this
// throws and Stripe retries. The entry names both the Stripe event and the dispute/warning, and either one already on
// the timeline counts as flagged, so a redelivered event or a second event for the same dispute isn't emailed twice.
const STRIPE_EVENT_RE = /^evt_[A-Za-z0-9_]{8,128}$/;
const STRIPE_OBJECT_RE = /^(?:dp|du|issfr|ch|re)_[A-Za-z0-9_]{1,128}$/;
export async function flagPaymentReversal(orderId, { eventId, objectId = null, kind, amountCents, reason, dueBy = null }) {
    uuid(orderId, 'Order');
    if (!['refund', 'dispute', 'fraud_warning'].includes(kind)) return false;
    const ids = [eventId, objectId].filter(id => typeof id === 'string' && (STRIPE_EVENT_RE.test(id) || STRIPE_OBJECT_RE.test(id)));
    if (!ids.length) return false;
    const { data: order, error } = await db().from('orders').select('id, code').eq('id', orderId).maybeSingle();
    if (error) throw error;
    if (!order) return false;
    const { data: earlier, error: eErr } = await db().from('order_events').select('detail').eq('order_id', orderId).eq('kind', 'payment').eq('client_visible', false);
    if (eErr) throw eErr;
    if ((earlier || []).some(e => ids.some(id => String(e.detail || '').includes(id)))) return false;   // already flagged
    // Early fraud warnings carry no amount, only the charge.
    const amount = Number.isFinite(Number(amountCents)) && amountCents != null ? money(Number(amountCents)) : null;
    const why = String(reason || 'no reason given').replaceAll('_', ' ').slice(0, 60);
    const due = Number.isSafeInteger(dueBy) && dueBy > 0
        ? new Date(dueBy * 1000).toLocaleDateString('en-US', { dateStyle: 'long', timeZone: 'America/Los_Angeles' }) : null;
    const payment = amount ? `the ${amount} payment` : 'a payment';
    const title = { refund: 'Payment refunded', dispute: 'Payment disputed', fraud_warning: 'Fraud warning on payment' }[kind];
    const subject = { refund: 'a payment was refunded', dispute: 'a payment was disputed', fraud_warning: 'a payment was flagged as possible fraud' }[kind];
    const lines = {
        // charge.refunded carries the charge's running total (amount_refunded) as of that event, not this one refund,
        // and Stripe may deliver events out of order, so it is described as of the event rather than as current.
        refund: [`When this refund happened, the card payment on ${order.code} had been refunded ${amount || '$0.00'} in total. Stripe can deliver refund events out of order, so check Stripe for the current total.`,
            'The order still shows as paid. Check Stripe and update the order if needed.'],
        dispute: [`${amount || 'The'} card payment on ${order.code} was disputed by the cardholder (${why}).`,
            due ? `Respond in Stripe before ${due}, or the dispute is lost by default.` : 'Respond to it in Stripe as soon as possible.',
            'Download the evidence pack for this order from your dashboard and upload it to the dispute in Stripe.'],
        fraud_warning: [`Stripe flagged ${payment} on ${order.code} as possibly fraudulent (${why}).`,
            'No money has been taken back yet. Consider refunding it in Stripe before it becomes a dispute.'],
    }[kind];
    console.error(`Stripe ${title.toLowerCase()} on ${order.code}: ${ids.join(' / ')}${amount ? ` (${amount})` : ''}`);
    const sent = await Promise.all(ADMIN_EMAILS.map(to => sendEmail({ to, subject: `${order.code}: ${subject}`, heading: title, lines }).catch(() => false)));
    if (!sent.some(Boolean)) throw new Error(`${title} alert for ${order.code} could not be emailed`);
    const what = kind === 'refund' ? `${amount || '$0.00'} refunded in total as of this event`
        : kind === 'dispute' ? `${amount || 'payment'} disputed (${why})${due ? `; evidence due by ${due}` : ''}`
        : `early fraud warning on ${payment} (${why})`;
    await addEvent(orderId, 'payment', title, `Stripe ${ids.join(' / ')}: ${what}. Nothing was changed on the order automatically.`, false);
    return true;
}

// The branch-era entry point for disputes and early fraud warnings; same rules, one implementation.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export async function flagDispute(orderId, eventType, obj, eventId = null) {
    if (!UUID_RE.test(String(orderId))) return false;
    const fraud = eventType === 'radar.early_fraud_warning.created';
    return flagPaymentReversal(orderId, { eventId, objectId: obj?.id ?? null, kind: fraud ? 'fraud_warning' : 'dispute',
        amountCents: fraud ? null : obj?.amount, reason: obj?.reason || obj?.fraud_type || null, dueBy: obj?.evidence_details?.due_by ?? null });
}

// Records what a client did on their tracking page, for Nick's dispute evidence. Never blocks the client: if the table
// doesn't exist yet or the write fails, the action still goes ahead.
const CLIENT_ACTIONS = new Set(['view', 'unlock', 'download', 'reply', 'payment', 'renew_payment']);
export async function logClientAction(request, orderId, action, detail = null) {
    if (!CLIENT_ACTIONS.has(action)) return;
    try {
        const ip = clientIp(request);
        if (action === 'view') {
            // A tracking page refreshes itself every 20 seconds; one view entry an hour per visitor is enough.
            const { data: n } = await db().rpc('hit_rate_limit', { p_bucket: `audit-view:${orderId}:${sha256(ip)}`, p_window_seconds: 3600 });
            if (n !== 1) return;
        }
        await db().from('client_audit_logs').insert({
            order_id: orderId, action, detail: detail ? String(detail).slice(0, 300) : null, ip_hash: sha256(ip),
            user_agent: String(request.headers.get('user-agent') || '').slice(0, 200) || null,
        }).then(() => {}, () => {});
    } catch { /* never block the client */ }
}

// A client who chose the daily summary gets no per-update status emails; the daily job sends one digest instead.
export async function prefersDigest(emailAddr) {
    const { data, error } = await db().from('client_preferences').select('notify_mode').eq('email', String(emailAddr || '').toLowerCase()).maybeSingle();
    return !error && data?.notify_mode === 'daily';
}

// The daily summary: for each client who chose it, one email listing what changed on their requests in the last day.
export async function sendDailyDigests(origin) {
    // Once per UTC day, whoever calls: Vercel can retry the cleanup job, and until CRON_SECRET is set anyone can run it.
    // The counter is an atomic database increment, so two runs at once can't both send.
    // Taken only after the preferences read succeeds, so a database hiccup doesn't use up the day's run.
    const { data: prefs, error } = await db().from('client_preferences').select('email').eq('notify_mode', 'daily').limit(500);
    if (error || !prefs?.length) return 0;
    if (await hitRateLimit('daily-digest-run', 86400) > 1) return 0;
    const since = new Date(Date.now() - 864e5).toISOString();
    let sent = 0;
    for (const { email: to } of prefs) {
        const { data: ords } = await db().from('orders').select('id, code, recipient_name, status').eq('client_email', to).limit(100);
        if (!ords?.length) continue;
        const { data: evs } = await db().from('order_events').select('order_id, title, created_at')
            .in('order_id', ords.map(o => o.id)).eq('client_visible', true).gte('created_at', since).order('created_at', { ascending: true }).limit(500);
        if (!evs?.length) continue;
        const byOrder = new Map(ords.map(o => [o.id, o]));
        const lines = [...new Set(evs.map(e => e.order_id))].map(id => {
            const o = byOrder.get(id);
            return `${o.code} (${o.recipient_name}): ${evs.filter(e => e.order_id === id).map(e => e.title).join('; ')}. Now: ${STATUSES[o.status]?.label || o.status}.`;
        });
        if (await sendEmail({ to, subject: "Your daily update from Nick's Process Services", heading: 'What changed today',
            lines: [...lines, 'Open your account to see each request.'], button: { label: 'Open your account', url: `${origin}/account.html` } }).catch(() => false)) sent++;
    }
    return sent;
}
