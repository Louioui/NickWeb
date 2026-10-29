// Business rules for service requests: prices, statuses, what clients may see, and emails.
import { db, addEvent, signedDownload, HttpError, IS_PROD } from './core.mjs';

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

export async function orderByToken(token) {
    if (typeof token !== 'string' || token.length < 20 || token.length > 64) throw new HttpError(404, 'This tracking link is not valid.');
    const { data, error } = await db().from('orders').select('*').eq('track_token', token).maybeSingle();
    if (error) throw error;
    if (!data) throw new HttpError(404, 'This tracking link is not valid.');
    return data;
}

// The client's view of an order: no internal notes, only client-visible events and files.
export async function clientView(order) {
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
    return {
        code: order.code,
        status: order.status,
        statusLabel: STATUSES[order.status]?.label,
        statusText: STATUSES[order.status]?.client,
        createdAt: order.created_at,
        recipient: order.recipient_name,
        docType: order.doc_type,
        address: [order.address, order.unit].filter(Boolean).join(', ') + (order.city ? `, ${order.city}` : '') + ` ${order.zip}`,
        tier: TIERS[order.tier]?.name || order.tier,
        addons: (order.addons || []).map(k => ADDONS[k]?.name).filter(Boolean),
        estimate: money(order.estimated_total_cents),
        amountDue: order.amount_due_cents != null ? money(order.amount_due_cents) : null,
        payUrl: order.status === 'awaiting_payment' ? order.payment_url : null,
        paidAt: order.paid_at,
        actionNote: order.status === 'action_required' ? order.action_note : null,
        events: events || [],
        files: (files || []).map(f => ({ id: f.id, kind: f.kind, name: f.filename, size: f.size_bytes, sha256: f.sha256 || null, at: f.created_at })),
    };
}

export async function fileForOrder(orderId, fileId) {
    const { data, error } = await db().from('order_files').select('storage_path, filename')
        .eq('order_id', orderId).eq('id', fileId).eq('uploaded', true).maybeSingle();
    if (error) throw error;
    if (!data) throw new HttpError(404, 'File not found.');
    return signedDownload(data.storage_path, data.filename);
}

export async function markPaid(orderId, amountCents, sessionId) {
    const { data: order, error } = await db().from('orders').select('id, status, paid_at').eq('id', orderId).maybeSingle();
    if (error) throw error;
    if (!order || order.paid_at) return false;           // already handled (webhook and redirect can both arrive)
    const { error: uErr } = await db().from('orders').update({
        status: 'paid', paid_at: new Date().toISOString(), stripe_session_id: sessionId,
    }).eq('id', orderId).is('paid_at', null);
    if (uErr) throw uErr;
    await addEvent(orderId, 'payment', `Payment received: ${money(amountCents)}`);
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
