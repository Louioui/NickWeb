// POST /api/request — a client submits a service request from the website.
//   { step: 'create', ...form, files: [{name, size, type}] } -> creates the order and returns upload links
//   { step: 'finish', t, fileIds }                           -> confirms uploads and sends the emails
import { db, handle, json, readJson, clientIp, siteOrigin, rateLimit, text, longText, email, phone as cleanPhone, cleanDate,
         cleanFileList, prepareUploads, confirmUploads, addEvent, randomToken, orderCode, HttpError, ADMIN_EMAILS } from './_lib/core.mjs';
import { TIERS, ADDONS, estimate, money, orderByToken, sendEmail } from './_lib/orders.mjs';

const DOC_TYPES = ['Summons & Complaint', 'Subpoena (Civil, Criminal, or Federal)', 'Writ of Garnishment', 'Small Claims Documents',
    'Eviction Notice', 'Divorce Papers', 'Child Custody & Support Order', 'Restraining Order', 'Order to Show Cause',
    'Debt Collection Notice', 'Other Legal Document'];

export const POST = handle(async (request) => {
    const body = await readJson(request);
    if (body.step === 'finish') return finish(request, body);

    // Bots fill every field, including this one that people never see.
    if (body.website) return json({ ok: true, code: 'NP-000000', trackUrl: '/' });
    await rateLimit(`request:${clientIp(request)}`, 8, 3600);

    const phone = cleanPhone(body.clientPhone);
    const zip = text(body.zip, { max: 10, required: true, label: 'ZIP code' });
    if (!/^\d{5}(-\d{4})?$/.test(zip)) throw new HttpError(400, 'Please enter a valid 5-digit ZIP code.');
    const docType = DOC_TYPES.includes(body.docType) ? body.docType : 'Other Legal Document';
    const deadline = cleanDate(body.deadline);
    const { keys: addons, cents } = estimate(body.tier, body.addons);
    if (body.acceptTerms !== true) throw new HttpError(400, 'Please accept the Terms of Service to submit your request.');
    const files = cleanFileList(body.files);

    const row = {
        code: orderCode(),
        track_token: randomToken(),
        client_name: text(body.clientName, { max: 120, required: true, label: 'Your name' }),
        client_firm: text(body.clientFirm, { max: 160 }),
        client_email: email(body.clientEmail),
        client_phone: phone,
        case_number: text(body.caseNumber, { max: 80 }),
        court: text(body.court, { max: 160 }),
        client_reference: text(body.clientReference, { max: 80 }),
        deadline,
        recipient_name: text(body.recipientName, { max: 160, required: true, label: 'Person to be served' }),
        doc_type: docType,
        address: text(body.address, { max: 200, required: true, label: 'Street address' }),
        unit: text(body.unit, { max: 40 }),
        city: text(body.city, { max: 80, required: true, label: 'City' }),
        zip,
        access_notes: longText(body.accessNotes, { max: 500, label: 'Gate code / access notes' }),
        physical_notes: longText(body.physicalNotes, { max: 1000, label: 'Description notes' }),
        instructions: longText(body.instructions, { max: 2000, label: 'Special instructions' }),
        tier: body.tier,
        addons,
        estimated_total_cents: cents,
    };

    let order = null;
    for (let attempt = 0; attempt < 4 && !order; attempt++) {      // retry on the rare duplicate NP- code
        const { data, error } = await db().from('orders').insert(row).select('id, code, track_token').single();
        if (!error) order = data;
        else if (error.code === '23505') row.code = orderCode();
        else throw error;
    }
    if (!order) throw new HttpError(500, 'Could not create your request. Please try again.');
    await addEvent(order.id, 'created', 'Request received', `${TIERS[row.tier].name} · estimate ${money(cents)}`);

    const uploads = await prepareUploads(order.id, 'client_document', files);
    return json({ ok: true, code: order.code, token: order.track_token, trackUrl: `/track.html#t=${order.track_token}`, uploads });
});

async function finish(request, body) {
    const order = await orderByToken(body.t);
    if (order.created_at < new Date(Date.now() - 60 * 60 * 1000).toISOString()) return json({ ok: true });  // only right after creating
    const uploaded = await confirmUploads(order.id, body.fileIds);
    if (uploaded.length) await addEvent(order.id, 'note', `${uploaded.length} document${uploaded.length === 1 ? '' : 's'} uploaded`);

    // Send each email once, even if the browser calls finish twice.
    const { data: already } = await db().from('order_events').select('id').eq('order_id', order.id).eq('title', 'Confirmation emailed').limit(1);
    if (already?.length) return json({ ok: true });
    await addEvent(order.id, 'note', 'Confirmation emailed', null, false);

    const origin = siteOrigin(request);
    const trackUrl = `${origin}/track.html#t=${order.track_token}`;
    const addonNames = (order.addons || []).map(k => ADDONS[k]?.name).filter(Boolean);
    await Promise.all([
        sendEmail({
            to: order.client_email,
            subject: `We received your request ${order.code}`,
            heading: `Thanks, ${order.client_name.split(' ')[0].slice(0, 40)}. Your request is in.`,
            lines: [
                `Reference: ${order.code}`,
                `Person to be served: ${order.recipient_name}`,
                `Service: ${TIERS[order.tier]?.name}${addonNames.length ? ' + ' + addonNames.join(', ') : ''} (estimate ${money(order.estimated_total_cents)})`,
                'Nick will review your documents and contact you to confirm details, the final price and timing. You can follow every step from your private tracking page. Keep this link to yourself.',
            ],
            button: { label: 'Track your request', url: trackUrl },
        }),
        ...ADMIN_EMAILS.map(to => sendEmail({
            to,
            subject: `New request ${order.code}: ${order.recipient_name} (${TIERS[order.tier]?.name})`,
            heading: 'New service request',
            lines: [
                `${order.client_name}${order.client_firm ? ` (${order.client_firm})` : ''} · ${order.client_phone} · ${order.client_email}`,
                `Serve: ${order.recipient_name} · ${order.doc_type}`,
                `Address: ${order.address}${order.unit ? ', ' + order.unit : ''}, ${order.city} ${order.zip}`,
                `Tier: ${TIERS[order.tier]?.name}${addonNames.length ? ' + ' + addonNames.join(', ') : ''} · estimate ${money(order.estimated_total_cents)}`,
                order.deadline ? `Deadline: ${order.deadline}` : 'No deadline given.',
                `${uploaded.length} document(s) attached.`,
            ],
            button: { label: 'Open in your dashboard', url: `${origin}/admin.html#${order.id}` },
        })),
    ]);
    return json({ ok: true });
}
