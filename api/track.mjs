// /api/track — the client's private tracking page (the long token in the link is the only key).
// Everything is POST with the token in the body, so it never appears in an address that servers log.
//   POST { t, action: 'view' }                     -> order status, timeline, files
//   POST { t, action: 'download', fileId }         -> short-lived download link
//   POST { t, action: 'confirm-payment', session } -> checks Stripe after the client returns from paying
//   POST { t, action: 'respond', ...fields, files }-> answers "Action required"; returns upload links
//   POST { t, action: 'respond-finish', fileIds }  -> confirms those uploads and tells Nick
import { db, handle, json, readJson, clientIp, siteOrigin, rateLimit, text, longText, cleanFileList,
         prepareUploads, confirmUploads, addEvent, uuid, HttpError, ADMIN_EMAILS } from './_lib/core.mjs';
import { orderByToken, clientView, fileForOrder, markPaid, sendEmail } from './_lib/orders.mjs';
import { stripeClient } from './_lib/stripe.mjs';

export const POST = handle(async (request) => {
    await rateLimit(`track:${clientIp(request)}`, 120, 600);
    const body = await readJson(request);
    const order = await orderByToken(body.t);

    if (body.action === 'view') {
        return json(await clientView(order));
    }

    if (body.action === 'download') {
        return json({ url: await fileForOrder(order.id, uuid(body.fileId, 'File')) });
    }

    if (body.action === 'confirm-payment') {
        if (typeof body.session !== 'string' || !body.session.startsWith('cs_')) throw new HttpError(400, 'Invalid payment session.');
        const session = await stripeClient().checkout.sessions.retrieve(body.session);
        if (session.metadata?.order_id === order.id && session.payment_status === 'paid') {
            await markPaid(order.id, session.amount_total, session.id);
        }
        return json(await clientView(await orderByToken(body.t)));
    }

    if (body.action === 'respond') {
        if (order.status !== 'action_required') throw new HttpError(409, 'Nothing is needed from you right now.');
        const changes = {};
        const address = text(body.address, { max: 200 });
        if (address) changes.address = address;
        const unit = text(body.unit, { max: 40 });
        if (unit) changes.unit = unit;
        const city = text(body.city, { max: 80 });
        if (city) changes.city = city;
        const zip = text(body.zip, { max: 10 });
        if (zip) {
            if (!/^\d{5}(-\d{4})?$/.test(zip)) throw new HttpError(400, 'Please enter a valid 5-digit ZIP code.');
            changes.zip = zip;
        }
        const access = longText(body.accessNotes, { max: 500 });
        if (access) changes.access_notes = access;
        const reply = longText(body.reply, { max: 2000, label: 'Your reply' });
        const files = cleanFileList(body.files);
        if (!Object.keys(changes).length && !reply && !files.length) throw new HttpError(400, 'Please add the missing information, a reply, or a file.');

        changes.status = 'received';
        changes.action_note = null;
        const { error } = await db().from('orders').update(changes).eq('id', order.id);
        if (error) throw error;
        const summary = [
            changes.address || changes.unit || changes.city || changes.zip ? 'Updated the service address' : null,
            changes.access_notes ? `Access notes: ${changes.access_notes}` : null,
            reply,
        ].filter(Boolean).join(' · ');
        await addEvent(order.id, 'action_response', 'You sent the requested information', summary || null);
        const uploads = await prepareUploads(order.id, 'action_upload', files);
        return json({ ok: true, uploads });
    }

    if (body.action === 'respond-finish') {
        const uploaded = await confirmUploads(order.id, body.fileIds);
        if (uploaded.length) await addEvent(order.id, 'note', `${uploaded.length} file${uploaded.length === 1 ? '' : 's'} added by you`);
        const origin = siteOrigin(request);
        await Promise.all(ADMIN_EMAILS.map(to => sendEmail({
            to,
            subject: `${order.code}: client sent the information you asked for`,
            heading: `${order.client_name} responded`,
            lines: [`Request ${order.code} (${order.recipient_name}) is back in your queue.`, uploaded.length ? `${uploaded.length} new file(s) attached.` : 'No new files.'],
            button: { label: 'Open in your dashboard', url: `${origin}/admin.html#${order.id}` },
        })));
        return json(await clientView(await orderByToken(body.t)));
    }

    throw new HttpError(400, 'Unknown action.');
});
