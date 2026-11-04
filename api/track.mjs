// /api/track — the client's private tracking page (the long token in the link is the only key).
// Everything is POST with the token in the body, so it never appears in an address that servers log.
//   POST { t, action: 'view' }                     -> order status, timeline, files
//   POST { t, action: 'download', fileId }         -> short-lived download link
//   POST { t, action: 'confirm-payment', session } -> checks Stripe after the client returns from paying
//   POST { t, action: 'respond', ...fields, files }-> answers Nick's question, or sends him a note on an open request;
//                                                      address changes are accepted only while Nick has asked for them
//   POST { t, action: 'respond-finish', fileIds }  -> confirms those uploads and tells Nick
//   POST { t, action: 'renew-payment-link' }       -> a fresh 24-hour payment link when the last one expired unpaid
import { randomInt } from 'node:crypto';
import { db, handle, json, readJson, clientIp, siteOrigin, rateLimit, hitRateLimit, peekRateLimit, text, longText, cleanFileList,
         prepareUploads, confirmUploads, addEvent, uuid, sha256, randomToken, timingSafeMatch, signToken, checkToken, verifyPin, HttpError, ADMIN_EMAILS, IS_PROD } from './_lib/core.mjs';
import { orderByToken, cleanTrackToken, clientView, fileForOrder, markPaid, flagUnappliedPayment, renewExpiredPaymentLink, sendEmail, logClientAction, CLIENT_NOTE_STATUSES } from './_lib/orders.mjs';
import { getClientSecurity, pinLocked } from './_lib/clients.mjs';
import { stripeClient } from './_lib/stripe.mjs';

// Unlocking a document-locked tracking page gives the browser a signed token that expires after 12 hours. It is tied
// to this order and this link, so it stops working at once if the link is replaced, and it can't be reused elsewhere.
const UNLOCK_HOURS = 12;
const unlockSubject = (order) => `${order.id}|${order.track_token}`;
const makeUnlockToken = (order) => signToken('track-unlock-v1', unlockSubject(order), UNLOCK_HOURS * 3600);
function isOrderUnlocked(order, body) {
    return !order.doc_lock || checkToken('track-unlock-v1', unlockSubject(order), body?.unlockToken);
}

export const POST = handle(async (request) => {
    const body = await readJson(request);
    cleanTrackToken(body.t);
    await rateLimit(`track:${clientIp(request)}`, 120, 600);
    const order = await orderByToken(body.t);
    const unlocked = isOrderUnlocked(order, body);

    if (body.action === 'view') {
        await logClientAction(request, order.id, 'view', unlocked ? 'unlocked page' : 'locked page');
        return json(await clientView(order, { unlocked }));
    }

    if (body.action === 'send-unlock-code') {
        await rateLimit(`track-unlock-send:${sha256(body.t)}`, 4, 900);
        const code = String(randomInt(100000, 1000000));
        const { error } = await db().from('track_unlock_codes').upsert({
            order_id: order.id,
            code_hash: sha256(`${order.id}:${code}`),
            tries: 0,
            expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
            created_at: new Date().toISOString(),
        });
        if (error) throw error;
        await sendEmail({
            to: order.client_email,
            subject: `${order.code}: Your 2-step document unlock code is ${code}`,
            heading: `Your document unlock code is ${code}`,
            lines: [
                `Enter this 6-digit code on the tracking page for ${order.code} to unlock full case details and download court documents.`,
                'This code expires in 10 minutes. You can also unlock anytime using your 6-digit Firm Security PIN.',
            ],
        });
        if (!IS_PROD && !process.env.RESEND_API_KEY) console.log(`[dev] track unlock code for ${order.code}: ${code}`);
        const maskedEmail = order.client_email.replace(/^(..).*(@.*)$/, '$1•••$2');
        return json({ ok: true, maskedEmail });
    }

    if (body.action === 'verify-unlock-code') {
        await rateLimit(`track-unlock-verify:${sha256(body.t)}`, 8, 900);
        const code = String(body.code || '').trim();
        if (!/^\d{6}$/.test(code)) throw new HttpError(400, 'Please enter a 6-digit verification code or Security PIN.');
        // 1. The client's Security PIN, if they set one. Wrong guesses here are counted on this order's own counter (5 per
        //    15 minutes), every time, so a tracking link can't be used to guess the PIN. It is separate from the portal's
        //    lockout, so someone holding a forwarded link can't lock the client out of their account.
        const sec = await getClientSecurity(order.client_email.toLowerCase());
        const pinBucket = `track-pin:${sha256(`${order.id}|${order.client_email.toLowerCase()}`)}`;
        const pinUsable = !!sec?.pin_hash && !pinLocked(sec) && (await peekRateLimit(pinBucket, 900)) < 5;
        let verified = pinUsable && verifyPin(code, sec.pin_hash);
        // 2. Otherwise the one-time code emailed to the client.
        if (!verified) {
            const { data: row, error: rowErr } = await db().from('track_unlock_codes').select('*').eq('order_id', order.id).maybeSingle();
            if (rowErr) throw rowErr;
            const codeOk = !!row && row.expires_at >= new Date().toISOString() && row.tries < 5 && timingSafeMatch(row.code_hash, sha256(`${order.id}:${code}`));
            if (!codeOk) {
                if (pinUsable) await hitRateLimit(pinBucket, 900);
                if (row) {
                    const nextTries = (row.tries || 0) + 1;
                    if (nextTries >= 5) await db().from('track_unlock_codes').delete().eq('order_id', order.id);
                    else await db().from('track_unlock_codes').update({ tries: nextTries }).eq('order_id', order.id);
                }
                throw new HttpError(401, 'That code or PIN is invalid or expired. Request a new code.');
            }
            await db().from('track_unlock_codes').delete().eq('order_id', order.id);
            verified = true;
        }
        const unlockToken = makeUnlockToken(order);
        await logClientAction(request, order.id, 'unlock');
        const view = await clientView(order, { unlocked: true });
        return json({ ok: true, unlockToken, ...view });
    }

    if (body.action === 'toggle-doc-lock') {
        await rateLimit(`track-write:${sha256(body.t)}`, 10, 900);
        if (order.doc_lock && !unlocked) {
            throw new HttpError(403, 'Unlock 2-Step Protection first before changing lock settings.');
        }
        const nextLock = body.locked !== undefined ? !!body.locked : !order.doc_lock;
        const { error } = await db().from('orders').update({ doc_lock: nextLock }).eq('id', order.id);
        if (error) throw error;
        await addEvent(order.id, 'note', nextLock ? '2-Step Document Protection enabled' : '2-Step Document Protection unlocked', null, true);
        const updatedOrder = { ...order, doc_lock: nextLock };
        const unlockToken = nextLock ? makeUnlockToken(updatedOrder) : null;
        const view = await clientView(updatedOrder, { unlocked: true });
        return json({ ok: true, unlockToken, ...view });
    }

    if (body.action === 'rotate-token') {
        await rateLimit(`track-write:${sha256(body.t)}`, 5, 900);
        if (order.doc_lock && !unlocked) {
            throw new HttpError(403, 'Verify your 2-Step code before rotating this private link.');
        }
        const newToken = randomToken(32);
        const { error } = await db().from('orders').update({ track_token: newToken }).eq('id', order.id);
        if (error) throw error;
        await addEvent(order.id, 'note', 'Private tracking link replaced', 'The previous link no longer works. A copy of the new link was emailed.', true);
        // Email a copy too, so the client still has a working link if this tab is closed.
        await sendEmail({
            to: order.client_email, subject: `${order.code}: your new private tracking link`,
            heading: 'Your tracking link was replaced',
            lines: [`You replaced the tracking link for ${order.code}. The previous link no longer works. Use the button below from now on.`,
                "If you didn't do this, call Nick at (209) 922-6817."],
            button: { label: 'Open your tracking page', url: `${siteOrigin(request)}/track.html#t=${newToken}` },
        });
        return json({ ok: true, token: newToken, trackUrl: `/track.html#t=${encodeURIComponent(newToken)}` });
    }

    if (body.action === 'download') {
        if (order.doc_lock && !unlocked) {
            throw new HttpError(403, '2-Step Document Protection is active. Verify your email code or Security PIN to download case documents.');
        }
        const fId = uuid(body.fileId, 'File');
        const url = await fileForOrder(order.id, fId);
        let fileSha256 = null;
        const { data: fRow } = await db().from('order_files').select('filename, sha256').eq('order_id', order.id).eq('id', fId).maybeSingle();
        fileSha256 = fRow?.sha256 || null;
        // Chain of custody: every document opened from the tracking page is recorded (privately) in the sealed timeline.
        await addEvent(order.id, 'note', 'Document downloaded from tracking page', fRow?.filename || null, false);
        await logClientAction(request, order.id, 'download', fRow?.filename || null);
        return json({ url, sha256: fileSha256, expiresInSeconds: 60 });
    }

    if (body.action === 'confirm-payment') {
        if (typeof body.session !== 'string' || !/^cs_[A-Za-z0-9_]{8,128}$/.test(body.session)) throw new HttpError(400, 'Invalid payment session.');
        await rateLimit(`track-pay:${sha256(body.t)}`, 10, 900);
        const session = await stripeClient().checkout.sessions.retrieve(body.session);
        if (session.metadata?.order_id === order.id && session.payment_status === 'paid') {
            if (await markPaid(order.id, session.amount_total, session.id)) await logClientAction(request, order.id, 'payment', session.id);
            else await flagUnappliedPayment(order.id, session.amount_total, session.id).catch(err => console.error(err.message));
        }
        return json(await clientView(await orderByToken(body.t), { unlocked }));
    }

    // 'renew-payment' is the name an older cached copy of track.js may still send.
    if (body.action === 'renew-payment-link' || body.action === 'renew-payment') {
        await rateLimit(`track-pay:${sha256(body.t)}`, 10, 900);
        await rateLimit(`track-renew:${sha256(body.t)}`, 3, 3600);
        const session = await renewExpiredPaymentLink(order, siteOrigin(request));
        await logClientAction(request, order.id, 'renew_payment', session.id);
        return json(await clientView(await orderByToken(body.t), { unlocked }));
    }

    if (body.action === 'respond') {
        await rateLimit(`track-write:${sha256(body.t)}`, 10, 900);
        // Nick's question can always be answered; on any other open request the client can still send a note or a
        // file (not an address change, which only Nick's question opens up). Finished requests take no new notes.
        const answeringAction = order.status === 'action_required';
        if (!CLIENT_NOTE_STATUSES.includes(order.status)) throw new HttpError(409, 'This request is finished. Call or text Nick if you need anything.');
        // A locked page can't be used to change the service address: unlock with the emailed code or PIN first.
        if (order.doc_lock && !unlocked) throw new HttpError(403, 'This request is locked. Enter the code we email you (or your Security PIN) to unlock it first.');
        const changes = {};
        const address = text(body.address, { max: 200 });
        if (address && !answeringAction) throw new HttpError(409, 'Address changes can only be sent when Nick has requested additional information. Please contact Nick for this change.');
        if (address) changes.address = address;
        const unit = text(body.unit, { max: 40 });
        if (unit && !answeringAction) throw new HttpError(409, 'Address changes can only be sent when Nick has requested additional information. Please contact Nick for this change.');
        if (unit) changes.unit = unit;
        const city = text(body.city, { max: 80 });
        if (city && !answeringAction) throw new HttpError(409, 'Address changes can only be sent when Nick has requested additional information. Please contact Nick for this change.');
        if (city) changes.city = city;
        const zip = text(body.zip, { max: 10 });
        if (zip) {
            if (!/^\d{5}(-\d{4})?$/.test(zip)) throw new HttpError(400, 'Please enter a valid 5-digit ZIP code.');
            if (!answeringAction) throw new HttpError(409, 'Address changes can only be sent when Nick has requested additional information. Please contact Nick for this change.');
            changes.zip = zip;
        }
        const access = longText(body.accessNotes, { max: 500 });
        if (access && !answeringAction) throw new HttpError(409, 'Access instructions can only be changed when Nick has requested additional information. Please contact Nick for this change.');
        if (access) changes.access_notes = access;
        const reply = longText(body.reply, { max: 2000, label: 'Your reply' });
        const files = cleanFileList(body.files);
        if (!Object.keys(changes).length && !reply && !files.length) throw new HttpError(400, 'Please add the missing information, a reply, or a file.');

        if (answeringAction) { changes.status = 'received'; changes.action_note = null; }
        if (Object.keys(changes).length) {
            const { error } = await db().from('orders').update(changes).eq('id', order.id);
            if (error) throw error;
        }
        let attemptCount = 0;
        try {
            const { count } = await db().from('order_events').select('id', { count: 'exact', head: true }).eq('order_id', order.id).eq('kind', 'attempt');
            if (typeof count === 'number') attemptCount = count;
        } catch { /* non-fatal */ }
        const amendDigest = sha256(`${order.code}|${changes.address || ''}|${changes.unit || ''}|${changes.city || ''}|${changes.zip || ''}|${changes.access_notes || ''}|${reply || ''}`).slice(0, 16);
        const summary = [
            changes.address || changes.unit || changes.city || changes.zip ? 'Updated the service address' : null,
            changes.access_notes ? `Access notes: ${changes.access_notes}` : null,
            reply,
            `[Cutoff stamp: after ${attemptCount} attempt(s) · SHA-256: ${amendDigest}]`,
        ].filter(Boolean).join(' · ');
        await addEvent(order.id, answeringAction ? 'action_response' : 'client_message', answeringAction ? 'You sent the requested information' : 'You sent Nick a message', summary || null);
        await logClientAction(request, order.id, 'reply', `${answeringAction ? 'answered Nick' : 'message'} after ${attemptCount} attempt(s)`);
        const uploads = await prepareUploads(order.id, 'action_upload', files);
        return json({ ok: true, uploads, responseType: answeringAction ? 'action_response' : 'client_message' });
    }

    if (body.action === 'respond-finish') {
        if (order.doc_lock && !unlocked) throw new HttpError(403, 'This request is locked. Unlock it first.');
        await rateLimit(`track-write:${sha256(body.t)}`, 10, 900);
        if (!CLIENT_NOTE_STATUSES.includes(order.status)) return json(await clientView(order, { unlocked }));
        const { files: uploaded, stillChecking, missing } = await confirmUploads(order.id, body.fileIds);
        // Told to the client too, so the page doesn't say "sent" for a file that isn't on the request yet.
        const fileStatus = { filesStillChecking: stillChecking, filesMissing: missing };
        if (uploaded.length) await addEvent(order.id, 'note', `${uploaded.length} file${uploaded.length === 1 ? '' : 's'} added by you`);
        const { data: recentEvents } = await db().from('order_events').select('id, kind, title, detail, created_at')
            .eq('order_id', order.id).order('created_at', { ascending: false }).order('seq', { ascending: false }).limit(20);
        const lastResponse = (recentEvents || []).find(e => e.kind === 'action_response' || e.kind === 'client_message');
        // A marker names the reply it covers, so a new reply with the same timestamp is never mistaken for an emailed one.
        // Markers without a reply id ('Reply emailed', written before client messages existed) fall back to timestamps.
        const markerDetail = lastResponse && `Emailed Nick about reply ${lastResponse.id}`;
        const emailed = lastResponse && (recentEvents || []).some(e => e.title === 'Client reply emailed' && e.detail === markerDetail
            || ((e.title === 'Reply emailed' || e.title === 'Client reply emailed') && !e.detail && e.created_at >= lastResponse.created_at));
        // One sender per reply: hit_rate_limit is an atomic upsert, so of several concurrent calls only the first sees 1.
        if (!lastResponse || emailed || await hitRateLimit(`reply-email:${lastResponse.id}`, 120) > 1) {
            return json({ ...await clientView(await orderByToken(body.t), { unlocked }), ...fileStatus });
        }
        const origin = siteOrigin(request);
        const sent = await Promise.all(ADMIN_EMAILS.map(to => sendEmail({
            to,
            subject: lastResponse?.kind === 'action_response' ? `${order.code}: client sent the information you asked for` : `${order.code}: client sent a message`,
            heading: lastResponse?.kind === 'action_response' ? `${order.client_name} responded` : `${order.client_name} sent a message`,
            lines: [`Request ${order.code} (${order.recipient_name}) is back in your queue.`, uploaded.length ? `${uploaded.length} new file(s) attached.` : 'No new files.',
                ...(stillChecking ? [`${stillChecking} more file(s) could not be checked yet; they will appear on the order once checked.`] : []),
                ...(missing ? [`${missing} file(s) did not reach storage.`] : [])],
            button: { label: 'Open in your dashboard', url: `${origin}/admin.html#${order.id}` },
        })));
        // Notification is best effort: the reply itself is already saved and flags the job on Nick's dashboard. The marker
        // records only a delivery every recipient accepted; after a failure a later call can send once the claim expires.
        if (sent.every(Boolean)) await addEvent(order.id, 'note', 'Client reply emailed', markerDetail, false);
        else console.error(`Client reply notification for ${order.code} was not accepted by every recipient`);
        return json({ ...await clientView(await orderByToken(body.t), { unlocked }), ...fileStatus });
    }

    throw new HttpError(400, 'Unknown action.');
});
