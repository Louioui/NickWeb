// POST /api/lookup { code, email } — "Track Existing Serve" for clients who lost their link.
// The answer is always the same, so nobody can use this to find out which codes or emails exist;
// if both match, the private link is emailed to the address on the order.
import { db, handle, json, readJson, clientIp, siteOrigin, rateLimit, text, email } from './_lib/core.mjs';
import { sendEmail } from './_lib/orders.mjs';

export const POST = handle(async (request) => {
    await rateLimit(`lookup:${clientIp(request)}`, 6, 900);
    const body = await readJson(request);
    const code = (text(body.code, { max: 20, required: true, label: 'Reference number' }) || '').toUpperCase().replace(/^(NP)?-?/, 'NP-');
    const addr = email(body.email);
    const { data: order } = await db().from('orders').select('code, track_token, client_email, client_name')
        .eq('code', code).eq('client_email', addr).maybeSingle();
    if (order) {
        await sendEmail({
            to: order.client_email,
            subject: `Your tracking link for ${order.code}`,
            heading: 'Here is your private tracking link',
            lines: [`You (or someone using your email) asked for the tracking link for request ${order.code}.`, 'Keep this link to yourself: anyone with it can see the status of this request.'],
            button: { label: 'Track your request', url: `${siteOrigin(request)}/track.html#t=${order.track_token}` },
        });
    }
    return json({ ok: true, message: 'If that reference number and email match a request, we just emailed you its private tracking link.' });
});
