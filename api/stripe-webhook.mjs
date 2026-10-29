// POST /api/stripe-webhook — Stripe tells us a checkout was paid. The signature check needs the raw body.
import { handle, json, HttpError } from './_lib/core.mjs';
import { markPaid } from './_lib/orders.mjs';
import { stripeClient } from './_lib/stripe.mjs';

export const POST = handle(async (request) => {
    const secret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!secret) throw new HttpError(503, 'Webhook not configured.');
    const raw = await request.text();
    let event;
    try {
        event = await stripeClient().webhooks.constructEventAsync(raw, request.headers.get('stripe-signature'), secret);
    } catch {
        throw new HttpError(400, 'Invalid signature.');
    }
    if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
        const s = event.data.object;
        if (s.payment_status === 'paid' && s.metadata?.order_id) await markPaid(s.metadata.order_id, s.amount_total, s.id);
    }
    return json({ received: true });
});
