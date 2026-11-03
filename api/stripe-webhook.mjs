// POST /api/stripe-webhook — Stripe tells us a checkout was paid. The signature check needs the raw body.
import { handle, json, HttpError } from './_lib/core.mjs';
import { markPaid, flagUnappliedPayment, flagPaymentReversal } from './_lib/orders.mjs';
import { stripeClient } from './_lib/stripe.mjs';

export const POST = handle(async (request) => {
    const secret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!secret) throw new HttpError(503, 'Webhook not configured.');
    const raw = await request.text();
    if (raw.length > 256 * 1024) throw new HttpError(413, 'Payload too large.');
    let event;
    try {
        event = await stripeClient().webhooks.constructEventAsync(raw, request.headers.get('stripe-signature'), secret);
    } catch {
        throw new HttpError(400, 'Invalid signature.');
    }
    if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
        const s = event.data.object;
        // A paid session that can't be applied (replaced link, short amount) is flagged for Nick rather than dropped.
        if (s.payment_status === 'paid' && s.metadata?.order_id && !(await markPaid(s.metadata.order_id, s.amount_total, s.id))) {
            await flagUnappliedPayment(s.metadata.order_id, s.amount_total, s.id);
        }
    } else if (event.type === 'charge.refunded' || event.type === 'charge.dispute.created') {
        // Both carry the PaymentIntent, whose metadata names the order (set in checkoutParams). Requires these two
        // event types to be ticked on the webhook endpoint in Stripe's dashboard.
        const obj = event.data.object;
        const pi = typeof obj.payment_intent === 'string' ? obj.payment_intent : obj.payment_intent?.id;
        if (pi) {
            const intent = await stripeClient().paymentIntents.retrieve(pi);
            const orderId = intent?.metadata?.order_id;
            if (typeof orderId === 'string' && /^[0-9a-f-]{36}$/i.test(orderId)) {
                const dispute = event.type === 'charge.dispute.created';
                await flagPaymentReversal(orderId, { eventId: event.id, kind: dispute ? 'dispute' : 'refund',
                    amountCents: dispute ? obj.amount : obj.amount_refunded, reason: dispute ? obj.reason : null });
            }
        }
    }
    return json({ received: true });
});
