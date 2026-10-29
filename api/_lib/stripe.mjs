// Stripe Checkout for an order. Nick sets the final amount; the site's price is only an estimate.
import Stripe from 'stripe';
import { HttpError, sha256 } from './core.mjs';

let stripe = null;
export function stripeClient() {
    if (!stripe) {
        const key = process.env.STRIPE_SECRET_KEY;
        if (!key) {
            console.error('STRIPE_SECRET_KEY is not set.');
            throw new HttpError(503, 'Card payments are not set up yet.');
        }
        stripe = new Stripe(key);
    }
    return stripe;
}

export function checkoutParams(order, amountCents, description, origin, nowMs = Date.now()) {
    const expiresAt = Math.floor(nowMs / 1000) + 86340; // 23h 59m hard expiry matching email copy
    const minuteBucket = Math.floor(nowMs / 60000);
    const idempotencyKey = `nps-checkout-${sha256(`${order.id}:${amountCents}:${description || ''}:${minuteBucket}`)}`;
    return {
        params: {
            mode: 'payment',
            customer_email: order.client_email,
            expires_at: expiresAt,
            line_items: [{
                quantity: 1,
                price_data: {
                    currency: 'usd',
                    unit_amount: amountCents,
                    product_data: { name: `Process service ${order.code}`, description: description || undefined },
                },
            }],
            metadata: { order_id: order.id, order_code: order.code },
            payment_intent_data: { metadata: { order_id: order.id, order_code: order.code }, description: `Process service ${order.code}` },
            // Stripe fills in {CHECKOUT_SESSION_ID} (query); the private code rides after "#", so no server ever logs it.
            success_url: `${origin}/track.html?paid={CHECKOUT_SESSION_ID}#t=${order.track_token}`,
            cancel_url: `${origin}/track.html#t=${order.track_token}`,
        },
        options: { idempotencyKey },
    };
}

export async function createCheckout(order, amountCents, description, origin) {
    const { params, options } = checkoutParams(order, amountCents, description, origin);
    const session = await stripeClient().checkout.sessions.create(params, options);
    return session;
}
