// Stripe Checkout for an order. Nick sets the final amount; the site's price is only an estimate.
import Stripe from 'stripe';
import { HttpError } from './core.mjs';

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

export async function createCheckout(order, amountCents, description, origin) {
    const session = await stripeClient().checkout.sessions.create({
        mode: 'payment',
        customer_email: order.client_email,
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
        success_url: `${origin}/track.html?t=${order.track_token}&paid={CHECKOUT_SESSION_ID}`,
        cancel_url: `${origin}/track.html?t=${order.track_token}`,
    });
    return session;
}
