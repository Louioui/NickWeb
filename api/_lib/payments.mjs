// A fresh Stripe Checkout link for the amount already due, used once the old link has expired (links last 23h59m).
// Shared by Nick's dashboard and the client's tracking page. It never changes the amount, never makes a second link
// while the old one can still be paid, and records a payment the client already made instead of asking again.
import { db, addEvent, HttpError } from './core.mjs';
import { markPaid, money } from './orders.mjs';
import { createCheckout, stripeClient } from './stripe.mjs';

export async function refreshPaymentLink(order, origin) {
    if (order.paid_at) throw new HttpError(409, 'This request is already paid.');
    const cents = Number(order.amount_due_cents);
    if (!Number.isSafeInteger(cents) || cents < 100) throw new HttpError(409, 'There is no amount due yet. Nick will send a payment link.');
    if (order.stripe_session_id?.startsWith('cs_')) {
        const old = await stripeClient().checkout.sessions.retrieve(order.stripe_session_id).catch(() => null);
        if (!old) throw new HttpError(503, 'Payment status could not be checked right now. Please try again in a minute.');
        if (old.payment_status === 'paid') {
            await markPaid(order.id, old.amount_total, old.id);
            throw new HttpError(409, 'This request was already paid. Refresh to see it.');
        }
        if (old.status === 'open' && old.url) return { url: old.url, fresh: false };   // still payable: no second link
    }
    const session = await createCheckout(order, cents, null, origin);
    const { error } = await db().from('orders').update({ payment_url: session.url, stripe_session_id: session.id }).eq('id', order.id).is('paid_at', null);
    if (error) throw error;
    await addEvent(order.id, 'payment', `New payment link created: ${money(cents)}`, 'The previous link had expired.');
    return { url: session.url, fresh: true };
}
