// Passwordless client accounts. No admin actions and no client-supplied ownership filters.
import { db, handle, json, readJson, rateLimit, clientIp, siteOrigin, email, text, cleanOrderCode, randomToken, addEvent, sha256, hashPin, verifyPin, HttpError, ADMIN_EMAILS } from './_lib/core.mjs';
import { clientAuth, clientCookie, savedClientSession, requireClient, verifiedClient, clientProfile } from './_lib/clients.mjs';
import { STATUSES, TIERS, money, sendEmail } from './_lib/orders.mjs';

// A client's PIN settings. Fails closed: if this lookup errors, sign-in stops instead of skipping the PIN.
async function getClientSecurity(emailAddr) {
    const { data, error } = await db().from('client_security_settings').select('pin_hash, failed_tries, locked_until').eq('email', emailAddr).maybeSingle();
    if (error) throw new HttpError(503, 'Sign-in is temporarily unavailable. Please try again in a minute.');
    return data || null;
}

export const POST = handle(async request => {
    const body = await readJson(request);
    const action = body.action;
    if (action === 'send-code') {
        const addr = email(body.email);
        await rateLimit(`client-email-ip:${clientIp(request)}`, 6, 900);
        await rateLimit(`client-email:${sha256(addr)}`, 3, 600);
        const signup = body.intent === 'signup';
        const name = signup ? text(body.name, { max: 120, required: true, label: 'Full name' }) : null;
        const firm = signup ? text(body.firm, { max: 160, label: 'Firm' }) : null;
        const origin = siteOrigin(request);
        const { error } = await clientAuth().auth.signInWithOtp({ email: addr, options: {
            shouldCreateUser: signup, emailRedirectTo: `${origin}/account.html`, ...(signup ? { data: { full_name: name, firm } } : {}),
        } });
        // Never reveal whether an address is registered. Configuration/provider failures stay generic.
        if (error && !['user_not_found', 'signup_disabled'].includes(error.code)) throw new HttpError(error.status === 429 ? 429 : 503, 'We could not send the verification email. Please try again later or use your tracking link.');
        return json({ ok: true });
    }
    if (action === 'verify-code' || action === 'session') {
        await rateLimit(`client-verify:${clientIp(request)}`, 10, 900);
        const auth = clientAuth();
        let session;
        if (action === 'verify-code') {
            const addr = email(body.email);
            const code = String(body.code || '').trim();
            if (!/^\d{6,8}$/.test(code)) throw new HttpError(400, 'Enter the verification code from your email.');
            await rateLimit(`client-verify-email:${sha256(addr)}`, 5, 900);

            const sec = await getClientSecurity(addr);
            if (sec?.locked_until && sec.locked_until > new Date().toISOString()) {
                throw new HttpError(429, 'Account temporarily locked after repeated failed 2FA attempts. Please wait 15 minutes.');
            }
            if (sec?.pin_hash) {
                const pin = String(body.pin || '').trim();
                if (!pin) {
                    return json({ ok: false, requiresPin: true, message: 'Enter your 6-digit Security PIN to complete 2-step sign-in.' }, 200);
                }
                if (!verifyPin(pin, sec.pin_hash)) {
                    const tries = (sec.failed_tries || 0) + 1;
                    const patch = { failed_tries: tries, updated_at: new Date().toISOString() };
                    if (tries >= 5) patch.locked_until = new Date(Date.now() + 15 * 60 * 1000).toISOString();
                    await db().from('client_security_settings').update(patch).eq('email', addr);
                    throw new HttpError(401, 'Invalid 6-digit Security PIN.');
                }
                if (sec.failed_tries > 0) {
                    await db().from('client_security_settings').update({ failed_tries: 0, locked_until: null }).eq('email', addr);
                }
            }

            const { data, error } = await auth.auth.verifyOtp({ email: addr, token: code, type: 'email' });
            if (error || !data.session) throw new HttpError(401, 'That code is invalid or expired. Please request a new email.');
            verifiedClient(data.user);
            session = data.session;
        } else {
            if (typeof body.access !== 'string' || !body.access || body.access.length > 4096 || /[\u0000-\u001F\u007F]/.test(body.access) ||
                typeof body.refresh !== 'string' || !body.refresh || body.refresh.length > 1024 || /[\u0000-\u001F\u007F]/.test(body.refresh)) {
                throw new HttpError(401, 'This sign-in link is invalid. Please request a new email.');
            }
            const { data, error } = await auth.auth.getUser(body.access);
            if (error) throw new HttpError(401, 'This sign-in link is invalid or expired. Please request a new email.');
            verifiedClient(data.user);
            session = { access_token: body.access, refresh_token: body.refresh };
        }
        return json({ ok: true }, 200, { 'set-cookie': clientCookie(request, session) });
    }
    if (action === 'logout') {
        const saved = savedClientSession(request);
        if (saved?.access) await clientAuth().auth.admin.signOut(saved.access, 'local').catch(() => {});
        return json({ ok: true }, 200, { 'set-cookie': clientCookie(request, null) });
    }
    if (action === 'logout-all') {
        const saved = savedClientSession(request);
        if (saved?.access) await clientAuth().auth.admin.signOut(saved.access, 'global').catch(() => {});
        return json({ ok: true }, 200, { 'set-cookie': clientCookie(request, null) });
    }
    const { user, renewed } = await requireClient(request);
    const headers = renewed ? { 'set-cookie': clientCookie(request, renewed) } : {};
    const clientEmail = user.email.toLowerCase();

    if (action === 'me') {
        const sec = await getClientSecurity(clientEmail);
        return json({ profile: { ...clientProfile(user), hasPin: !!sec?.pin_hash } }, 200, headers);
    }
    if (action === 'set-pin') {
        await rateLimit(`client-pin:${user.id}`, 10, 900);
        const pin = String(body.pin || '').trim();
        if (!/^\d{6}$/.test(pin)) throw new HttpError(400, 'Please enter a 6-digit numeric Security PIN.');
        const { error } = await db().from('client_security_settings').upsert({
            email: clientEmail,
            pin_hash: hashPin(pin),
            failed_tries: 0,
            locked_until: null,
            updated_at: new Date().toISOString(),
        });
        if (error) throw error;
        return json({ ok: true, hasPin: true }, 200, headers);
    }
    if (action === 'disable-pin') {
        await rateLimit(`client-pin:${user.id}`, 10, 900);
        const sec = await getClientSecurity(clientEmail);
        if (sec?.pin_hash) {
            const pin = String(body.pin || '').trim();
            if (!verifyPin(pin, sec.pin_hash)) {
                throw new HttpError(403, 'Enter your current 6-digit Security PIN to disable it.');
            }
            await db().from('client_security_settings').update({ pin_hash: null, updated_at: new Date().toISOString() }).eq('email', clientEmail);
        }
        return json({ ok: true, hasPin: false }, 200, headers);
    }
    if (action === 'rotate-token') {
        await rateLimit(`client-rotate:${user.id}`, 15, 900);
        const code = cleanOrderCode(body.code);
        const { data: order, error: oErr } = await db().from('orders').select('id, code, client_email').eq('client_email', clientEmail).eq('code', code).maybeSingle();
        if (oErr || !order) throw new HttpError(404, 'Order not found.');
        const newToken = randomToken(32);
        const { error } = await db().from('orders').update({ track_token: newToken }).eq('id', order.id);
        if (error) throw error;
        await addEvent(order.id, 'note', 'Private tracking link replaced', 'The previous link no longer works. A copy of the new link was emailed.', true);
        await sendEmail({
            to: order.client_email, subject: `${order.code}: your new private tracking link`,
            heading: 'Your tracking link was replaced',
            lines: [`You replaced the tracking link for ${order.code}. The previous link no longer works. Use the button below from now on.`,
                "If you didn't do this, call Nick at (209) 922-6817."],
            button: { label: 'Open your tracking page', url: `${siteOrigin(request)}/track.html#t=${newToken}` },
        });
        return json({ ok: true, code: order.code, trackUrl: `/track.html#t=${encodeURIComponent(newToken)}` }, 200, headers);
    }
    if (action === 'toggle-doc-lock') {
        await rateLimit(`client-doclock:${user.id}`, 20, 900);
        const code = cleanOrderCode(body.code);
        const { data: order, error: oErr } = await db().from('orders').select('id, code, doc_lock, client_email').eq('client_email', clientEmail).eq('code', code).maybeSingle();
        if (oErr || !order) throw new HttpError(404, 'Order not found.');
        const locked = body.locked !== undefined ? !!body.locked : !order.doc_lock;
        const { error } = await db().from('orders').update({ doc_lock: locked }).eq('id', order.id);
        if (error) throw error;
        await addEvent(order.id, 'note', locked ? '2-Step Document Protection enabled by client' : '2-Step Document Protection unlocked by client', null, true);
        return json({ ok: true, code: order.code, docLock: locked }, 200, headers);
    }
    if (action === 'request-purge') {
        await rateLimit(`client-purge:${user.id}`, 10, 900);
        const code = cleanOrderCode(body.code);
        const { data: order, error: oErr } = await db().from('orders').select('id, code, status, recipient_name, client_email').eq('client_email', clientEmail).eq('code', code).maybeSingle();
        if (oErr || !order) throw new HttpError(404, 'Order not found.');
        if (!['served', 'closed', 'cancelled'].includes(order.status)) {
            throw new HttpError(400, 'Confidential retention purge can only be requested on completed or closed orders.');
        }
        await addEvent(order.id, 'note', 'Client requested confidential document purge / retention seal', `Requested by verified account ${clientEmail}`, true);
        await Promise.all(ADMIN_EMAILS.map(to => sendEmail({
            to,
            subject: `${order.code}: Client requested confidential document purge`,
            heading: 'Confidential Retention Purge Request',
            lines: [
                `Verified client ${clientEmail} requested a confidential document purge for completed order ${order.code} (${order.recipient_name}).`,
                'Review the request in your dashboard to export the Chain-of-Custody record and purge stored PDFs if appropriate.',
            ],
        })));
        return json({ ok: true, code: order.code }, 200, headers);
    }
    if (action === 'list') {
        await rateLimit(`client-list:${user.id}`, 90, 60);
        const sec = await getClientSecurity(clientEmail);
        // Exact equality, not ilike: '+' addresses and wildcard characters cannot widen the query.
        let { data, error } = await db().from('orders').select('code,status,recipient_name,doc_type,tier,created_at,estimated_total_cents,amount_due_cents,paid_at,track_token,doc_lock,legal_hold')
            .eq('client_email', clientEmail).order('created_at', { ascending: false }).limit(100);
        if (error) {
            const fallback = await db().from('orders').select('code,status,recipient_name,doc_type,tier,created_at,estimated_total_cents,amount_due_cents,paid_at,track_token')
                .eq('client_email', clientEmail).order('created_at', { ascending: false }).limit(100);
            if (fallback.error) throw fallback.error;
            data = fallback.data;
        }
        return json({
            profile: { ...clientProfile(user), hasPin: !!sec?.pin_hash },
            orders: (data || []).map(o => ({
                code: o.code,
                status: o.status,
                label: STATUSES[o.status]?.label || o.status,
                recipient: o.recipient_name,
                document: o.doc_type,
                service: TIERS[o.tier]?.name,
                created: o.created_at,
                amount: money(o.amount_due_cents ?? o.estimated_total_cents),
                paid: !!o.paid_at,
                docLock: !!o.doc_lock,
                legalHold: o.status === 'served' || !!o.legal_hold,
                trackUrl: `/track.html#t=${encodeURIComponent(o.track_token)}`,
            })),
        }, 200, headers);
    }
    throw new HttpError(400, 'Unknown action.');
});
