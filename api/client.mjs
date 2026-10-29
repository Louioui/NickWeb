// Passwordless client accounts. No admin actions and no client-supplied ownership filters.
import { db, handle, json, readJson, rateLimit, clientIp, email, text, sha256, HttpError } from './_lib/core.mjs';
import { clientAuth, clientCookie, savedClientSession, requireClient, verifiedClient, clientProfile } from './_lib/clients.mjs';
import { STATUSES, TIERS, money } from './_lib/orders.mjs';
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
        const origin = new URL(request.url).origin;
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
            const { data, error } = await auth.auth.verifyOtp({ email: addr, token: code, type: 'email' });
            if (error || !data.session) throw new HttpError(401, 'That code is invalid or expired. Please request a new email.');
            verifiedClient(data.user);
            session = data.session;
        } else {
            if (typeof body.access !== 'string' || body.access.length > 4096 || typeof body.refresh !== 'string' || body.refresh.length > 1024) throw new HttpError(401, 'This sign-in link is invalid. Please request a new email.');
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
    const { user, renewed } = await requireClient(request);
    const headers = renewed ? { 'set-cookie': clientCookie(request, renewed) } : {};
    if (action === 'me') return json({ profile: clientProfile(user) }, 200, headers);
    if (action === 'list') {
        await rateLimit(`client-list:${user.id}`, 90, 60);
        // Exact equality, not ilike: '+' addresses and wildcard characters cannot widen the query.
        const { data, error } = await db().from('orders').select('code,status,recipient_name,doc_type,tier,created_at,estimated_total_cents,amount_due_cents,paid_at,track_token')
            .eq('client_email', user.email.toLowerCase()).order('created_at', { ascending: false }).limit(100);
        if (error) throw error;
        return json({ profile: clientProfile(user), orders: data.map(o => ({ code: o.code, status: o.status, label: STATUSES[o.status]?.label || o.status,
            recipient: o.recipient_name, document: o.doc_type, service: TIERS[o.tier]?.name, created: o.created_at,
            amount: money(o.amount_due_cents ?? o.estimated_total_cents), paid: !!o.paid_at, trackUrl: `/track.html#t=${encodeURIComponent(o.track_token)}` })) }, 200, headers);
    }
    throw new HttpError(400, 'Unknown action.');
});
