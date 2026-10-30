// Passwordless client accounts. No admin actions and no client-supplied ownership filters.
import { db, handle, json, readJson, rateLimit, clientIp, siteOrigin, email, text, cleanOrderCode, randomToken, addEvent, sha256, hashPin, verifyPin, HttpError, ADMIN_EMAILS } from './_lib/core.mjs';
import { clientAuth, clientCookie, savedClientSession, requireClient, verifiedClient, clientProfile,
         getClientSecurity, pinLocked, recordPinFailure, clearPinFailures,
         rememberDevice, isTrustedDevice, forgetDevices, DEVICE_COOKIE, isFreshSignIn } from './_lib/clients.mjs';
import { registrationOptions, registrationVerify, loginOptions, loginVerify, listPasskeys, removePasskey, dropPasskey, clearChallengeCookie } from './_lib/passkeys.mjs';
import { STATUSES, TIERS, money, sendEmail, sendSecurityAlert } from './_lib/orders.mjs';

const PIN_LOCKED_MESSAGE = 'Account temporarily locked after repeated wrong Security PINs. Please wait 15 minutes.';
const ASK_FOR_PIN = { ok: false, requiresPin: true, message: 'Enter your 6-digit Security PIN to complete 2-step sign-in.' };

// The PIN step of both sign-in paths. It runs only after the email address has been proven (a valid code or sign-in
// link), so nobody can test PINs or lock an account with just an email address. Wrong PINs count toward the lockout.
async function checkPin(addr, sec, pin, trusted = false) {
    if (!sec?.pin_hash || trusted) return true;   // a trusted device skips the PIN, but never the email code
    if (verifyPin(String(pin || '').trim(), sec.pin_hash)) {
        await clearPinFailures(addr, sec);
        return true;
    }
    await recordPinFailure(addr);
    return false;
}

// Last step of every sign-in path: the signed session cookie, the optional trusted-device cookie, and a login alert
// when the device isn't one the client trusted.
async function finishSignIn(request, body, session, userId, signedInAs, how = '') {
    const res = json({ ok: true }, 200, { 'set-cookie': clientCookie(request, session, userId) });
    // Remember this device (optional, 30 days). A sign-in from a device that isn't trusted is announced by email.
    const deviceCookie = body.remember !== false ? await rememberDevice(request, signedInAs.addr) : null;
    if (deviceCookie) res.headers.append('set-cookie', deviceCookie);
    if (!signedInAs.trusted) {
        await sendSecurityAlert(signedInAs.addr, 'New sign-in to your account', [
            `Your account was just signed in to${how} from a device we don't recognise (${String(request.headers.get('user-agent') || 'unknown browser').slice(0, 120)}).`,
            how ? 'If this wasn\'t you, remove any passkey you don\'t recognise under Security in your account, then use "Sign out all devices", and call Nick at (209) 922-6817.'
                : 'If this was you, nothing else is needed. If it wasn\'t, use "Sign out all devices" in your account as soon as you can, and call Nick at (209) 922-6817.',
        ]);
    }
    return res;
}

// Adding or removing a passkey needs proof beyond the session cookie: the Security PIN if one is set, otherwise a
// sign-in from the last 15 minutes. So a session left open, or a copied cookie, can't plant a passkey that would outlive
// "Sign out all devices".
async function requireReauth(clientEmail, userId, fresh, pin) {
    const sec = await getClientSecurity(clientEmail);
    if (sec?.pin_hash) {
        if (pinLocked(sec)) throw new HttpError(429, PIN_LOCKED_MESSAGE);
        if (!(await checkPin(clientEmail, sec, pin))) throw new HttpError(403, 'Enter your 6-digit Security PIN to continue.');
        return;
    }
    if (!isFreshSignIn(userId, fresh)) throw new HttpError(403, 'For your safety, please sign out and sign in again, then add or remove the passkey within 15 minutes.');
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
        let userId;
        let signedInAs = null;
        if (action === 'verify-code') {
            const addr = email(body.email);
            const code = String(body.code || '').trim();
            if (!/^\d{6,8}$/.test(code)) throw new HttpError(400, 'Enter the verification code from your email.');
            await rateLimit(`client-verify-email:${sha256(addr)}`, 5, 900);

            // Asked for before the code is used, so the code is still good once the PIN is typed. This does tell someone
            // who knows the address that it has a PIN; the PIN itself is only checked after a valid code.
            const sec = await getClientSecurity(addr);
            const trusted = await isTrustedDevice(request, addr);
            if (sec?.pin_hash && !trusted && !String(body.pin || '').trim()) return json(ASK_FOR_PIN);
            if (sec?.pin_hash && pinLocked(sec)) throw new HttpError(429, PIN_LOCKED_MESSAGE);

            const { data, error } = await auth.auth.verifyOtp({ email: addr, token: code, type: 'email' });
            if (error || !data.session) throw new HttpError(401, 'That code is invalid or expired. Please request a new email.');
            verifiedClient(data.user);
            if (!(await checkPin(addr, sec, body.pin, trusted))) {
                // The code is spent; drop the session Supabase just created so it can't be used without the PIN.
                await auth.auth.admin.signOut(data.session.access_token, 'local').catch(() => {});
                throw new HttpError(401, 'Wrong Security PIN. Request a new code and try again.');
            }
            session = data.session;
            userId = data.user.id;
            signedInAs = { addr, trusted };
        } else {
            if (typeof body.access !== 'string' || !body.access || body.access.length > 4096 || /[\u0000-\u001F\u007F]/.test(body.access) ||
                typeof body.refresh !== 'string' || !body.refresh || body.refresh.length > 1024 || /[\u0000-\u001F\u007F]/.test(body.refresh)) {
                throw new HttpError(401, 'This sign-in link is invalid. Please request a new email.');
            }
            const { data, error } = await auth.auth.getUser(body.access);
            if (error) throw new HttpError(401, 'This sign-in link is invalid or expired. Please request a new email.');
            const user = verifiedClient(data.user);
            // A sign-in link proves the email just like a code, and gets the same PIN step (the browser keeps the link's
            // tokens in memory and sends them again with the PIN).
            const addr = user.email.toLowerCase();
            const sec = await getClientSecurity(addr);
            const trusted = await isTrustedDevice(request, addr);
            if (sec?.pin_hash) {
                if (pinLocked(sec)) throw new HttpError(429, PIN_LOCKED_MESSAGE);
                if (!trusted && !String(body.pin || '').trim()) return json(ASK_FOR_PIN);
                if (!(await checkPin(addr, sec, body.pin, trusted))) throw new HttpError(401, 'Wrong Security PIN. Please try again.');
            }
            session = { access_token: body.access, refresh_token: body.refresh };
            userId = user.id;
            signedInAs = { addr, trusted };
        }
        return finishSignIn(request, body, session, userId, signedInAs);
    }
    if (action === 'passkey-login-options') {
        const { options, cookie } = await loginOptions(request, 'client');
        return json({ ok: true, options }, 200, { 'set-cookie': cookie });
    }
    if (action === 'passkey-login-verify') {
        await rateLimit(`client-verify:${clientIp(request)}`, 10, 900);
        // The passkey says whose account this is (from our records). It counts as both sign-in steps, so the PIN is skipped.
        const { ownerEmail, ownerUserId, credentialId } = await loginVerify(request, 'client', body.response);
        const auth = clientAuth();
        const failed = new HttpError(401, 'That passkey could not be used to sign in. Please use your email code.');
        // The account must still exist. (Making a sign-in token would otherwise quietly create a new account for the
        // email, so a deleted client's old passkey could bring it back.)
        const { data: owner, error: oErr } = ownerUserId ? await auth.auth.admin.getUserById(ownerUserId) : { data: null, error: true };
        if (oErr || !owner?.user || String(owner.user.email || '').toLowerCase() !== ownerEmail) {
            if (!oErr || oErr.status === 404) await dropPasskey(credentialId);
            throw failed;
        }
        // A one-time sign-in token made on the server and used at once; nothing is emailed.
        const { data: link, error: lErr } = await auth.auth.admin.generateLink({ type: 'magiclink', email: ownerEmail });
        const tokenHash = link?.properties?.hashed_token;
        if (lErr || !tokenHash) throw failed;
        const { data, error } = await auth.auth.verifyOtp({ token_hash: tokenHash, type: 'magiclink' });
        if (error || !data.session) throw failed;
        const user = verifiedClient(data.user);
        if (user.id !== ownerUserId || user.email.toLowerCase() !== ownerEmail) {
            await auth.auth.admin.signOut(data.session.access_token, 'local').catch(() => {});
            throw failed;
        }
        const trusted = await isTrustedDevice(request, ownerEmail);
        const res = await finishSignIn(request, body, data.session, user.id, { addr: ownerEmail, trusted }, ' with a passkey');
        res.headers.append('set-cookie', clearChallengeCookie(request, 'client'));
        return res;
    }
    if (action === 'logout') {
        const saved = savedClientSession(request);
        if (saved?.access) await clientAuth().auth.admin.signOut(saved.access, 'local').catch(() => {});
        return json({ ok: true }, 200, { 'set-cookie': clientCookie(request, null) });
    }
    if (action === 'logout-all') {
        const saved = savedClientSession(request);
        // Look up whose devices these are before the session is signed out (afterwards the session can't be read).
        const who = await requireClient(request).then(r => r.user.email.toLowerCase(), () => null);
        if (saved?.access) await clientAuth().auth.admin.signOut(saved.access, 'global').catch(() => {});
        if (who) await forgetDevices(who);   // trusted devices stop skipping the PIN
        const res = json({ ok: true }, 200, { 'set-cookie': clientCookie(request, null) });
        res.headers.append('set-cookie', `${DEVICE_COOKIE}=; Path=/api/client; HttpOnly; SameSite=Strict; Max-Age=0`);
        return res;
    }
    const { user, renewed, fresh } = await requireClient(request);
    const headers = renewed ? { 'set-cookie': clientCookie(request, renewed, user.id, fresh) } : {};
    const clientEmail = user.email.toLowerCase();

    if (action === 'me') {
        const sec = await getClientSecurity(clientEmail);
        return json({ profile: { ...clientProfile(user), hasPin: !!sec?.pin_hash } }, 200, headers);
    }
    if (action === 'passkeys') {
        return json({ ok: true, passkeys: await listPasskeys('client', clientEmail) }, 200, headers);
    }
    if (action === 'passkey-register-options') {
        await rateLimit(`client-passkey:${user.id}`, 10, 900);
        await requireReauth(clientEmail, user.id, fresh, body.pin);
        const { options, cookie } = await registrationOptions(request, 'client', clientEmail, user.id, clientProfile(user).name);
        const res = json({ ok: true, options }, 200, headers);
        res.headers.append('set-cookie', cookie);
        return res;
    }
    if (action === 'passkey-register-verify') {
        await rateLimit(`client-passkey:${user.id}`, 10, 900);
        const added = await registrationVerify(request, 'client', clientEmail, body.response, body.label, user.id);
        await sendSecurityAlert(clientEmail, 'A passkey was added to your account', [
            `A passkey${added.label ? ` ("${added.label}")` : ''} can now be used to sign in to your account.`,
            'If you didn\'t add it, remove it under Security in your account and call Nick at (209) 922-6817.',
        ]);
        const res = json({ ok: true, passkeys: await listPasskeys('client', clientEmail) }, 200, headers);
        res.headers.append('set-cookie', clearChallengeCookie(request, 'client'));
        return res;
    }
    if (action === 'passkey-remove') {
        await rateLimit(`client-passkey:${user.id}`, 10, 900);
        await requireReauth(clientEmail, user.id, fresh, body.pin);
        await removePasskey('client', clientEmail, body.id);
        await sendSecurityAlert(clientEmail, 'A passkey was removed from your account', ['That passkey can no longer be used to sign in.']);
        return json({ ok: true, passkeys: await listPasskeys('client', clientEmail) }, 200, headers);
    }
    if (action === 'set-pin') {
        await rateLimit(`client-pin:${user.id}`, 10, 900);
        const pin = String(body.pin || '').trim();
        if (!/^\d{6}$/.test(pin)) throw new HttpError(400, 'Please enter a 6-digit numeric Security PIN.');
        // Replacing a PIN needs the current one, so a session left open on a shared computer can't change it.
        const current = await getClientSecurity(clientEmail);
        if (current?.pin_hash) {
            if (pinLocked(current)) throw new HttpError(429, PIN_LOCKED_MESSAGE);
            if (!(await checkPin(clientEmail, current, body.currentPin))) throw new HttpError(403, 'Enter your current 6-digit Security PIN to change it.');
        }
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
            if (pinLocked(sec)) throw new HttpError(429, PIN_LOCKED_MESSAGE);
            if (!(await checkPin(clientEmail, sec, body.pin))) {
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
