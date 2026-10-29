// POST /api/admin { action, ... } — Nick's dashboard. Everything except the two login steps needs his session cookie.
import { randomInt } from 'node:crypto';
import { db, handle, json, readJson, clientIp, siteOrigin, rateLimit, getCookie, text, longText, email,
         sha256, randomToken, cleanFileList, prepareUploads, confirmUploads, addEvent, signedDownload, uuid,
         HttpError, ADMIN_EMAILS, IS_PROD, BUCKET, generateTotpSecret, verifyTotp, uaFingerprint, computeChainSeal, timingSafeMatch } from './_lib/core.mjs';
import { STATUSES, TIERS, ADDONS, money, sendEmail, sendSecurityAlert, markPaid } from './_lib/orders.mjs';
import { createCheckout, stripeClient } from './_lib/stripe.mjs';

const COOKIE = 'nps_admin';
const SESSION_DAYS = 14;

export const POST = handle(async (request) => {
    const body = await readJson(request);
    const a = body.action;
    if (a === 'send-code') return sendCode(request, body);
    if (a === 'verify-code') return verifyCode(request, body);

    const admin = await requireAdmin(request);
    if (a === 'me') return me(admin);
    if (a === 'logout') return logout(request, admin);
    if (a === 'logout-all') return logoutAll(request, admin);
    if (a === 'generate-recovery-codes') return generateRecoveryCodes(request, body, admin);
    if (a === 'totp-setup') return totpSetup(request, admin);
    if (a === 'totp-enable') return totpEnable(request, body, admin);
    if (a === 'totp-disable') return totpDisable(request, body, admin);
    if (a === 'list') return list();
    if (a === 'get') return json(await detail(body.id));
    if (a === 'update') return update(request, body, admin);
    if (a === 'rotate-token') return rotateToken(request, body, admin);
    if (a === 'toggle-doc-lock') return toggleDocLock(request, body, admin);
    if (a === 'unlock-legal-hold') return unlockLegalHold(request, body, admin);
    if (a === 'payment-link') return paymentLink(request, body, admin);
    if (a === 'proof-upload') return proofUpload(body);
    if (a === 'proof-finish') return proofFinish(request, body);
    if (a === 'file-url') return fileUrl(body);
    if (a === 'export') return exportOrder(request, body, admin);
    if (a === 'delete') return deleteOrder(request, body, admin);
    throw new HttpError(400, 'Unknown action.');
});

async function auditAdmin(request, emailAddr, action, targetCode = null, detailText = null) {
    try {
        await db().from('admin_audit_logs').insert({
            email: emailAddr,
            action,
            target_code: targetCode,
            detail: detailText,
            ip_hash: sha256(clientIp(request)),
        });
    } catch { /* non-fatal if admin_audit_logs migration is not applied yet */ }
}

// --- Login: an 8-digit code emailed to an allowed address, then a session cookie ---
async function sendCode(request, body) {
    await rateLimit(`admin-code:${clientIp(request)}`, 5, 900);
    const addr = email(body.email);
    await rateLimit(`admin-code-email:${sha256(addr)}`, 5, 900);
    if (ADMIN_EMAILS.includes(addr)) {
        // Nick's address is public, so cap how many codes exist for it per hour (each code allows only 5 guesses, and the
        // database also caps wrong guesses per hour across all codes; see supabase/migrations).
        const { data: issued, error: cErr } = await db().rpc('admin_codes_last_hour', { p_email: addr });
        if (cErr) throw cErr;
        if (issued >= 10) return json({ ok: true });   // same answer as always; just no new code
        const code = String(randomInt(0, 100000000)).padStart(8, '0');
        await db().from('admin_codes').insert({ email: addr, code_hash: sha256(`${addr}:${code}`), expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString() });
        await sendEmail({
            to: addr,
            subject: `Your dashboard login code: ${code}`,
            heading: `Your login code is ${code}`,
            lines: ['Enter this code on the dashboard login page. It expires in 10 minutes.', "If you didn't try to log in, you can ignore this email."],
        });
        if (!IS_PROD && !process.env.RESEND_API_KEY) console.log(`[dev] admin login code for ${addr}: ${code}`);
    }
    return json({ ok: true });   // same answer for any email, so the allowed address isn't revealed
}

async function getAdminTotp(emailAddr) {
    try {
        const { data } = await db().from('admin_totp_secrets').select('secret, enabled').eq('email', emailAddr).maybeSingle();
        return data || null;
    } catch { return null; }
}

async function requireStepUpIfEnabled(admin, totpInput) {
    const totpRow = await getAdminTotp(admin);
    if (totpRow?.enabled) {
        if (!verifyTotp(totpRow.secret, totpInput)) {
            throw new HttpError(403, 'Step-up 2FA required: please enter your 6-digit Authenticator App code.');
        }
    }
}

async function verifyCode(request, body) {
    await rateLimit(`admin-verify:${clientIp(request)}`, 10, 900);
    const addr = email(body.email);
    await rateLimit(`admin-verify-email:${sha256(addr)}`, 8, 900);
    const raw = String(body.code || '').trim().toUpperCase();
    const digits = raw.replace(/\D/g, '');
    const alnum = raw.replace(/[^A-Z0-9]/g, '');

    const totpRow = ADMIN_EMAILS.includes(addr) ? await getAdminTotp(addr) : null;
    const isEmailOtpFormat = digits.length === 8 && raw.replace(/\s+/g, '') === digits;
    if (totpRow?.enabled && isEmailOtpFormat && !body.totp) {
        return json({ ok: false, requiresTwoFactor: true, message: 'Enter your 6-digit Authenticator App code to complete 2-step sign-in.' }, 200);
    }

    let ok = false;
    let usedRecovery = false;
    if (isEmailOtpFormat) {
        if (totpRow?.enabled && !verifyTotp(totpRow.secret, body.totp)) {
            ok = false;
        } else {
            // Checked and counted in one locked database step (use_admin_code), so parallel guesses can't get past 5 tries per code.
            const { data, error } = await db().rpc('use_admin_code', { p_email: addr, p_hash: sha256(`${addr}:${digits}`) });
            if (error) throw error;
            ok = !!data;
        }
    }
    if (!ok && alnum.length === 8 && ADMIN_EMAILS.includes(addr)) {
        const { data, error } = await db().rpc('use_admin_recovery_code', { p_email: addr, p_hash: sha256(`${addr}:${alnum}`) });
        if (!error && data) { ok = true; usedRecovery = true; }
    }
    if (!ok) {
        if (ADMIN_EMAILS.includes(addr)) {
            await auditAdmin(request, addr, 'login_failed');
            // Automatic 2FA Challenge Burn & Brute-Force Lockout Shield: burn all active codes after 5 failed attempts
            try {
                const { data: fails } = await db().rpc('hit_rate_limit', { p_bucket: `admin-burn:${sha256(addr)}`, p_window_seconds: 900 });
                if (fails >= 5) {
                    await db().from('admin_codes').delete().eq('email', addr);
                    await auditAdmin(request, addr, 'challenge_burned_lockout', null, 'All pending login codes invalidated after 5 failed verification attempts');
                    await sendSecurityAlert(addr, 'Repeated failed login attempts blocked', [
                        '5 failed verification attempts were detected on your staff dashboard.',
                        'All pending email login codes have been automatically burned to prevent brute-force guessing.',
                    ]);
                }
            } catch { /* non-fatal */ }
        }
        throw new HttpError(401, 'That code is wrong or expired. Request a new one.');
    }
    const nowIso = new Date().toISOString();
    await db().from('admin_sessions').delete().eq('email', addr).lt('expires_at', nowIso);
    const { data: activeSessions } = await db().from('admin_sessions').select('token_hash, created_at')
        .eq('email', addr).order('created_at', { ascending: false });
    if (activeSessions && activeSessions.length >= 5) {
        const staleHashes = activeSessions.slice(4).map(s => s.token_hash);
        await db().from('admin_sessions').delete().in('token_hash', staleHashes);
    }
    const rawToken = randomToken(32);
    const uaHash = uaFingerprint(request);
    const boundCookie = `${rawToken}.${uaHash}`;
    await db().from('admin_sessions').insert({ token_hash: sha256(boundCookie), email: addr, expires_at: new Date(Date.now() + SESSION_DAYS * 864e5).toISOString() });
    await auditAdmin(request, addr, usedRecovery ? 'login_recovery_code' : 'login_success');
    if (usedRecovery) {
        await sendSecurityAlert(addr, 'Emergency recovery code used to sign in', [
            'An emergency 1-time backup recovery code was just used to access your staff dashboard.',
        ]);
    }
    const secure = new URL(request.url).hostname === 'localhost' ? '' : ' Secure;';   // HTTPS-only everywhere but local testing
    return json({ ok: true, totpEnabled: !!totpRow?.enabled }, 200, { 'set-cookie': `${COOKIE}=${boundCookie}; Path=/api/admin; HttpOnly;${secure} SameSite=Strict; Max-Age=${SESSION_DAYS * 86400}` });
}

async function requireAdmin(request) {
    const token = getCookie(request, COOKIE);
    if (typeof token !== 'string' || !/^[A-Za-z0-9_.-]{16,160}$/.test(token)) throw new HttpError(401, 'Please log in.');
    if (token.includes('.')) {
        const parts = token.split('.');
        if (parts.length !== 2 || !timingSafeMatch(parts[1], uaFingerprint(request))) {
            throw new HttpError(401, 'Session device mismatch. Please log in again.');
        }
    }
    const { data } = await db().from('admin_sessions').select('email, expires_at').eq('token_hash', sha256(token)).maybeSingle();
    if (!data || data.expires_at < new Date().toISOString() || !ADMIN_EMAILS.includes(data.email)) throw new HttpError(401, 'Please log in.');
    return data.email;
}

async function me(admin) {
    let recoveryRemaining = 0;
    let auditLogs = [];
    const totpRow = await getAdminTotp(admin);
    try {
        const { count, error } = await db().from('admin_recovery_codes').select('id', { count: 'exact', head: true }).eq('email', admin).eq('used', false);
        if (!error && typeof count === 'number') recoveryRemaining = count;
    } catch { /* table may not be migrated yet */ }
    try {
        const { data } = await db().from('admin_audit_logs').select('action, target_code, detail, created_at').eq('email', admin).order('created_at', { ascending: false }).limit(10);
        if (Array.isArray(data)) auditLogs = data;
    } catch { /* table may not be migrated yet */ }
    return json({ email: admin, recoveryRemaining, totpEnabled: !!totpRow?.enabled, auditLogs });
}

async function logout(request, admin) {
    const token = getCookie(request, COOKIE);
    if (typeof token === 'string' && /^[A-Za-z0-9_.-]{16,160}$/.test(token)) await db().from('admin_sessions').delete().eq('token_hash', sha256(token));
    await auditAdmin(request, admin, 'logout');
    const secure = new URL(request.url).hostname === 'localhost' ? '' : ' Secure;';
    return json({ ok: true }, 200, { 'set-cookie': `${COOKIE}=; Path=/api/admin; HttpOnly;${secure} SameSite=Strict; Max-Age=0` });
}

async function logoutAll(request, admin) {
    await db().from('admin_sessions').delete().eq('email', admin);
    await auditAdmin(request, admin, 'logout_all');
    const secure = new URL(request.url).hostname === 'localhost' ? '' : ' Secure;';
    return json({ ok: true }, 200, { 'set-cookie': `${COOKIE}=; Path=/api/admin; HttpOnly;${secure} SameSite=Strict; Max-Age=0` });
}

const RECOVERY_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
async function generateRecoveryCodes(request, body, admin) {
    await rateLimit(`admin-recovery-gen:${sha256(admin)}`, 3, 3600);
    await requireStepUpIfEnabled(admin, body?.totp);
    const codes = [];
    const rows = [];
    for (let i = 0; i < 8; i++) {
        let raw = '';
        for (let j = 0; j < 8; j++) raw += RECOVERY_ALPHABET[randomInt(0, RECOVERY_ALPHABET.length)];
        codes.push(`${raw.slice(0, 4)}-${raw.slice(4)}`);
        rows.push({ email: admin, code_hash: sha256(`${admin}:${raw}`) });
    }
    await db().from('admin_recovery_codes').delete().eq('email', admin).eq('used', false);
    const { error } = await db().from('admin_recovery_codes').insert(rows);
    if (error) throw new HttpError(503, 'Backup recovery codes require the latest database migration.');
    await auditAdmin(request, admin, 'generate_recovery_codes');
    return json({ codes, remaining: codes.length });
}

async function totpSetup(request, admin) {
    await rateLimit(`admin-totp:${sha256(admin)}`, 6, 900);
    const secret = generateTotpSecret(20);
    const { error } = await db().from('admin_totp_secrets').upsert({
        email: admin,
        secret,
        enabled: false,
        updated_at: new Date().toISOString(),
    });
    if (error) throw new HttpError(503, 'Authenticator 2FA requires the latest database migration.');
    await auditAdmin(request, admin, 'totp_setup_initiated');
    const otpauthUrl = `otpauth://totp/NicksProcessServices:${encodeURIComponent(admin)}?secret=${secret}&issuer=NicksProcessServices&algorithm=SHA1&digits=6&period=30`;
    return json({ ok: true, secret, otpauthUrl });
}

async function totpEnable(request, body, admin) {
    await rateLimit(`admin-totp:${sha256(admin)}`, 10, 900);
    const row = await getAdminTotp(admin);
    if (!row?.secret) throw new HttpError(400, 'Start 2FA setup first.');
    if (!verifyTotp(row.secret, body.totp)) throw new HttpError(400, 'Invalid 6-digit Authenticator code. Check your device clock and try again.');
    const { error } = await db().from('admin_totp_secrets').update({ enabled: true, updated_at: new Date().toISOString() }).eq('email', admin);
    if (error) throw error;
    await auditAdmin(request, admin, 'totp_enabled');
    await sendSecurityAlert(admin, 'Two-Step Verification (TOTP) Enabled', [
        'Authenticator App Two-Step Verification (RFC 6238 TOTP) is now active on your staff dashboard.',
    ]);
    return json({ ok: true, totpEnabled: true });
}

async function totpDisable(request, body, admin) {
    await rateLimit(`admin-totp:${sha256(admin)}`, 10, 900);
    const row = await getAdminTotp(admin);
    if (!row?.enabled) return json({ ok: true, totpEnabled: false });
    if (!verifyTotp(row.secret, body.totp)) throw new HttpError(403, 'Enter your current 6-digit Authenticator code to disable 2FA.');
    const { error } = await db().from('admin_totp_secrets').update({ enabled: false, updated_at: new Date().toISOString() }).eq('email', admin);
    if (error) throw error;
    await auditAdmin(request, admin, 'totp_disabled');
    await sendSecurityAlert(admin, 'Two-Step Verification (TOTP) Disabled', [
        'Authenticator App Two-Step Verification was disabled on your staff dashboard.',
    ]);
    return json({ ok: true, totpEnabled: false });
}

// --- Jobs ---
async function list() {
    const { data, error } = await db().from('orders')
        .select('id, code, status, created_at, updated_at, client_name, client_firm, client_email, recipient_name, city, zip, tier, deadline, estimated_total_cents, amount_due_cents, paid_at')
        .order('created_at', { ascending: false }).limit(500);
    if (error) throw error;
    return json({ orders: await withClientReplied(data), statuses: STATUSES, tiers: TIERS });
}

// A job "has a client reply" when the client's answer is newer than anything Nick has done on it since.
// Only "received" jobs can be in that state (answering sets it), which keeps the id list short enough for one query.
const NICK_KINDS = ['action', 'status', 'attempt', 'payment', 'proof'];
async function withClientReplied(list) {
    const ids = list.filter(o => o.status === 'received').map(o => o.id).slice(0, 150);
    if (!ids.length) return list.map(o => ({ ...o, client_replied: false }));
    const { data: evs, error } = await db().from('order_events').select('order_id, kind')
        .in('order_id', ids).in('kind', [...NICK_KINDS, 'action_response'])
        .order('created_at', { ascending: false }).limit(5000);
    if (error) throw error;
    const latest = new Map();
    for (const e of evs) if (!latest.has(e.order_id)) latest.set(e.order_id, e.kind);
    return list.map(o => ({ ...o, client_replied: latest.get(o.id) === 'action_response' }));
}

async function getOrder(id) {
    uuid(id, 'Order');
    const { data, error } = await db().from('orders').select('*').eq('id', id).maybeSingle();
    if (error) throw error;
    if (!data) throw new HttpError(404, 'Order not found.');
    return data;
}

async function detail(id) {
    const order = await getOrder(id);
    const [{ data: events }, fileRes] = await Promise.all([
        db().from('order_events').select('*').eq('order_id', id).order('created_at', { ascending: true }),
        db().from('order_files').select('id, kind, filename, size_bytes, sha256, created_at, uploaded').eq('order_id', id).order('created_at'),
    ]);
    let files = fileRes.data;
    if (fileRes.error) {
        const fallback = await db().from('order_files').select('id, kind, filename, size_bytes, created_at, uploaded').eq('order_id', id).order('created_at');
        files = fallback.data;
    }
    const uploadedFiles = (files || []).filter(f => f.uploaded);
    const integritySeal = computeChainSeal(order.code, order.created_at, events || [], uploadedFiles);
    const legalHold = order.status === 'served' || !!order.legal_hold;
    return {
        order: {
            ...order,
            legal_hold: legalHold,
            doc_lock: !!order.doc_lock,
            integrity_seal: integritySeal,
            tier_name: TIERS[order.tier]?.name,
            addon_names: (order.addons || []).map(k => ADDONS[k]?.name).filter(Boolean),
        },
        events,
        files: uploadedFiles,
        integritySeal,
        statuses: STATUSES,
    };
}

// One endpoint for Nick's job actions: change status, log an attempt, add a note, or ask the client for info.
async function update(request, body, admin) {
    const order = await getOrder(body.id);
    const kind = body.kind;
    const note = longText(body.note, { max: 2000, label: 'Note' });
    const trackUrl = `${siteOrigin(request)}/track.html#t=${order.track_token}`;

    if (kind === 'status') {
        if (!STATUSES[body.status] || body.status === 'action_required') throw new HttpError(400, 'Choose a status.');
        // Completed-Order Legal Hold Lock: prevent rolling back a 'served' order unless explicitly unlocked.
        const isHeld = order.status === 'served' || !!order.legal_hold;
        if (isHeld && body.status !== 'served' && body.status !== 'closed') {
            if (!body.unlockLegalHold) {
                throw new HttpError(423, 'This completed order is locked under Legal Hold to preserve chain-of-custody. Unlock Legal Hold first to change its status.');
            }
            await requireStepUpIfEnabled(admin, body.totp);
            await auditAdmin(request, admin, 'legal_hold_override', order.code, `Status changed from ${order.status} to ${body.status}`);
        }
        const patch = { status: body.status };
        if (body.status === 'served') {
            patch.served_at = new Date().toISOString();
            patch.legal_hold = true;
        } else if (body.unlockLegalHold) {
            patch.legal_hold = false;
        }
        const { error: uErr } = await db().from('orders').update(patch).eq('id', order.id);
        if (uErr && ('legal_hold' in patch)) {
            delete patch.legal_hold;
            await db().from('orders').update(patch).eq('id', order.id);
        }
        await addEvent(order.id, 'status', STATUSES[body.status].label, note, body.clientVisible !== false);
        if (body.notify) await sendEmail({
            to: order.client_email, subject: `${order.code}: ${STATUSES[body.status].label}`,
            heading: STATUSES[body.status].label,
            lines: [STATUSES[body.status].client, ...(note ? [note] : [])],
            button: { label: 'Track your request', url: trackUrl },
        });
    } else if (kind === 'attempt') {
        const outcome = text(body.outcome, { max: 120, required: true, label: 'Outcome' });
        const when = text(body.when, { max: 40 });   // blank means "now", which the entry's own timestamp already shows
        if (['received', 'paid', 'accepted'].includes(order.status)) await db().from('orders').update({ status: 'attempting' }).eq('id', order.id);
        await addEvent(order.id, 'attempt', `Attempt: ${outcome}`, [when, note].filter(Boolean).join(' · '), body.clientVisible !== false);
    } else if (kind === 'note') {
        if (!note) throw new HttpError(400, 'Write a note first.');
        await addEvent(order.id, 'note', body.clientVisible ? 'Update from Nick' : 'Internal note', note, !!body.clientVisible);
    } else if (kind === 'action') {
        if (!note) throw new HttpError(400, 'Tell the client what you need.');
        await db().from('orders').update({ status: 'action_required', action_note: note }).eq('id', order.id);
        await addEvent(order.id, 'action', 'Action required', note);
        await sendEmail({
            to: order.client_email, subject: `${order.code}: Nick needs a little more information`,
            heading: 'Action required on your request',
            lines: [note, 'Open your tracking page to send the missing details or upload a file.'],
            button: { label: 'Send the information', url: trackUrl },
        });
    } else {
        throw new HttpError(400, 'Unknown update.');
    }
    return json(await detail(order.id));
}

async function rotateToken(request, body, admin) {
    await rateLimit(`admin-rotate:${sha256(admin)}`, 20, 900);
    const order = await getOrder(body.id);
    const newToken = randomToken(32);
    const { error } = await db().from('orders').update({ track_token: newToken }).eq('id', order.id);
    if (error) throw error;
    await addEvent(order.id, 'note', 'Private tracking link rotated (previous link revoked)', null, true);
    await auditAdmin(request, admin, 'rotate_track_token', order.code);
    return json(await detail(order.id));
}

async function toggleDocLock(request, body, admin) {
    const order = await getOrder(body.id);
    const locked = body.locked !== undefined ? !!body.locked : !order.doc_lock;
    const { error } = await db().from('orders').update({ doc_lock: locked }).eq('id', order.id);
    if (error) throw new HttpError(503, '2-Step Document Lock requires the latest database migration.');
    await addEvent(order.id, 'note', locked ? '2-Step Document Protection enabled on tracking link' : '2-Step Document Protection unlocked', null, false);
    await auditAdmin(request, admin, locked ? 'doc_lock_enabled' : 'doc_lock_disabled', order.code);
    return json(await detail(order.id));
}

async function unlockLegalHold(request, body, admin) {
    await requireStepUpIfEnabled(admin, body.totp);
    const order = await getOrder(body.id);
    const hold = body.hold !== undefined ? !!body.hold : false;
    const { error } = await db().from('orders').update({ legal_hold: hold }).eq('id', order.id);
    if (error) { /* column may not be migrated yet; audit still recorded */ }
    await addEvent(order.id, 'note', hold ? 'Legal Hold lock applied' : 'Legal Hold unlocked by staff override', null, false);
    await auditAdmin(request, admin, hold ? 'legal_hold_locked' : 'legal_hold_unlocked', order.code);
    if (!hold) {
        await sendSecurityAlert(admin, `Legal Hold unlocked on ${order.code}`, [
            `Completed order ${order.code} (${order.recipient_name}) had its Legal Hold lock overridden on the staff dashboard.`,
        ]);
    }
    return json(await detail(order.id));
}

async function paymentLink(request, body, admin) {
    await rateLimit(`admin-paylink:${sha256(admin)}`, 20, 900);
    const order = await getOrder(body.id);
    const cents = Math.round(Number(body.amount) * 100);
    if (!Number.isFinite(cents) || cents < 100 || cents > 1000000) throw new HttpError(400, 'Enter an amount between $1 and $10,000.');
    if (order.paid_at) throw new HttpError(409, 'This order is already paid.');
    const description = text(body.description, { max: 300 });
    const origin = siteOrigin(request);
    // A new link replaces the old one. If the client already paid the old one, record that and stop;
    // otherwise close it, so they can't end up paying twice.
    if (order.stripe_session_id?.startsWith('cs_')) {
        const old = await stripeClient().checkout.sessions.retrieve(order.stripe_session_id).catch(() => null);
        if (old?.payment_status === 'paid') {
            await markPaid(order.id, old.amount_total, old.id);
            throw new HttpError(409, 'The client already paid the previous link. Refresh to see it.');
        }
        if (old?.status === 'open') await stripeClient().checkout.sessions.expire(old.id).catch(() => {});
    }
    const session = await createCheckout(order, cents, description, origin);
    await db().from('orders').update({ status: 'awaiting_payment', amount_due_cents: cents, payment_url: session.url, stripe_session_id: session.id }).eq('id', order.id);
    await addEvent(order.id, 'payment', `Payment requested: ${money(cents)}`, description);
    await auditAdmin(request, admin, 'payment_link', order.code, money(cents));
    await sendEmail({
        to: order.client_email, subject: `${order.code}: confirmed, ${money(cents)} due to start service`,
        heading: 'Your request is confirmed',
        lines: [`Total due: ${money(cents)}${description ? ` (${description})` : ''}.`, 'Payment must be sent to effectuate service. Attempts begin once payment is received.', 'Pay securely by card or Apple Pay. The link works for 24 hours; ask Nick for a new one if it expires.'],
        button: { label: `Pay ${money(cents)}`, url: session.url },
    });
    return json(await detail(order.id));
}

async function proofUpload(body) {
    const order = await getOrder(body.id);
    const files = cleanFileList(body.files);
    if (!files.length) throw new HttpError(400, 'Choose the proof of service file.');
    return json({ uploads: await prepareUploads(order.id, 'proof', files) });
}

async function proofFinish(request, body) {
    const order = await getOrder(body.id);
    const uploaded = await confirmUploads(order.id, body.fileIds);
    if (!uploaded.length) throw new HttpError(400, 'The upload did not finish. Please try again.');
    const detailText = uploaded.map(u => u.sha256 ? `${u.filename} (SHA-256: ${u.sha256.slice(0, 12)}…)` : u.filename).join(', ');
    await addEvent(order.id, 'proof', 'Proof of service uploaded', detailText);
    if (body.markServed) {
        const servedAt = new Date().toISOString();
        const { error: uErr } = await db().from('orders').update({ status: 'served', served_at: servedAt, legal_hold: true }).eq('id', order.id);
        if (uErr) await db().from('orders').update({ status: 'served', served_at: servedAt }).eq('id', order.id);
        await addEvent(order.id, 'status', STATUSES.served.label);
    }
    await sendEmail({
        to: order.client_email, subject: `${order.code}: your proof of service is ready`,
        heading: body.markServed ? 'Service complete' : 'New document on your request',
        lines: [body.markServed ? `${order.recipient_name} has been served.` : 'Nick added a document to your request.', 'Download it from your private tracking page.'],
        button: { label: 'Download proof of service', url: `${siteOrigin(request)}/track.html#t=${order.track_token}` },
    });
    return json(await detail(order.id));
}

async function fileUrl(body) {
    const { data, error } = await db().from('order_files').select('storage_path, filename').eq('id', uuid(body.fileId, 'File')).eq('uploaded', true).maybeSingle();
    if (error) throw error;
    if (!data) throw new HttpError(404, 'File not found.');
    return json({ url: await signedDownload(data.storage_path, data.filename) });
}

// --- Privacy requests: a client asks for a copy of their data, or for it to be deleted ---
// Nick finds their requests by searching their email in the dashboard, then exports or deletes each one.
async function exportOrder(request, body, admin) {
    await rateLimit(`admin-export:${sha256(admin)}`, 15, 900);
    const { order, events, files, integritySeal } = await detail(body.id);
    await auditAdmin(request, admin, 'export_order', order.code);
    const { track_token, payment_url, stripe_session_id, tier_name, addon_names, ...fields } = order;   // keys, not personal data
    return json({
        exported_at: new Date().toISOString(),
        integrity_seal: integritySeal,
        note: "All information Nick's Process Services holds for this request. Uploaded documents are listed; Nick sends copies on request.",
        request: { ...fields, tier: tier_name, addons: addon_names },
        timeline: events.map(({ created_at, title, detail: d, client_visible }) => ({ created_at, title, detail: d, shown_to_client: client_visible })),
        files: files.map(({ filename, kind, size_bytes, sha256: h, created_at }) => ({ filename, kind, size_bytes, sha256: h || null, created_at })),
    });
}

// Permanent: removes the stored documents, then the request with its timeline and file records (cascade).
async function deleteOrder(request, body, admin) {
    await rateLimit(`admin-delete:${sha256(admin)}`, 5, 900);
    const order = await getOrder(body.id);
    if ((order.status === 'served' || order.legal_hold) && !body.unlockLegalHold) {
        throw new HttpError(423, 'This served order is protected by Legal Hold and cannot be deleted without unlocking Legal Hold first.');
    }
    await requireStepUpIfEnabled(admin, body.totp);
    if (String(body.confirm || '').trim().toUpperCase() !== order.code) throw new HttpError(400, `Type ${order.code} to confirm.`);
    const { data: fileRows, error } = await db().from('order_files').select('storage_path').eq('order_id', order.id);
    if (error) throw error;
    const paths = (fileRows || []).map(f => f.storage_path);
    for (let i = 0; i < paths.length; i += 100) {
        const { error: sErr } = await db().storage.from(BUCKET).remove(paths.slice(i, i + 100));
        if (sErr) throw sErr;   // stop before deleting the record, so no stored document is ever orphaned
    }
    if (order.stripe_session_id?.startsWith('cs_') && !order.paid_at) {
        await stripeClient().checkout.sessions.expire(order.stripe_session_id).catch(() => {});   // no payable link left behind
    }
    const { error: dErr } = await db().from('orders').delete().eq('id', order.id);
    if (dErr) throw dErr;
    await auditAdmin(request, admin, 'delete_order', order.code, `${paths.length} file(s) deleted`);
    console.log(`Request ${order.code} and ${paths.length} file(s) permanently deleted at Nick's request.`);
    return json({ ok: true, deleted: order.code, files: paths.length });
}
