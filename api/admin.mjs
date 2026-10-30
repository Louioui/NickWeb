// POST /api/admin { action, ... } — Nick's dashboard. Everything except the two login steps needs his session cookie.
import { randomInt } from 'node:crypto';
import { db, handle, json, readJson, clientIp, siteOrigin, rateLimit, getCookie, text, longText, email,
         sha256, randomToken, cleanFileList, prepareUploads, confirmUploads, addEvent, signedDownload, uuid,
         HttpError, ADMIN_EMAILS, IS_PROD, BUCKET, generateTotpSecret, verifyTotp, encryptSecret, decryptSecret, keyedHash } from './_lib/core.mjs';
import { STATUSES, TIERS, ADDONS, money, sendEmail, sendSecurityAlert, markPaid, orderSeal } from './_lib/orders.mjs';
import { createCheckout, stripeClient } from './_lib/stripe.mjs';
import { registrationOptions, registrationVerify, loginOptions, loginVerify, listPasskeys, removePasskey, clearChallengeCookie } from './_lib/passkeys.mjs';

const COOKIE = 'nps_admin';
const SESSION_DAYS = 14;

export const POST = handle(async (request) => {
    const body = await readJson(request);
    const a = body.action;
    if (a === 'send-code') return sendCode(request, body);
    if (a === 'verify-code') return verifyCode(request, body);
    if (a === 'passkey-login-options') return passkeyLoginOptions(request);
    if (a === 'passkey-login-verify') return passkeyLoginVerify(request, body);

    const admin = await requireAdmin(request);
    if (a === 'me') return me(admin);
    if (a === 'logout') return logout(request, admin);
    if (a === 'logout-all') return logoutAll(request, admin);
    if (a === 'sessions') return sessions(request, admin);
    if (a === 'revoke-session') return revokeSession(request, body, admin);
    if (a === 'passkeys') return json({ ok: true, passkeys: await listPasskeys('admin', admin) });
    if (a === 'passkey-register-options') return passkeyRegisterOptions(request, body, admin);
    if (a === 'passkey-register-verify') return passkeyRegisterVerify(request, body, admin);
    if (a === 'passkey-remove') return passkeyRemove(request, body, admin);
    if (a === 'generate-recovery-codes') return generateRecoveryCodes(request, body, admin);
    if (a === 'totp-setup') return totpSetup(request, body, admin);
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
    if (a === 'file-url') return fileUrl(request, body, admin);
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
    } catch (err) { console.error('Audit log write failed:', err?.message); }   // never block Nick's work, but make it visible
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

const IDLE_HOURS = 12;   // a full day in the field without re-login, but a lost or forgotten device logs itself out

// Nick's authenticator settings. Fails closed: if this lookup errors, nobody gets in or past a step-up check.
async function getAdminTotp(addr) {
    const { data, error } = await db().from('admin_totp').select('secret_enc, pending_secret_enc, enabled').eq('email', addr).maybeSingle();
    if (error) throw new HttpError(503, 'Sign-in is temporarily unavailable. Please try again in a minute.');
    return data || null;
}

// Checks an authenticator code against a stored (encrypted) secret and consumes its 30-second step, so the same
// code can never be used twice. Guesses are rate-limited per purpose.
// The authenticator secret is encrypted with APP_SECRET. If it was set up under a different APP_SECRET (for example on a
// Preview that shares this database), it can't be read here: say so plainly instead of failing with a server error.
const TOTP_UNREADABLE = 'Your authenticator app was set up on a different copy of this site, so its codes can\'t be checked here. Ask your developer to reset two-step sign-in for your address, then set it up again here.';
function readTotpSecret(secretEnc) {
    try { return decryptSecret(secretEnc); }
    catch { throw new HttpError(409, TOTP_UNREADABLE); }
}
async function checkTotp(addr, secretEnc, code, bucket) {
    await rateLimit(`${bucket}:${sha256(addr)}`, 10, 900);
    const step = verifyTotp(readTotpSecret(secretEnc), code);
    if (!step) return false;
    const { data, error } = await db().rpc('use_admin_totp_step', { p_email: addr, p_step: step });
    if (error) throw error;
    return !!data;
}

// Step-up check before sensitive actions. With an authenticator on, a fresh code is required; returns whether one was checked.
// A fresh authenticator code, or (phone lost) one single-use recovery code, confirms a sensitive action.
async function requireStepUp(admin, code) {
    const row = await getAdminTotp(admin);
    if (!row?.enabled) return false;
    const typed = String(code || '').trim().toUpperCase();
    const recovery = typed.replace(/[^A-Z0-9]/g, '');
    if (!/^\d{6}$/.test(typed.replace(/\s+/g, '')) && recovery.length === 8) {
        await rateLimit(`admin-stepup:${sha256(admin)}`, 10, 900);
        const { data, error } = await db().rpc('use_admin_recovery_code', { p_email: admin, p_hash: recoveryHash(admin, recovery) });
        if (error) throw error;
        if (!data) throw new HttpError(403, 'That recovery code is wrong or already used.');
        return true;
    }
    if (!(await checkTotp(admin, row.secret_enc, typed, 'admin-stepup'))) {
        throw new HttpError(403, 'Enter the current 6-digit code from your authenticator app, or one of your recovery codes.');
    }
    return true;
}

const recoveryHash = (addr, code) => keyedHash('admin-recovery-v1', `${addr}:${code}`);

async function verifyCode(request, body) {
    await rateLimit(`admin-verify:${clientIp(request)}`, 10, 900);
    const addr = email(body.email);
    await rateLimit(`admin-verify-email:${sha256(addr)}`, 15, 900);
    const isAdmin = ADMIN_EMAILS.includes(addr);
    const raw = String(body.code || '').trim().toUpperCase();
    const digits = raw.replace(/\D/g, '');
    const isEmailCode = digits.length === 8 && raw.replace(/[\s-]+/g, '') === digits;
    const second = String(body.totp || '').trim().toUpperCase();
    const secondDigits = second.replace(/\s+/g, '');
    const secondRecovery = second.replace(/[^A-Z0-9]/g, '');
    const totpRow = isAdmin ? await getAdminTotp(addr) : null;

    // With an authenticator on, an email code alone is never enough. Ask for the second step before spending the code.
    if (totpRow?.enabled && isEmailCode && !second) {
        return json({ ok: false, requiresTwoFactor: true, message: 'Enter the 6-digit code from your authenticator app, or one of your recovery codes.' });
    }

    let ok = false;
    let method = 'email';
    if (isAdmin && isEmailCode) {
        // The email code is checked first (in one locked database step, use_admin_code: at most 5 tries per code, 25 per
        // hour), so a mistyped email code never uses up a single-use recovery code. A correct email code is spent either
        // way; after a wrong second step Nick requests a new one. Both failures give the same answer.
        const { data: emailOk, error } = await db().rpc('use_admin_code', { p_email: addr, p_hash: sha256(`${addr}:${digits}`) });
        if (error) throw error;
        ok = !!emailOk;
        if (ok && totpRow?.enabled) {
            if (/^\d{6}$/.test(secondDigits)) {
                ok = await checkTotp(addr, totpRow.secret_enc, secondDigits, 'admin-login-totp');
                method = 'email+authenticator';
            } else if (secondRecovery.length === 8) {
                // Lost phone: email code + one single-use recovery code.
                const { data, error: rErr } = await db().rpc('use_admin_recovery_code', { p_email: addr, p_hash: recoveryHash(addr, secondRecovery) });
                if (rErr) throw rErr;
                ok = !!data;
                method = 'email+recovery';
            } else {
                ok = false;
            }
        }
    } else if (isAdmin && !totpRow?.enabled && raw.replace(/[^A-Z0-9]/g, '').length === 8 && !isEmailCode) {
        // Without an authenticator, a recovery code can stand in for the email code (for example if Outlook is down).
        const { data, error } = await db().rpc('use_admin_recovery_code', { p_email: addr, p_hash: recoveryHash(addr, raw.replace(/[^A-Z0-9]/g, '')) });
        if (error) throw error;
        ok = !!data;
        method = 'recovery';
    }

    if (!ok) {
        if (isAdmin) {
            await auditAdmin(request, addr, 'login_failed');
            // Five failures in 15 minutes throw away every code already sent, and Nick is told. A fresh code still works.
            const { data: fails } = await db().rpc('hit_rate_limit', { p_bucket: `admin-burn:${sha256(addr)}`, p_window_seconds: 900 });
            if (fails === 5) {
                await db().from('admin_codes').delete().eq('email', addr).eq('used', false);
                await auditAdmin(request, addr, 'codes_burned', null, 'Pending login codes discarded after 5 failed attempts');
                await sendSecurityAlert(addr, 'Repeated failed sign-in attempts', [
                    'Five wrong codes were entered on your dashboard sign-in in the last 15 minutes.',
                    'Every login code that had been sent was cancelled. Request a new one when you want to sign in.',
                ]);
            }
        }
        throw new HttpError(401, 'That code is wrong or expired. Request a new one.');
    }

    return issueAdminSession(request, addr, method, !!totpRow?.enabled);
}

// Last step of every dashboard sign-in: at most 5 sessions, a new session cookie, an audit entry and a login alert.
async function issueAdminSession(request, addr, method, totpEnabled) {
    const nowIso = new Date().toISOString();
    await db().from('admin_sessions').delete().eq('email', addr).lt('expires_at', nowIso);
    const { data: activeSessions } = await db().from('admin_sessions').select('token_hash, created_at')
        .eq('email', addr).order('created_at', { ascending: false });
    if (activeSessions && activeSessions.length >= 5) {
        await db().from('admin_sessions').delete().in('token_hash', activeSessions.slice(4).map(s => s.token_hash));
    }
    const token = randomToken(32);
    const { error: sErr } = await db().from('admin_sessions').insert({ token_hash: sha256(token), email: addr, last_seen_at: nowIso,
        expires_at: new Date(Date.now() + SESSION_DAYS * 864e5).toISOString() });
    if (sErr) throw sErr;
    // The browser name is saved separately so sign-in still works before the user_agent column exists.
    // Cut to 200 characters rather than validated: an unusual browser must never make a sign-in fail.
    const agent = text(String(request.headers.get('user-agent') || '').slice(0, 200), { max: 200 });
    if (agent) await db().from('admin_sessions').update({ user_agent: agent }).eq('token_hash', sha256(token)).then(() => {}, () => {});
    await auditAdmin(request, addr, method.includes('recovery') ? 'login_recovery_code' : 'login_success', null, `Signed in with ${method}`);
    await sendSecurityAlert(addr, method.includes('recovery') ? 'Recovery code used to sign in' : 'New sign-in to your dashboard', [
        `Your dashboard was just signed into (${method === 'email' ? 'email code' : method === 'passkey' ? 'passkey' : method.replace('+', ' + ').replace('email', 'email code')}).`,
        `Browser: ${String(request.headers.get('user-agent') || 'unknown').slice(0, 120)}`,
        ...(method === 'passkey' ? ['If this wasn\'t you, remove any passkey you don\'t recognise under Security & Field App, then use Log Out All Devices.'] : []),
    ]);
    const secure = new URL(request.url).hostname === 'localhost' ? '' : ' Secure;';   // HTTPS-only everywhere but local testing
    return json({ ok: true, totpEnabled }, 200, { 'set-cookie': `${COOKIE}=${token}; Path=/api/admin; HttpOnly;${secure} SameSite=Strict; Max-Age=${SESSION_DAYS * 86400}` });
}

// --- Passkeys. A passkey asks for Face ID, a fingerprint or the device PIN and only works on this site, so it stands in
// for both the email code and the authenticator code. Adding one needs the authenticator app to be on, plus a fresh
// authenticator code, so a stolen session cookie can't plant a passkey of its own.
async function passkeyLoginOptions(request) {
    const { options, cookie } = await loginOptions(request, 'admin');
    return json({ ok: true, options }, 200, { 'set-cookie': cookie });
}

async function passkeyLoginVerify(request, body) {
    await rateLimit(`admin-verify:${clientIp(request)}`, 10, 900);
    const { ownerEmail } = await loginVerify(request, 'admin', body.response);
    // Checked again at every sign-in, so removing an address from ADMIN_EMAILS also shuts out its passkeys.
    if (!ADMIN_EMAILS.includes(ownerEmail)) throw new HttpError(401, 'That passkey could not be used to sign in. Please try again or use your email code.');
    const res = await issueAdminSession(request, ownerEmail, 'passkey', !!(await getAdminTotp(ownerEmail))?.enabled);
    res.headers.append('set-cookie', clearChallengeCookie(request, 'admin'));
    return res;
}

async function passkeyRegisterOptions(request, body, admin) {
    await rateLimit(`admin-passkey:${sha256(admin)}`, 10, 900);
    if (!(await getAdminTotp(admin))?.enabled) throw new HttpError(400, 'Turn on the authenticator app first, then add a passkey.');
    await requireStepUp(admin, body?.totp);
    // A stable id that isn't the email address (the passkey shows the email as its name).
    const { options, cookie } = await registrationOptions(request, 'admin', admin, keyedHash('admin-passkey-user-v1', admin).slice(0, 32), "Nick's dashboard");
    return json({ ok: true, options }, 200, { 'set-cookie': cookie });
}

async function passkeyRegisterVerify(request, body, admin) {
    await rateLimit(`admin-passkey:${sha256(admin)}`, 10, 900);
    const label = text(String(body.label || '').slice(0, 80), { max: 80 });
    await registrationVerify(request, 'admin', admin, body.response, label);
    await auditAdmin(request, admin, 'passkey_added', null, label ? `Passkey "${label}"` : 'Passkey');
    await sendSecurityAlert(admin, 'A passkey was added to your dashboard', [
        `A passkey${label ? ` ("${label}")` : ''} can now be used to sign in to your dashboard.`,
        `Browser: ${String(request.headers.get('user-agent') || 'unknown').slice(0, 120)}`,
    ]);
    return json({ ok: true, passkeys: await listPasskeys('admin', admin) }, 200, { 'set-cookie': clearChallengeCookie(request, 'admin') });
}

async function passkeyRemove(request, body, admin) {
    await rateLimit(`admin-passkey:${sha256(admin)}`, 10, 900);
    await requireStepUp(admin, body?.totp);
    await removePasskey('admin', admin, body.id);
    await auditAdmin(request, admin, 'passkey_removed');
    await sendSecurityAlert(admin, 'A passkey was removed from your dashboard', ['That passkey can no longer be used to sign in.']);
    return json({ ok: true, passkeys: await listPasskeys('admin', admin) });
}

async function requireAdmin(request) {
    const token = getCookie(request, COOKIE);
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{40,64}$/.test(token)) throw new HttpError(401, 'Please log in.');
    const hash = sha256(token);
    const { data } = await db().from('admin_sessions').select('email, expires_at, last_seen_at').eq('token_hash', hash).maybeSingle();
    if (!data || data.expires_at < new Date().toISOString() || !ADMIN_EMAILS.includes(data.email)) throw new HttpError(401, 'Please log in.');
    const idleMs = Date.now() - new Date(data.last_seen_at).getTime();
    if (idleMs > IDLE_HOURS * 3600e3) {
        await db().from('admin_sessions').delete().eq('token_hash', hash);
        throw new HttpError(401, `You were signed out after ${IDLE_HOURS} hours without activity. Please log in again.`);
    }
    if (idleMs > 5 * 60e3) await db().from('admin_sessions').update({ last_seen_at: new Date().toISOString() }).eq('token_hash', hash);
    return data.email;
}

async function me(admin) {
    const totpRow = await getAdminTotp(admin);
    const { count } = await db().from('admin_recovery_codes').select('id', { count: 'exact', head: true }).eq('email', admin).eq('used', false);
    const { data: auditLogs } = await db().from('admin_audit_logs').select('action, target_code, detail, created_at')
        .eq('email', admin).order('created_at', { ascending: false }).limit(10);
    return json({ email: admin, recoveryRemaining: count || 0, totpEnabled: !!totpRow?.enabled, auditLogs: auditLogs || [] });
}

async function logout(request, admin) {
    const token = getCookie(request, COOKIE);
    if (typeof token === 'string' && /^[A-Za-z0-9_-]{40,64}$/.test(token)) await db().from('admin_sessions').delete().eq('token_hash', sha256(token));
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

// Nick's signed-in devices. Each is identified by the start of its stored token hash (never the token itself).
const currentHash = (request) => {
    const token = getCookie(request, COOKIE);
    return typeof token === 'string' && /^[A-Za-z0-9_-]{40,64}$/.test(token) ? sha256(token) : '';
};
async function sessions(request, admin) {
    let { data, error } = await db().from('admin_sessions').select('token_hash, created_at, last_seen_at, expires_at, user_agent')
        .eq('email', admin).order('last_seen_at', { ascending: false });
    if (error) {   // before the user_agent migration
        ({ data, error } = await db().from('admin_sessions').select('token_hash, created_at, last_seen_at, expires_at')
            .eq('email', admin).order('last_seen_at', { ascending: false }));
        if (error) throw error;
    }
    const now = new Date().toISOString();
    const mine = currentHash(request);
    return json({ sessions: (data || []).filter(s => s.expires_at > now).map(s => ({
        id: s.token_hash.slice(0, 16), current: s.token_hash === mine, browser: s.user_agent || null,
        signedIn: s.created_at, lastSeen: s.last_seen_at,
    })) });
}
async function revokeSession(request, body, admin) {
    await rateLimit(`admin-revoke:${sha256(admin)}`, 20, 900);
    const id = String(body.sessionId || '');
    if (!/^[0-9a-f]{16}$/.test(id)) throw new HttpError(400, 'Choose a session.');
    const { data, error } = await db().from('admin_sessions').select('token_hash').eq('email', admin);
    if (error) throw error;
    const target = (data || []).find(s => s.token_hash.startsWith(id));
    if (!target) throw new HttpError(404, 'That session has already ended.');
    if (target.token_hash === currentHash(request)) throw new HttpError(400, 'This is the device you are using. Use Log out instead.');
    const { error: dErr } = await db().from('admin_sessions').delete().eq('token_hash', target.token_hash);
    if (dErr) throw dErr;
    await auditAdmin(request, admin, 'session_revoked', null, `Signed out device ${id.slice(0, 6)}`);
    return sessions(request, admin);
}

const RECOVERY_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
async function generateRecoveryCodes(request, body, admin) {
    await rateLimit(`admin-recovery-gen:${sha256(admin)}`, 3, 3600);
    await requireStepUp(admin, body?.totp);
    const codes = [];
    const rows = [];
    for (let i = 0; i < 8; i++) {
        let raw = '';
        for (let j = 0; j < 8; j++) raw += RECOVERY_ALPHABET[randomInt(0, RECOVERY_ALPHABET.length)];
        codes.push(`${raw.slice(0, 4)}-${raw.slice(4)}`);
        rows.push({ email: admin, code_hash: recoveryHash(admin, raw) });
    }
    await db().from('admin_recovery_codes').delete().eq('email', admin).eq('used', false);
    const { error } = await db().from('admin_recovery_codes').insert(rows);
    if (error) throw error;
    await auditAdmin(request, admin, 'generate_recovery_codes');
    await sendSecurityAlert(admin, 'New recovery codes created', ['A new set of 8 recovery codes was created. Every older unused code stopped working.']);
    return json({ codes, remaining: codes.length });
}

// Setting up (or changing) the authenticator. While one is already on, changing it needs a code from the current one,
// and the new secret waits as "pending" so the current authenticator keeps working until the new one is confirmed.
async function totpSetup(request, body, admin) {
    await rateLimit(`admin-totp:${sha256(admin)}`, 6, 900);
    const row = await getAdminTotp(admin);
    if (row?.enabled) await requireStepUp(admin, body?.totp);
    const secret = generateTotpSecret(20);
    const enc = encryptSecret(secret);
    const { error } = row
        ? await db().from('admin_totp').update(row.enabled ? { pending_secret_enc: enc } : { secret_enc: enc, pending_secret_enc: null }).eq('email', admin)
        : await db().from('admin_totp').insert({ email: admin, secret_enc: enc, enabled: false });
    if (error) throw error;
    await auditAdmin(request, admin, row?.enabled ? 'totp_change_started' : 'totp_setup_started');
    const label = encodeURIComponent(`Nick's Process Services:${admin}`);
    return json({ ok: true, secret, otpauthUrl: `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent("Nick's Process Services")}&algorithm=SHA1&digits=6&period=30` });
}

async function totpEnable(request, body, admin) {
    const row = await getAdminTotp(admin);
    const candidate = row?.pending_secret_enc || (!row?.enabled && row?.secret_enc);
    if (!candidate) throw new HttpError(400, 'Start authenticator setup first.');
    if (!(await checkTotp(admin, candidate, body.totp, 'admin-totp-confirm'))) {
        throw new HttpError(400, "That code didn't match. Check that your phone's clock is set automatically, then try the newest code.");
    }
    const { error } = await db().from('admin_totp').update({ secret_enc: candidate, pending_secret_enc: null, enabled: true }).eq('email', admin);
    if (error) throw error;
    await auditAdmin(request, admin, 'totp_enabled');
    await sendSecurityAlert(admin, 'Two-step sign-in turned on', ['Your dashboard now asks for a code from your authenticator app at every sign-in.']);
    return json({ ok: true, totpEnabled: true });
}

async function totpDisable(request, body, admin) {
    const row = await getAdminTotp(admin);
    if (!row?.enabled) return json({ ok: true, totpEnabled: false });
    if (!(await checkTotp(admin, row.secret_enc, body.totp, 'admin-stepup'))) {
        throw new HttpError(403, 'Enter the current 6-digit code from your authenticator app to turn two-step sign-in off.');
    }
    const { error } = await db().from('admin_totp').update({ enabled: false, pending_secret_enc: null }).eq('email', admin);
    if (error) throw error;
    await auditAdmin(request, admin, 'totp_disabled');
    await sendSecurityAlert(admin, 'Two-step sign-in turned off', ['Your dashboard now signs in with an email code only. If this wasn’t you, turn it back on and sign out everywhere.']);
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
    const integritySeal = await orderSeal(order.id);
    return {
        order: {
            ...order,
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
        // Legal hold (set automatically when an order is served) freezes the record; the database enforces it too.
        if (order.legal_hold && !['served', 'closed'].includes(body.status)) {
            throw new HttpError(423, 'This order is under legal hold, so its status can only move to Closed. Unlock legal hold first if it really needs to change.');
        }
        const patch = { status: body.status };
        if (body.status === 'served') Object.assign(patch, { served_at: new Date().toISOString(), legal_hold: true });
        const { error: uErr } = await db().from('orders').update(patch).eq('id', order.id);
        if (uErr) throw uErr;
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
        if (order.legal_hold) throw new HttpError(423, 'This order is served and under legal hold, so it can’t go back to "Action required". Add a note the client can see, or contact them directly.');
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

// Replaces a client's private link (for example if it was forwarded by mistake). The old one stops working at once,
// and the client is emailed the new one so they are never locked out.
async function rotateToken(request, body, admin) {
    await rateLimit(`admin-rotate:${sha256(admin)}`, 20, 900);
    const order = await getOrder(body.id);
    const newToken = randomToken(32);
    const { error } = await db().from('orders').update({ track_token: newToken }).eq('id', order.id);
    if (error) throw error;
    await addEvent(order.id, 'note', 'Private tracking link replaced', 'The previous link no longer works. The new link was emailed to the client.', true);
    await auditAdmin(request, admin, 'rotate_track_token', order.code);
    await sendEmail({
        to: order.client_email, subject: `${order.code}: your new private tracking link`,
        heading: 'Your tracking link was replaced',
        lines: [`For your security, the previous tracking link for ${order.code} no longer works. Use the button below from now on.`],
        button: { label: 'Open your tracking page', url: `${siteOrigin(request)}/track.html#t=${newToken}` },
    });
    return json(await detail(order.id));
}

async function toggleDocLock(request, body, admin) {
    await rateLimit(`admin-doclock:${sha256(admin)}`, 30, 900);
    const order = await getOrder(body.id);
    const locked = body.locked !== undefined ? !!body.locked : !order.doc_lock;
    const { error } = await db().from('orders').update({ doc_lock: locked }).eq('id', order.id);
    if (error) throw error;
    await addEvent(order.id, 'note', locked ? 'Document lock turned on' : 'Document lock turned off',
        locked ? 'Viewing documents and full details on the tracking page now needs a code emailed to the client.' : null, true);
    await auditAdmin(request, admin, locked ? 'doc_lock_enabled' : 'doc_lock_disabled', order.code);
    return json(await detail(order.id));
}

// Legal hold on/off. Unlocking needs a fresh authenticator code when two-step sign-in is on; otherwise Nick types the
// order's reference number. Either way it is written to the audit log and Nick is emailed.
async function unlockLegalHold(request, body, admin) {
    await rateLimit(`admin-hold:${sha256(admin)}`, 10, 900);
    const order = await getOrder(body.id);
    const hold = !!body.hold;
    if (!hold) {
        const usedTotp = await requireStepUp(admin, body.totp);
        if (!usedTotp && String(body.confirm || '').trim().toUpperCase() !== order.code) {
            throw new HttpError(400, `Type ${order.code} to confirm unlocking legal hold.`);
        }
    }
    const { error } = await db().from('orders').update({ legal_hold: hold }).eq('id', order.id);
    if (error) throw error;
    await addEvent(order.id, 'note', hold ? 'Legal hold turned on' : 'Legal hold unlocked by Nick', null, false);
    await auditAdmin(request, admin, hold ? 'legal_hold_on' : 'legal_hold_unlocked', order.code);
    if (!hold) await sendSecurityAlert(admin, `Legal hold unlocked on ${order.code}`, [`${order.code} (${order.recipient_name}) can be changed or deleted again.`]);
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
    // A served order (under legal hold) keeps its "Served" status while it's billed; the Pay button still shows.
    const { error: linkErr } = await db().from('orders').update({ amount_due_cents: cents, payment_url: session.url, stripe_session_id: session.id,
        ...(order.legal_hold ? {} : { status: 'awaiting_payment' }) }).eq('id', order.id);
    if (linkErr) throw linkErr;   // never email a payment link the system didn't record
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
    // All or nothing: the order is marked served and the client emailed only once every proof file is stored and checked.
    // Files already checked stay checked, so trying again only re-checks the rest.
    const { files: uploaded, stillChecking, missing, rejected } = await confirmUploads(order.id, body.fileIds);
    if (rejected) throw new HttpError(400, `${rejected} file(s) failed the file check (not a real PDF, Word file or photo) and were removed. Nothing was sent to the client. Upload the proof again.`);
    if (stillChecking) throw new HttpError(503, `${stillChecking} file(s) were stored but couldn't be checked yet. Nothing was sent to the client. Please try again in a minute.`);
    if (missing || !uploaded.length) throw new HttpError(400, 'The upload did not finish. Nothing was sent to the client. Please upload the proof again.');
    const detailText = uploaded.map(u => u.sha256 ? `${u.filename} (SHA-256: ${u.sha256.slice(0, 12)}…)` : u.filename).join(', ');
    await addEvent(order.id, 'proof', 'Proof of service uploaded', detailText);
    // Adding another proof to an order that is already served leaves its served time (frozen by legal hold) alone.
    if (body.markServed && order.status !== 'served') {
        const { error: uErr } = await db().from('orders').update({ status: 'served', served_at: new Date().toISOString(), legal_hold: true }).eq('id', order.id);
        if (uErr) throw uErr;
        await addEvent(order.id, 'status', STATUSES.served.label);
    }
    // The email carries the record's seal (the newest link in its hash chain) and each file's fingerprint. The client
    // keeps these outside our system, so any later change to the record or a file would no longer match them.
    const seal = await orderSeal(order.id);
    // File names would be scrubbed as "links" by the email filter ("proof.pdf" looks like a domain), so label by type.
    const fingerprints = uploaded.filter(u => u.sha256).map((u, i) => `File ${i + 1} (${String(u.filename).split('.').pop().toUpperCase()}): ${u.sha256}`);
    await sendEmail({
        to: order.client_email, subject: `${order.code}: your proof of service is ready`,
        heading: body.markServed ? 'Service complete' : 'New document on your request',
        lines: [body.markServed ? `${order.recipient_name} has been served.` : 'Nick added a document to your request.', 'Download it from your private tracking page.',
            ...(fingerprints.length ? ['SHA-256 file fingerprint(s), for your records:', ...fingerprints] : []),
            ...(seal.head ? [`Record seal (${seal.entries} timeline entries): ${seal.head}`] : [])],
        button: { label: 'Download proof of service', url: `${siteOrigin(request)}/track.html#t=${order.track_token}` },
    });
    return json(await detail(order.id));
}

async function fileUrl(request, body, admin) {
    const { data, error } = await db().from('order_files').select('storage_path, filename, orders(code)').eq('id', uuid(body.fileId, 'File')).eq('uploaded', true).maybeSingle();
    if (error) throw error;
    if (!data) throw new HttpError(404, 'File not found.');
    await auditAdmin(request, admin, 'download_file', data.orders?.code || null, data.filename);
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
    if (order.legal_hold) {
        throw new HttpError(423, 'This order is under legal hold and cannot be deleted. Unlock legal hold first (that step is logged and emailed to you).');
    }
    await requireStepUp(admin, body.totp);
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
