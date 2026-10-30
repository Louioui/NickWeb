// Client identity comes only from Supabase Auth's verified user, never a form field or user_metadata.
import { createClient } from '@supabase/supabase-js';
import { SUPABASE_URL, HttpError, getCookie, email, db, signToken, checkToken, randomToken, sha256 } from './core.mjs';
export const CLIENT_COOKIE = 'nps_client';

// --- Security PIN lockout (portal sign-in) ---
// A client's PIN settings. Fails closed: if this lookup errors, sign-in stops instead of skipping the PIN.
export async function getClientSecurity(emailAddr) {
    const { data, error } = await db().from('client_security_settings').select('pin_hash, failed_tries, locked_until').eq('email', emailAddr).maybeSingle();
    if (error) throw new HttpError(503, 'Sign-in is temporarily unavailable. Please try again in a minute.');
    return data || null;
}
const PIN_MAX_TRIES = 5;
const PIN_LOCK_MS = 15 * 60e3;
export const pinLocked = (sec) => !!sec?.locked_until && sec.locked_until > new Date().toISOString();

// Counts one wrong PIN. The write only lands if failed_tries is still the value just read (compare-and-swap), so
// parallel guesses can't share one count. A lock that has run out starts a fresh count instead of re-locking at once.
export async function recordPinFailure(emailAddr) {
    for (let attempt = 0; attempt < 5; attempt++) {
        const sec = await getClientSecurity(emailAddr);
        if (!sec) return;
        const lockOver = !!sec.locked_until && !pinLocked(sec);
        const tries = (lockOver ? 0 : sec.failed_tries || 0) + 1;
        const lockedUntil = tries >= PIN_MAX_TRIES ? new Date(Date.now() + PIN_LOCK_MS).toISOString() : (lockOver ? null : sec.locked_until);
        const { data, error } = await db().from('client_security_settings')
            .update({ failed_tries: tries, locked_until: lockedUntil, updated_at: new Date().toISOString() })
            .eq('email', emailAddr).eq('failed_tries', sec.failed_tries || 0).select('email');
        if (error) throw error;
        if (data?.length) return;
    }
    throw new HttpError(503, 'Sign-in is temporarily unavailable. Please try again in a minute.');
}
export async function clearPinFailures(emailAddr, sec) {
    if (!sec?.failed_tries && !sec?.locked_until) return;
    const { error } = await db().from('client_security_settings').update({ failed_tries: 0, locked_until: null }).eq('email', emailAddr);
    if (error) throw error;
}
export function clientAuth() {
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!key) throw new HttpError(503, 'Client accounts are not available yet. Please use your private tracking link.');
    return createClient(SUPABASE_URL, key, { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } });
}
// The server signs every session cookie it issues (HMAC, server-only key), and only after all sign-in steps, including
// the Security PIN, have passed. Supabase tokens on their own, put into a hand-made cookie, are refused by requireClient.
const SESSION_SECONDS = 86400 * 7;
const proofFor = (userId) => signToken('client-session-v1', userId, SESSION_SECONDS);
// "Signed in within the last 15 minutes", signed once at sign-in and carried over unchanged when the session renews, so
// a copied cookie can't make itself look fresh. Adding a passkey without a PIN needs it.
const FRESH_SECONDS = 15 * 60;
export const freshProofFor = (userId) => signToken('client-fresh-v1', userId, FRESH_SECONDS);
export const isFreshSignIn = (userId, fresh) => checkToken('client-fresh-v1', userId, fresh);
export function clientCookie(request, session, userId, fresh = session ? freshProofFor(userId) : null) {
    if (session && !userId) throw new Error('clientCookie needs the signed-in user id');
    const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
    const value = session ? encodeURIComponent(JSON.stringify({ access: session.access_token, refresh: session.refresh_token, proof: proofFor(userId), ...(fresh ? { fresh } : {}) })) : '';
    if (value.length > 3800) throw new HttpError(503, 'Sign-in could not be completed. Please use your tracking link.');
    return `${CLIENT_COOKIE}=${value}; Path=/api/client; HttpOnly; SameSite=Strict; Max-Age=${session ? 86400 * 7 : 0}${secure}`;
}
export function savedClientSession(request) {
    try {
        const parsed = JSON.parse(getCookie(request, CLIENT_COOKIE) || 'null');
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
        if (typeof parsed.access !== 'string' || typeof parsed.refresh !== 'string') return null;
        if (!parsed.access || !parsed.refresh || parsed.access.length > 4096 || parsed.refresh.length > 1024) return null;
        if (/[\u0000-\u001F\u007F]/.test(parsed.access) || /[\u0000-\u001F\u007F]/.test(parsed.refresh)) return null;
        const proof = typeof parsed.proof === 'string' && /^\d{10}\.[A-Za-z0-9_-]{43}$/.test(parsed.proof) ? parsed.proof : null;
        const fresh = typeof parsed.fresh === 'string' && /^\d{10}\.[A-Za-z0-9_-]{43}$/.test(parsed.fresh) ? parsed.fresh : null;
        return { access: parsed.access, refresh: parsed.refresh, proof, fresh };
    } catch { return null; }
}
// --- Trusted devices (30 days): a device the client has chosen to remember skips the Security PIN, never the email code. ---
export const DEVICE_COOKIE = 'nps_device';
const DEVICE_DAYS = 30;
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{40,64}$/;

// Remembers this device and returns the cookie to send back (or null if it couldn't be saved). Only the token's hash is stored.
export async function rememberDevice(request, emailAddr) {
    const token = randomToken(32);
    const expires = new Date(Date.now() + DEVICE_DAYS * 86400e3).toISOString();
    const { error } = await db().from('client_trusted_devices').insert({
        token_hash: sha256(token), email: emailAddr, expires_at: expires,
        user_agent: String(request.headers.get('user-agent') || '').slice(0, 200) || null,
    });
    if (error) return null;   // never let this optional step break a sign-in (for example before the table exists)
    const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
    return `${DEVICE_COOKIE}=${token}; Path=/api/client; HttpOnly; SameSite=Strict; Max-Age=${DEVICE_DAYS * 86400}${secure}`;
}

// True only for a device this client trusted and that hasn't expired. Any error means "not trusted", so the PIN is asked.
export async function isTrustedDevice(request, emailAddr) {
    const token = getCookie(request, DEVICE_COOKIE);
    if (!token || !TOKEN_SHAPE.test(token)) return false;
    const { data, error } = await db().from('client_trusted_devices').select('email, expires_at').eq('token_hash', sha256(token)).maybeSingle();
    if (error) return false;
    return !!data && data.email === emailAddr && data.expires_at > new Date().toISOString();
}

// "Sign out all devices" also forgets every trusted device, so the next sign-in on any of them asks for the PIN again.
export async function forgetDevices(emailAddr) {
    const { error } = await db().from('client_trusted_devices').delete().eq('email', emailAddr);
    if (error) throw error;
}

export function verifiedClient(user) {
    if (!user?.id || !user?.email || !user.email_confirmed_at) throw new HttpError(401, 'Please verify your email to sign in.');
    try { email(user.email); } catch { throw new HttpError(401, 'Please verify your email to sign in.'); }
    return user;
}
export async function requireClient(request) {
    const saved = savedClientSession(request);
    if (!saved?.access || !saved?.refresh) throw new HttpError(401, 'Please sign in to see your requests.');
    const auth = clientAuth();
    const signedOut = () => new HttpError(401, 'Your sign-in expired. Please sign in again.');
    const current = await auth.auth.getUser(saved.access);
    if (!current.error) {
        const user = verifiedClient(current.data.user);
        if (!checkToken('client-session-v1', user.id, saved.proof)) throw signedOut();
        return { user, renewed: null, fresh: saved.fresh };
    }
    // Only expired tokens may be refreshed. Other invalid identities remain signed out.
    if (current.error.code !== 'bad_jwt' && current.error.code !== 'jwt_expired' && !/expired/i.test(current.error.message || '')) throw new HttpError(401, 'Your sign-in expired. Please sign in again.');
    const { data, error } = await auth.auth.refreshSession({ refresh_token: saved.refresh });
    if (error || !data.session) throw signedOut();
    const user = verifiedClient(data.user);
    if (!checkToken('client-session-v1', user.id, saved.proof)) throw signedOut();
    return { user, renewed: data.session, fresh: saved.fresh };
}
export function clientProfile(user) {
    // Display-only metadata cannot grant roles, choose an email, or grant access to orders.
    const cleanMeta = (v, max) => String(v || '').replace(/[\u0000-\u001F\u007F\u202A-\u202E\u2066-\u2069]+/g, ' ').trim().slice(0, max);
    return { name: cleanMeta(user.user_metadata?.full_name, 120), firm: cleanMeta(user.user_metadata?.firm, 160), email: String(user.email || '').trim().toLowerCase() };
}
