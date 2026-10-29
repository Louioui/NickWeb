// Client identity comes only from Supabase Auth's verified user, never a form field or user_metadata.
import { createClient } from '@supabase/supabase-js';
import { SUPABASE_URL, HttpError, getCookie, email } from './core.mjs';
export const CLIENT_COOKIE = 'nps_client';
export function clientAuth() {
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!key) throw new HttpError(503, 'Client accounts are not available yet. Please use your private tracking link.');
    return createClient(SUPABASE_URL, key, { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } });
}
export function clientCookie(request, session) {
    const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
    const value = session ? encodeURIComponent(JSON.stringify({ access: session.access_token, refresh: session.refresh_token })) : '';
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
        return { access: parsed.access, refresh: parsed.refresh };
    } catch { return null; }
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
    const current = await auth.auth.getUser(saved.access);
    if (!current.error) return { user: verifiedClient(current.data.user), renewed: null };
    // Only expired tokens may be refreshed. Other invalid identities remain signed out.
    if (current.error.code !== 'bad_jwt' && current.error.code !== 'jwt_expired' && !/expired/i.test(current.error.message || '')) throw new HttpError(401, 'Your sign-in expired. Please sign in again.');
    const { data, error } = await auth.auth.refreshSession({ refresh_token: saved.refresh });
    if (error || !data.session) throw new HttpError(401, 'Your sign-in expired. Please sign in again.');
    return { user: verifiedClient(data.user), renewed: data.session };
}
export function clientProfile(user) {
    // Display-only metadata cannot grant roles, choose an email, or grant access to orders.
    const cleanMeta = (v, max) => String(v || '').replace(/[\u0000-\u001F\u007F\u202A-\u202E\u2066-\u2069]+/g, ' ').trim().slice(0, max);
    return { name: cleanMeta(user.user_metadata?.full_name, 120), firm: cleanMeta(user.user_metadata?.firm, 160), email: String(user.email || '').trim().toLowerCase() };
}
