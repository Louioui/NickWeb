// Passkeys (WebAuthn), shared by the client portal and Nick's dashboard. The server keeps only public keys; a passkey's
// private key never leaves the person's device, and the browser only offers it on this site's own address, so a
// look-alike phishing site gets nothing it can use. Every challenge is single-use, expires in 5 minutes, and is tied to
// the browser that asked for it (a short-lived cookie holds the challenge's id).
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { db, HttpError, IS_PROD, getCookie, rateLimit, clientIp } from './core.mjs';

const RP_NAME = "Nick's Process Services";
const CHALLENGE_MS = 5 * 60e3;
const MAX_PER_OWNER = 10;
const ID_SHAPE = /^[A-Za-z0-9_-]{16,1400}$/;
const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const UNAVAILABLE = 'Passkeys are not available yet. Please sign in with your email code.';

// Which site a passkey belongs to. Production is pinned to the real domain (both www and the bare domain). Previews and
// local testing use the address the request came in on. RP_ID / RP_ORIGINS override both.
export function relyingParty(request) {
    const url = new URL(request.url);
    const rpID = process.env.RP_ID || (IS_PROD ? 'nicksprocessservices.dev' : url.hostname);
    const origins = process.env.RP_ORIGINS ? process.env.RP_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
        : IS_PROD ? ['https://nicksprocessservices.dev', 'https://www.nicksprocessservices.dev'] : [url.origin];
    return { rpID, origins };
}

// A missing table (migration not applied yet) turns into "not available" instead of a crash.
function check(error) {
    if (!error) return;
    if (error.code === '42P01' || error.code === 'PGRST205' || /does not exist|schema cache/i.test(error.message || '')) throw new HttpError(503, UNAVAILABLE);
    throw error;
}

const cookieName = (kind) => `nps_pk_${kind}`;
const cookiePath = (kind) => (kind === 'admin' ? '/api/admin' : '/api/client');
function challengeCookie(request, kind, id) {
    const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
    return `${cookieName(kind)}=${id || ''}; Path=${cookiePath(kind)}; HttpOnly; SameSite=Strict; Max-Age=${id ? CHALLENGE_MS / 1000 : 0}${secure}`;
}
export const clearChallengeCookie = (request, kind) => challengeCookie(request, kind, null);

async function saveChallenge(request, kind, ownerEmail, purpose, challenge) {
    const nowIso = new Date().toISOString();
    await db().from('webauthn_challenges').delete().lt('expires_at', nowIso).then(() => {}, () => {});   // tidy up
    const { data, error } = await db().from('webauthn_challenges').insert({
        owner_kind: kind, owner_email: ownerEmail, purpose, challenge, used: false, expires_at: new Date(Date.now() + CHALLENGE_MS).toISOString(),
    }).select('id').single();
    check(error);
    return challengeCookie(request, kind, data.id);
}

// Uses up this browser's challenge in one database step: it only succeeds once, and only before it expires. Two
// requests racing with the same challenge can't both win.
async function takeChallenge(request, kind, ownerEmail, purpose) {
    const id = getCookie(request, cookieName(kind));
    const expired = new HttpError(400, 'This passkey request expired. Please try again.');
    if (!id || !UUID_SHAPE.test(id)) throw expired;
    let q = db().from('webauthn_challenges').update({ used: true })
        .eq('id', id).eq('owner_kind', kind).eq('purpose', purpose).eq('used', false).gt('expires_at', new Date().toISOString());
    q = ownerEmail ? q.eq('owner_email', ownerEmail) : q.is('owner_email', null);
    const { data, error } = await q.select('challenge');
    check(error);
    if (!data || data.length !== 1) throw expired;
    return data[0].challenge;
}

export async function listPasskeys(kind, ownerEmail) {
    const { data, error } = await db().from('webauthn_credentials').select('credential_id, label, created_at, last_used_at, transports')
        .eq('owner_kind', kind).eq('owner_email', ownerEmail).order('created_at', { ascending: true });
    check(error);
    // Public keys and counters stay on the server.
    return (data || []).map(c => ({ id: c.credential_id, label: c.label || 'Passkey', createdAt: c.created_at, lastUsedAt: c.last_used_at }));
}

// Step 1 of adding a passkey. The caller has already checked that the person is signed in and has re-proven who they are.
export async function registrationOptions(request, kind, ownerEmail, userId, displayName) {
    const existing = await listPasskeys(kind, ownerEmail);
    if (existing.length >= MAX_PER_OWNER) throw new HttpError(400, `You already have ${MAX_PER_OWNER} passkeys. Remove one before adding another.`);
    const { rpID } = relyingParty(request);
    const options = await generateRegistrationOptions({
        rpName: RP_NAME, rpID, userName: ownerEmail, userDisplayName: displayName || ownerEmail,
        userID: new TextEncoder().encode(userId),
        attestationType: 'none',
        excludeCredentials: existing.map(c => ({ id: c.id })),   // the same device can't be added twice
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    });
    const cookie = await saveChallenge(request, kind, ownerEmail, 'register', options.challenge);
    return { options, cookie };
}

const cleanLabel = (v) => String(v || '').replace(/[\u0000-\u001F\u007F‪-‮⁦-⁩]+/g, ' ').trim().slice(0, 80) || null;

// Step 2 of adding a passkey: checks the device's answer and saves its public key.
export async function registrationVerify(request, kind, ownerEmail, response, label, ownerUserId = null) {
    if (!response || typeof response !== 'object' || typeof response.id !== 'string' || !ID_SHAPE.test(response.id)) {
        throw new HttpError(400, 'That passkey could not be added. Please try again.');
    }
    const expectedChallenge = await takeChallenge(request, kind, ownerEmail, 'register');
    const { rpID, origins } = relyingParty(request);
    let result;
    try {
        result = await verifyRegistrationResponse({ response, expectedChallenge, expectedOrigin: origins, expectedRPID: rpID, requireUserVerification: true });
    } catch { result = null; }
    if (!result?.verified) throw new HttpError(400, 'That passkey could not be added. Please try again.');
    const { credential } = result.registrationInfo;
    if ((await listPasskeys(kind, ownerEmail)).length >= MAX_PER_OWNER) throw new HttpError(400, `You already have ${MAX_PER_OWNER} passkeys.`);
    const cleanName = cleanLabel(label);
    const { error } = await db().from('webauthn_credentials').insert({
        credential_id: credential.id, owner_kind: kind, owner_email: ownerEmail, owner_user_id: ownerUserId,
        public_key: Buffer.from(credential.publicKey).toString('base64url'), counter: credential.counter || 0,
        transports: (credential.transports || []).filter(t => typeof t === 'string' && t.length <= 20).slice(0, 8),
        label: cleanName,
    });
    if (error?.code === '23505') throw new HttpError(409, 'This passkey is already saved.');
    check(error);
    return { id: credential.id, label: cleanName };
}

// Step 1 of signing in. No email is asked for: the person picks a passkey on their device, and the passkey says who
// they are. Limited per network address because anyone can ask.
export async function loginOptions(request, kind) {
    await rateLimit(`passkey-options:${kind}:${clientIp(request)}`, 30, 900);
    const { rpID } = relyingParty(request);
    const options = await generateAuthenticationOptions({ rpID, userVerification: 'required' });
    const cookie = await saveChallenge(request, kind, null, 'login', options.challenge);
    return { options, cookie };
}

// Step 2 of signing in. Returns the email the passkey belongs to, taken from our own records, never from the request.
export async function loginVerify(request, kind, response) {
    await rateLimit(`passkey-verify:${kind}:${clientIp(request)}`, 20, 900);
    const failed = new HttpError(401, 'That passkey could not be used to sign in. Please try again or use your email code.');
    if (!response || typeof response !== 'object' || typeof response.id !== 'string' || !ID_SHAPE.test(response.id)) throw failed;
    const expectedChallenge = await takeChallenge(request, kind, null, 'login');
    const { data: cred, error } = await db().from('webauthn_credentials').select('credential_id, owner_email, owner_user_id, public_key, counter, transports')
        .eq('credential_id', response.id).eq('owner_kind', kind).maybeSingle();
    check(error);
    if (!cred) throw failed;
    const { rpID, origins } = relyingParty(request);
    let result;
    try {
        result = await verifyAuthenticationResponse({
            response, expectedChallenge, expectedOrigin: origins, expectedRPID: rpID, requireUserVerification: true,
            credential: { id: cred.credential_id, publicKey: new Uint8Array(Buffer.from(cred.public_key, 'base64url')), counter: Number(cred.counter) || 0, transports: cred.transports || [] },
        });
    } catch { result = null; }   // includes a counter that went backwards (a sign the passkey was copied)
    if (!result?.verified) throw failed;
    // The counter only moves forward: the write lands only if nobody else updated it since it was read.
    const { data: moved, error: uErr } = await db().from('webauthn_credentials')
        .update({ counter: result.authenticationInfo.newCounter, last_used_at: new Date().toISOString() })
        .eq('credential_id', cred.credential_id).eq('counter', cred.counter).select('credential_id');
    check(uErr);
    if (!moved?.length) throw failed;
    return { ownerEmail: cred.owner_email, ownerUserId: cred.owner_user_id, credentialId: cred.credential_id };
}

// Used when the account a passkey belonged to no longer exists.
export async function dropPasskey(id) {
    await db().from('webauthn_credentials').delete().eq('credential_id', id).then(() => {}, () => {});
}

export async function removePasskey(kind, ownerEmail, id) {
    if (typeof id !== 'string' || !ID_SHAPE.test(id)) throw new HttpError(400, 'Passkey not found.');
    const { data, error } = await db().from('webauthn_credentials').delete()
        .eq('credential_id', id).eq('owner_kind', kind).eq('owner_email', ownerEmail).select('credential_id');
    check(error);
    if (!data?.length) throw new HttpError(404, 'Passkey not found.');
}
