// Law-firm accounts (foundation): one firm, several staff, three roles.
//   admin     – manages staff, replaces tracking links, sees every request the firm made
//   billing   – pays open balances and downloads statements
//   paralegal – submits and tracks requests
// Nothing on the site calls this yet; the firm screens come later. Every check here happens on the server.
import { db, HttpError, email as cleanEmail, text, siteOrigin, addEvent } from './core.mjs';
import { sendEmail } from './orders.mjs';

export const FIRM_ROLES = ['admin', 'billing', 'paralegal'];
const UNAVAILABLE = 'Firm accounts are not set up yet.';
const check = (error) => {
    if (!error) return;
    if (error.code === '42P01' || error.code === 'PGRST205' || /schema cache|does not exist/i.test(error.message || '')) throw new HttpError(503, UNAVAILABLE);
    throw error;
};

// The signed-in person's current role in a firm, or null. Removed staff have no role.
export async function memberRole(firmId, emailAddr) {
    const { data, error } = await db().from('firm_members').select('role').eq('firm_id', firmId)
        .eq('email', String(emailAddr || '').toLowerCase()).is('removed_at', null).maybeSingle();
    check(error);
    return data?.role || null;
}
export async function requireRole(firmId, emailAddr, roles) {
    const role = await memberRole(firmId, emailAddr);
    if (!role || !roles.includes(role)) throw new HttpError(403, 'You don’t have access to that for this firm.');
    return role;
}

export async function createFirm(name, adminEmail) {
    const firmName = text(name, { max: 160, required: true, label: 'Firm name' });
    const admin = cleanEmail(adminEmail);
    const { data, error } = await db().from('firms').insert({ name: firmName }).select('id').single();
    check(error);
    const { error: mErr } = await db().from('firm_members').insert({ firm_id: data.id, email: admin, role: 'admin', added_by: admin });
    check(mErr);
    return data.id;
}

export async function addMember(firmId, actorEmail, memberEmail, role) {
    await requireRole(firmId, actorEmail, ['admin']);
    if (!FIRM_ROLES.includes(role)) throw new HttpError(400, 'Choose admin, billing or paralegal.');
    const addr = cleanEmail(memberEmail);
    // Re-adding someone who left gives them a fresh membership (their old devices and passkeys are already gone).
    const { error } = await db().from('firm_members').upsert({ firm_id: firmId, email: addr, role, added_by: String(actorEmail).toLowerCase(),
        created_at: new Date().toISOString(), removed_at: null });
    check(error);
    return { email: addr, role };
}

export async function listMembers(firmId, actorEmail) {
    await requireRole(firmId, actorEmail, ['admin']);
    const { data, error } = await db().from('firm_members').select('email, role, created_at, removed_at').eq('firm_id', firmId).order('created_at');
    check(error);
    return data || [];
}

// "Revoke staff member": one database step (firm_remove_member) ends the membership, deletes their trusted devices and
// passkeys, ends their sign-in sessions and replaces the tracking link of every open request they made for the firm.
// The firm's remaining admins are then emailed the new links, and each request's timeline records the change.
export async function removeMember(request, firmId, actorEmail, memberEmail) {
    const addr = cleanEmail(memberEmail);
    const { data: rotated, error } = await db().rpc('firm_remove_member', { p_firm: firmId, p_email: addr, p_actor: String(actorEmail || '').toLowerCase() });
    if (error && /Only an admin|last admin|not a current member/.test(error.message || '')) throw new HttpError(403, error.message.replace(/^.*?: /, ''));
    check(error);
    const changed = rotated || [];
    for (const o of changed) {
        await addEvent(o.order_id, 'note', 'Private tracking link replaced', 'A staff member left the firm, so the previous link no longer works.', true);
    }
    if (changed.length) {
        const { data: admins } = await db().from('firm_members').select('email').eq('firm_id', firmId).eq('role', 'admin').is('removed_at', null);
        const origin = siteOrigin(request);
        // One email per request: links are only ever sent as the email's button (typed text has links stripped).
        await Promise.all((admins || []).flatMap(({ email: to }) => changed.map(o => sendEmail({
            to, subject: `${o.code}: new tracking link after ${addr} left`,
            heading: 'New tracking link for an open request',
            lines: [`${addr} was removed from your firm. Their devices, passkeys and sign-ins were ended, and the private link for ${o.code} was replaced. The old link no longer works.`],
            button: { label: `Open ${o.code}`, url: `${origin}/track.html#t=${o.track_token}` },
        }).catch(() => false))));
    }
    return { removed: addr, linksReplaced: changed.map(o => o.code) };
}
