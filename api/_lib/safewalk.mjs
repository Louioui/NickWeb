// Safe-Walk: before a risky serve Nick starts a timer; if he doesn't check in ("I'm safe") before it runs out, his
// emergency contact is emailed the job's reference and address. Checked every minute by Vercel Cron (api/safewalk.mjs)
// and again whenever the dashboard is open. Each walk alerts at most once, in one database step.
import { db, HttpError, email as cleanEmail } from './core.mjs';
import { sendEmail } from './orders.mjs';

const UNAVAILABLE = 'Safe-Walk is not set up yet (its database tables need to be added).';
const missing = (error) => error && (error.code === '42P01' || error.code === 'PGRST205' || /schema cache|does not exist/i.test(error.message || ''));
const fail = (error) => { if (missing(error)) throw new HttpError(503, UNAVAILABLE); if (error) throw error; };

export async function getContact(admin) {
    const { data, error } = await db().from('admin_settings').select('emergency_email').eq('email', admin).maybeSingle();
    fail(error);
    return data?.emergency_email || null;
}
export async function setContact(admin, value) {
    const contact = value ? cleanEmail(value) : null;
    if (contact === admin) throw new HttpError(400, 'Use someone else\'s email address, not your own.');
    const { error } = await db().from('admin_settings').upsert({ email: admin, emergency_email: contact, updated_at: new Date().toISOString() });
    fail(error);
    return contact;
}
export async function activeWalk(admin) {
    const { data, error } = await db().from('safe_walks').select('id, started_at, due_at, order_code, alerted_at')
        .eq('email', admin).is('checked_in_at', null).order('started_at', { ascending: false }).limit(1);
    fail(error);
    return data?.[0] || null;
}
export async function startWalk(admin, minutes, order) {
    const m = Number(minutes);
    if (!Number.isInteger(m) || m < 5 || m > 180) throw new HttpError(400, 'Choose between 5 and 180 minutes.');
    if (!(await getContact(admin))) throw new HttpError(400, 'Add an emergency contact first.');
    await checkIn(admin);   // only one walk at a time
    const now = Date.now();
    const { error } = await db().from('safe_walks').insert({
        email: admin, started_at: new Date(now).toISOString(), due_at: new Date(now + m * 60e3).toISOString(),
        order_code: order?.code || null,
        address: order ? `${order.address}${order.unit ? ', ' + order.unit : ''}, ${order.city} ${order.zip}`.slice(0, 300) : null,
    });
    fail(error);
    return activeWalk(admin);
}
export async function checkIn(admin) {
    const { error } = await db().from('safe_walks').update({ checked_in_at: new Date().toISOString() }).eq('email', admin).is('checked_in_at', null);
    fail(error);
}

// Alerts every overdue walk once. The update only succeeds for a walk not yet alerted, so two checks running at the same
// moment can't both send. If the email fails, the alert is undone so the next check tries again.
export async function alertOverdueWalks() {
    const nowIso = new Date().toISOString();
    const { data: due, error } = await db().from('safe_walks').select('id')
        .is('checked_in_at', null).is('alerted_at', null).lt('due_at', nowIso).limit(20);
    if (missing(error)) return 0;
    if (error) throw error;
    let sent = 0;
    for (const { id } of due || []) {
        const { data: claimed, error: cErr } = await db().from('safe_walks').update({ alerted_at: nowIso })
            .eq('id', id).is('alerted_at', null).is('checked_in_at', null).select('email, started_at, due_at, order_code, address');
        if (cErr) throw cErr;
        const walk = claimed?.[0];
        if (!walk) continue;
        const contact = await getContact(walk.email).catch(() => null);
        const lines = [
            `Nick started a Safe-Walk timer at ${fmt(walk.started_at)} and has not checked in since it ran out at ${fmt(walk.due_at)} (California time).`,
            walk.address ? `He was serving papers at: ${walk.address}${walk.order_code ? ` (job ${walk.order_code})` : ''}.` : 'No job address was attached to the timer.',
            'Try calling him now. If you can\'t reach him and you are worried, call 911 and give them the address above.',
        ];
        const ok = contact && await sendEmail({ to: contact, subject: 'Safe-Walk alert: Nick has not checked in', heading: 'Nick has not checked in', lines }).catch(() => false);
        await sendEmail({ to: walk.email, subject: 'Safe-Walk: your timer ran out', heading: 'Your Safe-Walk timer ran out',
            lines: [ok ? 'Your emergency contact has been emailed.' : 'Your emergency contact could NOT be emailed. Check your Safe-Walk settings.', 'Open your dashboard and tap "I\'m safe" if you are.'] }).catch(() => false);
        if (ok) sent++;
        else await db().from('safe_walks').update({ alerted_at: null }).eq('id', id).then(() => {}, () => {});   // try again next minute
    }
    return sent;
}
const fmt = (iso) => new Intl.DateTimeFormat('en-US', { timeZone: 'America/Los_Angeles', hour: 'numeric', minute: '2-digit', month: 'short', day: 'numeric' }).format(new Date(iso));
