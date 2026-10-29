// GET /api/keepalive — run daily by Vercel Cron (vercel.json). A real query keeps the free Supabase project
// from pausing after 7 quiet days, and clears out expired login codes and sessions.
import { db, handle, json, HttpError } from './_lib/core.mjs';

export const GET = handle(async (request) => {
    const secret = process.env.CRON_SECRET;
    if (secret && request.headers.get('authorization') !== `Bearer ${secret}`) throw new HttpError(401, 'Unauthorized.');
    const now = new Date().toISOString();
    const { count, error } = await db().from('orders').select('id', { count: 'exact', head: true });
    if (error) throw error;
    await db().from('admin_codes').delete().lt('expires_at', now);
    await db().from('admin_sessions').delete().lt('expires_at', now);
    return json({ ok: true, orders: count });
});
