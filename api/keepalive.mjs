// GET /api/keepalive — run daily by Vercel Cron (vercel.json). A real query keeps the free Supabase project
// from pausing after 7 quiet days, and clears out expired login codes and sessions.
import { db, handle, json, HttpError, BUCKET } from './_lib/core.mjs';

export const GET = handle(async (request) => {
    const secret = process.env.CRON_SECRET;
    if (secret && request.headers.get('authorization') !== `Bearer ${secret}`) throw new HttpError(401, 'Unauthorized.');
    const now = new Date().toISOString();
    const { count, error } = await db().from('orders').select('id', { count: 'exact', head: true });
    if (error) throw error;
    await db().from('admin_codes').delete().lt('expires_at', now);
    await db().from('admin_sessions').delete().lt('expires_at', now);

    // Upload links that were handed out but never finished (closed tab, bots) would otherwise use up free storage.
    const dayAgo = new Date(Date.now() - 864e5).toISOString();
    const { data: stale } = await db().from('order_files').select('id, storage_path').eq('uploaded', false).lt('created_at', dayAgo).limit(500);
    if (stale?.length) {
        await db().storage.from(BUCKET).remove(stale.map(f => f.storage_path));
        await db().from('order_files').delete().in('id', stale.map(f => f.id));
    }
    return json({ ok: true, orders: count, staleUploadsRemoved: stale?.length || 0 });
});
