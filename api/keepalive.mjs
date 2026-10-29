// GET /api/keepalive — run daily by Vercel Cron (vercel.json). A real query keeps the free Supabase project
// from pausing after 7 quiet days, and clears out expired login codes and sessions.
import { db, handle, json, HttpError, BUCKET, addEvent, rateLimit, timingSafeMatch, inspectStoredFile } from './_lib/core.mjs';

const BATCH = 100;

export const GET = handle(async (request) => {
    // With CRON_SECRET set (recommended), only Vercel Cron can run this. Without it, anyone could, so it is throttled.
    const secret = process.env.CRON_SECRET;
    const authHeader = request.headers.get('authorization') || '';
    if (secret && !timingSafeMatch(authHeader, `Bearer ${secret}`)) throw new HttpError(401, 'Unauthorized.');
    if (!secret) await rateLimit('keepalive', 4, 3600);
    const now = new Date().toISOString();
    const dayAgo = new Date(Date.now() - 864e5).toISOString();
    const { count, error } = await db().from('orders').select('id', { count: 'exact', head: true });
    if (error) throw error;
    await db().from('admin_codes').delete().lt('expires_at', now);
    await db().from('admin_sessions').delete().lt('expires_at', now);
    await db().from('rate_limits').delete().lt('window_start', dayAgo);

    // Files still marked "not uploaded" a day later: if the file did reach storage (the browser lost its connection before
    // confirming), verify its magic bytes, keep it and show it; if it never arrived or is disguised, remove it. If storage
    // can't be reached, leave the row alone and try again tomorrow, so a stored upload is never lost or accepted unchecked.
    // Each run checks at most 100 files, starting at a different place in the (oldest-first) queue every day, so files that
    // keep failing can't take the whole batch day after day: with a stable queue, every pending upload is reached within
    // ceil(pending / 100) days, however long the queue is. No cursor is stored; the day number picks the starting point.
    const pending = () => db().from('order_files').select('id, order_id, storage_path, filename')
        .eq('uploaded', false).lt('created_at', dayAgo).order('created_at', { ascending: true });
    const { count: total, error: cErr } = await db().from('order_files').select('id', { count: 'exact', head: true })
        .eq('uploaded', false).lt('created_at', dayAgo);
    if (cErr) throw cErr;
    const start = total > BATCH ? (Math.floor(Date.now() / 864e5) * BATCH) % total : 0;
    const { data: first, error: sErr } = await pending().range(start, start + BATCH - 1);
    if (sErr) throw sErr;
    let batch = first || [];
    if (batch.length < BATCH && start > 0) {   // wrap around to the oldest uploads
        const { data: wrapped, error: wErr } = await pending().range(0, Math.min(BATCH - batch.length, start) - 1);
        if (wErr) throw wErr;
        batch = batch.concat(wrapped || []);
    }
    let recovered = 0;
    let retryLater = 0;
    const missing = [];
    for (const f of batch) {
        const check = await inspectStoredFile(f.storage_path, f.filename);
        if (check.state === 'unknown') { retryLater++; continue; }
        if (check.state !== 'ok') {
            if (check.state === 'bad') await db().storage.from(BUCKET).remove([f.storage_path]).catch(() => {});
            missing.push(f.id);
            continue;
        }
        const { error: uErr } = await db().from('order_files').update({ uploaded: true, sha256: check.sha256 }).eq('id', f.id);
        if (uErr) throw uErr;
        await addEvent(f.order_id, 'note', 'Document received', f.filename);
        recovered++;
    }
    if (missing.length) await db().from('order_files').delete().in('id', missing);
    return json({ ok: true, orders: count, uploadsRecovered: recovered, emptyUploadsRemoved: missing.length, uploadsToRetry: retryLater });
});
