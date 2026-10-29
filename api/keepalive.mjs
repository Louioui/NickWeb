// GET /api/keepalive — run daily by Vercel Cron (vercel.json). A real query keeps the free Supabase project
// from pausing after 7 quiet days, and clears out expired login codes and sessions.
import { db, handle, json, HttpError, BUCKET, addEvent, rateLimit, timingSafeMatch, verifyFileMagic, sha256 } from './_lib/core.mjs';

export const GET = handle(async (request) => {
    // With CRON_SECRET set (recommended), only Vercel Cron can run this. Without it, anyone could, so it is throttled.
    const secret = process.env.CRON_SECRET;
    const authHeader = request.headers.get('authorization') || '';
    if (secret && !timingSafeMatch(authHeader, `Bearer ${secret}`)) throw new HttpError(401, 'Unauthorized.');
    if (!secret) await rateLimit('keepalive', 4, 3600);
    const now = new Date().toISOString();
    const { count, error } = await db().from('orders').select('id', { count: 'exact', head: true });
    if (error) throw error;
    await db().from('admin_codes').delete().lt('expires_at', now);
    await db().from('admin_sessions').delete().lt('expires_at', now);

    // Files still marked "not uploaded" a day later: if the file did reach storage (the browser lost its connection before
    // confirming), verify its magic bytes, keep it and show it; if it never arrived or is disguised, remove it.
    const dayAgo = new Date(Date.now() - 864e5).toISOString();
    const { data: stale } = await db().from('order_files').select('id, order_id, storage_path, filename').eq('uploaded', false).lt('created_at', dayAgo).limit(100);
    let recovered = 0;
    const missing = [];
    for (const f of stale || []) {
        const { data: exists } = await db().storage.from(BUCKET).exists(f.storage_path);
        if (exists) {
            let fileHash = null;
            let validMagic = true;
            try {
                const { data: blob } = await db().storage.from(BUCKET).download(f.storage_path);
                if (blob) {
                    const buf = Buffer.from(await blob.arrayBuffer());
                    if (!verifyFileMagic(buf, f.filename)) validMagic = false;
                    else fileHash = sha256(buf);
                }
            } catch { /* non-fatal */ }
            if (!validMagic) {
                await db().storage.from(BUCKET).remove([f.storage_path]).catch(() => {});
                missing.push(f.id);
                continue;
            }
            const patch = fileHash ? { uploaded: true, sha256: fileHash } : { uploaded: true };
            await db().from('order_files').update(patch).eq('id', f.id);
            await addEvent(f.order_id, 'note', 'Document received', f.filename);
            recovered++;
        } else {
            missing.push(f.id);
        }
    }
    if (missing.length) await db().from('order_files').delete().in('id', missing);
    return json({ ok: true, orders: count, uploadsRecovered: recovered, emptyUploadsRemoved: missing.length });
});
