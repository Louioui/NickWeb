// GET /api/safewalk — run every minute by Vercel Cron (vercel.json): emails the emergency contact for any Safe-Walk timer
// that ran out without a check-in. Harmless to call more often: each walk alerts at most once.
import { handle, json, HttpError, rateLimit, timingSafeMatch } from './_lib/core.mjs';
import { alertOverdueWalks } from './_lib/safewalk.mjs';

export const GET = handle(async (request) => {
    // With CRON_SECRET set (recommended), only Vercel Cron can run this. Without it, anyone could, so it is throttled.
    const secret = process.env.CRON_SECRET;
    if (secret && !timingSafeMatch(request.headers.get('authorization') || '', `Bearer ${secret}`)) throw new HttpError(401, 'Unauthorized.');
    if (!secret) await rateLimit('safewalk-cron', 120, 3600);
    return json({ ok: true, alerted: await alertOverdueWalks() });
});
