// POST /api/feedback { answers, consent, name?, email?, website? } — a client's answers to Nick's question set
// (feedback.html). Public, so it is rate limited per network address and has the same bot trap as the request form.
import { handle, json, readJson, rateLimit, clientIp, keyedHash } from './_lib/core.mjs';
import { saveClientAnswers, SURVEY_BODY_BYTES } from './_lib/surveys.mjs';

export const POST = handle(async (request) => {
    const body = await readJson(request, SURVEY_BODY_BYTES);   // 30 long answers can pass the usual 64 KB
    const ip = clientIp(request);
    await rateLimit(`feedback:${ip}`, 5, 3600);
    if (body.website) return json({ ok: true });   // bot trap: a hidden field only bots fill in
    await saveClientAnswers({ answers: body.answers, consent: body.consent, name: body.name, email: body.email, ipHash: keyedHash('survey-ip-v1', ip) });   // keyed, so a copy of the table can't be matched back to addresses
    return json({ ok: true });
});
