// Saving and reading the survey answers (Nick's and his clients'). Answers are plain text keyed by question id; nothing
// is saved without consent. The question wording lives in assets/js/surveys.js.
import { db, HttpError, text, email as cleanEmail } from './core.mjs';

// Only the questions that exist (01–30 in each set; keep in step with assets/js/surveys.js).
export const FORMS = { 'nick-v1': /^n(0[1-9]|[12]\d|30)$/, 'client-v1': /^c(0[1-9]|[12]\d|30)$/ };
// The database allows 150,000 bytes of answers; a little under that leaves room for the JSON around them.
const MAX_ANSWER_BYTES = 140000;
// The public client form may send up to 200 KB (30 long answers pass the usual 64 KB). Nick's dashboard keeps 64 KB and
// saves long answers in batches instead.
export const SURVEY_BODY_BYTES = 200 * 1024;
const PAGE = 100;
const UNAVAILABLE = 'Saving answers is not set up yet. Please try again later.';
const missing = (e) => e && (e.code === '42P01' || e.code === 'PGRST205' || /schema cache|does not exist/i.test(e.message || ''));

// Keeps only real question ids and text answers, each cut to a sensible length, with control characters removed.
export function cleanAnswers(form, raw) {
    const idShape = FORMS[form];
    if (!idShape) throw new HttpError(400, 'Unknown form.');
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new HttpError(400, 'Please answer at least one question.');
    const out = {};
    for (const [k, v] of Object.entries(raw).slice(0, 60)) {
        if (!idShape.test(k) || typeof v !== 'string') continue;
        const s = v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F‪-‮⁦-⁩]/g, '').trim().slice(0, 4000);
        if (s) out[k] = s;
    }
    if (!Object.keys(out).length) throw new HttpError(400, 'Please answer at least one question.');
    if (Buffer.byteLength(JSON.stringify(out), 'utf8') > MAX_ANSWER_BYTES) throw new HttpError(400, 'Your answers are too long to send in one go. Please shorten the longest ones.');
    return out;
}

export async function saveClientAnswers({ answers, consent, name, email, ipHash }) {
    if (consent !== true) throw new HttpError(400, 'Please tick the box to give permission to use your answers.');
    const row = { form: 'client-v1', answers: cleanAnswers('client-v1', answers), consent: true, ip_hash: ipHash,
        contact_name: text(name, { max: 120 }), contact_email: email ? cleanEmail(email) : null };
    const { error } = await db().from('survey_responses').insert(row);
    if (missing(error)) throw new HttpError(503, UNAVAILABLE);
    if (error) throw error;
}

// Nick has one set of answers, which he can come back and update. Long answers arrive in several smaller saves (the
// dashboard API takes at most 64 KB a request): each save replaces the questions it carries; `cleared` lists questions
// he emptied, and `replace: true` (the first batch) starts the set again from just this batch.
export async function saveNickAnswers(admin, { answers, consent, cleared, replace }) {
    if (consent !== true) throw new HttpError(400, 'Please tick the box to give permission to use your answers.');
    const now = new Date().toISOString();
    const { data: existing, error: rErr } = await db().from('survey_responses').select('id, answers').eq('form', 'nick-v1').eq('respondent', admin).maybeSingle();
    if (missing(rErr)) throw new HttpError(503, UNAVAILABLE);
    if (rErr) throw rErr;
    const merged = { ...(replace || !existing ? {} : existing.answers || {}) };
    for (const id of Array.isArray(cleared) ? cleared : []) if (FORMS['nick-v1'].test(id)) delete merged[id];
    Object.assign(merged, answers && Object.keys(answers).length ? cleanAnswers('nick-v1', answers) : {});
    if (!Object.keys(merged).length) throw new HttpError(400, 'Please answer at least one question.');
    if (Buffer.byteLength(JSON.stringify(merged), 'utf8') > MAX_ANSWER_BYTES) throw new HttpError(400, 'Your answers are too long to save. Please shorten the longest ones.');
    const { error } = existing
        ? await db().from('survey_responses').update({ answers: merged, consent: true, updated_at: now }).eq('id', existing.id)
        : await db().from('survey_responses').insert({ form: 'nick-v1', respondent: admin, answers: merged, consent: true });
    if (error) throw error;
}

// One page of answers, newest first. Pass the last row's created_at as `before` to get the next page, so a long list
// never becomes one oversized response.
export async function listAnswers(before) {
    let q = db().from('survey_responses').select('id, form, respondent, contact_name, contact_email, answers, created_at, updated_at')
        .order('created_at', { ascending: false }).order('id', { ascending: false }).limit(PAGE + 1);
    if (typeof before === 'string' && !Number.isNaN(Date.parse(before))) q = q.lt('created_at', before);
    const { data, error } = await q;
    if (missing(error)) throw new HttpError(503, UNAVAILABLE);
    if (error) throw error;
    const rows = data || [];
    return { responses: rows.slice(0, PAGE), more: rows.length > PAGE };
}
// Nick's own answers, wherever they fall in the list.
export async function ownAnswers(admin) {
    const { data, error } = await db().from('survey_responses').select('id, form, respondent, answers, created_at, updated_at')
        .eq('form', 'nick-v1').eq('respondent', admin).maybeSingle();
    if (missing(error)) throw new HttpError(503, UNAVAILABLE);
    if (error) throw error;
    return data || null;
}
