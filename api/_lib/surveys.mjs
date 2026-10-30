// Saving and reading the survey answers (Nick's and his clients'). Answers are plain text keyed by question id; nothing
// is saved without consent. The question wording lives in assets/js/surveys.js.
import { db, HttpError, text, email as cleanEmail } from './core.mjs';

export const FORMS = { 'nick-v1': /^n\d{2}$/, 'client-v1': /^c\d{2}$/ };
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

// Nick has one set of answers, which he can come back and update.
export async function saveNickAnswers(admin, { answers, consent }) {
    if (consent !== true) throw new HttpError(400, 'Please tick the box to give permission to use your answers.');
    const now = new Date().toISOString();
    const clean = cleanAnswers('nick-v1', answers);
    const { data: existing, error: rErr } = await db().from('survey_responses').select('id').eq('form', 'nick-v1').eq('respondent', admin).maybeSingle();
    if (missing(rErr)) throw new HttpError(503, UNAVAILABLE);
    if (rErr) throw rErr;
    const { error } = existing
        ? await db().from('survey_responses').update({ answers: clean, consent: true, updated_at: now }).eq('id', existing.id)
        : await db().from('survey_responses').insert({ form: 'nick-v1', respondent: admin, answers: clean, consent: true });
    if (error) throw error;
}

export async function listAnswers() {
    const { data, error } = await db().from('survey_responses').select('id, form, respondent, contact_name, contact_email, answers, created_at, updated_at')
        .order('created_at', { ascending: false }).limit(2000);
    if (missing(error)) throw new HttpError(503, UNAVAILABLE);
    if (error) throw error;
    return data || [];
}
