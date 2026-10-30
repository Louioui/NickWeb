// The client feedback form (feedback.html). Questions come from assets/js/surveys.js; answers go to /api/feedback,
// only with the client's permission. A draft is kept on this device until it is sent.
(() => {
    const $ = (id) => document.getElementById(id);
    const { esc } = NPS;
    const form = NPS_SURVEYS.client;
    const DRAFT = 'nps_feedback_draft_v1';

    $('fb-title').textContent = form.title;
    $('fb-intro').textContent = form.intro;
    $('fb-count').textContent = `${form.questions.length} questions, all optional.`;
    $('fb-consent-text').textContent = form.consent;
    $('fb-questions').innerHTML = form.questions.map((q, i) => `
        <li class="panel p-5 sm:p-6 space-y-2">
            <label for="q-${q.id}" class="block text-sm font-semibold text-ink"><span class="text-bronze mr-1">${i + 1}.</span> ${esc(q.q)}</label>
            ${q.type === 'choice'
                ? `<select id="q-${q.id}" class="field" data-q="${q.id}"><option value="">Choose one (optional)</option>${q.options.map(o => `<option>${esc(o)}</option>`).join('')}</select>`
                : q.type === 'short'
                    ? `<input id="q-${q.id}" class="field" maxlength="4000" data-q="${q.id}">`
                    : `<textarea id="q-${q.id}" class="field h-28 resize-y" maxlength="4000" data-q="${q.id}" placeholder="Please tell as much as you can"></textarea>`}
        </li>`).join('');

    const fields = () => [...document.querySelectorAll('[data-q]')];
    const collect = () => Object.fromEntries(fields().map(el => [el.dataset.q, el.value.trim()]).filter(([, v]) => v));
    try {
        const saved = JSON.parse(localStorage.getItem(DRAFT) || '{}');
        fields().forEach(el => { if (saved.answers?.[el.dataset.q]) el.value = saved.answers[el.dataset.q]; });
        if (saved.name) $('fb-name').value = saved.name;
        if (saved.email) $('fb-email').value = saved.email;
    } catch { /* no draft */ }
    $('feedback-form').addEventListener('input', () => {
        try { localStorage.setItem(DRAFT, JSON.stringify({ answers: collect(), name: $('fb-name').value, email: $('fb-email').value })); } catch { /* storage off */ }
    });

    $('feedback-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const err = $('fb-error');
        const answers = collect();
        const problem = !Object.keys(answers).length ? 'Please answer at least one question.'
            : !$('fb-consent').checked ? 'Please tick the box to say Nick may use your answers.' : '';
        err.classList.toggle('hidden', !problem);
        err.textContent = problem;
        // Take the person to what needs fixing: the permission box, or the first question.
        if (problem) return (!Object.keys(answers).length ? document.querySelector('[data-q]') : $('fb-consent')).focus();
        const btn = $('fb-submit');
        btn.disabled = true; btn.textContent = 'Sending…';
        try {
            await NPS.post('/api/feedback', { answers, consent: true, name: $('fb-name').value.trim(), email: $('fb-email').value.trim(), website: $('fb-website').value });
            try { localStorage.removeItem(DRAFT); } catch { /* storage off */ }
            $('feedback-form').classList.add('hidden');
            $('fb-done').classList.remove('hidden');
            $('fb-done').setAttribute('tabindex', '-1');
            $('fb-done').focus();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        } catch (ex) {
            err.textContent = ex.message;
            err.classList.remove('hidden');
            err.scrollIntoView({ block: 'center', behavior: 'smooth' });
        } finally { btn.disabled = false; btn.textContent = 'Send my answers'; }
    });
})();
