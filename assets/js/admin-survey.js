// The Survey window in Nick's dashboard: his own questions (saved to the server, so his developer can read them), his
// clients' answers from feedback.html, and the link + QR code to share. Loaded after admin.js and surveys.js.
(() => {
    const $ = (id) => document.getElementById(id);
    const { esc } = NPS;
    const { nick, client } = NPS_SURVEYS;
    let tab = 'mine', responses = null, returnFocus = null;
    const link = `${location.origin}/feedback.html`;

    async function load() {
        try { responses = (await api('survey-list')).responses; }
        catch (err) { responses = { error: err.status === 503 ? 'Saving answers is not set up yet (its database table needs to be added).' : err.message }; }
    }
    const mine = () => Array.isArray(responses) ? responses.find(r => r.form === nick.id) : null;
    const clients = () => Array.isArray(responses) ? responses.filter(r => r.form === client.id) : [];

    function render() {
        document.querySelectorAll('[data-survey-tab]').forEach(b => { const on = b.dataset.surveyTab === tab; b.classList.toggle('is-active', on); b.setAttribute('aria-pressed', String(on)); });
        $('survey-count').textContent = Array.isArray(responses) ? `(${clients().length})` : '';
        const body = $('survey-body');
        if (responses?.error) { body.innerHTML = `<p class="result-box result-warn text-sm">${esc(responses.error)}</p>`; return; }
        if (tab === 'mine') {
            const saved = mine()?.answers || {};
            body.innerHTML = `<p class="text-sm text-muted leading-relaxed">${esc(nick.intro)}</p>
                <p class="text-xs text-muted">${Object.keys(saved).length} of ${nick.questions.length} answered${mine()?.updated_at ? `, last saved ${esc(NPS.fmtDate(mine().updated_at))}` : ''}. You can save and come back later.</p>
                <ol class="space-y-4">${nick.questions.map((q, i) => `<li><label for="sv-${q.id}" class="block text-sm font-semibold text-ink mb-1"><span class="text-bronze mr-1">${i + 1}.</span> ${esc(q.q)}</label>
                    ${q.type === 'short' ? `<input id="sv-${q.id}" class="field" data-sv="${q.id}" maxlength="4000" value="${esc(saved[q.id] || '')}">`
                        : `<textarea id="sv-${q.id}" class="field h-24 resize-y" data-sv="${q.id}" maxlength="4000">${esc(saved[q.id] || '')}</textarea>`}</li>`).join('')}</ol>
                <label class="flex items-start gap-3 text-sm"><input id="sv-consent" type="checkbox" class="mt-1 w-5 h-5 accent-primary" ${mine() ? 'checked' : ''}> <span>${esc(nick.consent)}</span></label>
                <p id="sv-msg" class="hidden result-box text-sm" role="status"></p>
                <button type="button" class="btn btn-pine btn-sm" data-sv-save>Save my answers</button>`;
            return;
        }
        if (tab === 'answers') {
            const list = clients();
            body.innerHTML = !list.length ? '<p class="text-sm text-muted">No client answers yet. Share the link from the "Share with clients" tab.</p>' : `
                <div class="flex flex-wrap items-center justify-between gap-2"><p class="text-sm text-muted">${list.length} client${list.length === 1 ? '' : 's'} answered. Only you and your developer can see these.</p>
                <button type="button" class="btn btn-outline btn-sm" data-sv-csv><i class="fa-solid fa-file-csv"></i> Download all (CSV)</button></div>
                ${list.map(r => `<details class="panel p-4"><summary class="cursor-pointer text-sm font-semibold text-primary">${esc(r.contact_name || 'No name given')}${r.contact_email ? ` · ${esc(r.contact_email)}` : ''} · ${esc(NPS.fmtDate(r.created_at))} · ${Object.keys(r.answers || {}).length} answers</summary>
                    <dl class="mt-3 space-y-3 text-sm">${client.questions.filter(q => r.answers?.[q.id]).map(q => `<div><dt class="text-muted">${esc(q.q)}</dt><dd class="whitespace-pre-line text-ink">${esc(r.answers[q.id])}</dd></div>`).join('')}</dl></details>`).join('')}`;
            return;
        }
        body.innerHTML = `<p class="text-sm text-muted">Give this link to your clients, or let them scan the code on your phone. They answer ${client.questions.length} simple questions; nothing is saved unless they tick the permission box.</p>
            <div class="flex flex-wrap items-center gap-2"><input class="field font-mono text-xs flex-1 min-w-[14rem]" readonly value="${esc(link)}" aria-label="Link to the client questions">
            <button type="button" class="btn btn-pine btn-sm" data-sv-copy>Copy link</button></div>
            <div id="sv-qr" class="inline-block bg-white p-3 rounded-sm" aria-label="QR code for the client questions"></div>`;
        try { const qr = qrcode(0, 'M'); qr.addData(link); qr.make(); $('sv-qr').innerHTML = qr.createSvgTag({ cellSize: 5, margin: 2 }); } catch { /* QR library missing */ }
    }

    const csvCell = (v) => { const t = String(v ?? ''); return /^[=+\-@\t\r]/.test(t) ? `"'${t.replace(/"/g, '""')}"` : /[",\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t; };
    function downloadCsv() {
        const head = ['Sent', 'Name', 'Email', ...client.questions.map((q, i) => `${i + 1}. ${q.q}`)];
        const rows = clients().map(r => [r.created_at.slice(0, 16).replace('T', ' '), r.contact_name, r.contact_email, ...client.questions.map(q => r.answers?.[q.id] || '')]);
        const url = URL.createObjectURL(new Blob([[head, ...rows].map(row => row.map(csvCell).join(',')).join('\n')], { type: 'text/csv' }));
        const a = Object.assign(document.createElement('a'), { href: url, download: 'client-answers.csv' });
        document.body.append(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    async function open() {
        returnFocus = document.activeElement;
        $('survey-modal').classList.remove('hidden');
        $('survey-body').innerHTML = '<p class="text-sm text-muted">Loading…</p>';
        $('survey-title').focus();
        await load();
        render();
    }
    function close() { $('survey-modal').classList.add('hidden'); if (returnFocus?.isConnected) returnFocus.focus(); }

    document.addEventListener('click', async (e) => {
        if (e.target.closest('[data-survey-open]')) return open();
        if ($('survey-modal').classList.contains('hidden')) return;
        if (e.target === $('survey-modal') || e.target.closest('[data-survey-close]')) return close();
        const t = e.target.closest('[data-survey-tab]');
        if (t) { tab = t.dataset.surveyTab; return render(); }
        if (e.target.closest('[data-sv-csv]')) return downloadCsv();
        if (e.target.closest('[data-sv-copy]')) {
            const b = e.target.closest('[data-sv-copy]');
            try { await navigator.clipboard.writeText(link); b.textContent = 'Copied'; } catch { b.textContent = 'Copy failed'; }
            return setTimeout(() => { b.textContent = 'Copy link'; }, 2000);
        }
        if (e.target.closest('[data-sv-save]')) {
            const b = e.target.closest('[data-sv-save]'), msg = $('sv-msg');
            const answers = Object.fromEntries([...document.querySelectorAll('[data-sv]')].map(el => [el.dataset.sv, el.value.trim()]).filter(([, v]) => v));
            b.disabled = true;
            try {
                await api('survey-save', { answers, consent: $('sv-consent').checked });
                await load();
                msg.className = 'result-box result-ok text-sm'; const n = Object.keys(answers).length; msg.textContent = `Saved ${n} answer${n === 1 ? '' : 's'}. Your developer can read them now.`;
            } catch (err) { msg.className = 'result-box result-err text-sm'; msg.textContent = err.message; }
            finally { b.disabled = false; msg.classList.remove('hidden'); }
        }
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !$('survey-modal').classList.contains('hidden')) close();
    });
})();
