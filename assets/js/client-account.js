// Passwordless client portal. Production credentials are stored only in HttpOnly server cookies.
(() => {
    const $ = id => document.getElementById(id), { esc } = NPS;
    let mode = location.hash === '#signup' ? 'signup' : 'signin', pendingEmail = '', sending = false, cooldownUntil = 0;
    let orders = [], filter = 'all', signedIn = false;
    const post = (action, data = {}) => NPS.post('/api/client', { action, ...data }, { notify: ['verify-code', 'session', 'logout'].includes(action) });
    function showError(message) { $('account-error').textContent = message || ''; $('account-error').classList.toggle('hidden', !message); }
    function setMode(next) {
        mode = next;
        $('account-name').required = mode === 'signup';
        $('account-signup-fields').classList.toggle('hidden', mode !== 'signup');
        $('auth-title').textContent = mode === 'signup' ? 'Create your client account' : 'Welcome back';
        $('auth-intro').textContent = mode === 'signup' ? 'Keep your requests and proof of service together. Start by verifying your email address.' : 'Sign in to see your service requests, updates, payments and proof of service.';
        $('send-client-email').textContent = mode === 'signup' ? 'Create account & verify email' : 'Send sign-in email';
        for (const name of ['signin', 'signup']) { $('mode-' + name).classList.toggle('is-active', mode === name); $('mode-' + name).setAttribute('aria-pressed', String(mode === name)); }
        $('account-email-form').classList.remove('hidden'); $('account-code-form').classList.add('hidden'); showError('');
    }
    function showAuth() {
        signedIn = false; orders = []; $('client-orders').replaceChildren(); $('client-identity').textContent = '';
        $('account-loading').classList.add('hidden'); $('client-workspace').classList.add('hidden'); $('account-auth').classList.remove('hidden'); setMode(mode);
    }
    $('mode-signin').onclick = () => { if (!sending) setMode('signin'); };
    $('mode-signup').onclick = () => { if (!sending) setMode('signup'); };
    $('change-client-email').onclick = () => { if (!sending) { setMode(mode); $('account-email').focus(); } };
    async function sendEmail() {
        if (sending) return;
        const addr = $('account-email').value.trim().toLowerCase();
        if (addr === pendingEmail && Date.now() < cooldownUntil) { showError('Please wait a minute before requesting another verification email.'); return; }
        sending = true; showError('');
        const btn = $('send-client-email'); btn.disabled = true; $('resend-client-email').disabled = true; btn.textContent = 'Sending verification…';
        try {
            const result = await post('send-code', { email: addr, intent: mode, name: $('account-name').value.trim(), firm: $('account-firm').value.trim() });
            pendingEmail = addr; cooldownUntil = Date.now() + 60000;
            $('verification-email').textContent = addr;
            $('account-email-form').classList.add('hidden'); $('account-code-form').classList.remove('hidden');
            $('demo-client-code').classList.toggle('hidden', !result.demo);
            $('account-code').value = ''; $('account-code').focus();
        } catch (err) { showError(err.message); }
        finally { sending = false; btn.disabled = false; $('resend-client-email').disabled = false; btn.textContent = mode === 'signup' ? 'Create account & verify email' : 'Send sign-in email'; }
    }
    $('account-email-form').onsubmit = e => { e.preventDefault(); sendEmail(); };
    $('resend-client-email').onclick = sendEmail;
    $('account-code-form').onsubmit = async e => {
        e.preventDefault(); if (sending) return; sending = true; showError('');
        const btn = e.target.querySelector('button[type="submit"]'); btn.disabled = true; btn.textContent = 'Verifying…';
        try { await post('verify-code', { email: pendingEmail, code: $('account-code').value.trim() }); $('account-code').value = ''; await load(); }
        catch (err) { showError(err.message); }
        finally { sending = false; btn.disabled = false; btn.textContent = 'Verify & sign in'; }
    };
    function renderOrders() {
        const q = $('client-search').value.trim().toLowerCase();
        const done = o => ['served', 'closed', 'cancelled'].includes(o.status);
        const shown = orders.filter(o => (filter === 'all' || (filter === 'done' ? done(o) : !done(o))) && (!q || [o.code, o.recipient, o.document].some(v => (v || '').toLowerCase().includes(q))));
        $('client-count').textContent = `${shown.length} ${shown.length === 1 ? 'request' : 'requests'}`;
        $('client-orders').innerHTML = shown.length ? shown.map(o => `<a class="client-request" href="${esc(o.trackUrl)}"><div class="flex flex-wrap justify-between gap-3"><span class="text-xs text-muted">${esc(o.code)}</span><span class="status-pill ${done(o) || o.paid ? 'status-done' : o.status === 'action_required' ? 'status-alert' : 'status-live'}">${esc(o.label)}</span></div><h2 class="font-serif text-lg text-primary mt-3">${esc(o.recipient)}</h2><p class="text-sm text-muted mt-1">${esc(o.document)}</p><div class="flex flex-wrap justify-between gap-3 text-xs mt-4"><span>${esc(NPS.fmtDate(o.created, false))} · ${esc(o.service || '')}</span><span class="font-semibold text-primary">${esc(o.amount)} ${o.paid ? 'paid' : 'estimate / due'} · View request →</span></div></a>`).join('') : `<div class="p-8 text-center"><h2 class="font-serif text-xl text-primary mb-3">${orders.length ? 'No matching requests' : 'Your first request starts here'}</h2><p class="text-sm text-muted mb-5">${orders.length ? 'Try another name, reference or filter.' : 'Submit a service request using your verified email. It will appear here for updates, payment and proof.'}</p>${orders.length ? '<button id="clear-client-filter" type="button" class="btn btn-outline btn-sm">Show all requests</button>' : '<a href="/?client=1#checkout" class="btn btn-pine btn-sm">Start a request</a>'}</div>`;
        $('clear-client-filter')?.addEventListener('click', () => { filter = 'all'; $('client-search').value = ''; setFilterButtons(); renderOrders(); });
    }
    function setFilterButtons() { document.querySelectorAll('[data-client-filter]').forEach(btn => { btn.setAttribute('aria-pressed', String(btn.dataset.clientFilter === filter)); btn.classList.toggle('is-active', btn.dataset.clientFilter === filter); }); }
    document.querySelectorAll('[data-client-filter]').forEach(btn => btn.onclick = () => { filter = btn.dataset.clientFilter; setFilterButtons(); renderOrders(); });
    $('client-search').oninput = renderOrders;
    async function load() {
        $('client-refresh').disabled = true;
        try {
            const result = await post('list');
            orders = result.orders; signedIn = true;
            $('client-identity').textContent = [result.profile.name, result.profile.email].filter(Boolean).join(' · ');
            $('account-loading').classList.add('hidden'); $('account-auth').classList.add('hidden'); $('client-workspace').classList.remove('hidden');
            $('client-feedback').classList.add('hidden'); renderOrders();
            $('client-sync').textContent = `Updated ${new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`;
        } catch (err) {
            if (err.status === 401) { showAuth(); return; }
            if (!signedIn) { showAuth(); showError(err.message); }
            else { $('client-feedback').textContent = err.message + ' Your last update is still shown. Refresh to try again.'; $('client-feedback').classList.remove('hidden'); }
        } finally { $('client-refresh').disabled = false; }
    }
    $('client-refresh').onclick = load;
    $('client-logout').onclick = async () => {
        $('client-logout').disabled = true;
        try { await post('logout'); showAuth(); }
        catch (err) { $('client-feedback').textContent = 'Sign-out did not finish. Please try again.'; $('client-feedback').classList.remove('hidden'); }
        finally { $('client-logout').disabled = false; }
    };
    NPS.onChange(() => { if (signedIn && !document.hidden) load(); });
    document.addEventListener('visibilitychange', () => { if (signedIn && !document.hidden) load(); });
    addEventListener('pageshow', e => { if (e.persisted) load(); });
    async function start() {
        const callback = window.NPS_AUTH_CALLBACK; delete window.NPS_AUTH_CALLBACK;
        if (callback) {
            try { if (callback.error) throw new Error('This sign-in link has expired. Please request a new email.'); await post('session', { access: callback.access, refresh: callback.refresh }); }
            catch (err) { showAuth(); showError(err.message); return; }
            finally { callback.access = null; callback.refresh = null; }
        }
        await load();
    }
    setMode(mode); start();
})();
