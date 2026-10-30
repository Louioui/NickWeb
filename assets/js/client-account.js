// Passwordless client portal. Production credentials are stored only in HttpOnly server cookies.
(() => {
    const $ = id => document.getElementById(id), { esc } = NPS;
    let mode = location.hash === '#signup' ? 'signup' : 'signin', pendingEmail = '', sending = false, cooldownUntil = 0;
    let orders = [], filter = 'all', signedIn = false;
    // Set while the server is waiting for the Security PIN: after a code ({ kind: 'code' }) or a sign-in link, whose
    // tokens stay in memory only until the PIN is sent ({ kind: 'link', access, refresh }).
    let pinFor = null;
    const post = (action, data = {}) => NPS.post('/api/client', { action, ...data }, { notify: ['verify-code', 'session', 'passkey-login-verify', 'logout', 'logout-all'].includes(action) });
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
        pinFor = null; $('account-pin').value = ''; $('account-pin').required = false; $('account-pin-wrap').classList.add('hidden');
        $('account-code-wrap').classList.remove('hidden'); $('account-code').required = true; showEmailHints(true);
    }
    // The "email is on its way" note and the Resend / Change email buttons only make sense after a code was sent.
    function showEmailHints(on) {
        $('verification-email').closest('.result-box').classList.toggle('hidden', !on);
        $('resend-client-email').parentElement.classList.toggle('hidden', !on);
    }
    function showPinStep(next) {
        pinFor = next;
        $('account-email-form').classList.add('hidden'); $('account-code-form').classList.remove('hidden');
        $('account-code-wrap').classList.toggle('hidden', next.kind === 'link'); $('account-code').required = next.kind !== 'link';
        showEmailHints(next.kind !== 'link');
        $('account-pin-wrap').classList.remove('hidden'); $('account-pin').required = true; $('account-pin').value = ''; $('account-pin').focus();
    }
    function scrubClientState() {
        try { sessionStorage.clear(); } catch {}
        try { navigator.serviceWorker?.controller?.postMessage({ type: 'CLEAR_AUTH_CACHE' }); } catch {}
    }
    // --- Security panel: the Security PIN (asked for after the email code or link at every sign-in) and global sign-out ---
    function securityFeedback(message, ok) {
        const box = $('security-feedback');
        box.textContent = message || '';
        box.className = `result-box ${ok ? 'result-ok' : 'result-err'} text-sm`;
        box.classList.toggle('hidden', !message);
    }
    function clearPinFields() { for (const id of ['pin-current', 'pin-new', 'pin-confirm']) $(id).value = ''; }
    function showSecurity(hasPin) {
        $('pin-status').textContent = hasPin
            ? 'Your Security PIN is on: signing in needs your email code (or link) and this PIN. It also unlocks locked tracking pages.'
            : 'Add a 6-digit Security PIN so that someone who gets into your email still can’t sign in here.';
        $('pin-current-wrap').classList.toggle('hidden', !hasPin);
        $('pin-remove').classList.toggle('hidden', !hasPin);
        $('pin-save').textContent = hasPin ? 'Change PIN' : 'Save PIN';
    }
    $('pin-form').onsubmit = async e => {
        e.preventDefault(); securityFeedback('');
        const next = $('pin-new').value.trim(), again = $('pin-confirm').value.trim();
        if (!/^\d{6}$/.test(next)) return securityFeedback('Your new PIN must be exactly 6 digits.');
        if (next !== again) return securityFeedback('The two new PINs don’t match.');
        $('pin-save').disabled = true;
        try {
            await post('set-pin', { pin: next, currentPin: $('pin-current').value.trim() });
            clearPinFields(); showSecurity(true); hasPinNow = true; loadPasskeys(); securityFeedback('Your Security PIN is saved. You’ll be asked for it at your next sign-in.', true);
        } catch (err) { securityFeedback(err.message); $('pin-current').value = ''; }
        finally { $('pin-save').disabled = false; }
    };
    $('pin-remove').onclick = async () => {
        securityFeedback('');
        const current = $('pin-current').value.trim();
        if (!/^\d{6}$/.test(current)) return securityFeedback('Enter your current PIN above to turn it off.');
        $('pin-remove').disabled = true;
        try { await post('disable-pin', { pin: current }); clearPinFields(); showSecurity(false); hasPinNow = false; loadPasskeys(); securityFeedback('Your Security PIN is off.', true); }
        catch (err) { securityFeedback(err.message); $('pin-current').value = ''; }
        finally { $('pin-remove').disabled = false; }
    };
    // --- Passkeys: sign in with Face ID / fingerprint / device PIN. Shown only where the browser supports them. ---
    const PK = window.SimpleWebAuthnBrowser;
    const passkeysSupported = !!PK?.browserSupportsWebAuthn?.();
    let hasPinNow = false;
    const passkeyError = (err) => (err?.name === 'NotAllowedError' || err?.name === 'AbortError')
        ? 'The passkey request was cancelled or timed out.'
        : err?.name === 'InvalidStateError' ? 'This device already has a passkey for your account.' : (err?.message || 'The passkey did not work. Please try again.');
    function renderPasskeys(list) {
        $('passkey-list').replaceChildren(...(list.length ? list : [null]).map(k => {
            const li = document.createElement('li');
            if (!k) { li.className = 'text-muted'; li.textContent = 'No passkeys yet.'; return li; }
            li.className = 'flex flex-wrap items-center justify-between gap-3 rule-b pb-2';
            const info = document.createElement('span');
            info.textContent = `${k.label} · added ${NPS.fmtDate(k.createdAt, false)}${k.lastUsedAt ? ` · last used ${NPS.fmtDate(k.lastUsedAt, false)}` : ''}`;
            const btn = document.createElement('button');
            btn.type = 'button'; btn.className = 'text-sm text-primary underline underline-offset-2'; btn.textContent = 'Remove';
            btn.dataset.passkeyRemove = k.id;
            li.append(info, btn);
            return li;
        }));
    }
    async function loadPasskeys() {
        if (!passkeysSupported) return;
        $('passkey-section').classList.remove('hidden');
        $('passkey-pin-wrap').classList.toggle('hidden', !hasPinNow);
        $('passkey-pin-help').textContent = hasPinNow ? 'Adding or removing a passkey needs your Security PIN.' : 'Adding or removing a passkey works within 15 minutes of signing in. If it has been longer, sign out and back in first.';
        try { renderPasskeys((await post('passkeys')).passkeys); }
        catch { $('passkey-section').classList.add('hidden'); }   // not set up yet (or the demo): hide it
    }
    $('passkey-add').onclick = async () => {
        securityFeedback(''); $('passkey-add').disabled = true;
        try {
            const pin = $('passkey-pin').value.trim();
            const { options } = await post('passkey-register-options', hasPinNow ? { pin } : {});
            const response = await PK.startRegistration({ optionsJSON: options });
            renderPasskeys((await post('passkey-register-verify', { response, label: $('passkey-label').value.trim() })).passkeys);
            $('passkey-label').value = '';
            securityFeedback('Passkey added. Next time, choose "Sign in with a passkey".', true);
        } catch (err) { securityFeedback(passkeyError(err)); }
        finally { $('passkey-add').disabled = false; $('passkey-pin').value = ''; }
    };
    $('passkey-list').addEventListener('click', async (e) => {
        const id = e.target.closest('[data-passkey-remove]')?.dataset.passkeyRemove;
        if (!id) return;
        securityFeedback('');
        const pin = $('passkey-pin').value.trim();
        if (hasPinNow && !/^\d{6}$/.test(pin)) return securityFeedback('Enter your Security PIN above to remove a passkey.');
        try { renderPasskeys((await post('passkey-remove', { id, ...(hasPinNow ? { pin } : {}) })).passkeys); securityFeedback('Passkey removed.', true); }
        catch (err) { securityFeedback(err.message); }
        finally { $('passkey-pin').value = ''; }
    });
    $('passkey-signin-wrap').classList.toggle('hidden', !passkeysSupported);
    $('passkey-signin').onclick = async () => {
        if (sending) return; sending = true; showError(''); $('passkey-signin').disabled = true;
        try {
            const { options } = await post('passkey-login-options');
            const response = await PK.startAuthentication({ optionsJSON: options });
            await post('passkey-login-verify', { response, remember: true });
            await load();
        } catch (err) { showError(passkeyError(err)); }
        finally { sending = false; $('passkey-signin').disabled = false; }
    };
    $('client-logout-all').onclick = async () => {
        $('client-logout-all').disabled = true;
        try { await post('logout-all'); scrubClientState(); showAuth(); }
        catch { securityFeedback('Signing out everywhere did not finish. Please try again.'); }
        finally { $('client-logout-all').disabled = false; }
    };

    function showAuth() {
        signedIn = false; orders = []; pendingEmail = ''; cooldownUntil = 0;
        clearPinFields(); securityFeedback('');
        $('client-orders').replaceChildren(); $('client-identity').textContent = '';
        $('account-code').value = ''; $('client-search').value = '';
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
        try {
            const pin = pinFor ? $('account-pin').value.trim() : '';
            const remember = $('account-remember').checked;
            const result = pinFor?.kind === 'link'
                ? await post('session', { access: pinFor.access, refresh: pinFor.refresh, pin, remember })
                : await post('verify-code', { email: pendingEmail, code: $('account-code').value.trim(), ...(pin ? { pin } : {}), remember });
            if (result.requiresPin) { showPinStep(pinFor || { kind: 'code' }); return; }
            pinFor = null; $('account-code').value = ''; $('account-pin').value = ''; await load();
        }
        catch (err) { showError(err.message); if (pinFor) $('account-pin').value = ''; }   // a wrong PIN is never resent
        finally { sending = false; btn.disabled = false; btn.textContent = 'Verify & sign in'; }
    };
    function renderOrders() {
        const q = $('client-search').value.trim().toLowerCase();
        const done = o => ['served', 'closed', 'cancelled'].includes(o.status);
        const shown = orders.filter(o => (filter === 'all' || (filter === 'done' ? done(o) : !done(o))) && (!q || [o.code, o.recipient, o.document, o.reference, o.caseNumber].some(v => (v || '').toLowerCase().includes(q))));
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
            const signedInBefore = signedIn;
            orders = result.orders; signedIn = true;
            $('client-identity').textContent = [result.profile.name, result.profile.email].filter(Boolean).join(' · ');
            showSecurity(!!result.profile.hasPin);
            if (!signedInBefore || hasPinNow !== !!result.profile.hasPin) { hasPinNow = !!result.profile.hasPin; loadPasskeys(); }
            if (!signedInBefore) loadNotify();
            $('account-loading').classList.add('hidden'); $('account-auth').classList.add('hidden'); $('client-workspace').classList.remove('hidden');
            $('client-feedback').classList.add('hidden'); renderOrders();
            $('client-sync').textContent = `Updated ${new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`;
        } catch (err) {
            if (err.status === 401) { scrubClientState(); showAuth(); return; }
            if (!signedIn) { showAuth(); showError(err.message); }
            else { $('client-feedback').textContent = err.message + ' Your last update is still shown. Refresh to try again.'; $('client-feedback').classList.remove('hidden'); }
        } finally { $('client-refresh').disabled = false; }
    }

    // CSV of the requests shown (with the firm's own reference), for law-firm accounting.
    const csvCell = (v) => { const t = String(v ?? ''); return /^[=+\-@\t\r]/.test(t) ? `"'${t.replace(/"/g, '""')}"` : /[",\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t; };
    $('client-export').onclick = () => {
        const head = ['Reference', 'Your reference', 'Case number', 'Person to serve', 'Document', 'Service', 'Status', 'Requested', 'Amount', 'Paid on'];
        const rows = orders.map(o => [o.code, o.reference, o.caseNumber, o.recipient, o.document, o.service, o.label, (o.created || '').slice(0, 10), o.amount, o.paidAt ? o.paidAt.slice(0, 10) : '']);
        const url = URL.createObjectURL(new Blob([[head, ...rows].map(r => r.map(csvCell).join(',')).join('\n')], { type: 'text/csv' }));
        const a = Object.assign(document.createElement('a'), { href: url, download: 'my-requests.csv' });
        document.body.append(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
    // Instant emails or a daily summary.
    async function loadNotify() {
        try {
            const { mode } = await post('get-notify');
            $('notify-section').classList.toggle('hidden', !mode);
            document.querySelectorAll('[name="notify-mode"]').forEach(r => { r.checked = r.value === mode; });
        } catch { $('notify-section').classList.add('hidden'); }
    }
    document.querySelectorAll('[name="notify-mode"]').forEach(r => r.addEventListener('change', async () => {
        try { await post('set-notify', { mode: r.value }); securityFeedback(r.value === 'daily' ? 'You\'ll get one summary email a day.' : 'You\'ll get an email for each update.', true); }
        catch (err) { securityFeedback(err.message); loadNotify(); }
    }));
    $('client-refresh').onclick = load;
    $('client-logout').onclick = async () => {
        $('client-logout').disabled = true;
        try { await post('logout'); scrubClientState(); showAuth(); }
        catch (err) { $('client-feedback').textContent = 'Sign-out did not finish. Please try again.'; $('client-feedback').classList.remove('hidden'); }
        finally { $('client-logout').disabled = false; }
    };
    NPS.onChange(() => { if (signedIn && !document.hidden) load(); });
    document.addEventListener('visibilitychange', () => { if (signedIn && !document.hidden) load(); });
    addEventListener('pageshow', e => { if (e.persisted) load(); });
    async function start() {
        const callback = window.NPS_AUTH_CALLBACK; delete window.NPS_AUTH_CALLBACK;
        if (callback) {
            try {
                if (callback.error) throw new Error('This sign-in link has expired. Please request a new email.');
                const result = await post('session', { access: callback.access, refresh: callback.refresh });
                if (result.requiresPin) { showAuth(); showPinStep({ kind: 'link', access: callback.access, refresh: callback.refresh }); return; }
            }
            catch (err) { showAuth(); showError(err.message); return; }
            finally { callback.access = null; callback.refresh = null; }
        }
        await load();
    }
    setMode(mode); start();
})();
