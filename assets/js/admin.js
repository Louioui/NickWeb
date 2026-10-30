const $ = id => document.getElementById(id);
const { esc } = NPS;

const PILL = {
    received: 'status-live', action_required: 'status-alert', awaiting_payment: 'status-live', paid: 'status-done',
    accepted: 'status-live', attempting: 'status-live', served: 'status-done', closed: 'status-muted', cancelled: 'status-muted',
};
const FILTERS = {
    active: { label: 'Active', test: o => !['served', 'closed', 'cancelled'].includes(o.status) },
    review: { label: 'New', test: o => o.status === 'received' },
    waiting: { label: 'Waiting on client', test: o => ['action_required', 'awaiting_payment'].includes(o.status) },
    working: { label: 'In progress', test: o => ['paid', 'accepted', 'attempting'].includes(o.status) },
    today: { label: 'Due today', test: o => isOpen(o) && ((o.deadline && daysUntil(o.deadline) <= 2) || (o.tier === 'sameday' && !o.deadline)) },
    urgent: { label: 'Due soon', test: o => isOpen(o) && o.deadline && daysUntil(o.deadline) <= 7 },
    done: { label: 'Done', test: o => ['served', 'closed', 'cancelled'].includes(o.status) },
    all: { label: 'All', test: () => true },
};
// Some timeline entries are written for the client ("You sent..."); on Nick's screen they read from his side.
const NICK_WORDING = { 'You sent the requested information': 'Client sent the requested information' };
const ATTEMPT_OUTCOMES = ['No answer', 'Served', 'Subject not home', 'Spoke with resident, subject not there', 'Left with co-resident (substituted service)',
    'Refused / evading', 'Gated, no access', 'Wrong address / moved', 'Business closed', 'Other'];
// One tap fills the outcome; the time is "now" unless Nick picks another.
const QUICK_OUTCOMES = ['No answer', 'Served', 'Wrong address / moved', 'Refused / evading', 'Left with co-resident (substituted service)'];
// Saved messages for the note and "Ask client" tabs.
const TEMPLATES = {
    action: ['Please confirm the unit or apartment number.', 'Please send the gate code or building access instructions.',
        'No answer on the first attempt. Is there a best time of day to reach them?', 'The address looks out of date. Do you have a newer one?',
        'Please send a recent photo or description of the person to serve.'],
    note: ['First attempt made, no answer. I will try again at a different time of day.', 'Served. I am preparing the proof of service now.',
        'Attempts are on schedule. I will update you after the next one.'],
};
// Days since Nick last contacted the client (an entry the client can see), shown on open jobs.
const daysSince = iso => iso ? Math.floor((Date.now() - new Date(iso).getTime()) / 864e5) : null;

let orders = [];
let statuses = {};
let filter = 'active';
let current = null;           // { order, events, files } for the open job
let actionTab = 'attempt';
let openJobVersion = 0;
let actionBusy = false;
let routeStops = [];          // jobs on today's route
let bulkIds = [];             // served/cancelled jobs shown under "Done", for one-tap closing
const drafts = new Map();
const draftKey = () => current ? `${current.order.id}:${actionTab}` : '';

function rememberDraft() {
    const form = $('action-form');
    if (!current || !form || !formDirty) return;
    drafts.set(draftKey(), Array.from(form.querySelectorAll('input, textarea, select')).map(el => ({
        id: el.id, value: el.value, checked: el.checked, files: el.type === 'file' ? Array.from(el.files) : null,
    })));
}

function restoreDraft() {
    const draft = drafts.get(draftKey());
    if (!draft) return;
    for (const item of draft) {
        const el = $(item.id);
        if (!el) continue;
        if (item.files) { const transfer = new DataTransfer(); item.files.forEach(file => transfer.items.add(file)); el.files = transfer.files; }
        else { el.value = item.value; if (el.type === 'checkbox') el.checked = item.checked; }
    }
    formDirty = true;
    $('draft-status').classList.remove('hidden');
}

const READ_ONLY = new Set(['me', 'list', 'get', 'file-url', 'export', 'send-code', 'verify-code', 'sessions', 'passkeys', 'passkey-login-options']);
async function api(action, data = {}) {
    try {
        return await NPS.post('/api/admin', { action, ...data }, { notify: !READ_ONLY.has(action) });
    } catch (err) {
        if (err.status === 401 && !['verify-code', 'send-code', 'passkey-login-verify'].includes(action)) showLogin();
        throw err;
    }
}

// --- Login ---
function scrubClientState() {
    drafts.clear();
    lastGeneratedCodes = [];
    current = null;
    orders = [];
    formDirty = false;
    if ($('job-list')) $('job-list').innerHTML = '';
    if ($('detail')) $('detail').innerHTML = '';
    if ($('recovery-codes-list')) $('recovery-codes-list').innerHTML = '';
    try { sessionStorage.clear(); } catch {}
    try {
        for (const k of Object.keys(localStorage)) {
            if (k.startsWith('nps_admin')) localStorage.removeItem(k);
        }
    } catch {}
    if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({ type: 'CLEAR_AUTH_CACHE' });
    }
}
function showLogin() {
    scrubClientState();
    $('dash-view').classList.add('hidden');
    $('whoami').classList.replace('flex', 'hidden');
    $('login-view').classList.remove('hidden');
    showEmailStep();
}
function showEmailStep() {
    $('email-form').classList.remove('hidden');
    $('code-form').classList.add('hidden');
    $('login-error').classList.add('hidden');
    $('login-email').focus();
}
function loginError(msg) {
    $('login-error').textContent = msg;
    $('login-error').classList.remove('hidden');
}
$('email-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    if (btn.disabled) return;
    btn.disabled = true;
    btn.textContent = 'Sending code…';
    $('login-error').classList.add('hidden');
    try {
        await api('send-code', { email: $('login-email').value.trim() });
        $('email-form').classList.add('hidden');
        $('code-form').classList.remove('hidden');
        $('login-code').value = '';
        $('login-code').focus();
    } catch (err) { loginError(err.message); }
    finally { btn.disabled = false; btn.textContent = 'Email Me a Login Code'; }
});
$('code-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    if (btn.disabled) return;
    btn.disabled = true;
    btn.textContent = 'Checking code…';
    try {
        const res = await api('verify-code', { email: $('login-email').value.trim(), code: $('login-code').value, totp: $('login-totp').value.trim() });
        if (res.requiresTwoFactor) {
            // Two-step sign-in is on: the email code is kept, and the second box appears.
            $('totp-wrap').classList.remove('hidden');
            loginError(res.message);
            $('login-totp').focus();
            return;
        }
        $('totp-wrap').classList.add('hidden');
        $('login-totp').value = '';
        start();
    } catch (err) { loginError(err.message); }
    finally { btn.disabled = false; btn.textContent = 'Log In'; }
});
async function logout() {
    await api('logout').catch(() => {});
    showLogin();
}

// --- Job list + stats ---
// Compare calendar days in Nick's local timezone, independent of the current hour or DST.
const daysUntil = d => {
    if (!d) return null;
    const today = new Date();
    const [year, month, day] = d.split('-').map(Number);
    return Math.round((Date.UTC(year, month - 1, day) - Date.UTC(today.getFullYear(), today.getMonth(), today.getDate())) / 864e5);
};
const isOpen = o => !['served', 'closed', 'cancelled'].includes(o.status);

function renderStats() {
    const soon = orders.filter(o => isOpen(o) && o.deadline && daysUntil(o.deadline) <= 7).length;
    const tiles = [
        ['New or client replied', orders.filter(FILTERS.review.test).length, 'review'],
        ['Waiting on client', orders.filter(FILTERS.waiting.test).length, 'waiting'],
        ['In progress', orders.filter(FILTERS.working.test).length, 'working'],
        ['Due soon or overdue', soon, 'urgent'],
    ];
    $('stats').innerHTML = tiles.map(([label, n, f]) => `
        <button type="button" class="stat-tile text-left hover:border-primary transition-colors" data-click="setFilter" data-arg="${f}">
            <div class="stat-num">${n}</div><div class="stat-label">${label}</div>
        </button>`).join('');
}

function setFilter(f) {
    filter = f;
    $('search').value = '';
    renderList();
}

function renderList() {
    $('filters').innerHTML = Object.entries(FILTERS).map(([k, f]) =>
        `<button type="button" aria-pressed="${k === filter}" class="tab-btn ${k === filter ? 'is-active' : ''}" data-click="setFilter" data-arg="${k}">${f.label} <span class="text-muted">${orders.filter(f.test).length}</span></button>`).join('');
    const q = $('search').value.trim().toLowerCase();
    const shown = orders.filter(FILTERS[filter].test).filter(o => !q ||
        [o.code, o.client_name, o.client_firm, o.client_email, o.recipient_name, o.city, o.zip].some(v => (v || '').toLowerCase().includes(q)));
    // "Due today": overdue first, then soonest deadline, Same-Day Rush jobs without a date at the top of the rest.
    if (filter === 'today') shown.sort((a, b) => (a.deadline ? daysUntil(a.deadline) : -0.5) - (b.deadline ? daysUntil(b.deadline) : -0.5));
    // Today's route: every unserved job on the "Due today" board, in list order (Google Maps takes up to 9 stops in between).
    routeStops = filter === 'today' ? shown.filter(o => o.address && !['served', 'closed', 'cancelled'].includes(o.status)).slice(0, 10) : [];
    $('route-bar').classList.toggle('hidden', !routeStops.length);
    $('route-text').textContent = routeStops.length ? `${routeStops.length} stop${routeStops.length === 1 ? '' : 's'}${shown.length > routeStops.length ? ` (first ${routeStops.length})` : ''}, starting from where you are.` : '';
    const closable = filter === 'done' ? shown.filter(o => ['served', 'cancelled'].includes(o.status)) : [];
    bulkIds = closable.map(o => o.id);
    $('bulk-bar').classList.toggle('hidden', !closable.length);
    $('bulk-text').textContent = closable.length ? `${closable.length} served or cancelled ${closable.length === 1 ? 'job is' : 'jobs are'} ready to close.` : '';
    $('list-count').textContent = `${shown.length} ${shown.length === 1 ? 'request' : 'requests'}`;
    $('job-list').innerHTML = shown.length ? shown.map(o => {
        const days = daysUntil(o.deadline);
        const due = o.deadline && isOpen(o)
            ? `<span class="${days <= 3 ? 'text-[#7a1f1c] font-semibold' : 'text-muted'}"><i class="fa-regular fa-calendar mr-1"></i>${days < 0 ? 'Past due' : days === 0 ? 'Due today' : `Due in ${days}d`}</span>` : '';
        return `
        <button type="button" aria-pressed="${current?.order.id === o.id}" class="job-row ${current?.order.id === o.id ? 'is-active' : ''}" data-click="openJob" data-arg="${esc(o.id)}">
            <span class="font-semibold text-sm text-ink truncate">${esc(o.recipient_name)}</span>
            ${o.client_replied
                ? '<span class="status-pill status-alert"><i class="fa-solid fa-reply mr-1"></i>Client replied</span>'
                : `<span class="status-pill ${PILL[o.status]}">${esc(statuses[o.status]?.label || o.status)}</span>`}
            <span class="text-xs text-muted truncate">${esc(o.code)} · ${esc(o.city || '')} · ${esc(o.client_firm || o.client_name)}</span>
            <span class="text-xs text-right">${due}${isOpen(o) && o.last_contact_at !== undefined ? ` <span class="${daysSince(o.last_contact_at) >= 3 || o.last_contact_at === null ? 'text-[#7a1f1c]' : 'text-muted'}" title="Last update the client can see">· ${o.last_contact_at ? `contact ${daysSince(o.last_contact_at)}d ago` : 'no contact yet'}</span>` : ''}</span>
        </button>`;
    }).join('') : `<div class="p-8 text-center text-sm text-muted"><p class="font-semibold text-primary mb-2">${q ? 'No matching requests' : 'You’re all caught up here'}</p><p>${q ? 'Try a name, reference number, email, or city.' : 'Requests in this category will appear here.'}</p><button type="button" class="btn btn-outline btn-sm mt-4" data-click="setFilter" data-arg="all">Show all requests</button></div>`;
}
$('search').addEventListener('input', renderList);

async function loadList() {
    const r = await api('list');
    orders = r.orders;
    statuses = r.statuses;
    renderStats();
    renderList();
    $('dashboard-error').classList.add('hidden');
    $('sync-status').textContent = `Updated ${new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`;
}

async function refreshJobs() {
    const btn = $('refresh-jobs');
    btn.disabled = true;
    $('sync-status').textContent = 'Checking for updates…';
    try { await loadList(); refreshSafeWalk(); }
    catch (err) {
        if (err.status !== 401) {
            $('dashboard-error').textContent = `${err.message} Your current list is still shown. Use Refresh jobs to try again.`;
            $('dashboard-error').classList.remove('hidden');
            $('sync-status').textContent = 'Could not update';
        }
    } finally { btn.disabled = false; }
}

// --- Case detail ---
async function openJob(id) {
    if (actionBusy) return;
    rememberDraft();
    const version = ++openJobVersion;
    current = null;
    formDirty = false;
    history.replaceState(null, '', '#' + id);
    $('detail-pane').classList.remove('hidden');
    if (window.innerWidth < 1024) $('list-pane').classList.add('hidden');
    $('detail-pane').setAttribute('aria-busy', 'true');
    $('detail').classList.add('hidden');
    $('detail-empty').classList.remove('hidden');
    $('detail-empty').textContent = 'Opening request…';
    try {
        const result = await api('get', { id });
        if (version !== openJobVersion) return;
        current = result;
        if (result.statuses) statuses = result.statuses;
        actionTab = 'attempt';
        renderDetail();
        renderList();
        $('detail-pane').scrollIntoView({ behavior: 'smooth', block: 'start' });
        $('job-title')?.focus({ preventScroll: true });   // keyboard and screen-reader users land on the job they opened
    } catch (err) {
        if (version !== openJobVersion) return;
        if (err.status === 401) return;
        current = null;
        history.replaceState(null, '', location.pathname);
        $('detail').classList.add('hidden');
        $('detail-empty').classList.remove('hidden');
        $('detail-empty').innerHTML = `<p class="result-box result-err text-left">${esc(err.status === 404 ? "That job wasn't found. It may have been opened from an old link." : err.message)}</p><button type="button" class="btn btn-outline btn-sm mt-4" data-click="backToList">Back to requests</button>`;
    } finally { if (version === openJobVersion) $('detail-pane').setAttribute('aria-busy', 'false'); }
}

function backToList() {
    if (actionBusy) return;
    rememberDraft();
    ++openJobVersion;
    current = null;
    history.replaceState(null, '', location.pathname);
    $('list-pane').classList.remove('hidden');
    $('detail-pane').classList.add('hidden');
    $('detail').classList.add('hidden');
    $('detail-empty').classList.remove('hidden');
    $('detail-empty').innerHTML = '<p class="font-serif text-lg text-primary mb-2">Ready for your next job</p><p>Choose a request to review documents, contact the client, or log an attempt.</p>';
    renderList();
}

const row = (k, v) => v ? `<dt>${k}</dt><dd>${v}</dd>` : '';

function renderDetail() {
    const { order: o, events, files } = current;
    const fullAddress = `${o.address}${o.unit ? ', ' + o.unit : ''}, ${o.city} ${o.zip}`;
    const mapUrl = 'https://www.google.com/maps/search/?api=1&query=' + encodeURIComponent(fullAddress);
    const fileChip = f => `<button type="button" class="file-chip" data-click="downloadFile" data-arg="${esc(f.id)}" ${f.sha256 ? `title="Verified SHA-256 fingerprint: ${esc(f.sha256)}"` : ''}><i class="fa-solid ${f.kind === 'proof' ? 'fa-file-signature' : 'fa-file-lines'} text-bronze"></i><span>${esc(f.filename)}</span><span class="text-muted font-normal">${NPS.fmtSize(f.size_bytes)}</span>${f.sha256 ? `<span class="text-[11px] font-mono text-primary bg-primaryLight/60 px-1.5 py-0.5 rounded-sm"><i class="fa-solid fa-shield-halved mr-0.5" aria-hidden="true"></i>SHA-256 ${esc(f.sha256.slice(0, 8))}…</span>` : ''}</button>`;
    const groups = [['Client documents', 'client_document'], ['Sent after "Action required"', 'action_upload'], ['Proof of service', 'proof']]
        .map(([label, kind]) => [label, files.filter(f => f.kind === kind)]).filter(([, list]) => list.length);

    $('detail-empty').classList.add('hidden');
    $('detail').classList.remove('hidden');
    $('detail').innerHTML = `
        <div class="panel p-6 sm:p-8">
            <button type="button" data-click="backToList" class="lg:hidden text-xs font-semibold text-primary mb-4"><i class="fa-solid fa-arrow-left mr-1"></i> All jobs</button>
            <div class="flex flex-wrap items-start justify-between gap-3 pb-5 rule-b">
                <div>
                    <p class="text-xs text-muted">${esc(o.code)} · received ${esc(NPS.fmtDate(o.created_at))}</p>
                    <h2 id="job-title" tabindex="-1" class="font-display text-[2rem] leading-tight text-primary">${esc(o.recipient_name)}</h2>
                    <p class="text-sm text-muted">${esc(o.doc_type)}</p>
                </div>
                <span class="status-pill ${PILL[o.status]}">${esc(statuses[o.status]?.label || o.status)}</span>
            </div>
            ${o.action_note ? `<div class="result-box result-warn mt-5 text-sm"><strong>You asked the client:</strong> ${esc(o.action_note)}</div>` : ''}
            ${attemptWindowsHtml(o, events)}
            ${substitutedService(events).attempted && !substitutedService(events).mailed ? '<p class="result-box result-warn text-sm mt-4"><i class="fa-solid fa-envelope mr-1" aria-hidden="true"></i> Substituted service: the follow-up first-class mailing isn\'t logged yet. Log it in the <strong>Field &amp; court</strong> tab.</p>' : ''}
            <div class="grid sm:grid-cols-2 gap-x-8 gap-y-6 mt-6">
                <dl class="review-recap content-start">
                    ${row('Address', `<a href="${mapUrl}" target="_blank" rel="noopener noreferrer" class="text-primary font-semibold underline underline-offset-2">${esc(fullAddress)}</a> <button type="button" class="text-xs text-primary font-semibold ml-1" data-click="copyAddress"><i class="fa-regular fa-copy" aria-hidden="true"></i> Copy</button>`)}
                    ${row('Access', esc(o.access_notes || ''))}
                    ${row('Description', esc(o.physical_notes || ''))}
                    ${row('Instructions', esc(o.instructions || ''))}
                    ${row('Deadline', o.deadline ? esc(NPS.fmtDate(o.deadline, false)) : '')}
                </dl>
                <dl class="review-recap content-start">
                    ${row('Client', esc(o.client_name) + (o.client_firm ? `<br><span class="text-muted">${esc(o.client_firm)}</span>` : ''))}
                    ${row('Phone', `<a href="tel:${esc(o.client_phone.replace(/[^\d+]/g, ''))}" class="text-primary font-semibold">${esc(o.client_phone)}</a>`)}
                    ${row('Email', `<a href="mailto:${esc(o.client_email)}" class="text-primary font-semibold break-all">${esc(o.client_email)}</a>`)}
                    ${row('Case #', esc(o.case_number || ''))}
                    ${row('Court', esc(o.court || ''))}
                    ${row('Their ref.', esc(o.client_reference || ''))}
                    ${row('Service', esc(o.tier_name + (o.addon_names.length ? ' + ' + o.addon_names.join(', ') : '')))}
                    ${row('Estimate', NPS.money(o.estimated_total_cents))}
                    ${row(o.paid_at ? 'Paid' : 'Amount due', o.amount_due_cents != null ? NPS.money(o.amount_due_cents) + (o.paid_at ? ` on ${esc(NPS.fmtDate(o.paid_at, false))}` : '') : '')}
                </dl>
            </div>
            ${groups.length ? `<div class="mt-7 pt-5 rule-t space-y-4">${groups.map(([label, list]) => `
                <div><p class="field-label">${label}</p><div class="flex flex-wrap gap-2">${list.map(fileChip).join('')}</div></div>`).join('')}</div>` : ''}
        </div>

        <div class="panel">
            <div class="flex flex-wrap gap-1 px-4 pt-3 rule-b" role="group" aria-label="Actions for this request">
                ${[['attempt', 'Log attempt'], ['status', 'Status'], ['note', 'Note'], ['action', 'Ask client'], ['payment', 'Payment link'], ['proof', 'Proof of service'], ['field', 'Field & court'], ['privacy', 'Privacy']]
                    .map(([k, l]) => `<button type="button" aria-pressed="${k === actionTab}" class="tab-btn ${k === actionTab ? 'is-active' : ''}" data-click="setActionTab" data-arg="${k}">${l}</button>`).join('')}
            </div>
            <div id="draft-status" class="hidden text-xs text-bronze px-6 pt-4"><p role="status">Unsaved changes · kept while you switch jobs or actions in this tab.</p><button type="button" data-click="discardDraft" class="underline underline-offset-2 mt-2 py-2">Discard this draft</button></div>
            <form id="action-form" class="p-6 space-y-4" novalidate>${actionForm(o)}</form>
        </div>

        <div class="panel p-6 sm:p-8">
            <h2 class="serif-title text-xl mb-6 pb-4 rule-b">Timeline</h2>
            <ol class="timeline">${events.slice().reverse().map(ev => `
                <li>
                    <span class="timeline-dot ${ev.kind === 'action' ? 'is-alert' : ev.kind === 'payment' ? 'is-gold' : ev.kind === 'proof' ? 'is-done' : ''}"></span>
                    <p class="text-sm font-semibold text-ink">${esc(NICK_WORDING[ev.title] || ev.title.replace(/ added by you$/, ' added by the client'))} ${ev.client_visible ? '' : '<span class="status-pill status-muted ml-1">Only you</span>'}</p>
                    ${ev.detail ? `<p class="text-sm text-muted mt-0.5 whitespace-pre-line">${esc(ev.detail)}</p>` : ''}
                    <p class="text-[11px] text-muted mt-1">${esc(NPS.fmtDate(ev.created_at))}</p>
                </li>`).join('')}
            </ol>
        </div>`;
    $('action-form').addEventListener('submit', submitAction);
    const dirty = () => { formDirty = true; $('draft-status').classList.remove('hidden'); };
    $('action-form').addEventListener('input', dirty);
    $('action-form').addEventListener('change', dirty);
    formDirty = false;
    restoreDraft();
}

function setActionTab(k) {
    if (actionBusy || k === actionTab) return;
    rememberDraft();
    actionTab = k;
    renderDetail();
}

function discardDraft() {
    if (actionBusy) return;
    drafts.delete(draftKey());
    formDirty = false;
    renderDetail();
}

const check = (id, label, on) => `<label class="flex items-center gap-2 text-sm"><input type="checkbox" id="${id}" ${on ? 'checked' : ''} class="w-4 h-4 accent-primary"> ${label}</label>`;
const submitBtn = label => `<p id="action-error" class="result-box result-err hidden" role="alert"></p><button type="submit" class="btn btn-pine">${label}</button>`;

function actionForm(o) {
    if (actionTab === 'privacy') {
        const seal = o.integrity_seal || {};
        const stepUp = totpEnabled ? `
            <div><label for="f-stepup" class="field-label">Code from your authenticator app</label>
            <input id="f-stepup" inputmode="text" maxlength="9" spellcheck="false" autocomplete="one-time-code" class="field font-mono tracking-widest max-w-[12rem] uppercase" placeholder="000000"><p class="text-xs text-muted mt-1">Or one of your recovery codes (XXXX-XXXX).</p></div>` : `
            <div><label for="f-stepup" class="field-label">Step-up code from your email</label>
            <div class="flex flex-wrap items-center gap-2"><input id="f-stepup" inputmode="numeric" maxlength="9" spellcheck="false" autocomplete="one-time-code" class="field font-mono tracking-widest max-w-[12rem]" placeholder="12345678">
            <button type="button" class="btn btn-outline btn-sm" data-click="emailStepUp" data-arg="f-stepup">Email me a code</button></div>
            <p class="text-xs text-muted mt-1">Needed to unlock legal hold or delete a request. Turn on two-step sign-in to use your authenticator app instead.</p></div>`;
        return `
        <div class="space-y-3 pb-5 rule-b">
            <p class="text-sm font-semibold text-primary"><i class="fa-solid fa-shield-halved text-bronze mr-1"></i> Protection</p>
            <p class="text-xs ${seal.verified ? 'text-primary' : 'text-[#7a1f1c] font-semibold'}">
                ${seal.verified
                    ? `<i class="fa-solid fa-circle-check mr-1"></i> Record seal verified: all ${seal.entries} timeline entries are unchanged since they were written.`
                    : `<i class="fa-solid fa-triangle-exclamation mr-1"></i> Record seal does NOT match. A timeline entry was changed after it was written. Don't delete anything; call your developer.`}
                ${seal.head ? `<br><span class="font-mono text-muted break-all">Seal: ${esc(seal.head)}</span>` : ''}</p>
            <div class="flex flex-wrap gap-2">
                <button type="button" class="btn btn-outline btn-sm" data-click="printRecord"><i class="fa-solid fa-print"></i> Print record</button>
                <button type="button" class="btn btn-outline btn-sm" data-click="evidencePack"><i class="fa-solid fa-scale-balanced"></i> Dispute evidence pack</button>
                ${o.paid_at ? '<button type="button" class="btn btn-outline btn-sm" data-click="printReceiptJob"><i class="fa-solid fa-receipt"></i> Receipt</button>' : ''}
                <button type="button" class="btn btn-outline btn-sm" data-click="toggleDocLockJob"><i class="fa-solid ${o.doc_lock ? 'fa-lock-open' : 'fa-lock'}"></i> ${o.doc_lock ? 'Turn off document lock' : 'Lock documents on tracking page'}</button>
                <button type="button" class="btn btn-outline btn-sm" data-click="rotateLink"><i class="fa-solid fa-link-slash"></i> Replace client's tracking link</button>
            </div>
            <p class="text-xs text-muted">Document lock: the client's page shows the status but hides the full address and documents until they enter a code we email them. Replacing the link stops the old one immediately and emails the client the new one.</p>
            <div class="pt-2">
                <p class="text-xs font-semibold ${o.legal_hold ? 'text-primary' : 'text-muted'}"><i class="fa-solid fa-scale-balanced mr-1"></i> Legal hold: ${o.legal_hold ? 'ON (the service record, proofs and timeline are frozen)' : 'off'}</p>
                ${o.legal_hold ? `
                    <p class="text-xs text-muted mt-1">Turned on automatically when the job was served. Unlock only if a real mistake must be fixed; it's logged and emailed to you.</p>
                    ${stepUp || `<div class="mt-2"><label for="f-hold-confirm" class="field-label">Type ${esc(o.code)} to unlock</label><input id="f-hold-confirm" class="field uppercase max-w-[12rem]" autocomplete="off" spellcheck="false"></div>`}
                    <button type="button" class="btn btn-sm mt-2 border-[#9c2a26] text-[#7a1f1c] hover:bg-[#fbeceb]" data-click="setLegalHold" data-arg="false">Unlock legal hold</button>`
                : `<button type="button" class="btn btn-outline btn-sm mt-2" data-click="setLegalHold" data-arg="true">Put under legal hold now</button>`}
            </div>
            <p id="protect-error" class="result-box result-err hidden" role="alert"></p>
        </div>
        <p class="text-sm text-muted pt-4">When a client asks for a copy of their information or for it to be deleted, search their email in the job list to find all of their requests, then use these on each one.</p>
        <div class="flex flex-wrap gap-3 pb-5 rule-b">
            <button type="button" class="btn btn-outline btn-sm" data-click="exportJob"><i class="fa-solid fa-file-arrow-down"></i> Download all data (file)</button>
        </div>
        <div class="space-y-3">
            <p class="text-sm font-semibold text-[#7a1f1c]"><i class="fa-solid fa-triangle-exclamation mr-1"></i> Delete permanently</p>
            ${o.legal_hold ? `<p class="text-xs text-muted">This request is under legal hold, so it can't be deleted. Unlock legal hold first.</p>` : `
            <p class="text-xs text-muted">Removes this request, its timeline, and every uploaded document and proof. It can't be undone. Check your own record-keeping obligations before deleting.</p>
            <div><label for="f-confirm" class="field-label">Type ${esc(o.code)} to confirm</label><input id="f-confirm" class="field uppercase" autocomplete="off" spellcheck="false"></div>
            ${stepUp}
            <p id="action-error" class="result-box result-err hidden" role="alert"></p>
            <button type="submit" class="btn btn-sm border-[#9c2a26] text-[#7a1f1c] hover:bg-[#fbeceb]">Delete this request forever</button>`}
        </div>`;
    }
    if (actionTab === 'field') {
        const sub = substitutedService(current.events);
        const started = stakeoutStart(o.id);
        const today = new Date().toLocaleDateString('en-CA');
        return `
        <div class="space-y-3 pb-5 rule-b">
            <p class="text-sm font-semibold text-primary"><i class="fa-solid fa-stopwatch text-bronze mr-1" aria-hidden="true"></i> Stakeout timer</p>
            <p class="text-xs text-muted">${started ? `Running since ${esc(new Date(started).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }))}. Stop it to save the time on the timeline.` : 'Start it when you begin waiting. The first hour is included in the $100 stakeout; time past it is noted.'}</p>
            <div class="flex flex-wrap gap-2">${started
                ? '<button type="button" class="btn btn-pine btn-sm" data-click="stopStakeout">Stop and save</button><button type="button" class="btn btn-outline btn-sm" data-click="cancelStakeout">Cancel timer</button>'
                : '<button type="button" class="btn btn-pine btn-sm" data-click="startStakeout">Start stakeout</button>'}</div>
        </div>
        ${sub.attempted ? `<div class="space-y-3 pb-5 rule-b">
            <p class="text-sm font-semibold text-primary"><i class="fa-solid fa-envelope text-bronze mr-1" aria-hidden="true"></i> Substituted service follow-up mailing</p>
            <p class="text-xs text-muted">${sub.mailed ? 'A mailing is already logged. Log another if you sent a second one.' : 'You left the papers with a co-resident. Log the first-class mailing that follows (CCP § 415.20).'}</p>
            <div class="grid sm:grid-cols-2 gap-4">
                <div><label for="f-mail-date" class="field-label">Date mailed</label><input id="f-mail-date" type="date" class="field" value="${today}" max="${today}"></div>
                <div><label for="f-mail-city" class="field-label">City mailed from</label><input id="f-mail-city" class="field" maxlength="80"></div>
            </div>
            ${submitBtn('Log mailing')}
        </div>` : '<p id="action-error" class="result-box result-err hidden" role="alert"></p>'}
        ${safeWalkSection()}
        <div class="space-y-3 pb-5 rule-b">
            <p class="text-sm font-semibold text-primary"><i class="fa-solid fa-car text-bronze mr-1" aria-hidden="true"></i> Mileage and expenses</p>
            <p class="text-xs text-muted">${current.expenses?.miles == null ? 'Not set up yet.' : `This job so far: ${current.expenses.miles} mi, ${NPS.money(current.expenses.feesCents)} in fees. Only you see these.`}</p>
            <div class="grid sm:grid-cols-3 gap-3">
                <div><label for="f-miles" class="field-label">Miles</label><input id="f-miles" type="number" min="0" step="0.1" class="field" inputmode="decimal"></div>
                <div><label for="f-fees" class="field-label">Fees ($)</label><input id="f-fees" type="number" min="0" step="0.01" class="field" inputmode="decimal"></div>
                <div><label for="f-exp-label" class="field-label">What for</label><input id="f-exp-label" class="field" maxlength="120" placeholder="Parking"></div>
            </div>
            <div class="flex flex-wrap gap-2"><button type="button" class="btn btn-outline btn-sm" data-click="addExpense">Add</button>
            <button type="button" class="btn btn-outline btn-sm" data-click="downloadExpenses"><i class="fa-solid fa-file-csv"></i> This year's expenses (CSV)</button></div>
        </div>
        <div class="space-y-3">
            <p class="text-sm font-semibold text-primary"><i class="fa-solid fa-gavel text-bronze mr-1" aria-hidden="true"></i> Court paperwork drafts</p>
            <p class="text-xs text-muted">Printable drafts from this job's record, for you to check and sign yourself. They are not filed or signed by the site.</p>
            <div class="flex flex-wrap gap-2">
                <button type="button" class="btn btn-outline btn-sm" data-click="printDiligenceLog"><i class="fa-solid fa-list-check"></i> Diligence log</button>
                <button type="button" class="btn btn-outline btn-sm" data-click="printPosSheet"><i class="fa-solid fa-file-signature"></i> POS-010 data sheet</button>
            </div>
        </div>`;
    }
    if (actionTab === 'attempt') return `
        <div class="flex flex-wrap gap-2" role="group" aria-label="Quick outcome">${QUICK_OUTCOMES.map(x =>
            `<button type="button" class="tab-btn" data-click="quickOutcome" data-arg="${esc(x)}">${esc(x.replace(' (substituted service)', ''))}</button>`).join('')}</div>
        <div class="grid sm:grid-cols-2 gap-4">
            <div><label for="f-outcome" class="field-label">Outcome</label><select id="f-outcome" class="field">${ATTEMPT_OUTCOMES.map(x => `<option>${x}</option>`).join('')}</select></div>
            <div><label for="f-when" class="field-label">When (leave blank for now)</label><input id="f-when" type="datetime-local" class="field"></div>
        </div>
        <div><label for="f-note" class="field-label">Details</label><textarea id="f-note" class="field h-20 resize-none" placeholder="e.g. Lights on, car in driveway, no answer after 3 knocks"></textarea></div>
        ${check('f-visible', 'Client can see this attempt', true)}
        ${submitBtn('Log Attempt')}`;
    if (actionTab === 'status') return `
        <div><label for="f-status" class="field-label">New status</label><select id="f-status" class="field">${Object.entries(statuses)
            .filter(([k]) => k !== 'action_required').map(([k, s]) => `<option value="${k}" ${k === o.status ? 'selected' : ''}>${esc(s.label)}</option>`).join('')}</select></div>
        <div><label for="f-note" class="field-label">Note (optional)</label><textarea id="f-note" class="field h-20 resize-none"></textarea></div>
        ${check('f-visible', 'Client can see this', true)}
        ${check('f-notify', 'Email the client about it', false)}
        ${submitBtn('Update Status')}`;
    if (actionTab === 'note') return `
        ${templatePicker('note')}
        <div><label for="f-note" class="field-label">Note</label><textarea id="f-note" class="field h-24 resize-none"></textarea></div>
        ${check('f-visible', 'Client can see this note (otherwise only you can)', false)}
        ${submitBtn('Save Note')}`;
    if (actionTab === 'action') return `
        <p class="text-sm text-muted">The client gets an email and a form on their tracking page to answer, fix the address, or upload a file.</p>
        ${templatePicker('action')}
        <div><label for="f-note" class="field-label">What do you need?</label><textarea id="f-note" class="field h-24 resize-none" placeholder="e.g. The apartment number is missing. Which unit does the subject live in?"></textarea></div>
        ${submitBtn('Send to Client')}`;
    if (actionTab === 'payment') {
        if (o.paid_at) return `<p class="result-box result-ok text-sm">Paid ${NPS.money(o.amount_due_cents)} on ${esc(NPS.fmtDate(o.paid_at))}.</p>`;
        return `
        ${o.payment_url && o.status === 'awaiting_payment' ? `<p class="result-box result-warn text-sm">A payment link for ${NPS.money(o.amount_due_cents)} was already sent. Sending a new one replaces it.</p>` : ''}
        <div class="grid sm:grid-cols-3 gap-4">
            <div><label for="f-amount" class="field-label">Amount ($)</label><input id="f-amount" type="number" min="1" step="0.01" class="field" value="${((o.amount_due_cents ?? o.estimated_total_cents) / 100).toFixed(2)}"></div>
            <div class="sm:col-span-2"><label for="f-desc" class="field-label">What it covers (shown to client)</label><input id="f-desc" class="field" value="${esc(o.tier_name + (o.addon_names.length ? ' + ' + o.addon_names.join(', ') : ''))}"></div>
        </div>
        ${printingFeeNote()}
        <p class="text-xs text-muted">The client gets an email with a secure Stripe link (card or Apple Pay). The job moves to "Paid" by itself when they pay.</p>
        ${submitBtn('Send Payment Link')}`;
    }
    return `
        <div><label for="f-proof" class="field-label">Proof of service file(s)</label><input id="f-proof" type="file" multiple accept=".pdf,.docx,.jpg,.jpeg,.png,.heic,.heif,.webp" class="block w-full text-sm text-muted file:mr-4 file:cursor-pointer file:border file:border-solid file:border-primary file:bg-transparent file:px-4 file:py-2 file:text-xs file:font-semibold file:text-primary"></div>
        ${check('f-served', 'Mark the job as Served', o.status !== 'served')}
        <p class="text-xs text-muted">The client gets an email and can download the file from their tracking page.</p>
        ${submitBtn('Upload Proof')}`;
}

async function submitAction(e) {
    e.preventDefault();
    const form = e.target;
    const btn = form.querySelector('button[type="submit"]');
    const errBox = $('action-error');
    const v = id => $(id)?.value?.trim() ?? '';
    const on = id => !!$(id)?.checked;
    const id = current.order.id;
    const savedKey = draftKey();
    const savedAction = actionTab;
    let partialUpload = '';
    actionBusy = true;
    btn.disabled = true;
    const originalLabel = btn.textContent;
    btn.textContent = 'Saving…';
    form.setAttribute('aria-busy', 'true');
    form.setAttribute('inert', '');
    $('save-feedback').classList.add('hidden');
    errBox.classList.add('hidden');
    try {
        if (actionTab === 'attempt') {
            const when = v('f-when') ? new Date(v('f-when')).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '';
            const at = v('f-when') ? new Date(v('f-when')).toISOString() : '';
            current = await api('update', { id, kind: 'attempt', outcome: v('f-outcome'), when, at, note: v('f-note'), clientVisible: on('f-visible') });
        } else if (actionTab === 'status') {
            current = await api('update', { id, kind: 'status', status: v('f-status'), note: v('f-note'), clientVisible: on('f-visible'), notify: on('f-notify') });
        } else if (actionTab === 'note') {
            current = await api('update', { id, kind: 'note', note: v('f-note'), clientVisible: on('f-visible') });
        } else if (actionTab === 'action') {
            current = await api('update', { id, kind: 'action', note: v('f-note') });
        } else if (actionTab === 'privacy') {
            const code = current.order.code;
            await api('delete', { id, confirm: v('f-confirm'), totp: v('f-stepup') });
            drafts.delete(savedKey);
            formDirty = false;
            actionBusy = false;
            backToList();
            await loadList();
            $('detail-pane').classList.remove('hidden');
            $('detail-empty').innerHTML = `<p class="result-box result-ok text-left">${esc(code)} and its documents were permanently deleted.</p>`;
            return;
        } else if (actionTab === 'field') {
            current = await api('update', { id, kind: 'mailing', date: v('f-mail-date'), city: v('f-mail-city') });
        } else if (actionTab === 'payment') {
            current = await api('payment-link', { id, amount: v('f-amount'), description: v('f-desc') });
        } else {
            const files = Array.from($('f-proof').files);
            const problem = files.length ? NPS.checkFiles(files) : 'Choose the proof of service file.';
            if (problem) throw new Error(problem);
            const { uploads } = await api('proof-upload', { id, files: files.map(NPS.fileMeta) });
            const up = await NPS.uploadAll(uploads, files);
            // Proof is all or nothing: if any file didn't upload, nothing is marked served or sent to the client.
            if (up.failed.length) throw new Error(`${up.failed.join(', ')} did not upload, so nothing was sent to the client. Please try the upload again.`);
            current = await api('proof-finish', { id, fileIds: up.ok, markServed: on('f-served') });
        }
        drafts.delete(savedKey);
        formDirty = false;
        renderDetail();
        const messages = { field: 'Mailing logged on the timeline.', attempt: 'Attempt logged.', status: 'Status updated.', note: 'Note saved.', action: 'Request for information sent to the client.', payment: 'Payment link sent to the client.', proof: 'Proof of service uploaded.' };
        const feedback = $('save-feedback');
        feedback.textContent = (messages[savedAction] || 'Saved.') + partialUpload;
        feedback.className = `desk-feedback result-box ${partialUpload ? 'result-warn' : 'result-ok'}`;
        clearTimeout(feedbackTimer);
        if (!partialUpload) feedbackTimer = setTimeout(() => feedback.classList.add('hidden'), 7000);
        await refreshJobs();
    } catch (err) {
        if (err.status === 401) return;
        errBox.textContent = err.message;
        errBox.classList.remove('hidden');
        errBox.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    } finally {
        actionBusy = false;
        btn.disabled = false;
        btn.textContent = originalLabel;
        form.setAttribute('aria-busy', 'false');
        form.removeAttribute('inert');
    }
}

function protectionError(err) {
    const box = $('protect-error');
    box.textContent = err.message;
    box.classList.remove('hidden');
    box.scrollIntoView({ block: 'nearest' });
}
async function setLegalHold(hold) {
    try {
        current = await api('unlock-legal-hold', { id: current.order.id, hold, totp: $('f-stepup')?.value.trim(), confirm: $('f-hold-confirm')?.value.trim() });
        renderDetail();
    } catch (err) { protectionError(err); }
}
async function toggleDocLockJob() {
    try {
        current = await api('toggle-doc-lock', { id: current.order.id, locked: !current.order.doc_lock });
        renderDetail();
    } catch (err) { protectionError(err); }
}
async function rotateLink() {
    if (!confirm(`Replace the tracking link for ${current.order.code}? The old link stops working immediately and the client is emailed the new one.`)) return;
    try {
        current = await api('rotate-token', { id: current.order.id });
        renderDetail();
    } catch (err) { protectionError(err); }
}
// --- Field tools ---
function quickOutcome(outcome) {
    const sel = $('f-outcome');
    if (!sel) return;
    sel.value = outcome;
    document.querySelectorAll('[data-click="quickOutcome"]').forEach(b => b.classList.toggle('is-active', b.dataset.arg === outcome));
    formDirty = true;
    $('f-note')?.focus();
}
function templatePicker(kind) {
    return `<div><label for="f-template" class="field-label">Saved message</label><select id="f-template" class="field" data-template="${kind}">
        <option value="">Choose one to fill in, or type your own below</option>${TEMPLATES[kind].map((t, i) => `<option value="${i}">${esc(t)}</option>`).join('')}</select></div>`;
}
document.addEventListener('change', (e) => {
    const sel = e.target.closest('[data-template]');
    if (!sel || sel.value === '') return;
    const note = $('f-note');
    if (note) { note.value = TEMPLATES[sel.dataset.template][Number(sel.value)]; formDirty = true; note.focus(); }
});
// Printing: first 100 pages free, $0.15 a page after (Nick's price list). Counted from the client's PDFs.
function printingFeeNote() {
    const pdfs = (current.files || []).filter(f => f.kind !== 'proof' && /\.pdf$/i.test(f.filename));
    if (!pdfs.length) return '';
    const counted = pdfs.filter(f => Number.isInteger(f.page_count));
    const pages = counted.reduce((n, f) => n + f.page_count, 0);
    const fee = Math.max(0, pages - 100) * 15;
    const unknown = pdfs.length - counted.length;
    return `<p class="result-box ${fee ? 'result-warn' : 'result-ok'} text-sm">Printing: ${pages} page${pages === 1 ? '' : 's'} in ${counted.length} PDF${counted.length === 1 ? '' : 's'}${unknown ? ` (${unknown} not counted)` : ''}. ${fee ? `Printing fee: ${NPS.money(fee)} (pages over 100 at $0.15). Add it to the amount if it applies.` : 'Within the 100 free pages.'}</p>`;
}
// Which time-of-day windows have been tried (Standard and Expedited promise morning, evening and night attempts).
function attemptWindowsHtml(o, events) {
    if (!['standard', 'expedited'].includes(o.tier)) return '';
    const tried = new Set(events.filter(e => e.kind === 'attempt').map(e => /^Attempt \(([^)]+)\)/.exec(e.title)?.[1]).filter(Boolean));
    const label = { morning: 'Morning (before 12)', 'afternoon/evening': 'Afternoon/evening (12–7 PM)', night: 'Night (after 7 PM)' };
    return `<div class="flex flex-wrap items-center gap-2 mt-4"><span class="text-xs text-muted">Attempt windows:</span>${Object.entries(label).map(([k, l]) =>
        `<span class="status-pill ${tried.has(k) ? 'status-done' : 'status-muted'}"><i class="fa-solid ${tried.has(k) ? 'fa-check' : 'fa-clock'} mr-1" aria-hidden="true"></i>${l}</span>`).join('')}</div>`;
}
async function copyAddress(_, btn) {
    const o = current.order;
    const text = `${o.address}${o.unit ? ', ' + o.unit : ''}, ${o.city} ${o.zip}`;
    try { await navigator.clipboard.writeText(text); btn.textContent = 'Copied'; }
    catch { btn.textContent = 'Copy failed'; }
    setTimeout(() => { btn.innerHTML = '<i class="fa-regular fa-copy" aria-hidden="true"></i> Copy'; }, 2000);
}
async function bulkCloseShown() {
    if (!bulkIds.length || !confirm(`Close ${bulkIds.length} finished ${bulkIds.length === 1 ? 'job' : 'jobs'}? Clients can still open their tracking pages.`)) return;
    try {
        const r = await api('bulk-close', { ids: bulkIds });
        const fb = $('save-feedback');
        fb.textContent = `Closed ${r.closed.length} ${r.closed.length === 1 ? 'job' : 'jobs'}.${r.skipped ? ` ${r.skipped} changed in the meantime and were left as they are.` : ''}`;
        fb.className = 'desk-feedback result-box result-ok';
        await refreshJobs();
    } catch (err) { if (err.status !== 401) alert(err.message); }
}
async function evidencePack() {
    try { NPS.printEvidencePack(await api('evidence-pack', { id: current.order.id })); }
    catch (err) { if (err.status !== 401) alert(err.message); }
}
function printReceiptJob() {
    const o = current.order;
    NPS.printReceipt({ code: o.code, caseNumber: o.case_number, court: o.court, clientReference: o.client_reference, tier: o.tier_name,
        addons: o.addon_names, amountPaid: NPS.money(o.amount_due_cents), paidAt: o.paid_at, clientName: o.client_name, clientFirm: o.client_firm });
}

// --- Security setup card (first logins) and the low recovery-codes banner ---
async function renderSecurityNudges(me) {
    let passkeyCount = 0;
    try { passkeyCount = (await api('passkeys')).passkeys.length; } catch { passkeyCount = -1; }   // -1: passkeys not set up on the server yet
    let dismissed = false;
    try { dismissed = sessionStorage.getItem('nps_setup_card_hidden') === '1'; } catch { /* storage off */ }
    const steps = [
        ['Turn on the authenticator app', me.totpEnabled],
        ['Save your recovery codes', (me.recoveryRemaining || 0) > 0],
        ...(passkeyCount >= 0 && window.PublicKeyCredential ? [['Add Face ID / Touch ID (passkey)', passkeyCount > 0]] : []),
    ];
    const todo = steps.filter(([, done]) => !done).length;
    const card = $('setup-card');
    card.classList.toggle('hidden', !todo || dismissed);
    card.innerHTML = todo ? `<div class="flex flex-wrap items-start justify-between gap-3">
        <div><p class="font-serif text-lg text-primary"><i class="fa-solid fa-shield-halved text-bronze mr-1" aria-hidden="true"></i> Secure your dashboard</p>
        <p class="text-xs text-muted mt-1">So someone who gets into your email still can't get in. It takes about two minutes.</p>
        <ol class="mt-3 space-y-1 text-sm">${steps.map(([l, done]) => `<li><i class="fa-solid ${done ? 'fa-circle-check text-primary' : 'fa-circle text-muted'} mr-2" aria-hidden="true"></i>${esc(l)}</li>`).join('')}</ol></div>
        <div class="flex flex-wrap gap-2"><button type="button" data-click="openSecurityModal" class="btn btn-pine btn-sm">Set it up</button>
        <button type="button" data-click="hideSetupCard" class="btn btn-outline btn-sm">Later</button></div></div>` : '';
    const low = me.totpEnabled && (me.recoveryRemaining || 0) <= 3;
    const banner = $('recovery-banner');
    banner.classList.toggle('hidden', !low);
    banner.innerHTML = low ? `<i class="fa-solid fa-key mr-1" aria-hidden="true"></i> Only ${me.recoveryRemaining || 0} recovery code${me.recoveryRemaining === 1 ? '' : 's'} left. <button type="button" data-click="openSecurityModal" class="underline underline-offset-2 font-semibold">Make a new set</button>` : '';
}
function hideSetupCard() {
    $('setup-card').classList.add('hidden');
    try { sessionStorage.setItem('nps_setup_card_hidden', '1'); } catch { /* storage off */ }
}

// --- Field & court tab ---
const SUBSTITUTED = 'Left with co-resident';
function substitutedService(events) {
    return {
        attempted: events.some(e => e.kind === 'attempt' && e.title.includes(SUBSTITUTED)),
        mailed: events.some(e => e.title === 'Substituted service: follow-up mailing sent'),
    };
}
// The stakeout start time lives on this device only, so a timer survives switching jobs or reloading the page.
const stakeoutKey = (id) => `nps_stakeout_${id}`;
function stakeoutStart(id) { try { return localStorage.getItem(stakeoutKey(id)); } catch { return null; } }
function startStakeout() {
    try { localStorage.setItem(stakeoutKey(current.order.id), new Date().toISOString()); } catch { alert('This browser cannot keep a timer. Note the start time yourself.'); }
    renderDetail();
}
function cancelStakeout() {
    if (!confirm('Cancel this stakeout timer without saving it?')) return;
    try { localStorage.removeItem(stakeoutKey(current.order.id)); } catch { /* storage off */ }
    renderDetail();
}
async function stopStakeout() {
    const start = stakeoutStart(current.order.id);
    if (!start) return renderDetail();
    try {
        current = await api('update', { id: current.order.id, kind: 'stakeout', start, end: new Date().toISOString(), clientVisible: true });
        try { localStorage.removeItem(stakeoutKey(current.order.id)); } catch { /* storage off */ }
        renderDetail();
        await refreshJobs();
    } catch (err) { if (err.status !== 401) alert(err.message); }
}
const caseAddress = (o) => `${o.address}${o.unit ? ', ' + o.unit : ''}, ${o.city} ${o.zip}`;
const ptParts = (iso) => {
    const d = new Date(iso);
    return { date: d.toLocaleDateString('en-US', { timeZone: 'America/Los_Angeles', month: 'short', day: 'numeric', year: 'numeric' }),
        time: d.toLocaleTimeString('en-US', { timeZone: 'America/Los_Angeles', hour: 'numeric', minute: '2-digit' }) };
};
// A chronological table of every attempt, to attach to a declaration of due diligence.
function printDiligenceLog() {
    const o = current.order;
    const attempts = current.events.filter(e => e.kind === 'attempt');
    const rowsHtml = attempts.map(e => {
        const { date, time } = ptParts(e.created_at);
        const m = /^Attempt(?: \(([^)]+)\))?: (.*)$/.exec(e.title) || [];
        return `<tr><td>${esc(date)}</td><td>${esc(time)}</td><td>${esc(m[1] || '')}</td><td>${esc(caseAddress(o))}</td><td>${esc(m[2] || e.title)}</td><td>${esc(e.detail || '')}</td></tr>`;
    }).join('') || '<tr><td colspan="6">No attempts logged yet.</td></tr>';
    NPS.printPage(`Diligence log ${o.code}`, `<h1>Log of service attempts</h1>
        <p style="margin-top:0;color:#566860;font-size:13px">${esc(o.code)} · ${esc(o.recipient_name)} · ${esc(o.doc_type)}${o.case_number ? ` · Case ${esc(o.case_number)}` : ''}${o.court ? ` · ${esc(o.court)}` : ''}</p>
        <table><thead><tr><th>Date</th><th>Time (California)</th><th>Window</th><th>Address</th><th>Outcome</th><th>Field notes</th></tr></thead><tbody>${rowsHtml}</tbody></table>
        <p style="font-size:11px;color:#566860;margin-top:16px">Times are when each attempt was logged, unless the notes give a different time. The address shown is the service address on file today.
        Draft for your review; attach it to your declaration of due diligence only after checking it.</p>`);
}
// The facts a POS-010 needs, gathered from the record so nothing is retyped. Nick checks, completes and signs the form.
function printPosSheet() {
    const o = current.order;
    const sub = substitutedService(current.events);
    const served = [...current.events].reverse().find(e => e.kind === 'attempt' && (/: Served/.test(e.title) || e.title.includes(SUBSTITUTED)));
    const when = o.served_at || served?.created_at;
    const mailing = current.events.find(e => e.title === 'Substituted service: follow-up mailing sent');
    const blank = '<span style="display:inline-block;min-width:220px;border-bottom:1px solid #10221a">&nbsp;</span>';
    const r = (k, v) => `<tr><th style="width:38%">${esc(k)}</th><td>${v}</td></tr>`;
    NPS.printPage(`POS-010 data ${o.code}`, `<h1>Proof of service: data sheet</h1>
        <p style="margin-top:0;color:#566860;font-size:13px">For Judicial Council form POS-010. Copy these facts onto the official form, check them, and sign it yourself.</p>
        <table><tbody>
        ${r('Case number', esc(o.case_number || '') || blank)}${r('Court', esc(o.court || '') || blank)}
        ${r('Documents served', esc(o.doc_type || '') || blank)}${r('Party served', esc(o.recipient_name || '') || blank)}
        ${r('Address where served', esc(caseAddress(o)))}
        ${r('Date of service', when ? esc(ptParts(when).date) : blank)}${r('Time of service', when ? esc(ptParts(when).time) : blank)}
        ${r('Manner of service', sub.attempted ? 'Substituted service (left with a co-resident), CCP § 415.20' : served ? 'Personal service' : blank)}
        ${sub.attempted ? r('Follow-up mailing', mailing ? esc(mailing.detail || '') : '<strong>Not logged yet</strong>') : ''}
        ${r('Person who served (name)', blank)}${r('Registered process server: county', blank)}${r('Registration number', blank)}
        ${r('Fee for service', o.amount_due_cents != null ? esc(NPS.money(o.amount_due_cents)) : blank)}
        </tbody></table>
        <p style="font-size:11px;color:#566860;margin-top:16px">Blank lines are details this site doesn't hold. This sheet is not a court form and is not filed by the site.</p>`);
}

function openRoute() {
    if (!routeStops.length) return;
    const addr = (o) => `${o.address}${o.unit ? ' ' + o.unit : ''}, ${o.city} ${o.zip}`;
    const stops = routeStops.map(addr);
    const url = 'https://www.google.com/maps/dir/?api=1&travelmode=driving&destination=' + encodeURIComponent(stops.at(-1)) +
        (stops.length > 1 ? '&waypoints=' + encodeURIComponent(stops.slice(0, -1).join('|')) : '');
    window.open(url, '_blank', 'noopener');
}
async function addExpense(_, btn) {
    btn.disabled = true;
    try {
        const r = await api('expense-add', { id: current.order.id, miles: $('f-miles').value, fees: $('f-fees').value, label: $('f-exp-label').value.trim() });
        current.expenses = { miles: r.miles, feesCents: r.feesCents };
        renderDetail();
    } catch (err) { if (err.status !== 401) alert(err.message); btn.disabled = false; }
}
async function downloadExpenses() {
    try {
        const r = await api('expenses-csv', {});
        const url = URL.createObjectURL(new Blob([r.csv], { type: 'text/csv' }));
        const a = Object.assign(document.createElement('a'), { href: url, download: `expenses-${r.from}-to-${r.to}.csv` });
        document.body.append(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) { if (err.status !== 401) alert(err.message); }
}

// --- Safe-Walk ---
let safeWalk = { contact: null, walk: null, unavailable: false };
async function refreshSafeWalk() {
    try { Object.assign(safeWalk, await api('safewalk-status'), { unavailable: false }); }
    catch (err) { if (err.status === 503) safeWalk.unavailable = true; }
    const w = safeWalk.walk, banner = $('safewalk-banner');
    banner.classList.toggle('hidden', !w);
    if (w) {
        const late = new Date(w.due_at) < new Date();
        banner.innerHTML = `<div class="flex flex-wrap items-center justify-between gap-3"><span><i class="fa-solid fa-person-walking mr-1" aria-hidden="true"></i>
            Safe-Walk ${late ? `<strong>ran out at ${esc(new Date(w.due_at).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }))}</strong>${w.alerted_at ? ': your emergency contact was emailed.' : ': alerting your emergency contact.'}`
            : `is on until ${esc(new Date(w.due_at).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }))}`}${w.order_code ? ` (${esc(w.order_code)})` : ''}.</span>
            <button type="button" class="btn btn-pine btn-sm" data-click="safeWalkSafe">I'm safe</button></div>`;
    }
}
function safeWalkSection() {
    if (safeWalk.unavailable) return '<div class="pb-5 rule-b"><p class="text-sm font-semibold text-primary">Safe-Walk</p><p class="text-xs text-muted">Not set up yet.</p></div>';
    return `<div class="space-y-3 pb-5 rule-b">
        <p class="text-sm font-semibold text-primary"><i class="fa-solid fa-person-walking text-bronze mr-1" aria-hidden="true"></i> Safe-Walk check-in</p>
        <p class="text-xs text-muted">Before a risky serve, start a timer. If you don't tap "I'm safe" in time, ${safeWalk.contact ? `<strong>${esc(safeWalk.contact)}</strong>` : 'your emergency contact'} is emailed this job's address. Test it once before you rely on it. It needs signal to check in, and it is not a substitute for calling 911.</p>
        ${safeWalk.walk ? '<button type="button" class="btn btn-pine btn-sm" data-click="safeWalkSafe">I\'m safe</button>'
            : safeWalk.contact ? `<div class="flex flex-wrap gap-2">${[15, 30, 60].map(m => `<button type="button" class="btn btn-outline btn-sm" data-click="safeWalkStart" data-arg="${m}">${m} min</button>`).join('')}</div>` : ''}
        <details class="text-xs"><summary class="cursor-pointer text-primary font-semibold">${safeWalk.contact ? 'Change emergency contact' : 'Add an emergency contact'}</summary>
            <div class="grid sm:grid-cols-2 gap-3 mt-3">
                <div><label for="f-sw-contact" class="field-label">Their email</label><input id="f-sw-contact" type="email" class="field" value="${esc(safeWalk.contact || '')}"></div>
                <div><label for="f-sw-code" class="field-label">${totpEnabled ? 'Authenticator or recovery code' : 'Step-up code from your email'}</label>
                <div class="flex flex-wrap gap-2"><input id="f-sw-code" class="field font-mono max-w-[10rem]" maxlength="9" autocomplete="one-time-code">
                ${totpEnabled ? '' : '<button type="button" class="btn btn-outline btn-sm" data-click="emailStepUp" data-arg="f-sw-code">Email me a code</button>'}</div></div>
            </div>
            <button type="button" class="btn btn-outline btn-sm mt-3" data-click="safeWalkContact">Save contact</button></details>
    </div>`;
}
async function safeWalkStart(minutes) {
    try { Object.assign(safeWalk, await api('safewalk-start', { minutes: Number(minutes), id: current?.order.id })); await refreshSafeWalk(); renderDetail(); }
    catch (err) { if (err.status !== 401) alert(err.message); }
}
async function safeWalkSafe() {
    try { await api('safewalk-safe'); safeWalk.walk = null; await refreshSafeWalk(); if (current) renderDetail(); }
    catch (err) { if (err.status !== 401) alert(`${err.message} If you can't check in, call your emergency contact.`); }
}
async function safeWalkContact() {
    try {
        const r = await api('safewalk-contact', { contact: $('f-sw-contact').value.trim(), totp: $('f-sw-code').value.trim() });
        safeWalk.contact = r.contact;
        renderDetail();
    } catch (err) { if (err.status !== 401) alert(err.message); }
}

function printRecord() {
    const o = current.order;
    NPS.printChainOfCustody({
        code: o.code, statusLabel: statuses[o.status]?.label || o.status, legalHold: o.legal_hold,
        recipient: o.recipient_name, docType: o.doc_type,
        address: [o.address, o.unit].filter(Boolean).join(', ') + `, ${o.city} ${o.zip}`,
        seal: o.integrity_seal, files: current.files, events: current.events,
    });
}
async function exportJob() {
    const data = await api('export', { id: current.order.id });
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const a = Object.assign(document.createElement('a'), { href: url, download: `${current.order.code}-data.json` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function downloadFile(fileId, btn) {
    btn.disabled = true;
    try {
        const { url } = await api('file-url', { fileId });
        location.href = url;   // the link is sent as a download, so the dashboard stays open
    } catch (err) {
        if (err.status !== 401) btn.insertAdjacentHTML('afterend', `<span class="text-xs text-[#7a1f1c]">${esc(err.message)}</span>`);
    } finally {
        btn.disabled = false;
    }
}

// --- Live refresh: at once when a client acts in another tab, otherwise every 30 seconds. ---
// The open job is only redrawn when Nick hasn't started typing in its action form.
let formDirty = false;
let feedbackTimer;
addEventListener('beforeunload', e => {
    if (formDirty || drafts.size || actionBusy) { e.preventDefault(); e.returnValue = ''; }
});
async function refresh() {
    if (actionBusy || document.hidden || $('dash-view').classList.contains('hidden')) return;
    try {
        await loadList();
        if (current && !formDirty) {
            const id = current.order.id;
            const version = openJobVersion;
            const result = await api('get', { id });
            if (formDirty || actionBusy || version !== openJobVersion || current?.order.id !== id) return;
            current = result;
            renderDetail();
        }
    } catch (err) { if (err.status !== 401) $('sync-status').textContent = 'Updates paused · use Refresh jobs to retry'; }
}
NPS.onChange(refresh);
setInterval(refresh, 30000);
document.addEventListener('visibilitychange', refresh);

// --- Security & Field App Modal + PWA ---
let deferredInstallPrompt = null;
let lastGeneratedCodes = [];
window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredInstallPrompt = e;
    $('pwa-install-btn')?.classList.remove('hidden');
});
function updateRecoveryBadge(n) {
    const count = Number(n) || 0;
    const badge = $('recovery-remaining-badge');
    if (!badge) return;
    badge.textContent = `${count} unused`;
    badge.className = `status-pill ${count > 0 ? 'status-done' : 'status-muted'}`;
}
// Signed-in devices: newest activity first; any device but this one can be signed out here.
const deviceName = (ua) => {
    if (!ua) return 'Browser not recorded';
    const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
    const os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '';
    return os ? `${browser} on ${os}` : browser;
};
function renderSessions(list) {
    $('session-list').innerHTML = list.map(s => `
        <li class="flex flex-wrap items-center justify-between gap-2 p-3 border border-[color:var(--hair-ink)] rounded-sm">
            <div class="text-xs"><p class="font-semibold text-ink">${esc(deviceName(s.browser))}${s.current ? ' <span class="status-pill status-done ml-1">This device</span>' : ''}</p>
                <p class="text-muted">Signed in ${esc(NPS.fmtDate(s.signedIn))} · last active ${esc(NPS.fmtDate(s.lastSeen))}</p></div>
            ${s.current ? '' : `<button type="button" class="btn btn-outline btn-sm" data-revoke-session="${esc(s.id)}">Sign out</button>`}
        </li>`).join('') || '<li class="text-xs text-muted">No other devices are signed in.</li>';
}
async function loadSessions() {
    try { renderSessions((await api('sessions')).sessions); }
    catch { $('session-list').innerHTML = '<li class="text-xs text-muted">Signed-in devices could not be loaded.</li>'; }
}
$('session-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-revoke-session]');
    if (!btn) return;
    btn.disabled = true;
    try { renderSessions((await api('revoke-session', { sessionId: btn.dataset.revokeSession })).sessions); }
    catch (err) { const msg = $('security-modal-msg'); msg.textContent = err.message; msg.className = 'result-box result-err text-xs'; btn.disabled = false; }
});

// --- Passkeys (Face ID / fingerprint / device PIN). Shown only where the browser supports them. ---
const PK = window.SimpleWebAuthnBrowser;
const passkeysSupported = !!PK?.browserSupportsWebAuthn?.();
$('passkey-login-wrap').classList.toggle('hidden', !passkeysSupported);
const passkeyError = (err) => (err?.name === 'NotAllowedError' || err?.name === 'AbortError')
    ? 'The passkey request was cancelled or timed out.'
    : err?.name === 'InvalidStateError' ? 'This device already has a passkey for your dashboard.' : (err?.message || 'The passkey did not work. Please try again.');
async function passkeyLogin() {
    $('login-error').classList.add('hidden');
    try {
        const { options } = await api('passkey-login-options');
        const response = await PK.startAuthentication({ optionsJSON: options });
        await api('passkey-login-verify', { response });
        start();
    } catch (err) { loginError(passkeyError(err)); }
}
function renderAdminPasskeys(list) {
    $('admin-passkey-list').innerHTML = list.map(k => `
        <li class="flex flex-wrap items-center justify-between gap-2 p-3 border border-[color:var(--hair-ink)] rounded-sm">
            <div><p class="font-semibold text-ink">${esc(k.label)}</p><p class="text-muted">Added ${esc(NPS.fmtDate(k.createdAt, false))}${k.lastUsedAt ? ` · last used ${esc(NPS.fmtDate(k.lastUsedAt))}` : ''}</p></div>
            <button type="button" class="btn btn-outline btn-sm" data-passkey-remove="${esc(k.id)}">Remove</button>
        </li>`).join('') || '<li class="text-muted">No passkeys yet.</li>';
}
async function loadAdminPasskeys() {
    if (!passkeysSupported) return;
    try { renderAdminPasskeys((await api('passkeys')).passkeys); $('admin-passkey-section').classList.remove('hidden'); }
    catch { $('admin-passkey-section').classList.add('hidden'); }   // not set up yet: hide it
}
async function addAdminPasskey() {
    try {
        const { options } = await api('passkey-register-options', { totp: $('admin-passkey-totp').value.trim() });
        const response = await PK.startRegistration({ optionsJSON: options });
        renderAdminPasskeys((await api('passkey-register-verify', { response, label: $('admin-passkey-label').value.trim() })).passkeys);
        $('admin-passkey-label').value = '';
        securityMessage('Passkey added. Next time, choose "Log in with a passkey".');
    } catch (err) { securityMessage(passkeyError(err), 'err'); }
    finally { $('admin-passkey-totp').value = ''; }
}
$('admin-passkey-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-passkey-remove]');
    if (!btn) return;
    btn.disabled = true;
    try {
        renderAdminPasskeys((await api('passkey-remove', { id: btn.dataset.passkeyRemove, totp: $('admin-passkey-totp').value.trim() })).passkeys);
        securityMessage('Passkey removed.');
    } catch (err) { securityMessage(err.message, 'err'); btn.disabled = false; }
    finally { $('admin-passkey-totp').value = ''; }
});

function openSecurityModal() {
    loadSessions();
    loadAdminPasskeys();
    $('security-modal-msg').classList.add('hidden');
    $('recovery-codes-box').classList.add('hidden');
    $('copy-recovery-btn').classList.add('hidden');
    $('security-modal').classList.remove('hidden');
}
function closeSecurityModal() {
    $('security-modal').classList.add('hidden');
}
$('security-modal').addEventListener('click', (e) => {
    if (e.target === $('security-modal')) closeSecurityModal();
});
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('security-modal').classList.contains('hidden')) closeSecurityModal();
});
async function installPwaApp() {
    if (!deferredInstallPrompt) return;
    deferredInstallPrompt.prompt();
    await deferredInstallPrompt.userChoice.catch(() => {});
    deferredInstallPrompt = null;
    $('pwa-install-btn').classList.add('hidden');
}
async function generateRecoveryCodes() {
    const btn = $('gen-recovery-btn');
    btn.disabled = true;
    $('security-modal-msg').classList.add('hidden');
    try {
        const { codes, remaining } = await api('generate-recovery-codes', { totp: $('totp-current-input').value.trim() });
        $('totp-current-input').value = '';
        lastGeneratedCodes = codes || [];
        updateRecoveryBadge(remaining ?? lastGeneratedCodes.length);
        $('recovery-codes-list').innerHTML = lastGeneratedCodes.map(c => `<div class="px-2 py-1 bg-white border border-[color:var(--hair-ink)] rounded-sm text-center select-all">${esc(c)}</div>`).join('');
        $('recovery-codes-box').classList.remove('hidden');
        $('copy-recovery-btn').classList.remove('hidden');
    } catch (err) {
        const msg = $('security-modal-msg');
        msg.textContent = err.message;
        msg.className = 'result-box result-err text-xs';
    } finally {
        btn.disabled = false;
    }
}
async function copyRecoveryCodes() {
    if (!lastGeneratedCodes.length) return;
    try {
        await navigator.clipboard.writeText(lastGeneratedCodes.join('\n'));
        const msg = $('security-modal-msg');
        msg.textContent = 'Backup recovery codes copied to clipboard.';
        msg.className = 'result-box result-ok text-xs';
    } catch {
        const msg = $('security-modal-msg');
        msg.textContent = 'Select and copy the codes above.';
        msg.className = 'result-box result-warn text-xs';
    }
}
// --- Two-step sign-in (authenticator app) ---
let totpEnabled = false;
function securityMessage(text, kind = 'ok') {
    const msg = $('security-modal-msg');
    msg.textContent = text;
    msg.className = `result-box result-${kind} text-xs`;
}
function updateSecurityState(enabled) {
    totpEnabled = !!enabled;
    $('totp-status-badge').textContent = totpEnabled ? 'On' : 'Off';
    $('totp-status-badge').className = `status-pill ${totpEnabled ? 'status-done' : 'status-muted'}`;
    $('totp-setup-label').textContent = totpEnabled ? 'Move to a New Phone' : 'Turn On Two-Step Sign-In';
    $('totp-disable-btn').classList.toggle('hidden', !totpEnabled);
    $('totp-current-wrap').classList.remove('hidden');
    $('totp-current-label').textContent = totpEnabled ? 'Current code from your authenticator app' : 'Step-up code from your email';
    $('totp-current-input').placeholder = totpEnabled ? '000000 or XXXX-XXXX' : '12345678';
    $('totp-current-help').textContent = totpEnabled
        ? 'Needed to change your phone, turn two-step off, or create new recovery codes. Lost your phone? Type one of your recovery codes (XXXX-XXXX) instead.'
        : 'Needed to turn on two-step sign-in or create recovery codes. Tap "Email me a code", then type the 8-digit code here.';
    $('stepup-email-btn').classList.toggle('hidden', totpEnabled);
}
// F-09: with two-step off, sensitive actions are confirmed with an 8-digit code emailed to Nick a moment ago.
async function emailStepUp(targetId, btn) {
    if (btn) btn.disabled = true;
    try {
        const { minutes } = await api('stepup-send-code');
        const msg = `Step-up code sent to your email. It works for ${minutes} minutes.`;
        if (targetId === 'f-stepup') { const e = $('action-error'); if (e) { e.textContent = msg; e.className = 'result-box result-ok text-sm'; } }
        else securityMessage(msg);
        $(targetId)?.focus();
    } catch (err) {
        if (targetId === 'f-stepup') { const e = $('action-error'); if (e) { e.textContent = err.message; e.className = 'result-box result-err'; } }
        else securityMessage(err.message, 'err');
    } finally { if (btn) btn.disabled = false; }
}

async function startTotpSetup() {
    $('security-modal-msg').classList.add('hidden');
    try {
        // When it's already on, the current code proves it's Nick; the old phone keeps working until the new one is confirmed.
        const { secret, otpauthUrl } = await api('totp-setup', { totp: $('totp-current-input').value.trim() });
        $('totp-current-input').value = '';
        const qr = qrcode(0, 'M');
        qr.addData(otpauthUrl);
        qr.make();
        $('totp-qr').innerHTML = qr.createSvgTag({ cellSize: 5, margin: 2 });
        $('totp-secret-display').textContent = secret.replace(/(.{4})/g, '$1 ').trim();
        $('totp-uri-link').href = otpauthUrl;
        $('totp-setup-box').classList.remove('hidden');
        $('totp-verify-input').value = '';
        $('totp-verify-input').focus();
    } catch (err) { securityMessage(err.message, 'err'); }
}
async function confirmTotpEnable() {
    try {
        await api('totp-enable', { totp: $('totp-verify-input').value.trim() });
        $('totp-setup-box').classList.add('hidden');
        $('totp-qr').innerHTML = '';
        $('totp-secret-display').textContent = '';
        updateSecurityState(true);
        securityMessage('Two-step sign-in is on. Next time you sign in, have your authenticator app ready. Create recovery codes now in case you lose your phone.');
    } catch (err) { securityMessage(err.message, 'err'); }
}
async function disableTotp() {
    if (!confirm('Turn off two-step sign-in? Your dashboard would be protected by your email alone.')) return;
    try {
        await api('totp-disable', { totp: $('totp-current-input').value.trim() });
        $('totp-current-input').value = '';
        updateSecurityState(false);
        securityMessage('Two-step sign-in is off.', 'warn');
    } catch (err) { securityMessage(err.message, 'err'); }
}

async function logoutAllDevices() {
    const btn = $('logout-all-btn');
    btn.disabled = true;
    try {
        await api('logout-all');
        closeSecurityModal();
        showLogin();
    } catch (err) {
        const msg = $('security-modal-msg');
        msg.textContent = err.message;
        msg.className = 'result-box result-err text-xs';
    } finally {
        btn.disabled = false;
    }
}
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
}

// --- Start: already logged in? ---
async function start() {
    try {
        const me = await api('me');
        $('login-view').classList.add('hidden');
        $('dash-view').classList.remove('hidden');
        $('whoami').classList.replace('hidden', 'flex');
        $('whoami-email').textContent = me.email;
        $('security-modal-email').textContent = me.email;
        updateRecoveryBadge(me.recoveryRemaining);
        updateSecurityState(me.totpEnabled);
        renderSecurityNudges(me);
        refreshSafeWalk();
        await refreshJobs();
        const hashId = location.hash.slice(1);
        if (hashId) openJob(hashId);
    } catch (err) {
        if (err.status !== 401) {
            showLogin();
            loginError(err.message);
        }
    }
}
start();

// Buttons say what they do with data-click (and data-arg) instead of inline onclick, so the page's Content Security
// Policy can refuse inline scripts. Only the functions listed here can be triggered this way.
const CLICK_ACTIONS = {
    backToList, closeSecurityModal, refreshJobs, exportJob, showEmailStep, rotateLink, toggleDocLockJob, printRecord,
    discardDraft, logout, openSecurityModal, logoutAllDevices, copyRecoveryCodes, generateRecoveryCodes,
    confirmTotpEnable, disableTotp, startTotpSetup, installPwaApp, passkeyLogin, addAdminPasskey,
    emailStepUp: (arg, el) => emailStepUp(arg, el),
    safeWalkStart: (arg) => safeWalkStart(arg), safeWalkSafe, safeWalkContact,
    openRoute, addExpense: (arg, el) => addExpense(arg, el), downloadExpenses,
    startStakeout, stopStakeout, cancelStakeout, printDiligenceLog, printPosSheet,
    quickOutcome: (arg) => quickOutcome(arg), copyAddress: (arg, el) => copyAddress(arg, el), bulkCloseShown, evidencePack, printReceiptJob, hideSetupCard,
    setLegalHold: (arg) => setLegalHold(arg === 'true'),
    setActionTab: (arg) => setActionTab(arg),
    setFilter: (arg) => setFilter(arg),
    openJob: (arg) => openJob(arg),
    downloadFile: (arg, el) => downloadFile(arg, el),
};
document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-click]');
    if (el && Object.hasOwn(CLICK_ACTIONS, el.dataset.click)) CLICK_ACTIONS[el.dataset.click](el.dataset.arg, el);
});
