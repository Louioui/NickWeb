const $ = id => document.getElementById(id);
const { esc } = NPS;

const PILL = {
    received: 'status-live', action_required: 'status-alert', awaiting_payment: 'status-live', paid: 'status-done',
    accepted: 'status-live', attempting: 'status-live', served: 'status-done', closed: 'status-muted', cancelled: 'status-muted',
};
const FILTERS = {
    priority: { label: 'Due today & 48h', test: o => isPriority(o) },
    active: { label: 'Active', test: o => !['served', 'closed', 'cancelled'].includes(o.status) },
    review: { label: 'New', test: o => o.status === 'received' },
    waiting: { label: 'Waiting on client', test: o => ['action_required', 'awaiting_payment'].includes(o.status) },
    working: { label: 'In progress', test: o => ['paid', 'accepted', 'attempting'].includes(o.status) },
    urgent: { label: 'Due soon', test: o => isOpen(o) && o.deadline && daysUntil(o.deadline) <= 7 },
    done: { label: 'Done', test: o => ['served', 'closed', 'cancelled'].includes(o.status) },
    all: { label: 'All', test: () => true },
};
// Some timeline entries are written for the client ("You sent..."); on Nick's screen they read from his side.
const NICK_WORDING = { 'You sent the requested information': 'Client sent the requested information' };
const ATTEMPT_OUTCOMES = ['No answer', 'Served', 'Wrong address / moved', 'Refused / evading', 'Left with co-resident (Substituted Service)',
    'Subject not home', 'Spoke with resident, subject not there', 'Gated, no access', 'Business closed', 'Other'];
const ATTEMPT_PRESETS = [['No answer', 'No answer'], ['Served', 'Served'], ['Wrong address', 'Wrong address / moved'],
    ['Refused', 'Refused / evading'], ['Left with co-resident', 'Left with co-resident (Substituted Service)']];
const MESSAGE_TEMPLATES = {
    action: ['Please confirm the unit or gate code.', 'No answer on the first attempt. Is there a best time window to try again?', 'Please confirm the current service address.'],
    note: ['Client confirmed the unit or gate code.', 'No answer on the first attempt. Follow up with the client about a better time window.', 'Served. Preparing Proof of Service now.'],
};

let orders = [];
let statuses = {};
let filter = 'active';
let current = null;           // { order, events, files } for the open job
let actionTab = 'attempt';
let openJobVersion = 0;
let actionBusy = false;
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
const isPriority = o => isOpen(o) && o.deadline && new Date(`${o.deadline}T23:59:59`).getTime() <= Date.now() + 48 * 3600e3;

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
    shown.sort((a, b) => Number(isPriority(b)) - Number(isPriority(a)) ||
        (isPriority(a) && isPriority(b)
            ? a.deadline.localeCompare(b.deadline) || Number(b.tier === 'sameday') - Number(a.tier === 'sameday')
            : 0));
    $('list-count').textContent = `${shown.length} ${shown.length === 1 ? 'request' : 'requests'}`;
    $('job-list').innerHTML = shown.length ? shown.map(o => {
        const days = daysUntil(o.deadline);
        const contactDays = Math.max(0, Math.floor((Date.now() - new Date(o.last_contact_at || o.created_at).getTime()) / 864e5));
        const contact = isOpen(o) ? `<span class="text-xs ${contactDays >= 3 ? 'text-[#7a1f1c] font-semibold' : 'text-muted'}">${contactDays}d since last contact</span>` : '';
        const due = o.deadline && isOpen(o)
            ? `<span class="${days <= 3 ? 'text-[#7a1f1c] font-semibold' : 'text-muted'}"><i class="fa-regular fa-calendar mr-1"></i>${days < 0 ? 'Past due' : days === 0 ? 'Due today' : `Due in ${days}d`}</span>` : '';
        return `
        <button type="button" aria-pressed="${current?.order.id === o.id}" class="job-row ${current?.order.id === o.id ? 'is-active' : ''}" data-click="openJob" data-arg="${esc(o.id)}">
            <span class="font-semibold text-sm text-ink truncate">${esc(o.recipient_name)}</span>
            ${o.client_replied
                ? '<span class="status-pill status-alert"><i class="fa-solid fa-reply mr-1"></i>Client replied</span>'
                : `<span class="status-pill ${PILL[o.status]}">${esc(statuses[o.status]?.label || o.status)}</span>`}
            <span class="text-xs text-muted truncate">${esc(o.code)} · ${esc(o.city || '')} · ${esc(o.client_firm || o.client_name)}</span>
            <span class="text-xs text-right">${due}${contact ? `<span class="block mt-1">${contact}</span>` : ''}</span>
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
    try { await loadList(); }
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
function attemptWindow(event) {
    const stamped = /^Attempted at: (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)/.exec(event.detail || '');
    const when = new Date(stamped?.[1] || event.created_at);
    if (!Number.isFinite(when.getTime())) return null;
    const hour = Number(new Intl.DateTimeFormat('en-US', { timeZone: 'America/Los_Angeles', hour: 'numeric', hourCycle: 'h23' }).format(when));
    return hour < 12 ? 'Morning' : hour < 19 ? 'Afternoon / evening' : 'Night';
}

function renderDetail() {
    const { order: o, events, files } = current;
    const attemptedWindows = new Set(events.filter(e => e.kind === 'attempt').map(attemptWindow).filter(Boolean));
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
            ${['standard', 'expedited'].includes(o.tier) ? `<div class="mt-5"><p class="field-label">Attempt windows</p><div class="flex flex-wrap gap-2">${['Morning', 'Afternoon / evening', 'Night'].map(name => `<span class="status-pill ${attemptedWindows.has(name) ? 'status-done' : 'status-muted'}">${attemptedWindows.has(name) ? '✓' : 'Needed:'} ${name}</span>`).join('')}</div><p class="text-xs text-muted mt-2">Older attempts without a recorded attempt time use the time they were logged.</p></div>` : ''}
            <div class="grid sm:grid-cols-2 gap-x-8 gap-y-6 mt-6">
                <dl class="review-recap content-start">
                    ${row('Address', `<a href="${mapUrl}" target="_blank" rel="noopener noreferrer" class="text-primary font-semibold underline underline-offset-2">${esc(fullAddress)}</a><button type="button" class="btn btn-outline btn-sm mt-2" data-click="copyAddress">Copy Full Address</button>`)}
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
            <div class="mt-7 pt-5 rule-t">${o.receipt ? '<button type="button" class="btn btn-outline btn-sm mr-2" data-click="printReceipt">Open printable receipt</button>' : ''}<button type="button" class="btn btn-outline btn-sm" data-click="downloadDisputePack">Download Dispute Evidence Pack</button><p class="text-xs text-muted mt-2">Printable HTML and source JSON in one ZIP file.</p></div>
        </div>

        <div class="panel">
            <div class="flex flex-wrap gap-1 px-4 pt-3 rule-b" role="group" aria-label="Actions for this request">
                ${[['attempt', 'Log attempt'], ['status', 'Status'], ['note', 'Note'], ['action', 'Ask client'], ['payment', 'Payment link'], ['proof', 'Proof of service'], ['privacy', 'Privacy']]
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
                    ${ev.detail ? `<p class="text-sm text-muted mt-0.5 whitespace-pre-line">${esc(ev.kind === 'attempt' ? NPS.fmtAttemptDetail(ev.detail) : ev.detail)}</p>` : ''}
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
        const stepUp = `
            <div><label for="f-stepup" class="field-label">${totpEnabled ? 'Code from your authenticator app' : 'Emailed security code'}</label>
            <input id="f-stepup" inputmode="text" maxlength="9" spellcheck="false" autocomplete="one-time-code" class="field font-mono tracking-widest max-w-[12rem] uppercase" placeholder="${totpEnabled ? '000000' : '00000000'}">
            ${totpEnabled ? '<p class="text-xs text-muted mt-1">Or one of your recovery codes (XXXX-XXXX).</p>' : '<button type="button" class="btn btn-outline btn-sm mt-2" data-click="sendStepUpCode">Email me a 5-minute security code</button>'}</div>`;
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
                <button type="button" class="btn btn-outline btn-sm" data-click="toggleDocLockJob"><i class="fa-solid ${o.doc_lock ? 'fa-lock-open' : 'fa-lock'}"></i> ${o.doc_lock ? 'Turn off document lock' : 'Lock documents on tracking page'}</button>
                <button type="button" class="btn btn-outline btn-sm" data-click="rotateLink"><i class="fa-solid fa-link-slash"></i> Replace client's tracking link</button>
            </div>
            <p class="text-xs text-muted">Document lock: the client's page shows the status but hides the full address and documents until they enter a code we email them. Replacing the link stops the old one immediately and emails the client the new one.</p>
            <div class="pt-2">
                <p class="text-xs font-semibold ${o.legal_hold ? 'text-primary' : 'text-muted'}"><i class="fa-solid fa-scale-balanced mr-1"></i> Legal hold: ${o.legal_hold ? 'ON (the service record, proofs and timeline are frozen)' : 'off'}</p>
                ${o.legal_hold ? `
                    <p class="text-xs text-muted mt-1">Turned on automatically when the job was served. Unlock only if a real mistake must be fixed; it's logged and emailed to you.</p>
                    ${stepUp}
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
    if (actionTab === 'attempt') return `
        <div><p class="field-label">Quick outcome</p><div class="flex flex-wrap gap-2">${ATTEMPT_PRESETS.map(([label, value]) => `<button type="button" class="btn btn-outline btn-sm" data-attempt-preset="${esc(value)}">${esc(label)}</button>`).join('')}</div></div>
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
        <div><label for="f-template" class="field-label">Saved note</label><select id="f-template" class="field"><option value="">Choose a template…</option>${MESSAGE_TEMPLATES.note.map((value, i) => `<option value="${i}">${esc(value)}</option>`).join('')}</select></div>
        <div><label for="f-note" class="field-label">Note</label><textarea id="f-note" class="field h-24 resize-none"></textarea></div>
        ${check('f-visible', 'Client can see this note (otherwise only you can)', false)}
        ${submitBtn('Save Note')}`;
    if (actionTab === 'action') return `
        <p class="text-sm text-muted">The client gets an email and a form on their tracking page to answer, fix the address, or upload a file.</p>
        <div><label for="f-template" class="field-label">Saved reply request</label><select id="f-template" class="field"><option value="">Choose a template…</option>${MESSAGE_TEMPLATES.action.map((value, i) => `<option value="${i}">${esc(value)}</option>`).join('')}</select></div>
        <div><label for="f-note" class="field-label">What do you need?</label><textarea id="f-note" class="field h-24 resize-none" placeholder="e.g. The apartment number is missing. Which unit does the subject live in?"></textarea></div>
        ${submitBtn('Send to Client')}`;
    if (actionTab === 'payment') {
        if (o.paid_at) return `<p class="result-box result-ok text-sm">Paid ${NPS.money(o.paid_amount_cents ?? o.amount_due_cents)} on ${esc(NPS.fmtDate(o.paid_at))}.</p>`;
        const printing = current.printing;
        return `
        <div class="result-box result-info text-sm"><strong>PDF printing:</strong> ${printing.complete ? `${printing.pages} page${printing.pages === 1 ? '' : 's'} across ${printing.pdfs} document PDF${printing.pdfs === 1 ? '' : 's'} · ${NPS.money(printing.feeCents)} estimated fee (first 100 pages free; $0.15 per additional page)` : `${printing.countedPdfs} of ${printing.pdfs} document PDFs counted. Review older or unreadable PDFs before quoting a printing fee.`}</div>
        ${o.payment_url && o.status === 'awaiting_payment' ? `<p class="result-box result-warn text-sm">A payment link for ${NPS.money(o.amount_due_cents)} was already sent. Sending a new one replaces it.</p>` : ''}
        <div class="grid sm:grid-cols-3 gap-4">
            <div><label for="f-amount" class="field-label">Amount ($)</label><input id="f-amount" type="number" min="1" step="0.01" class="field" value="${((o.amount_due_cents ?? o.estimated_total_cents) / 100).toFixed(2)}"></div>
            <div class="sm:col-span-2"><label for="f-desc" class="field-label">What it covers (shown to client)</label><input id="f-desc" class="field" value="${esc(o.tier_name + (o.addon_names.length ? ' + ' + o.addon_names.join(', ') : ''))}"></div>
        </div>
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
            const when = v('f-when') ? new Date(v('f-when')).toISOString() : '';
            current = await api('update', { id, kind: 'attempt', outcome: v('f-outcome'), when, note: v('f-note'), clientVisible: on('f-visible') });
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
        const messages = { attempt: 'Attempt logged.', status: 'Status updated.', note: 'Note saved.', action: 'Request for information sent to the client.', payment: 'Payment link sent to the client.', proof: 'Proof of service uploaded.' };
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
function printRecord() {
    const o = current.order;
    NPS.printChainOfCustody({
        code: o.code, statusLabel: statuses[o.status]?.label || o.status, legalHold: o.legal_hold,
        recipient: o.recipient_name, docType: o.doc_type,
        address: [o.address, o.unit].filter(Boolean).join(', ') + `, ${o.city} ${o.zip}`,
        seal: o.integrity_seal, files: current.files, events: current.events,
    });
}
function printReceipt() { if (current?.order?.receipt) NPS.printReceipt(current.order.receipt); }
async function exportJob() {
    const data = await api('export', { id: current.order.id });
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const a = Object.assign(document.createElement('a'), { href: url, download: `${current.order.code}-data.json` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function downloadDisputePack(_arg, button) {
    if (!current) return;
    button.disabled = true;
    const code = current.order.code;
    try {
        const res = await fetch('/api/admin', { method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'dispute-pack', id: current.order.id }) });
        if (!res.ok) {
            const error = await res.json().catch(() => ({}));
            throw new Error(error.error || 'Could not prepare the evidence pack.');
        }
        const url = URL.createObjectURL(await res.blob());
        const link = Object.assign(document.createElement('a'), { href: url, download: `${code}-dispute-evidence.zip` });
        document.body.append(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        $('save-feedback').textContent = 'Dispute evidence pack downloaded.';
        $('save-feedback').className = 'desk-feedback result-box result-ok';
    } catch (err) {
        $('save-feedback').textContent = err.message;
        $('save-feedback').className = 'desk-feedback result-box result-err';
    } finally { button.disabled = false; }
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
let recoveryRemaining = 0;
let passkeyCount = null;
let securitySetupDismissed = false;
try { securitySetupDismissed = sessionStorage.getItem('nps-security-setup-dismissed') === '1'; } catch { /* storage disabled */ }
function updateSecuritySetup() {
    const needsSetup = !totpEnabled || passkeyCount === 0;
    $('security-setup-card').classList.toggle('hidden', !needsSetup || securitySetupDismissed);
    $('security-setup-steps').innerHTML = [
        `${totpEnabled ? '✓' : '1.'} Turn on your authenticator app`,
        `${recoveryRemaining > 3 ? '✓' : '2.'} Save a fresh set of recovery codes`,
        `${passkeyCount > 0 ? '✓' : '3.'} Add Face ID, Touch ID, or a device passkey`,
    ].map(step => `<li>${step}</li>`).join('');
    $('recovery-warning').classList.toggle('hidden', recoveryRemaining > 3);
    $('recovery-warning-text').textContent = `${recoveryRemaining} unused recovery codes remain. Generate a new set and save it somewhere private.`;
}
function dismissSecuritySetup() {
    securitySetupDismissed = true;
    try { sessionStorage.setItem('nps-security-setup-dismissed', '1'); } catch { /* storage disabled */ }
    updateSecuritySetup();
}
function openRecoverySetup() {
    openSecurityModal();
    $('totp-current-input').focus();
}
window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredInstallPrompt = e;
    $('pwa-install-btn')?.classList.remove('hidden');
});
function updateRecoveryBadge(n) {
    const count = Number(n) || 0;
    recoveryRemaining = count;
    const badge = $('recovery-remaining-badge');
    if (!badge) return;
    badge.textContent = `${count} unused`;
    badge.className = `status-pill ${count > 0 ? 'status-done' : 'status-muted'}`;
    updateSecuritySetup();
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
    passkeyCount = list.length;
    updateSecuritySetup();
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
async function sendStepUpCode() {
    try {
        await api('send-step-up-code');
        if ($('security-modal').classList.contains('hidden')) alert('A security code was emailed to you. It expires in 5 minutes.');
        else securityMessage('A security code was emailed to you. It expires in 5 minutes.');
    } catch (err) {
        if ($('security-modal').classList.contains('hidden')) alert(err.message);
        else securityMessage(err.message, 'err');
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
    updateSecuritySetup();
    $('totp-status-badge').textContent = totpEnabled ? 'On' : 'Off';
    $('totp-status-badge').className = `status-pill ${totpEnabled ? 'status-done' : 'status-muted'}`;
    $('totp-setup-label').textContent = totpEnabled ? 'Move to a New Phone' : 'Turn On Two-Step Sign-In';
    $('totp-disable-btn').classList.toggle('hidden', !totpEnabled);
    $('totp-current-wrap').classList.remove('hidden');
    $('totp-current-wrap').querySelector('label').textContent = totpEnabled ? 'Current code from your authenticator app' : 'Emailed security code';
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
        await loadAdminPasskeys();
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

async function copyAddress() {
    if (!current) return;
    const o = current.order;
    const address = `${o.address}${o.unit ? ', ' + o.unit : ''}, ${o.city} ${o.zip}`;
    const feedback = $('save-feedback');
    try {
        await navigator.clipboard.writeText(address);
        feedback.textContent = 'Full address copied.';
        feedback.className = 'desk-feedback result-box result-ok';
    } catch {
        feedback.textContent = 'Could not copy the address. Select the address link and copy it manually.';
        feedback.className = 'desk-feedback result-box result-err';
    }
}

// Buttons say what they do with data-click (and data-arg) instead of inline onclick, so the page's Content Security
// Policy can refuse inline scripts. Only the functions listed here can be triggered this way.
const CLICK_ACTIONS = {
    backToList, closeSecurityModal, refreshJobs, exportJob, downloadDisputePack, showEmailStep, rotateLink, toggleDocLockJob, printRecord, printReceipt, copyAddress,
    discardDraft, logout, openSecurityModal, logoutAllDevices, copyRecoveryCodes, generateRecoveryCodes, sendStepUpCode,
    dismissSecuritySetup, openRecoverySetup,
    confirmTotpEnable, disableTotp, startTotpSetup, installPwaApp, passkeyLogin, addAdminPasskey,
    setLegalHold: (arg) => setLegalHold(arg === 'true'),
    setActionTab: (arg) => setActionTab(arg),
    setFilter: (arg) => setFilter(arg),
    openJob: (arg) => openJob(arg),
    downloadFile: (arg, el) => downloadFile(arg, el),
};
document.addEventListener('click', (e) => {
    const preset = e.target.closest('[data-attempt-preset]');
    if (preset) {
        $('f-outcome').value = preset.dataset.attemptPreset;
        $('f-when').value = new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16);
        formDirty = true;
        $('draft-status').classList.remove('hidden');
        return;
    }
    const el = e.target.closest('[data-click]');
    if (el && Object.hasOwn(CLICK_ACTIONS, el.dataset.click)) CLICK_ACTIONS[el.dataset.click](el.dataset.arg, el);
});
document.addEventListener('change', (e) => {
    if (e.target.id !== 'f-template' || !['action', 'note'].includes(actionTab) || !e.target.value) return;
    const message = MESSAGE_TEMPLATES[actionTab][Number(e.target.value)];
    if (!message || !$('f-note')) return;
    $('f-note').value = message;
    $('f-note').dispatchEvent(new Event('input', { bubbles: true }));
    $('f-note').focus();
});
