// The private code travels after "#", which browsers never send to a server, so it can't end up in a log.
// Links with ?t= (older emails, and Stripe's return after paying) still work and are moved behind "#" right away.
const params = new URLSearchParams(location.search);
const token = new URLSearchParams(location.hash.slice(1)).get('t') || params.get('t') || '';
const paidSession = params.get('paid');
if (params.has('t') || params.has('paid')) history.replaceState(null, '', `${location.pathname}#t=${encodeURIComponent(token)}`);
// After unlocking a locked request, the server's signed 12-hour token rides along on every call from this tab.
const unlockKey = `nps-unlock-${token.slice(0, 12)}`;
let unlockToken = (() => { try { return sessionStorage.getItem(unlockKey) || ''; } catch { return ''; } })();
const trackCall = (body, opts) => NPS.post('/api/track', { t: token, unlockToken, ...body }, opts);
const view = () => trackCall({ action: 'view' }, { notify: false });
// Opening another request's link in this tab only changes the part after "#", which doesn't reload the page by itself.
addEventListener('hashchange', () => {
    if (new URLSearchParams(location.hash.slice(1)).get('t') !== token) location.reload();
});
const $ = id => document.getElementById(id);
const { esc } = NPS;

const PILL = {
    received: 'status-live', action_required: 'status-alert', awaiting_payment: 'status-live', paid: 'status-done',
    accepted: 'status-live', attempting: 'status-live', served: 'status-done', closed: 'status-done', cancelled: 'status-muted',
};
const STAGES = ['Received', 'Payment', 'Attempting service', 'Served'];
const STAGE_OF = { received: 0, action_required: 0, awaiting_payment: 1, paid: 2, accepted: 2, attempting: 2, served: 3, closed: 3 };
const DOT = { action: 'is-alert', payment: 'is-gold', proof: 'is-done', status: '' };

let order = null;
let actionSending = false;
let lastView = null;   // the latest view, for the receipt and reply box
let refreshing = false;

function render(o) {
    order = o;
    $('lock-panel').classList.toggle('hidden', !(o.docLock && !o.unlocked));
    $('loading').classList.add('hidden');
    $('not-found').classList.add('hidden');
    $('order').classList.remove('hidden');
    $('tracking-error').classList.add('hidden');
    $('tracking-sync').textContent = `Updated ${new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`;
    document.title = `${o.code} · ${o.statusLabel} | Nick's Process Services`;

    $('o-code').textContent = o.code;
    $('o-status-label').textContent = o.statusLabel;
    $('o-status-text').textContent = o.statusText;
    $('o-status-pill').textContent = o.statusLabel;
    $('o-status-pill').className = `status-pill mt-1 ${PILL[o.status] || 'status-muted'}`;
    $('o-recipient').textContent = o.recipient;
    $('o-doc').textContent = o.docType;
    $('o-address').textContent = o.address;
    $('o-service').textContent = o.tier + (o.addons.length ? ' + ' + o.addons.join(', ') : '');
    $('o-price-label').textContent = o.paidAt ? 'Paid' : o.amountDue ? 'Amount due' : 'Estimate';
    $('o-price').textContent = o.amountDue || o.estimate;
    $('o-created').textContent = NPS.fmtDate(o.createdAt);

    const stage = STAGE_OF[o.status];
    $('o-progress').classList.toggle('hidden', stage === undefined);
    $('o-progress').innerHTML = STAGES.map((name, i) => {
        const cls = i < stage || o.status === 'served' || o.status === 'closed' ? 'is-done' : i === stage ? 'is-current' : '';
        return `<li class="wizard-step ${cls}" ${i === stage ? 'aria-current="step"' : ''}><span class="wizard-num" aria-hidden="true">${i < stage || cls === 'is-done' ? '<i class="fa-solid fa-check text-[0.65rem]"></i>' : i + 1}</span><span>${name}</span></li>`;
    }).join('');

    const safePayUrl = typeof o.payUrl === 'string' && (/^https:\/\/checkout\.stripe\.com\//i.test(o.payUrl) || /^\/__mock-pay\b/.test(o.payUrl)) ? o.payUrl : null;
    $('pay-panel').classList.toggle('hidden', !safePayUrl);
    if (safePayUrl) {
        $('pay-amount').textContent = o.amountDue;
        $('pay-btn').href = safePayUrl;
    }

    // The reply box: answering Nick's question, or (on any open, unlocked request) sending him a note or a file.
    const answering = !!o.actionNote;
    $('action-panel').classList.toggle('hidden', !answering && !o.canReply);
    $('action-note').classList.toggle('hidden', !answering);
    if (answering) $('action-note').textContent = o.actionNote;
    $('action-address').classList.toggle('hidden', !answering);
    $('action-access-wrap').classList.toggle('hidden', !answering);
    $('action-kicker').innerHTML = answering ? '<i class="fa-solid fa-triangle-exclamation mr-1"></i> Action required' : '<i class="fa-regular fa-comment mr-1"></i> Message Nick';
    $('action-kicker').className = `font-serif italic mb-1 ${answering ? 'text-[#7a1f1c]' : 'text-bronze'}`;
    $('action-title').textContent = answering ? 'Nick needs a little more from you' : 'Send Nick a note or a file';
    $('a-reply').placeholder = answering ? "Answer Nick's question here" : 'For example: they usually get home after 6 PM';
    $('action-panel').classList.toggle('border-[#9c2a26]/40', answering);

    $('receipt-panel').classList.toggle('hidden', !o.receipt);
    if (o.receipt) {
        $('receipt-amount').textContent = o.receipt.amountPaid;
        $('receipt-date').textContent = NPS.fmtDate(o.receipt.paidAt);
    }
    lastView = o;

    const proof = o.files.filter(f => f.kind === 'proof');
    const docs = o.files.filter(f => f.kind !== 'proof');
    const chip = f => `<span class="inline-flex flex-wrap items-center gap-2"><button type="button" class="file-chip" data-file="${esc(f.id)}" ${f.sha256 ? `title="SHA-256 fingerprint: ${esc(f.sha256)}"` : ''}><i class="fa-solid ${f.kind === 'proof' ? 'fa-file-signature' : 'fa-file-lines'} text-bronze"></i><span>${esc(f.name)}</span><span class="text-muted font-normal">${NPS.fmtSize(f.size)}</span>${f.sha256 ? `<span class="text-[11px] font-mono text-primary bg-primaryLight/60 px-1.5 py-0.5 rounded-sm"><i class="fa-solid fa-shield-halved mr-0.5" aria-hidden="true"></i>SHA-256 ${esc(f.sha256.slice(0, 8))}…</span>` : ''}</button>${f.sha256 ? `<button type="button" class="text-xs text-primary font-semibold underline underline-offset-2" data-verify="${esc(f.id)}">Verify file</button>` : ''}</span>`;
    $('proof-files').innerHTML = proof.map(chip).join('');
    $('doc-files').innerHTML = docs.map(chip).join('');
    $('proof-block').classList.toggle('hidden', !proof.length);
    $('docs-block').classList.toggle('hidden', !docs.length);
    $('files-panel').classList.toggle('hidden', !o.files.length);

    $('timeline').innerHTML = o.events.slice().reverse().map(ev => `
        <li>
            <span class="timeline-dot ${DOT[ev.kind] ?? ''}"></span>
            <p class="text-sm font-semibold text-ink">${esc(ev.title)}</p>
            ${ev.detail ? `<p class="text-sm text-muted mt-0.5 whitespace-pre-line">${esc(ev.detail)}</p>` : ''}
            <p class="text-[11px] text-muted mt-1">${esc(NPS.fmtDate(ev.created_at))}</p>
        </li>`).join('');
}

function showNotFound(msg, retry = false, title = '') {
    $('loading').classList.add('hidden');
    $('order').classList.add('hidden');
    $('not-found').classList.remove('hidden');
    $('retry-tracking').classList.toggle('hidden', !retry);
    $('recover-tracking').classList.toggle('hidden', retry);
    $('not-found-title').textContent = title || (retry ? 'We couldn’t load your request right now' : "We couldn't open this tracking link");
    $('not-found-msg').textContent = msg || 'The link may be incomplete. Use the full link from your confirmation email, or have it sent to you again.';
}

async function load() {
    $('not-found').classList.add('hidden');
    $('loading').classList.remove('hidden');
    if (!token && paidSession) {
        // Back from paying, but the private code didn't come along. The payment is still recorded (Stripe tells the server directly).
        return showNotFound('Your payment is being recorded. Open your request from the link in your email to follow the next steps.', false, 'Thank you for your payment');
    }
    if (!token) return showNotFound();
    try {
        if (paidSession) {
            // Back from Stripe: confirm the payment (the address bar was already cleaned up above).
            const o = await NPS.post('/api/track', { t: token, action: 'confirm-payment', session: paidSession });
            render(o);
            const banner = $('paid-banner');
            banner.innerHTML = o.paidAt
                ? '<i class="fa-solid fa-circle-check mr-1"></i> <strong>Thank you, your payment was received.</strong> A receipt is on its way to your email.'
                : '<i class="fa-solid fa-clock mr-1"></i> Your payment is processing. This page will update once it clears.';
            banner.classList.remove('hidden');
            return;
        }
        render(await view());
    } catch (err) {
        showNotFound(err.status === 404 ? null : `${err.message} Your tracking link has been kept. Please try again.`, err.status !== 404);
    }
}

// Verify a file: download it, compute its SHA-256 in this browser, and compare with the fingerprint taken when it was stored.
document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-verify]');
    if (!btn) return;
    btn.disabled = true;
    btn.parentElement.querySelectorAll('.verify-result').forEach(el => el.remove());
    const show = (ok, msg) => btn.insertAdjacentHTML('afterend', `<span class="verify-result status-pill ${ok ? 'status-done' : 'status-alert'}">${esc(msg)}</span>`);
    try {
        const { url, sha256 } = await trackCall({ action: 'download', fileId: btn.dataset.verify });
        const r = await NPS.verifyFileSha256(url, sha256);
        show(r.ok, r.ok ? 'Matches the stored fingerprint' : 'Does not match the stored fingerprint');
    } catch (err) { show(false, err.message); }
    finally { btn.disabled = false; }
});
$('renew-pay').addEventListener('click', async () => {
    const btn = $('renew-pay'), msg = $('renew-pay-msg');
    btn.disabled = true;
    try {
        const o = await trackCall({ action: 'renew-payment' });
        render(o);
        msg.className = 'result-box result-ok text-sm mt-3';
        msg.textContent = o.paidAt ? 'Your payment was already received.' : 'Here is a new payment link. It works for 24 hours.';
    } catch (err) {
        msg.className = 'result-box result-warn text-sm mt-3';
        msg.textContent = err.message;
    } finally { btn.disabled = false; }
});
$('receipt-btn').addEventListener('click', () => { if (lastView?.receipt) NPS.printReceipt(lastView.receipt); });

document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-file]');
    if (!btn) return;
    btn.disabled = true;
    btn.parentElement.querySelectorAll('.file-error').forEach(el => el.remove());
    try {
        const { url } = await trackCall({ action: 'download', fileId: btn.dataset.file }, { notify: false });
        location.href = url;
    } catch (err) {
        btn.insertAdjacentHTML('afterend', `<span class="file-error text-xs text-[#7a1f1c]" role="alert">${esc(err.message)}</span>`);
    } finally {
        btn.disabled = false;
    }
});

$('lock-send').addEventListener('click', async () => {
    $('lock-error').classList.add('hidden');
    $('lock-send').disabled = true;
    try {
        const r = await trackCall({ action: 'send-unlock-code' }, { notify: false });
        $('lock-sent').textContent = `We emailed a code to ${r.maskedEmail}. It works for 10 minutes.`;
        $('lock-sent').classList.remove('hidden');
        $('lock-code').focus();
    } catch (err) {
        $('lock-error').textContent = err.message;
        $('lock-error').classList.remove('hidden');
    } finally { $('lock-send').disabled = false; }
});
$('lock-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('lock-error').classList.add('hidden');
    try {
        const r = await trackCall({ action: 'verify-unlock-code', code: $('lock-code').value.trim() }, { notify: false });
        unlockToken = r.unlockToken;
        try { sessionStorage.setItem(unlockKey, unlockToken); } catch { /* private mode: stays unlocked until reload */ }
        $('lock-code').value = '';
        render(r);
    } catch (err) {
        $('lock-error').textContent = err.message;
        $('lock-error').classList.remove('hidden');
    }
});

$('action-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (actionSending) return;
    const errBox = $('action-error');
    const btn = e.target.querySelector('button[type="submit"]');
    const files = Array.from($('a-files').files);
    const problem = NPS.checkFiles(files);
    errBox.classList.toggle('hidden', !problem);
    errBox.textContent = problem;
    if (problem) return;
    actionSending = true;
    const wasAnswering = !!lastView?.actionNote;
    btn.disabled = true;
    btn.textContent = 'Sending your reply…';
    try {
        const r = await trackCall({
            action: 'respond',
            address: $('a-address').value, unit: $('a-unit').value, city: $('a-city').value, zip: $('a-zip').value.trim(),
            accessNotes: $('a-access').value, reply: $('a-reply').value, files: files.map(NPS.fileMeta),
        });
        const up = r.uploads?.length ? await NPS.uploadAll(r.uploads, files) : { ok: [], failed: [] };
        const done = await trackCall({ action: 'respond-finish', fileIds: up.ok });
        render(done);
        e.target.reset();
        actionDirty = false;
        const feedback = $('reply-feedback');
        const notChecked = (done.filesStillChecking || 0) + (done.filesMissing || 0);
        feedback.className = `result-box ${up.failed.length || notChecked ? 'result-warn' : 'result-ok'} text-sm`;
        feedback.textContent = !wasAnswering && !up.failed.length && !notChecked ? 'Your note was sent to Nick.' : up.failed.length
            ? `Your reply was sent, but ${up.failed.join(', ')} didn't upload. Please call Nick at (209) 922-6817.`
            : done.filesMissing
            ? `Your reply was sent, but ${done.filesMissing} file(s) didn't arrive. Please send them again or call Nick at (209) 922-6817.`
            : done.filesStillChecking
            ? `Your reply was sent. ${done.filesStillChecking} file(s) are still being checked and will appear on your request once they are; Nick has been told.`
            : 'Your reply was sent to Nick. Your request is ready for his review; there’s nothing else you need to do right now.';
        window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err) {
        errBox.textContent = err.message;
        errBox.classList.remove('hidden');
    } finally {
        actionSending = false;
        btn.disabled = false;
        btn.innerHTML = 'Send to Nick <i class="fa-solid fa-paper-plane" aria-hidden="true"></i>';
    }
});

// Keep the page current while it is open: right away when the site changes in another tab, otherwise every 20 seconds.
// Never while the client is typing an answer, so their reply isn't wiped.
let actionDirty = false;
$('action-form').addEventListener('input', () => { actionDirty = true; });
async function refresh(manual = false) {
    manual = manual === true; // Event listeners pass an Event, not a manual refresh request.
    if (!order || refreshing || actionSending || document.hidden) return;
    if (actionDirty) {
        if (manual) $('tracking-sync').textContent = 'Finish sending your reply first. Your draft is kept.';
        return;
    }
    refreshing = true;
    $('refresh-tracking').disabled = true;
    if (manual) $('tracking-sync').textContent = 'Checking for updates…';
    try {
        const before = order.status;
        const result = await view();
        if (actionDirty || actionSending) {
            if (manual) $('tracking-sync').textContent = 'Update paused while you reply. Your draft is kept.';
            return;
        }
        render(result);
        if (order.status !== before) $('paid-banner').classList.add('hidden');   // "payment received" is old news once Nick moves on
    } catch (err) {
        $('tracking-sync').textContent = 'Could not check for updates';
        $('tracking-error').textContent = `${err.message} Your last update is still shown. Use Check for updates to retry.`;
        $('tracking-error').classList.remove('hidden');
    } finally { refreshing = false; $('refresh-tracking').disabled = false; }
}
NPS.onChange(refresh);
setInterval(refresh, 20000);
document.addEventListener('visibilitychange', refresh);

load();

// Buttons use data-click instead of inline onclick, so the page's Content Security Policy can refuse inline scripts.
const CLICK_ACTIONS = { refresh: () => refresh(true), load: () => load() };
document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-click]');
    if (el && Object.hasOwn(CLICK_ACTIONS, el.dataset.click)) CLICK_ACTIONS[el.dataset.click]();
});
