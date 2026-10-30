// Field helpers shared by Nick's dashboard, the tracking page and the client portal: job priority, attempt time
// windows, the multi-stop route, saved messages, the printing fee, and the printable receipt / court-prep sheets.
// Pure functions (no page access), so scripts/check-field-tools.mjs can test them in Node.
const NPSField = (() => {
    const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const money = (cents) => '$' + ((Number(cents) || 0) / 100).toFixed(2);
    const DAY = 864e5;
    const OPEN = ['received', 'action_required', 'awaiting_payment', 'paid', 'accepted', 'attempting'];
    const isOpen = (o) => OPEN.includes(o.status);

    // Whole calendar days from today (local time) to a YYYY-MM-DD deadline; negative = overdue.
    function daysUntil(deadline, now = new Date()) {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(String(deadline || ''))) return null;
        const [y, m, d] = deadline.split('-').map(Number);
        return Math.round((Date.UTC(y, m - 1, d) - Date.UTC(now.getFullYear(), now.getMonth(), now.getDate())) / DAY);
    }
    // 'overdue' (any tier), 'due48' (rush or expedited due within 2 days), 'today' (any tier due today), or null.
    function urgency(o, now = new Date()) {
        if (!isOpen(o)) return null;
        const days = daysUntil(o.deadline, now);
        if (days == null) return null;
        if (days < 0) return 'overdue';
        if (days === 0) return 'today';
        if (days <= 2 && ['sameday', 'expedited'].includes(o.tier)) return 'due48';
        return null;
    }
    const URGENCY_RANK = { overdue: 0, today: 1, due48: 2 };
    // Priority order: overdue, due today, rush/expedited due within 48 hours, then the rest by nearest deadline.
    function prioritySort(list, now = new Date()) {
        return list.slice().sort((a, b) => {
            const ra = URGENCY_RANK[urgency(a, now)] ?? 9, rb = URGENCY_RANK[urgency(b, now)] ?? 9;
            if (ra !== rb) return ra - rb;
            const da = daysUntil(a.deadline, now) ?? 1e6, db = daysUntil(b.deadline, now) ?? 1e6;
            return da - db || String(a.created_at).localeCompare(String(b.created_at));
        });
    }
    const daysSince = (iso, now = Date.now()) => (iso ? Math.max(0, Math.floor((now - new Date(iso).getTime()) / DAY)) : null);

    // Attempt time windows for Standard and Expedited serves: morning (before 12pm), afternoon/evening (12-7pm), night
    // (after 7pm). The hour comes from the time Nick typed for the attempt ("Oct 30, 7:05 PM"), else when it was logged.
    const WINDOWS = [['morning', 'Morning <12pm'], ['evening', 'Afternoon/Evening 12–7pm'], ['night', 'Night >7pm']];
    function attemptHour(ev) {
        const m = /(\d{1,2}):(\d{2})\s*(AM|PM)/i.exec(String(ev.detail || ''));
        if (m) return (Number(m[1]) % 12) + (m[3].toUpperCase() === 'PM' ? 12 : 0);
        const d = new Date(ev.created_at);
        return Number.isNaN(d.getTime()) ? null : d.getHours();
    }
    function windowFor(hour) {
        if (hour == null) return null;
        return hour < 12 ? 'morning' : hour < 19 ? 'evening' : 'night';
    }
    function attemptWindows(events) {
        const done = new Set();
        for (const ev of events || []) if (ev.kind === 'attempt') { const w = windowFor(attemptHour(ev)); if (w) done.add(w); }
        return WINDOWS.map(([key, label]) => ({ key, label, done: done.has(key) }));
    }
    const needsWindows = (tier) => tier === 'standard' || tier === 'expedited';

    // Substituted service (CCP § 415.20): left with a co-resident, so a copy must also be mailed. True until a
    // "Follow-up copy mailed" entry is logged after the latest substituted attempt.
    function needsSubServiceMailing(events) {
        let lastSub = null, lastMail = null;
        for (const ev of events || []) {
            if (ev.kind === 'attempt' && /co-resident|substituted/i.test(ev.title)) lastSub = ev.created_at;
            if (/Follow-up copy mailed/i.test(`${ev.title} ${ev.detail || ''}`)) lastMail = ev.created_at;
        }
        return !!lastSub && !(lastMail && lastMail >= lastSub);
    }

    // Google Maps directions for up to 9 stops, starting from where the phone is (no origin = current location).
    function routeUrl(addresses) {
        const stops = (addresses || []).map(a => String(a || '').trim()).filter(Boolean).slice(0, 9);
        if (!stops.length) return null;
        const u = new URL('https://www.google.com/maps/dir/');
        u.searchParams.set('api', '1');
        u.searchParams.set('destination', stops[stops.length - 1]);
        if (stops.length > 1) u.searchParams.set('waypoints', stops.slice(0, -1).join('|'));
        u.searchParams.set('travelmode', 'driving');
        return u.toString();
    }
    const fullAddress = (o) => [o.address, o.unit, o.city, o.zip].filter(Boolean).join(', ');

    const ATTEMPT_PRESETS = ['No answer', 'Served', 'Refused', 'Left with co-resident', 'Wrong / bad address'];
    const TEMPLATES = [
        'Please confirm the apartment/unit number or gate code.',
        'No answer on recent attempts — do you have a best time window or work address?',
        'Please upload a clear photo or physical description of the subject.',
        'Service completed — preparing your Proof of Service now.',
    ];
    const printingFeeCents = (pages) => Math.max(0, (Number(pages) || 0) - 100) * 15;   // first 100 free, then 15¢

    // Plain-English "what happens next" for the client's tracking page.
    function nextStep(o) {
        // Same promises as the public page: Expedited first attempt within 48 hours, Same-Day Rush within 24 hours of
        // receiving the documents. Standard has no first-attempt promise (attempts are spread over 10 days).
        const first = { expedited: ' within 48 hours of receiving your documents', sameday: ' within 24 hours of receiving your documents' }[o.tier] || '';
        return {
            received: 'We have your request. Nick is reviewing it and will send a payment link or a question if anything is missing.',
            action_required: 'Nick needs something from you before he can continue. Please answer below.',
            awaiting_payment: 'Waiting for payment before service begins. Use the Pay button below.',
            paid: `Payment received. Nick will make the first attempt${first}.`,
            accepted: `Nick has accepted the job and will make the first attempt${first}.`,
            attempting: 'Nick is attempting service. Each attempt appears in the timeline below.',
            served: 'Service is complete. Your Proof of Service is (or will shortly be) available below.',
            closed: 'This request is closed.',
            cancelled: 'This request was cancelled.',
        }[o.status] || '';
    }

    const page = (title, body) => `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)}</title>
        <style>body{font-family:Georgia,serif;color:#10221a;margin:32px;line-height:1.5}h1,h2{color:#0d422e;margin-bottom:6px}h2{font-size:17px;margin-top:24px}
        table{width:100%;border-collapse:collapse;margin-top:8px;font-family:sans-serif;font-size:12px}th{background:#e6eee9;text-align:left;padding:8px;border:1px solid #cdd7d1}
        td{padding:8px;border:1px solid #cdd7d1;vertical-align:top}.mono{font-family:monospace;font-size:11px;word-break:break-all}.muted{color:#566860;font-size:12px}
        .box{margin:14px 0;padding:12px;border:1px solid #cdd7d1;font-family:sans-serif;font-size:13px}.right{text-align:right}
        @media print{.no-print{display:none}}</style></head><body>
        <div class="no-print right"><button id="print-doc" type="button" style="padding:8px 16px;background:#0d422e;color:#fff;border:0;cursor:pointer;font-weight:600">Print / Save as PDF</button></div>
        ${body}</body></html>`;
    const when = (iso) => (iso ? new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }) : '');

    // Itemized receipt. r: { code, paidAt, clientName, clientFirm, caseNumber, court, tierName, tierCents, addons:[{name,cents}],
    // printingPages, printingFeeCents, totalCents, stripeRef }
    function receiptHtml(r) {
        const rows = [[r.tierName || 'Service', r.tierCents], ...(r.addons || []).map(a => [a.name, a.cents])];
        if (r.printingFeeCents > 0) rows.push([`Printing: ${r.printingPages} pages (first 100 free, then $0.15/page)`, r.printingFeeCents]);
        const itemsCents = rows.reduce((n, [, c]) => n + (Number(c) || 0), 0);
        const adjust = (Number(r.totalCents) || 0) - itemsCents;
        if (adjust !== 0 && rows.every(([, c]) => c != null)) rows.push([adjust > 0 ? 'Other charges as quoted' : 'Adjustment / discount', adjust]);
        return page(`Receipt ${r.code}`, `<h1>Receipt</h1><p class="muted">Nick's Process Services · (209) 922-6817</p>
            <div class="box"><div><strong>Request:</strong> ${esc(r.code)}</div><div><strong>Date paid:</strong> ${esc(when(r.paidAt))}</div>
            <div><strong>Client:</strong> ${esc(r.clientName)}${r.clientFirm ? `, ${esc(r.clientFirm)}` : ''}</div>
            ${r.caseNumber ? `<div><strong>Case number:</strong> ${esc(r.caseNumber)}</div>` : ''}${r.court ? `<div><strong>Court:</strong> ${esc(r.court)}</div>` : ''}</div>
            <table><thead><tr><th>Item</th><th class="right">Amount</th></tr></thead><tbody>
            ${rows.map(([n, c]) => `<tr><td>${esc(n)}</td><td class="right">${c == null ? '' : esc(money(c))}</td></tr>`).join('')}
            <tr><td><strong>Total paid</strong></td><td class="right"><strong>${esc(money(r.totalCents))}</strong></td></tr></tbody></table>
            <p class="muted">Paid by card through Stripe${r.stripeRef ? ` (reference ${esc(r.stripeRef)})` : ''}. Keep this receipt for your records.</p>`);
    }

    // Attempt log for a Declaration of Due Diligence: every attempt, oldest first.
    function diligenceHtml(o, events) {
        const attempts = (events || []).filter(e => e.kind === 'attempt');
        const rows = attempts.map(e => {
            const d = new Date(e.created_at);
            const w = WINDOWS.find(([k]) => k === windowFor(attemptHour(e)))?.[1] || '';
            const outcome = String(e.title || '').replace(/^Attempt:\s*/, '');
            return `<tr><td>${esc(d.toLocaleDateString('en-US'))}</td><td>${esc(d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }))}</td>
                <td>${esc(w)}</td><td>${esc(fullAddress(o))}</td><td>${esc(outcome)}</td><td style="white-space:pre-line">${esc(e.detail || '')}</td></tr>`;
        }).join('') || '<tr><td colspan="6" class="muted">No attempts logged yet.</td></tr>';
        return page(`Diligence log ${o.code}`, `<h1>Attempt log: ${esc(o.code)}</h1>
            <p class="muted">For preparing a Declaration of Due Diligence. Times are when each attempt was logged, unless Nick entered the attempt time.</p>
            <div class="box"><div><strong>Person to serve:</strong> ${esc(o.recipient_name)}</div><div><strong>Case number:</strong> ${esc(o.case_number || '')}</div>
            <div><strong>Court:</strong> ${esc(o.court || '')}</div><div><strong>Address:</strong> ${esc(fullAddress(o))}</div><div><strong>Attempts:</strong> ${attempts.length}</div></div>
            <table><thead><tr><th>Date</th><th>Time</th><th>Window</th><th>Address</th><th>Outcome</th><th>Notes</th></tr></thead><tbody>${rows}</tbody></table>`);
    }

    // A review sheet with the facts Nick copies onto the official Judicial Council POS-010. It is not the form itself.
    function pos010Html(o, events, server = {}) {
        const served = [...(events || [])].reverse().find(e => e.kind === 'attempt' && /served|co-resident|substituted/i.test(e.title))
            || [...(events || [])].reverse().find(e => e.kind === 'status' && /served/i.test(e.title));
        const manner = served && /co-resident|substituted/i.test(served.title) ? 'Substituted service (CCP § 415.20): left with a competent adult; copy mailed (see log)' : served ? 'Personal service' : '';
        const line = (k, v) => `<tr><td style="width:38%"><strong>${esc(k)}</strong></td><td>${esc(v || '')}</td></tr>`;
        return page(`POS-010 draft ${o.code}`, `<h1>POS-010 draft sheet: ${esc(o.code)}</h1>
            <p class="muted">Review sheet only. Fill in and sign the official Judicial Council form POS-010; check every line against the original documents.</p>
            <table><tbody>${line('Case number', o.case_number)}${line('Court', o.court)}${line('Documents served', o.doc_type)}
            ${line('Party served', o.recipient_name)}${line('Address where served', fullAddress(o))}
            ${line('Date and time of service', served ? when(served.created_at) : o.served_at ? when(o.served_at) : '')}
            ${line('Manner of service', manner)}${line('Server name', server.name || "Nick's Process Services")}
            ${line('Registration number / county', server.registration || '')}${line('Server phone', server.phone || '(209) 922-6817')}
            ${line('Requested by', [o.client_name, o.client_firm].filter(Boolean).join(', '))}</tbody></table>`);
    }

    // Dispute & court evidence pack from the evidence-pack API action. Facts from the records only.
    function evidenceHtml(p) {
        const o = p.order || {};
        const table = (head, rows) => `<table><thead><tr>${head.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows || `<tr><td colspan="${head.length}" class="muted">None recorded.</td></tr>`}</tbody></table>`;
        const seal = p.timeline_seal || {};
        return page(`Evidence pack ${o.code}`, `<h1>Dispute & court evidence pack: ${esc(o.code)}</h1>
            <p class="muted">Generated ${esc(when(p.generated_at))} from Nick's Process Services records.</p>
            <div class="box"><div><strong>Client:</strong> ${esc([o.client_name, o.client_firm].filter(Boolean).join(', '))} · ${esc(o.client_email)}</div>
            <div><strong>Person to serve:</strong> ${esc(o.recipient_name)} · ${esc(o.address)}</div>
            <div><strong>Case / court:</strong> ${esc(o.case_number || '')} ${o.court ? '· ' + esc(o.court) : ''}</div>
            <div><strong>Service:</strong> ${esc(o.tier || '')}${(o.addons || []).length ? ' + ' + esc(o.addons.join(', ')) : ''}</div>
            <div><strong>Payment:</strong> ${o.paid_at ? `${esc(money(o.amount_due_cents))} paid ${esc(when(o.paid_at))}` : 'not paid'}${o.stripe_session_id ? ` · Stripe Checkout ${esc(o.stripe_session_id)}` : ''}</div></div>
            <h2>1. Client attestation when the request was submitted</h2>${table(['When', 'Entry', 'Details'], (p.attestation || []).map(e => `<tr><td>${esc(when(e.created_at))}</td><td>${esc(e.title)}</td><td style="white-space:pre-line">${esc(e.detail || '')}</td></tr>`).join(''))}
            <h2>2. Payments</h2>${table(['When', 'Entry', 'Details'], (p.payments || []).map(e => `<tr><td>${esc(when(e.created_at))}</td><td>${esc(e.title)}</td><td>${esc(e.detail || '')}</td></tr>`).join(''))}
            <h2>3. Service attempts</h2>${table(['When logged', 'Outcome', 'Notes'], (p.attempts || []).map(e => `<tr><td>${esc(when(e.created_at))}</td><td>${esc(String(e.title).replace(/^Attempt:\s*/, ''))}</td><td style="white-space:pre-line">${esc(e.detail || '')}</td></tr>`).join(''))}
            <h2>4. Files and SHA-256 fingerprints</h2>${table(['File', 'Type', 'Stored', 'SHA-256'], (p.files || []).map(f => `<tr><td>${esc(f.filename)}</td><td>${esc(f.kind)}</td><td>${esc(when(f.created_at))}</td><td class="mono">${esc(f.sha256 || 'not recorded')}</td></tr>`).join(''))}
            <h2>5. Timeline seal (chained SHA-256 hash)</h2><div class="box">${seal.verified ? `Verified: all ${esc(String(seal.entries || 0))} timeline entries are unchanged since they were written.` : 'DOES NOT VERIFY: a timeline entry was changed after it was written.'}<br><span class="mono">${esc(seal.head || '')}</span></div>
            <h2>6. Client activity (views, unlocks, downloads, replies)</h2>${p.client_actions == null ? '<p class="muted">The client activity log is not available yet.</p>' : table(['When', 'Action', 'Details', 'Network (SHA-256 of IP)', 'Browser'], p.client_actions.map(l => `<tr><td>${esc(when(l.created_at))}</td><td>${esc(l.action.replace(/_/g, ' '))}</td><td>${esc(l.detail || '')}</td><td class="mono">${esc((l.ip_hash || '').slice(0, 16))}${l.ip_hash ? '…' : ''}</td><td>${esc(l.user_agent || '')}</td></tr>`).join(''))}
            <p class="muted">How to check: each file's fingerprint can be recomputed from the file (for example "shasum -a 256" on a Mac). IP addresses are kept only as SHA-256 hashes.</p>`);
    }

    // CSV for a law firm's accounting: one row per request.
    function ordersCsv(list) {
        const cell = (v) => { const s = String(v ?? ''); return /^[=+\-@\t\r]/.test(s) ? `"'${s.replace(/"/g, '""')}"` : `"${s.replace(/"/g, '""')}"`; };
        const head = ['Reference', 'Status', 'Person to serve', 'Document', 'Service', 'Your reference', 'Submitted', 'Amount', 'Paid on'];
        const rows = (list || []).map(o => [o.code, o.label, o.recipient, o.document, o.service, o.reference, o.created, o.amount, o.paidAt]);
        return [head, ...rows].map(r => r.map(cell).join(',')).join('\r\n');
    }

    return { esc, money, daysUntil, urgency, prioritySort, daysSince, isOpen, WINDOWS, attemptHour, windowFor, attemptWindows, needsWindows,
        needsSubServiceMailing, routeUrl, fullAddress, ATTEMPT_PRESETS, TEMPLATES, printingFeeCents, nextStep,
        receiptHtml, diligenceHtml, pos010Html, evidenceHtml, ordersCsv };
})();
