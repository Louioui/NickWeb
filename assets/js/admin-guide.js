// Nick's dashboard guide: short lessons on what each part of the dashboard does, why it's there, what sets it off, and
// how it helps. Each lesson can point at the real thing on screen ("Show me") and ends with one quick check. Progress is
// kept in this browser only. Loaded after admin.js; no inline scripts (the page's security policy forbids them).
(() => {
    const $ = (id) => document.getElementById(id);
    const { esc } = NPS;

    // what: what it is · why: how it helps Nick · when: what triggers it · tips: how to use it well
    const LESSONS = [
        {
            id: 'start', icon: 'fa-compass', title: 'How the website works',
            what: 'A client fills in the request form on the front page and uploads their papers. The site gives them a reference number (NP-123456) and a private tracking link, and emails you. Everything after that happens here.',
            why: 'Every request, file, attempt, payment and proof lives in one place, so you never chase texts, emails and notes again.',
            when: 'A new request appears at the top of your list the moment a client submits it, and you get an email with a link straight to it.',
            tips: ['The client sees only what you choose to share, on their tracking page.', 'Anything marked "Only you" stays private.'],
            show: { target: 'stats', say: 'These four tiles are your day at a glance. Tap one to filter the list.' },
            quiz: { q: 'Where does a new request show up first?', options: ['In your list here, plus an email to you', 'Only in your text messages', 'On the front page'], answer: 0 },
        },
        {
            id: 'list', icon: 'fa-list', title: 'Your job list and "Due today"',
            what: 'The list shows every request. Filters across the top sort it: Active, New, Waiting on client, In progress, Due today, Due soon and Done.',
            why: '"Due today" puts overdue jobs and anything due in the next 2 days at the top, so nothing slips. Each job also shows how many days since you last updated the client.',
            when: 'A red "Client replied" tag appears when a client answers or sends a note after your last update. "Contact 3d ago" turns red when it\'s been 3 days or more.',
            tips: ['On "Due today", tap "Open today\'s route" to get every stop in Google Maps.', 'On "Done", one tap closes every served or cancelled job.'],
            show: { target: 'filters', say: 'Tap "Due today" to see what needs you first.' },
            quiz: { q: 'What does a red "Client replied" tag mean?', options: ['The client answered after your last update', 'The client paid', 'The job is overdue'], answer: 0 },
        },
        {
            id: 'attempt', icon: 'fa-door-closed', title: 'Logging an attempt',
            what: 'Open a job, then the "Log attempt" tab. Tap a quick button (No answer, Served, Wrong address, Refused, Left with co-resident), add a note if you like, and save.',
            why: 'Each attempt is stamped with the time and its window (morning, afternoon/evening or night). Standard and Expedited promise attempts at different times, and the badges on the job show which windows you still need.',
            when: 'The first attempt moves the job to "Attempting service" by itself. If "Client can see this" is ticked, it appears on their tracking page straight away.',
            tips: ['Leave the time blank to use "now".', 'Logging from the car takes about three taps.'],
            show: { tab: 'attempt', say: 'Here are the quick buttons. One tap fills in the outcome.' },
            quiz: { q: 'What do the morning / afternoon / night badges tell you?', options: ['Which time windows you have tried', 'When the client is home', 'Your working hours'], answer: 0 },
        },
        {
            id: 'ask', icon: 'fa-comments', title: 'Talking to the client',
            what: '"Ask client" sends a question (a missing unit number, a gate code) and sets the job to "Action required". "Note" saves a note, private unless you tick to share it. Both have saved messages you can pick instead of typing.',
            why: 'The client answers on their tracking page, can fix the address and upload files, and you get an email when they do. No phone tag.',
            when: 'Clients can also send you a note or a file at any time on an open job. You\'ll see the red "Client replied" tag.',
            tips: ['Use a saved message, then edit it if needed.', 'A shared note also counts as contacting the client.'],
            show: { tab: 'action', say: 'Pick a saved message from the list, or type your own.' },
            quiz: { q: 'What happens when you send "Ask client"?', options: ['The client is emailed and the job shows "Action required"', 'The job is closed', 'Nothing until you call them'], answer: 0 },
        },
        {
            id: 'pay', icon: 'fa-credit-card', title: 'Getting paid',
            what: 'The "Payment link" tab sends the client a secure Stripe link for the amount you set (card, Apple Pay or Google Pay).',
            why: 'The site checks the PDF page counts for you and shows the printing fee (first 100 pages free, $0.15 a page after). You never count pages by hand.',
            when: 'When the client pays, the job moves to "Paid" by itself and you\'re emailed. Links last 24 hours; the client can get a fresh one from their page if it expires.',
            tips: ['If a payment doesn\'t match (an old link, a short amount), you get a "Payment needs review" alert instead of it being lost.', 'Card numbers never touch this site; Stripe handles them.'],
            show: { tab: 'payment', say: 'Set the amount and send. The printing fee shows here when there are PDFs.' },
            quiz: { q: 'How do you know a client paid?', options: ['The job moves to "Paid" by itself and you\'re emailed', 'You check your bank every day', 'The client texts you'], answer: 0 },
        },
        {
            id: 'proof', icon: 'fa-file-signature', title: 'Proof of service and legal hold',
            what: 'The "Proof of service" tab uploads the proof and can mark the job Served. The client is emailed and can download it.',
            why: 'Every file gets a SHA-256 fingerprint when it\'s stored, and the timeline is chained so any later change shows up. A served job goes under legal hold, so its record can\'t be changed or deleted by accident.',
            when: 'Marking Served turns legal hold on automatically. Unlocking it later needs your authenticator or an emailed step-up code, and you get an alert.',
            tips: ['The client can tap "Verify file" to check their copy matches your fingerprint.', 'Every change on a held job is blocked, so double-check before marking Served.'],
            show: { tab: 'proof', say: 'Upload the proof here and tick "Mark the job as Served".' },
            quiz: { q: 'What does legal hold do?', options: ['Freezes the served job so it can\'t be changed by accident', 'Hides the job from you', 'Charges the client again'], answer: 0 },
        },
        {
            id: 'field', icon: 'fa-gavel', title: 'Field & court tools',
            what: 'The "Field & court" tab has a stakeout timer, the substituted-service mailing log, mileage and fees, and printable drafts: a diligence log and a POS-010 data sheet.',
            why: 'Stakeout time is recorded for you (time past the first included hour is noted). The drafts pull the case facts from the record, so you only check them and sign the real form yourself.',
            when: 'After "Left with co-resident", the job reminds you to log the follow-up mailing until you do.',
            tips: ['Mileage and fees are private and download as a CSV for your taxes.', 'The drafts leave blanks for details the site doesn\'t hold, like your registration number.'],
            show: { tab: 'field', say: 'Start the stakeout timer here, and print the diligence log when a serve fails.' },
            quiz: { q: 'Who signs the POS-010?', options: ['You do, on the official form', 'The website files it', 'The client'], answer: 0 },
        },
        {
            id: 'safe', icon: 'fa-person-walking', title: 'Safe-Walk',
            what: 'Before a risky serve, start a 15, 30 or 60 minute timer in "Field & court". A banner with "I\'m safe" stays at the top of the dashboard.',
            why: 'If you don\'t tap "I\'m safe" in time, your emergency contact is emailed the job\'s address so someone knows where you are.',
            when: 'The site checks every minute. It alerts once, and tries again if the email fails. Changing your contact needs a step-up code.',
            tips: ['Test it once with your own email before you rely on it.', 'It needs signal to check in, and it never replaces calling 911.'],
            show: { tab: 'field', say: 'Safe-Walk is in this tab. Add your emergency contact first.' },
            quiz: { q: 'What happens if you forget to tap "I\'m safe"?', options: ['Your emergency contact is emailed the job address', 'Nothing', 'The job is cancelled'], answer: 0 },
        },
        {
            id: 'security', icon: 'fa-shield-halved', title: 'Keeping your dashboard safe',
            what: '"Security & App" (top right) is where you turn on the authenticator app, save recovery codes, add Face ID / Touch ID (a passkey), and see every device signed in.',
            why: 'Your dashboard holds clients\' court papers and people\'s home addresses. With these on, someone who gets into your email still can\'t get in.',
            when: 'Deleting a job, unlocking legal hold or changing security settings asks for a fresh code. You\'re emailed about every new sign-in.',
            tips: ['Keep recovery codes in a password manager, not your email.', 'Lost phone? A recovery code works instead of the authenticator code.'],
            show: { modal: true, say: 'Everything about your sign-in lives here.' },
            quiz: { q: 'Why turn on the authenticator app?', options: ['So access to your email alone isn\'t enough to get in', 'To make the site faster', 'To send texts'], answer: 0 },
        },
        {
            id: 'client', icon: 'fa-user', title: 'What your client sees',
            what: 'Each client has a private tracking page for each request: the status, a progress bar, your shared updates, the amount due with a Pay button, your questions, and the proof once you upload it. Firms with many requests can use the client portal to see them all.',
            why: 'Clients check their page instead of calling you. Pages start locked: a forwarded link shows only the status until the client enters an emailed code or their PIN.',
            when: 'Anything you share, any payment link and any proof appears there straight away.',
            tips: ['Clients can also print a receipt after paying.', 'Your developer will walk you through the client side in your meeting.'],
            show: null,
            quiz: { q: 'What does a forwarded tracking link show before it\'s unlocked?', options: ['Only the status and dates', 'Everything, including the address', 'Nothing at all'], answer: 0 },
        },
    ];

    const KEY = 'nps_guide_done_v1';
    const loadDone = () => { try { return new Set(JSON.parse(localStorage.getItem(KEY) || '[]')); } catch { return new Set(); } };
    const saveDone = (set) => { try { localStorage.setItem(KEY, JSON.stringify([...set])); } catch { /* storage off */ } };
    let done = loadDone();
    let index = 0;

    function render() {
        const l = LESSONS[index];
        $('guide-progress').textContent = `${done.size} of ${LESSONS.length} learned`;
        $('guide-bar').style.width = `${Math.round((done.size / LESSONS.length) * 100)}%`;
        $('guide-nav').innerHTML = LESSONS.map((x, i) => `<button type="button" class="tab-btn ${i === index ? 'is-active' : ''}" data-guide-go="${i}" aria-pressed="${i === index}">
            ${done.has(x.id) ? '<i class="fa-solid fa-circle-check text-primary mr-1" aria-hidden="true"></i>' : ''}${i + 1}</button>`).join('');
        $('guide-body').innerHTML = `
            <h3 class="font-display text-2xl text-primary"><i class="fa-solid ${l.icon} text-bronze mr-2" aria-hidden="true"></i>${esc(l.title)}</h3>
            <div class="space-y-3 text-sm leading-relaxed">
                <p><strong class="text-primary">What it is.</strong> ${esc(l.what)}</p>
                <p><strong class="text-primary">How it helps you.</strong> ${esc(l.why)}</p>
                <p><strong class="text-primary">What sets it off.</strong> ${esc(l.when)}</p>
                <ul class="list-disc pl-5 text-muted">${l.tips.map(t => `<li>${esc(t)}</li>`).join('')}</ul>
            </div>
            ${l.show ? '<button type="button" class="btn btn-outline btn-sm" data-guide-show><i class="fa-solid fa-eye" aria-hidden="true"></i> Show me</button>' : ''}
            <div class="rule-t pt-4 space-y-2">
                <p class="text-sm font-semibold text-ink">Quick check: ${esc(l.quiz.q)}</p>
                <div class="flex flex-col gap-2">${l.quiz.options.map((o, i) => `<button type="button" class="btn btn-outline btn-sm text-left justify-start" data-guide-answer="${i}">${esc(o)}</button>`).join('')}</div>
                <p id="guide-feedback" class="hidden result-box text-sm" role="status"></p>
            </div>`;
        $('guide-back').disabled = index === 0;
        $('guide-next').textContent = index === LESSONS.length - 1 ? 'Finish' : 'Next';
    }

    function open(at = 0) {
        index = at;
        render();
        $('guide-modal').classList.remove('hidden');
        $('guide-title').focus();
    }
    function close() { $('guide-modal').classList.add('hidden'); }

    // "Show me": close the guide and point at the real thing. Lessons about a job's tabs need a job open.
    function showMe() {
        const s = LESSONS[index].show;
        close();
        if (s.modal) { openSecurityModal(); return; }
        if (s.tab) {
            if (typeof current === 'undefined' || !current) {
                const first = document.querySelector('.job-row');
                if (!first) return toast('Open any job first, then tap "Show me" again.');
                first.click();
                setTimeout(() => { setActionTab(s.tab); spotlight(document.getElementById('action-form'), s.say); }, 700);
                return;
            }
            setActionTab(s.tab);
            setTimeout(() => spotlight(document.getElementById('action-form'), s.say), 50);
            return;
        }
        spotlight(document.getElementById(s.target), s.say);
    }
    function spotlight(el, say) {
        if (!el) return toast(say);
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        const before = el.style.boxShadow;
        el.style.boxShadow = '0 0 0 4px #b08d57, 0 0 0 9px rgba(176,141,87,.25)';
        el.style.transition = 'box-shadow .3s';
        toast(say);
        setTimeout(() => { el.style.boxShadow = before; }, 4500);
    }
    function toast(msg) {
        const t = $('save-feedback');
        t.innerHTML = `<i class="fa-solid fa-graduation-cap mr-1" aria-hidden="true"></i> ${esc(msg)} <button type="button" class="underline underline-offset-2 ml-2" data-guide-reopen>Back to the guide</button>`;
        t.className = 'desk-feedback result-box result-ok';
        clearTimeout(toast.timer);
        toast.timer = setTimeout(() => t.classList.add('hidden'), 9000);
    }

    document.addEventListener('click', (e) => {
        if (e.target.closest('[data-guide-open]')) return open(done.size >= LESSONS.length ? 0 : Math.max(0, LESSONS.findIndex(l => !done.has(l.id))));
        if (e.target.closest('[data-guide-reopen]')) return open(index);
        if (!$('guide-modal') || $('guide-modal').classList.contains('hidden')) return;
        if (e.target === $('guide-modal') || e.target.closest('[data-guide-close]')) return close();
        const go = e.target.closest('[data-guide-go]');
        if (go) { index = Number(go.dataset.guideGo); return render(); }
        if (e.target.closest('[data-guide-show]')) return showMe();
        const ans = e.target.closest('[data-guide-answer]');
        if (ans) {
            const ok = Number(ans.dataset.guideAnswer) === LESSONS[index].quiz.answer;
            const fb = $('guide-feedback');
            fb.className = `result-box ${ok ? 'result-ok' : 'result-warn'} text-sm`;
            fb.textContent = ok ? 'Right. Lesson learned.' : 'Not quite. Read "What sets it off" again and try once more.';
            if (ok) { done.add(LESSONS[index].id); saveDone(done); $('guide-progress').textContent = `${done.size} of ${LESSONS.length} learned`; $('guide-bar').style.width = `${Math.round((done.size / LESSONS.length) * 100)}%`; }
            return;
        }
        if (e.target.closest('#guide-back')) { if (index > 0) { index--; render(); } return; }
        if (e.target.closest('#guide-next')) {
            if (index < LESSONS.length - 1) { index++; render(); }
            else { close(); toast(done.size === LESSONS.length ? 'You finished the guide. Open it any time from the Guide button.' : `You've learned ${done.size} of ${LESSONS.length}. Come back to finish the rest.`); }
        }
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && $('guide-modal') && !$('guide-modal').classList.contains('hidden')) close();
    });
})();
