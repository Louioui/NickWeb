// Included ONLY by build-demo.mjs in the isolated static preview, never by the production pages.
(() => {
    'use strict';
    const randomUUID = () => crypto.randomUUID();
    const randomInt = (min, max) => min + Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296 * (max - min));
    const randomBytes = n => {
        const bytes = crypto.getRandomValues(new Uint8Array(n));
        return { toString: type => type === 'hex' ? [...bytes].map(b => b.toString(16).padStart(2, '0')).join('') : btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '') };
    };
    const Buffer = { from: value => typeof value === 'string' ? Uint8Array.from(value, c => c.charCodeAt(0) & 255) : new Uint8Array(value) };
    class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
    /* BUSINESS_RULES */
    /* MOCK_API */

    const DB_NAME = 'nps-isolated-demo-v1';
    const nativeFetch = window.fetch.bind(window);
    let cookie = '';
    const database = new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = () => req.result.createObjectStore('state');
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(new Error('Demo storage is unavailable. Allow website storage, then reload.'));
    });
    const readState = async () => {
        const db = await database;
        return new Promise((resolve, reject) => {
            const tx = db.transaction('state', 'readonly');
            const req = tx.objectStore('state').get('workspace');
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    };
    const writeState = async () => {
        const db = await database;
        return new Promise((resolve, reject) => {
            const tx = db.transaction('state', 'readwrite');
            tx.objectStore('state').put({
                orders: [...orders],
                events,
                files: [...files],
                sessions: [...sessions],
                sessionEmails: [...sessionEmails],
                adminRecoveryCodes: [...adminRecoveryCodes].map(([k, v]) => [k, [...v]]),
                clients: [...clients],
                clientSessions: [...clientSessions],
                clientCodes: [...clientCodes],
                cookie,
            }, 'workspace');
            tx.oncomplete = resolve;
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error || new Error('Demo storage is full. Reset the demo workspace.'));
        });
    };
    function restore(state) {
        if (!state) return;
        orders.clear(); state.orders.forEach(([k, v]) => orders.set(k, v));
        events.splice(0, events.length, ...state.events);
        files.clear(); state.files.forEach(([k, v]) => files.set(k, v));
        sessions.clear(); state.sessions.forEach(s => sessions.add(s));
        sessionEmails.clear(); (state.sessionEmails || []).forEach(([k, v]) => sessionEmails.set(k, v));
        adminRecoveryCodes.clear(); (state.adminRecoveryCodes || []).forEach(([k, v]) => adminRecoveryCodes.set(k, new Set(v)));
        clients.clear(); (state.clients || []).forEach(([k,v]) => clients.set(k,v));
        clientSessions.clear(); (state.clientSessions || []).forEach(([k,v]) => clientSessions.set(k,v));
        clientCodes.clear(); (state.clientCodes || []).forEach(([k,v]) => clientCodes.set(k,v));
        cookie = state.cookie || '';
    }
    let queue = Promise.resolve();
    function inWorkspace(fn) {
        const run = async () => {
            restore(await readState());
            const result = await fn();
            await writeState();
            return result;
        };
        const work = () => navigator.locks ? navigator.locks.request(DB_NAME, run) : run();
        const next = queue.then(work, work);
        queue = next.catch(() => {});
        return next;
    }
    window.fetch = async (input, options) => {
        const base = input instanceof Request ? input : new Request(new URL(input, location.href), options);
        const url = new URL(base.url);
        // Every API call is handled locally. There is no path from this demo to Supabase, Resend or Stripe.
        if (url.origin !== location.origin || (!url.pathname.startsWith('/api/') && !url.pathname.startsWith('/__mock'))) return nativeFetch(input, options);
        try {
            return await inWorkspace(async () => {
                const req = { url: base.url, method: base.method, headers: { get: key => key.toLowerCase() === 'cookie' ? cookie : base.headers.get(key) }, text: () => base.text(), formData: () => base.formData() };
                const result = url.pathname.startsWith('/api/') ? await handleMockApi(url.pathname.slice(5), req) : await handleMockRoute(req);
                if (!result) return json({ error: 'This feature is unavailable in the demo.' }, 404);
                const setCookie = result.headers.get('x-demo-session');
                if (setCookie) {
                    const values = new Map(cookie.split(';').map(v => v.trim()).filter(Boolean).map(v => { const i=v.indexOf('='); return [v.slice(0,i), v.slice(i+1)]; }));
                    const pair = setCookie.split(';')[0], i = pair.indexOf('=');
                    values.set(pair.slice(0,i),pair.slice(i+1));
                    cookie = [...values].map(([k,v]) => `${k}=${v}`).join('; ');
                }
                if (result.headers.get('content-type')?.includes('application/json')) {
                    const data = await result.json();
                    if (data.url?.startsWith('/__mock-file/')) {
                        const fileResponse = await handleMockRoute(new Request(new URL(data.url, location.origin)));
                        data.url = URL.createObjectURL(await fileResponse.blob());
                    }
                    if (data.payUrl?.startsWith('/__mock-pay')) data.payUrl = data.payUrl.replace('/__mock-pay', '/demo-checkout.html');
                    return json(data, result.status);
                }
                return result;
            });
        } catch (err) { return json({ error: err.message || 'Demo storage failed. Try reloading the demo.' }, 503); }
    };
    async function mount() {
        const style = document.createElement('style');
        style.textContent = '.nps-demo-bar{padding:10px 18px;background:#fff1ce;color:#3b3019;border-bottom:1px solid #d8b46b;font:12px/1.5 system-ui,sans-serif;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}.nps-demo-bar a{color:#0d422e;text-decoration:underline;font-weight:700}.nps-demo-table{width:100%;border-collapse:collapse;font-size:14px}.nps-demo-table td,.nps-demo-table th{padding:12px 8px;border-bottom:1px solid #d6ded8;text-align:left}.nps-demo-table a{color:#0d422e;font-weight:600}.nps-demo-scroll{overflow-x:auto}.nps-demo-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px;margin:20px 0}.nps-demo-card{background:#fff;border:1px solid #d6ded8;border-radius:4px;padding:18px}.nps-demo-card h2{margin:0 0 8px;font-size:18px;color:#0d422e}.nps-demo-btn{display:inline-block;padding:10px 14px;margin:6px 6px 0 0;background:#0d422e;color:#f6e9cc;border:1px solid #0d422e;border-radius:2px;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none}.nps-demo-btn-alt{background:#fff;color:#0d422e}.nps-demo-steps{background:#fff;border:1px solid #d8b46b;border-radius:4px;padding:18px;margin:20px 0}.nps-demo-steps ol{margin:10px 0 0;padding-left:20px;line-height:1.7}';
        document.head.append(style);
        const bar = document.createElement('aside');
        bar.className = 'nps-demo-bar';
        bar.setAttribute('aria-label', 'Demo notice');
        bar.innerHTML = '<span><strong>DEMO</strong> · Sample data only. No emails or charges. Use test documents only.</span><a href="/demo.html">Demo workspace &amp; 1-click login</a>';
        document.body.prepend(bar);
        const setCookiePair = (name, val) => {
            const values = new Map(cookie.split(';').map(v => v.trim()).filter(Boolean).map(v => { const i = v.indexOf('='); return [v.slice(0, i), v.slice(i + 1)]; }));
            values.set(name, val);
            cookie = [...values].map(([k, v]) => `${k}=${v}`).join('; ');
        };
        const hub = document.getElementById('demo-hub');
        if (hub) {
            try {
                const rows = await inWorkspace(() => [...orders.values()].sort((a, b) => b.created_at.localeCompare(a.created_at)));
                const byCode = Object.fromEntries(rows.map(o => [o.code, o]));
                const linkFor = code => byCode[code] ? `/track.html#t=${encodeURIComponent(byCode[code].track_token)}` : '/demo.html';
                hub.innerHTML = `<h1>Try Nick’s workflow</h1><p>This preview is separate from the live website. Requests and test documents stay in this browser and are shared between its demo tabs.</p>
                <div class="nps-demo-grid">
                    <section class="nps-demo-card">
                        <h2>1. Try as a Client</h2>
                        <p style="font-size:14px;color:#42544b;margin:0 0 10px">Open the private client portal with one click, or test manual verification with code <strong>${MOCK_CLIENT_CODE}</strong>.</p>
                        <button type="button" class="nps-demo-btn" data-demo-client="paralegal@example.com">Sign in as Jordan Vance (5 sample requests)</button>
                        <button type="button" class="nps-demo-btn nps-demo-btn-alt" data-demo-client="${DEVTEAM_EMAIL}">Sign in as ${DEVTEAM_EMAIL}</button>
                        <p style="font-size:13px;margin:12px 0 0"><a href="/account.html#signup">Manual client sign-up / login</a> · <a href="/#checkout">Submit a new service request</a></p>
                    </section>
                    <section class="nps-demo-card">
                        <h2>2. Try as Nick (Staff Dashboard)</h2>
                        <p style="font-size:14px;color:#42544b;margin:0 0 10px">Jump straight into Nick’s service desk, or log in manually with code <strong>${MOCK_ADMIN_CODE}</strong> (or a generated backup recovery code).</p>
                        <button type="button" class="nps-demo-btn" data-demo-admin="${ADMIN_EMAIL}">Open dashboard as Nick (${ADMIN_EMAIL})</button>
                        <button type="button" class="nps-demo-btn nps-demo-btn-alt" data-demo-admin="${DEVTEAM_EMAIL}">Open dashboard as ${DEVTEAM_EMAIL}</button>
                        <p style="font-size:13px;margin:12px 0 0"><a href="/admin.html">Open dashboard login screen</a></p>
                    </section>
                </div>
                <section class="nps-demo-steps">
                    <h2 style="margin:0;font-size:18px;color:#0d422e">Guided 4-Step End-to-End Walkthrough</h2>
                    <ol style="font-size:14px">
                        <li><strong>Reply to an “Action required” request:</strong> Open <a href="${linkFor('NP-649025')}">NP-649025 (Dana Whitfield)</a> as the client, supply the missing suite number, and click <em>Send to Nick</em>.</li>
                        <li><strong>Complete a simulated payment:</strong> Open <a href="${linkFor('NP-403182')}">NP-403182 (Pacific Harbor Logistics LLC)</a>, click <em>Pay Securely</em>, and click <em>Simulate successful payment</em> ($175.00).</li>
                        <li><strong>Work the queue as Nick:</strong> Click <em>Open dashboard as Nick</em> above to see the <em>Client replied</em> badge and <em>Paid</em> status, log a service attempt, upload Proof of Service, or test <em>Security &amp; App</em> backup recovery codes.</li>
                        <li><strong>Verify Proof of Service &amp; SHA-256 fingerprint:</strong> Open <a href="${linkFor('NP-894771')}">NP-894771 (Alicia Moreno — Served)</a> to download the Proof of Service PDF and inspect its verified SHA-256 chain-of-custody badge.</li>
                    </ol>
                </section>
                <h2>Sample client tracking pages</h2><div class="nps-demo-scroll"><table class="nps-demo-table"><caption style="text-align:left;padding-bottom:8px;font-weight:600">Try each stage of a service request</caption><thead><tr><th scope="col">Reference</th><th scope="col">Status</th><th scope="col">Person to serve</th><th scope="col">Open</th></tr></thead><tbody>${rows.map(o => `<tr><td>${escape(o.code)}</td><td>${escape(STATUSES[o.status].label)}</td><td>${escape(o.recipient_name)}</td><td><a href="/track.html#t=${encodeURIComponent(o.track_token)}">Client view</a> · <a href="/admin.html#${o.id}">Nick’s view</a></td></tr>`).join('')}</tbody></table></div><p>Demo links work only in this browser’s workspace. On another device, open this workspace to get that device’s sample links.</p><button type="button" id="reset-demo" style="padding:12px 16px;margin-top:20px">Reset sample workspace</button>`;
                hub.querySelectorAll('[data-demo-client]').forEach(btn => {
                    btn.onclick = async () => {
                        const addr = btn.getAttribute('data-demo-client');
                        await inWorkspace(() => {
                            if (!clients.has(addr)) clients.set(addr, { email: addr, name: addr === DEVTEAM_EMAIL ? 'Dev Team' : 'Demo Client', firm: 'Partnership With Media', verified: true });
                            const tok = randomBytes(24).toString('base64url');
                            clientSessions.set(tok, addr);
                            setCookiePair('nps_client', tok);
                        });
                        location.href = '/account.html';
                    };
                });
                hub.querySelectorAll('[data-demo-admin]').forEach(btn => {
                    btn.onclick = async () => {
                        const addr = btn.getAttribute('data-demo-admin');
                        await inWorkspace(() => {
                            const tok = randomBytes(24).toString('base64url');
                            sessions.add(tok);
                            sessionEmails.set(tok, addr);
                            setCookiePair('nps_admin', tok);
                        });
                        location.href = '/admin.html';
                    };
                });
                document.getElementById('reset-demo').onclick = async () => {
                    if (!confirm('Clear this browser’s demo requests and test documents and start with fresh samples?')) return;
                    const db = await database; const tx = db.transaction('state', 'readwrite'); tx.objectStore('state').clear(); tx.oncomplete = () => location.reload();
                };
            } catch (err) { hub.textContent = err.message; }
        }
        const checkout = document.getElementById('demo-checkout');
        if (checkout) {
            const params = new URLSearchParams(location.search), existing = new URLSearchParams(location.hash.slice(1));
            const t = params.get('t') || existing.get('t'), session = params.get('s') || existing.get('s');
            history.replaceState(null, '', `/demo-checkout.html#t=${encodeURIComponent(t || '')}&s=${encodeURIComponent(session || '')}`);
            const hash = new URLSearchParams(location.hash.slice(1));
            const savedToken = t || hash.get('t'), savedSession = session || hash.get('s');
            try {
                const response = await fetch('/api/track', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'view', t: savedToken }) });
                const o = await response.json(); if (!response.ok) throw new Error(o.error);
                checkout.innerHTML = `<h1>Simulated checkout</h1><p>${escape(o.code)} · ${escape(o.amountDue || o.estimate)}</p><p>No card details are needed. This only changes the status of a sample request in your browser.</p><button id="simulate-pay" type="button" style="padding:14px 20px">Simulate successful payment</button><p><a href="/track.html#t=${encodeURIComponent(savedToken)}">Back to request</a></p><p id="demo-pay-error" role="alert"></p>`;
                document.getElementById('simulate-pay').onclick = async e => {
                    e.target.disabled = true;
                    const r = await fetch('/api/track', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'confirm-payment', t: savedToken, session: savedSession }) });
                    if (r.ok) location.href = `/track.html#t=${encodeURIComponent(savedToken)}`;
                    else { document.getElementById('demo-pay-error').textContent = (await r.json()).error; e.target.disabled = false; }
                };
            } catch (err) { checkout.textContent = err.message; }
        }
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount, { once: true }); else mount();
})();
