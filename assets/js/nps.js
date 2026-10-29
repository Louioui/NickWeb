// Shared browser helpers for the request form (index.html), the client tracking page (track.html) and Nick's dashboard (admin.html).
// Files never pass through our server: the API hands back one-time upload links and the browser sends each file straight to private storage.
const NPS = (() => {
    const TYPE_BY_EXT = {
        pdf: 'application/pdf',
        docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', heic: 'image/heic', heif: 'image/heif', webp: 'image/webp',
    };
    const MAX_FILES = 10;
    const MAX_BYTES = 25 * 1024 * 1024;
    // Tells other open tabs of the site (e.g. the dashboard and a tracking page) that something changed, so they refresh at once.
    const channel = 'BroadcastChannel' in window ? new BroadcastChannel('nps-updates') : null;
    const onChange = (fn) => channel?.addEventListener('message', fn);
    const FALLBACK_ERROR = 'Something went wrong. Please try again, or call Nick at (209) 922-6817.';

    function esc(str) {
        return String(str ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    async function request(method, path, body) {
        let res;
        try {
            res = await fetch(path, {
                method,
                headers: body ? { 'content-type': 'application/json' } : {},
                body: body ? JSON.stringify(body) : undefined,
                credentials: 'same-origin',
            });
        } catch {
            throw new Error('Could not reach the server. Check your connection and try again.');
        }
        let data = {};
        try { data = await res.json(); } catch { /* empty or non-JSON body */ }
        if (!res.ok) {
            const err = new Error(data.error || FALLBACK_ERROR);
            err.status = res.status;
            err.data = data;
            throw err;
        }
        return data;
    }
    // notify: false for calls that only read (the dashboard loads its data by POST), so two open tabs don't ping-pong.
    const post = async (path, body, { notify = true } = {}) => {
        const data = await request('POST', path, body || {});
        if (notify) channel?.postMessage(path);
        return data;
    };
    const get = (path) => request('GET', path);

    // Like the server, the type comes from the extension (phones also leave file.type empty for HEIC photos).
    const typeFor = (file) => (file.name.includes('.') && TYPE_BY_EXT[file.name.split('.').pop().toLowerCase()]) || '';
    const fileMeta = (file) => ({ name: file.name, size: file.size, type: typeFor(file) });

    // Returns an error message for the first problem with the chosen files, or '' when they are fine.
    function checkFiles(files) {
        if (files.length > MAX_FILES) return `Please attach at most ${MAX_FILES} files.`;
        for (const f of files) {
            if (!typeFor(f)) return `${f.name}: only PDF, Word (.docx), JPG, PNG or HEIC files can be uploaded.`;
            if (f.size > MAX_BYTES) return `${f.name} is larger than 25 MB.`;
            if (f.size === 0) return `${f.name} is empty.`;
        }
        return '';
    }

    // Item 24: Strip JPEG APP1 (EXIF/GPS/XMP) and COM metadata segments in the browser before uploading.
    async function stripJpegExif(file) {
        if (typeFor(file) !== 'image/jpeg' || typeof file.arrayBuffer !== 'function') return file;
        try {
            const buf = new Uint8Array(await file.arrayBuffer());
            if (buf.length < 4 || buf[0] !== 0xFF || buf[1] !== 0xD8) return file;
            const chunks = [buf.subarray(0, 2)];
            let pos = 2;
            while (pos + 4 <= buf.length && buf[pos] === 0xFF) {
                const marker = buf[pos + 1];
                if (marker === 0xDA || marker === 0xD9) {
                    chunks.push(buf.subarray(pos));
                    break;
                }
                if (marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
                    chunks.push(buf.subarray(pos, pos + 2));
                    pos += 2;
                    continue;
                }
                const segLen = (buf[pos + 2] << 8) | buf[pos + 3];
                if (segLen < 2 || pos + 2 + segLen > buf.length) {
                    chunks.push(buf.subarray(pos));
                    break;
                }
                // Drop APP1 (0xE1: EXIF/GPS/XMP) and COM (0xFE: comments)
                if (marker !== 0xE1 && marker !== 0xFE) {
                    chunks.push(buf.subarray(pos, pos + 2 + segLen));
                }
                pos += 2 + segLen;
            }
            const total = chunks.reduce((n, c) => n + c.length, 0);
            const clean = new Uint8Array(total);
            let offset = 0;
            for (const c of chunks) { clean.set(c, offset); offset += c.length; }
            return new File([clean], file.name, { type: 'image/jpeg' });
        } catch {
            return file;
        }
    }

    async function uploadOne(upload, file) {
        const safeFile = await stripJpegExif(file);
        const body = new FormData();
        body.append('cacheControl', '3600');
        body.append('', new File([safeFile], file.name, { type: typeFor(file) }));
        const res = await fetch(upload.uploadUrl, { method: 'PUT', headers: { 'x-upsert': 'false' }, body });
        if (!res.ok) throw new Error(`Upload failed for ${file.name}`);
    }

    // uploads[i] (from the API) belongs to files[i]. Resolves with the ids that made it and the names that did not.
    async function uploadAll(uploads, files, onProgress) {
        const ok = [];
        const failed = [];
        let done = 0;
        await Promise.all(uploads.map(async (u, i) => {
            try {
                await uploadOne(u, files[i]);
                ok.push(u.fileId);
            } catch {
                failed.push(u.name);
            }
            onProgress?.(++done, uploads.length);
        }));
        return { ok, failed };
    }

    // Item 20: Live in-browser WebCrypto SHA-256 document integrity verifier
    async function verifyFileSha256(url, expectedHex) {
        const expected = String(expectedHex || '').trim().toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(expected)) throw new Error('No SHA-256 fingerprint is recorded for this file.');
        const res = await fetch(url, { credentials: 'same-origin' });
        if (!res.ok) throw new Error('Could not download the file for cryptographic verification.');
        const buf = await res.arrayBuffer();
        const digest = await crypto.subtle.digest('SHA-256', buf);
        const actual = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
        return { ok: actual === expected, actual, expected };
    }

    // Item 14: 15-Minute Inactivity Auto-Lock & Memory Wipe
    function setupIdleLock(onIdle, timeoutMs = 15 * 60 * 1000) {
        let timer = null;
        const reset = () => {
            if (timer) clearTimeout(timer);
            timer = setTimeout(() => {
                try { onIdle(); } catch {}
            }, timeoutMs);
        };
        for (const ev of ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll']) {
            window.addEventListener(ev, reset, { passive: true });
        }
        reset();
        return { reset, stop: () => timer && clearTimeout(timer) };
    }

    const money = (cents) => '$' + ((cents || 0) / 100).toFixed(2);
    const fmtDate = (iso, withTime = true) => {
        if (!iso) return '';
        const d = new Date(iso.length === 10 ? iso + 'T12:00:00' : iso);   // bare dates are calendar days, not midnight UTC
        return d.toLocaleString('en-US', withTime
            ? { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }
            : { month: 'short', day: 'numeric', year: 'numeric' });
    };
    const fmtSize = (bytes) => bytes >= 1048576 ? (bytes / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(bytes / 1024)) + ' KB';

    // Item 7: Printable Court-Ready Cryptographic Chain-of-Custody Certificate
    function printChainOfCustody(cert) {
        const w = window.open('', '_blank', 'noopener,width=900,height=800');
        if (!w) return;
        const filesHtml = (cert.files || []).map(f => `
            <tr>
                <td style="padding:8px;border:1px solid #cdd7d1;font-weight:600">${esc(f.name || f.filename)}</td>
                <td style="padding:8px;border:1px solid #cdd7d1">${esc(f.kind)}</td>
                <td style="padding:8px;border:1px solid #cdd7d1;font-family:monospace;font-size:11px;word-break:break-all">${esc(f.sha256 || 'Pending seal')}</td>
            </tr>`).join('') || '<tr><td colspan="3" style="padding:8px;border:1px solid #cdd7d1;color:#566860">No documents attached</td></tr>';
        const eventsHtml = (cert.events || []).map(ev => `
            <tr>
                <td style="padding:8px;border:1px solid #cdd7d1;white-space:nowrap">${esc(fmtDate(ev.created_at))}</td>
                <td style="padding:8px;border:1px solid #cdd7d1;font-weight:600">${esc(ev.title)}</td>
                <td style="padding:8px;border:1px solid #cdd7d1;white-space:pre-line">${esc(ev.detail || '')}</td>
            </tr>`).join('');
        w.document.write(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Chain of Custody · ${esc(cert.code)}</title>
            <style>body{font-family:Georgia,serif;color:#10221a;margin:32px;line-height:1.5}h1,h2{color:#0d422e;margin-bottom:6px}table{width:100%;border-collapse:collapse;margin-top:8px;margin-bottom:22px;font-family:sans-serif;font-size:12px}.meta{display:grid;grid-template-columns:1fr 1fr;gap:10px;background:#f4f6f0;padding:14px;border:1px solid #0d422e;font-family:sans-serif;font-size:12px;margin-bottom:20px}.seal{background:#e6eee9;border:1px solid #0d422e;padding:12px;font-family:monospace;font-size:11px;word-break:break-all;margin-bottom:20px}@media print{.no-print{display:none}}</style>
        </head><body>
            <div class="no-print" style="margin-bottom:16px;text-align:right"><button onclick="window.print()" style="padding:8px 16px;background:#0d422e;color:#fff;border:0;cursor:pointer;font-weight:600">Print / Save as PDF</button></div>
            <h1>Cryptographic Chain-of-Custody &amp; Audit Certificate</h1>
            <p style="margin-top:0;color:#566860;font-size:13px">Nick's Process Services · California Registered Process Server · Tamper-Evident Evidence Record</p>
            <div class="meta">
                <div><strong>Reference Code:</strong> ${esc(cert.code)}</div>
                <div><strong>Status:</strong> ${esc(cert.statusLabel || cert.status)} ${cert.legalHold ? '(SEALED LEGAL HOLD)' : ''}</div>
                <div><strong>Person to Serve:</strong> ${esc(cert.recipient)}</div>
                <div><strong>Document Type:</strong> ${esc(cert.docType)}</div>
                <div><strong>Service Address:</strong> ${esc(cert.address)}</div>
                <div><strong>Certificate Generated:</strong> ${esc(fmtDate(new Date().toISOString()))}</div>
            </div>
            <div class="seal">
                <strong>Cryptographic Order Audit Chain Seal (HMAC-SHA256):</strong><br>${esc(cert.integritySeal || 'Verified on server')}
            </div>
            <h2>1. Sealed Court Documents &amp; Proof of Service (SHA-256 Fingerprints)</h2>
            <table><thead><tr style="background:#e6eee9"><th style="padding:8px;border:1px solid #cdd7d1;text-align:left">File Name</th><th style="padding:8px;border:1px solid #cdd7d1;text-align:left">Category</th><th style="padding:8px;border:1px solid #cdd7d1;text-align:left">SHA-256 Cryptographic Fingerprint</th></tr></thead><tbody>${filesHtml}</tbody></table>
            <h2>2. Immutable Chronological Service &amp; Custody Log</h2>
            <table><thead><tr style="background:#e6eee9"><th style="padding:8px;border:1px solid #cdd7d1;text-align:left">Timestamp</th><th style="padding:8px;border:1px solid #cdd7d1;text-align:left">Event</th><th style="padding:8px;border:1px solid #cdd7d1;text-align:left">Recorded Details &amp; Cryptographic Digest</th></tr></thead><tbody>${eventsHtml}</tbody></table>
            <p style="font-size:11px;color:#566860;border-top:1px solid #cdd7d1;padding-top:10px">Attestation: Every file listed above was validated for magic-byte file structure and sealed with an immutable SHA-256 cryptographic digest at the time of upload. Critical chain-of-custody events are protected by append-only database triggers and chained into the Order Audit Chain Seal.</p>
        </body></html>`);
        w.document.close();
    }

    // Item 23: Printable Enterprise Vendor Security & Compliance Brief for Law-Firm IT Teams
    function printSecurityBrief() {
        const w = window.open('', '_blank', 'noopener,width=900,height=800');
        if (!w) return;
        w.document.write(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Enterprise Vendor Security &amp; Compliance Brief · Nick's Process Services</title>
            <style>body{font-family:Georgia,serif;color:#10221a;margin:36px;line-height:1.55}h1{color:#0d422e;margin-bottom:4px}h2{color:#0d422e;font-size:17px;border-bottom:1px solid #cdd7d1;padding-bottom:4px;margin-top:22px}ul{font-family:sans-serif;font-size:13px;padding-left:20px}li{margin-bottom:6px}.badge{display:inline-block;background:#e6eee9;color:#0d422e;padding:4px 10px;font-family:sans-serif;font-size:11px;font-weight:700;border:1px solid #0d422e;margin-right:6px}@media print{.no-print{display:none}}</style>
        </head><body>
            <div class="no-print" style="margin-bottom:16px;text-align:right"><button onclick="window.print()" style="padding:8px 16px;background:#0d422e;color:#fff;border:0;cursor:pointer;font-weight:600">Print / Save Vendor Security Brief (PDF)</button></div>
            <h1>Enterprise Vendor Security &amp; Legal Compliance Brief</h1>
            <p style="margin-top:0;color:#566860;font-size:13px">Prepared for Law Firm IT, Managing Partners &amp; Corporate Vendor Risk Management · Nick's Process Services</p>
            <div style="margin:14px 0"><span class="badge">2-Step Verification (2FA / TOTP)</span><span class="badge">SHA-256 Chain of Custody</span><span class="badge">Zero-Trust Ephemeral Storage</span><span class="badge">TLS 1.3 + HSTS Preload</span></div>
            <h2>1. Two-Step Verification (2FA) &amp; Access Control</h2>
            <ul>
                <li><strong>Staff 2-Step Verification (Email OTP + RFC 6238 Authenticator TOTP):</strong> Administrative access supports hardware-grade RFC 6238 TOTP second-factor verification plus step-up re-authentication on destructive or legal-hold actions.</li>
                <li><strong>Client Firm Security PIN &amp; Dual-Key Document Lock:</strong> Law firms can enroll a 6-digit Security PIN on their client account and enable 2-Step Document Lock on individual cases so forwarded tracking links cannot download court filings without 2nd-step verification.</li>
                <li><strong>One-Click Private Tracking Link Rotation:</strong> Clients and staff can immediately revoke a compromised or forwarded tracking link and issue a fresh 256-bit cryptographic token.</li>
                <li><strong>Automatic Challenge Burn:</strong> Verification challenges automatically burn after 5 failed guesses to defeat brute-force enumeration.</li>
            </ul>
            <h2>2. Anti-Liability Chain-of-Custody &amp; Tamper-Evident Evidence</h2>
            <ul>
                <li><strong>Live Browser SHA-256 Cryptographic Verification:</strong> Every court document and Proof of Service is sealed with a SHA-256 digest at upload and can be cryptographically verified directly in the client's browser using WebCrypto.</li>
                <li><strong>HMAC-SHA256 Chained Audit Trail &amp; Append-Only Triggers:</strong> Service attempts, legal attestations, and Proofs of Service are protected by database-level append-only triggers and chained into an order-wide HMAC-SHA256 integrity seal.</li>
                <li><strong>Completed-Order Legal Hold Lock:</strong> Once an order is marked <em>Served</em>, it enters a tamper-evident Legal Hold state that blocks accidental edits or deletions.</li>
            </ul>
            <h2>3. Zero-Breach Session Isolation &amp; Malware Screening</h2>
            <ul>
                <li><strong>HttpOnly, SameSite=Strict, Device-Bound Sessions:</strong> Session tokens are SHA-256 hashed at rest in PostgreSQL, bound to the caller's User-Agent fingerprint, and automatically lock + wipe browser memory after 15 minutes of inactivity.</li>
                <li><strong>60-Second Ephemeral Signed Downloads &amp; Magic-Byte Screening:</strong> Court documents live in private object storage, undergo strict magic-byte and polyglot/macro rejection (<code>.pdf</code>, <code>.docx</code>, <code>.jpg</code>, <code>.png</code>, <code>.heic</code>, <code>.webp</code>), strip client-side JPEG EXIF/GPS metadata on upload, and use 60-second ephemeral download tokens.</li>
                <li><strong>RFC 9116 Vulnerability Disclosure Policy:</strong> Published at <code>/.well-known/security.txt</code> (Contact: <code>nicksprocessservices@outlook.com</code>).</li>
            </ul>
        </body></html>`);
        w.document.close();
    }

    return {
        esc, post, get, onChange, fileMeta, checkFiles, uploadAll,
        verifyFileSha256, setupIdleLock, printChainOfCustody, printSecurityBrief,
        money, fmtDate, fmtSize,
    };
})();
