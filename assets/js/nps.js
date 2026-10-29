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

    const money = (cents) => '$' + ((cents || 0) / 100).toFixed(2);
    const fmtDate = (iso, withTime = true) => {
        if (!iso) return '';
        const d = new Date(iso.length === 10 ? iso + 'T12:00:00' : iso);   // bare dates are calendar days, not midnight UTC
        return d.toLocaleString('en-US', withTime
            ? { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }
            : { month: 'short', day: 'numeric', year: 'numeric' });
    };
    const fmtSize = (bytes) => bytes >= 1048576 ? (bytes / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(bytes / 1024)) + ' KB';

    // Printable service record for Nick (court files, disputes). It states what the system really does, nothing more:
    // SHA-256 fingerprints taken when each file was stored, and the timeline's hash-chain seal checked by the database.
    function printChainOfCustody(cert) {
        // Not opened with 'noopener': that makes window.open return null, so nothing could be written to the new tab.
        const w = window.open('', '_blank', 'width=900,height=800');
        if (!w) { alert('Allow pop-ups for this site to print the record.'); return; }
        w.opener = null;
        const seal = cert.seal || {};
        const cell = 'padding:8px;border:1px solid #cdd7d1;vertical-align:top';
        const filesHtml = (cert.files || []).map(f => `
            <tr><td style="${cell};font-weight:600">${esc(f.name || f.filename)}</td><td style="${cell}">${esc(f.kind)}</td>
                <td style="${cell};font-family:monospace;font-size:11px;word-break:break-all">${esc(f.sha256 || 'not recorded')}</td></tr>`).join('')
            || `<tr><td colspan="3" style="${cell};color:#566860">No documents attached</td></tr>`;
        const eventsHtml = (cert.events || []).map(ev => `
            <tr><td style="${cell};white-space:nowrap">${esc(fmtDate(ev.created_at))}</td><td style="${cell};font-weight:600">${esc(ev.title)}</td>
                <td style="${cell};white-space:pre-line">${esc(ev.detail || '')}</td><td style="${cell}">${ev.client_visible === false ? 'Internal' : 'Shown to client'}</td></tr>`).join('');
        w.document.write(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Service record ${esc(cert.code)}</title>
            <style>body{font-family:Georgia,serif;color:#10221a;margin:32px;line-height:1.5}h1,h2{color:#0d422e;margin-bottom:6px}h2{font-size:17px;margin-top:24px}
            table{width:100%;border-collapse:collapse;margin-top:8px;font-family:sans-serif;font-size:12px}th{background:#e6eee9;text-align:left;padding:8px;border:1px solid #cdd7d1}
            .meta div{margin:2px 0}.seal{margin:16px 0;padding:12px;border:1px solid #cdd7d1;font-family:sans-serif;font-size:12px;word-break:break-all}
            @media print{.no-print{display:none}}</style></head><body>
            <div class="no-print" style="text-align:right"><button onclick="window.print()" style="padding:8px 16px;background:#0d422e;color:#fff;border:0;cursor:pointer;font-weight:600">Print / Save as PDF</button></div>
            <h1>Service record: ${esc(cert.code)}</h1>
            <p style="margin-top:0;color:#566860;font-size:13px">Nick's Process Services · printed ${esc(fmtDate(new Date().toISOString()))}</p>
            <div class="meta"><div><strong>Status:</strong> ${esc(cert.statusLabel)}${cert.legalHold ? ' (legal hold on)' : ''}</div>
                <div><strong>Person to serve:</strong> ${esc(cert.recipient)}</div><div><strong>Document:</strong> ${esc(cert.docType)}</div>
                <div><strong>Address:</strong> ${esc(cert.address)}</div></div>
            <div class="seal"><strong>Timeline seal (SHA-256 hash chain, ${esc(String(seal.entries || 0))} entries):</strong> ${seal.verified ? 'verified: no entry has changed since it was written' : 'DOES NOT VERIFY: an entry was changed after it was written'}<br>${esc(seal.head || '')}</div>
            <h2>Files and their SHA-256 fingerprints</h2>
            <table><thead><tr><th>File</th><th>Type</th><th>SHA-256 (taken when stored)</th></tr></thead><tbody>${filesHtml}</tbody></table>
            <h2>Timeline</h2>
            <table><thead><tr><th>When</th><th>Entry</th><th>Details</th><th>Visibility</th></tr></thead><tbody>${eventsHtml}</tbody></table>
            <p style="font-size:11px;color:#566860;margin-top:20px">How to check this record: each file's fingerprint can be recomputed from the file itself (for example with "shasum -a 256" on a Mac).
            Each timeline entry is linked to the one before it by a SHA-256 hash written when the entry was created; the seal above is the newest link, and the same value was emailed to the client when proof was uploaded.</p>
        </body></html>`);
        w.document.close();
    }

    return {
        esc, post, get, onChange, fileMeta, checkFiles, uploadAll,
        verifyFileSha256, printChainOfCustody,
        money, fmtDate, fmtSize,
    };
})();
