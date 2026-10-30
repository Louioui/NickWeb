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

    // Photos are cleaned in the browser before upload, so camera location (GPS) and other hidden metadata never reach
    // storage: JPEG and PNG/WebP metadata blocks are dropped; HEIC/HEIF (iPhone) GPS and XMP data are blanked in place.
    const join = (chunks) => {
        const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
        let offset = 0;
        for (const c of chunks) { out.set(c, offset); offset += c.length; }
        return out;
    };
    const ascii = (buf, at, len) => String.fromCharCode(...buf.subarray(at, at + len));

    // PNG: drop the eXIf, tEXt, iTXt, zTXt and tIME chunks; image chunks are copied unchanged.
    function stripPng(buf) {
        if (buf.length < 8 || buf[0] !== 0x89 || ascii(buf, 1, 3) !== 'PNG') return null;
        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        const chunks = [buf.subarray(0, 8)];
        let pos = 8;
        while (pos + 12 <= buf.length) {
            const len = view.getUint32(pos);
            const end = pos + 12 + len;
            if (end > buf.length) return null;
            if (!['eXIf', 'tEXt', 'iTXt', 'zTXt', 'tIME'].includes(ascii(buf, pos + 4, 4))) chunks.push(buf.subarray(pos, end));
            pos = end;
        }
        return join(chunks);
    }

    // WebP: drop the EXIF and XMP chunks, clear their flags in the VP8X header and fix the RIFF size.
    function stripWebp(buf) {
        if (buf.length < 12 || ascii(buf, 0, 4) !== 'RIFF' || ascii(buf, 8, 4) !== 'WEBP') return null;
        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        const chunks = [buf.slice(0, 12)];
        let pos = 12;
        while (pos + 8 <= buf.length) {
            const id = ascii(buf, pos, 4);
            const end = pos + 8 + view.getUint32(pos + 4, true) + (view.getUint32(pos + 4, true) & 1);
            if (end > buf.length) return null;
            if (id === 'VP8X') { const c = buf.slice(pos, end); c[8] &= ~0x0C; chunks.push(c); }   // 0x08 EXIF, 0x04 XMP
            else if (id !== 'EXIF' && id !== 'XMP ') chunks.push(buf.subarray(pos, end));
            pos = end;
        }
        const out = join(chunks);
        new DataView(out.buffer).setUint32(4, out.length - 8, true);
        return out;
    }

    // HEIC/HEIF: the container is hard to rebuild in a browser, so the GPS section inside the embedded EXIF block (and
    // any XMP packet) is overwritten with zeros or spaces in place. Nothing moves, so the image itself is untouched.
    // The EXIF block is found by its TIFF header ("II*\0" or "MM\0*"), with or without an "Exif\0\0" prefix. Because
    // those four bytes can also occur by chance in image data, nothing is changed unless the whole structure checks out.
    const TIFF_SIZES = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8 };
    function gpsRanges(buf, t) {
        const little = buf[t] === 0x49;
        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        const u16 = (at) => view.getUint16(at, little), u32 = (at) => view.getUint32(at, little);
        const inside = (at, len) => at >= t && len >= 0 && at + len <= buf.length;
        const ifd0Off = u32(t + 4);
        if (ifd0Off < 8 || ifd0Off > 65535 || !inside(t + ifd0Off, 2)) return null;
        const ifd0 = t + ifd0Off, n = u16(ifd0);
        if (n < 1 || n > 200 || !inside(ifd0 + 2, n * 12)) return null;
        let gpsOff = 0;
        for (let e = 0; e < n; e++) {
            const entry = ifd0 + 2 + e * 12;
            if (!TIFF_SIZES[u16(entry + 2)]) return null;   // not a real IFD
            if (u16(entry) === 0x8825) gpsOff = u32(entry + 8);
        }
        if (!gpsOff || gpsOff > 65535 || !inside(t + gpsOff, 2)) return null;
        const gps = t + gpsOff, count = u16(gps);
        if (count < 1 || count > 40 || !inside(gps + 2, count * 12)) return null;
        const ranges = [[gps, 2 + count * 12]];
        for (let g = 0; g < count; g++) {
            const ge = gps + 2 + g * 12;
            const size = TIFF_SIZES[u16(ge + 2)];
            if (!size || u16(ge) > 0x1F) return null;       // GPS tags are 0x00-0x1F
            const bytes = size * u32(ge + 4);
            if (bytes > 4) {
                const at = t + u32(ge + 8);
                if (bytes > 4096 || !inside(at, bytes)) return null;
                ranges.push([at, bytes]);
            }
        }
        return ranges;
    }
    function wipeIsoGps(buf) {
        const out = buf.slice();
        for (let i = 0; i + 8 < out.length; i++) {
            const ii = out[i] === 0x49 && out[i + 1] === 0x49 && out[i + 2] === 0x2A && out[i + 3] === 0;
            const mm = out[i] === 0x4D && out[i + 1] === 0x4D && out[i + 2] === 0 && out[i + 3] === 0x2A;
            if (!ii && !mm) continue;
            let ranges = null;
            try { ranges = gpsRanges(out, i); } catch { /* not EXIF */ }
            for (const [at, len] of ranges || []) out.fill(0, at, at + len);
        }
        const xmp = new TextDecoder('latin1').decode(out);
        for (let at = xmp.indexOf('<x:xmpmeta'); at !== -1; at = xmp.indexOf('<x:xmpmeta', at + 1)) {
            const end = xmp.indexOf('</x:xmpmeta>', at);
            if (end !== -1) out.fill(0x20, at, end + 12);
        }
        return out;
    }

    // Returns cleaned bytes for a photo type, or null to upload the original (unknown type or unexpected structure).
    function stripPhotoBytes(buf, type) {
        if (type === 'image/png') return stripPng(buf);
        if (type === 'image/webp') return stripWebp(buf);
        if (type === 'image/heic' || type === 'image/heif') return wipeIsoGps(buf);
        if (type === 'image/jpeg') return stripJpeg(buf);
        return null;
    }

    async function stripPhotoMetadata(file) {
        const type = typeFor(file);
        if (!type.startsWith('image/') || typeof file.arrayBuffer !== 'function') return file;
        try {
            const clean = stripPhotoBytes(new Uint8Array(await file.arrayBuffer()), type);
            return clean ? new File([clean], file.name, { type }) : file;
        } catch {
            return file;
        }
    }

    // JPEG: drop APP1 (EXIF/GPS/XMP) and COM (comment) segments.
    function stripJpeg(buf) {
        if (buf.length < 4 || buf[0] !== 0xFF || buf[1] !== 0xD8) return null;
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
        return join(chunks);
    }

    async function uploadOne(upload, file) {
        const safeFile = await stripPhotoMetadata(file);
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
            <div class="no-print" style="text-align:right"><button id="print-record" type="button" style="padding:8px 16px;background:#0d422e;color:#fff;border:0;cursor:pointer;font-weight:600">Print / Save as PDF</button></div>
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
        // A listener, not an inline onclick: the pop-up inherits the dashboard's Content Security Policy.
        w.document.getElementById('print-record')?.addEventListener('click', () => w.print());
    }

    // A plain printable page in a new tab, with a Print button wired by a listener (the pop-up inherits the page's
    // Content Security Policy, so no inline script).
    function printPage(title, bodyHtml) {
        const w = window.open('', '_blank', 'width=900,height=800');
        if (!w) { alert('Allow pop-ups for this site to print.'); return; }
        w.opener = null;
        w.document.write(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)}</title>
            <style>body{font-family:Georgia,serif;color:#10221a;margin:32px;line-height:1.5}h1,h2{color:#0d422e;margin-bottom:6px}h2{font-size:17px;margin-top:24px}
            table{width:100%;border-collapse:collapse;margin-top:8px;font-family:sans-serif;font-size:12px}th{background:#e6eee9;text-align:left;padding:8px;border:1px solid #cdd7d1}
            td{padding:8px;border:1px solid #cdd7d1;vertical-align:top}.mono{font-family:monospace;font-size:11px;word-break:break-all}
            @media print{.no-print{display:none}}</style></head><body>
            <div class="no-print" style="text-align:right"><button id="print-page" type="button" style="padding:8px 16px;background:#0d422e;color:#fff;border:0;cursor:pointer;font-weight:600">Print / Save as PDF</button></div>
            ${bodyHtml}</body></html>`);
        w.document.close();
        w.document.getElementById('print-page')?.addEventListener('click', () => w.print());
    }
    const rows = (pairs) => pairs.filter(([, v]) => v).map(([k, v]) => `<tr><th style="width:35%">${esc(k)}</th><td>${esc(v)}</td></tr>`).join('');

    // Itemized receipt for a paid request (client's tracking page, or Nick's dashboard).
    function printReceipt(r) {
        printPage(`Receipt ${r.code}`, `<h1>Receipt</h1>
            <p style="margin-top:0;color:#566860;font-size:13px">Nick's Process Services · printed ${esc(fmtDate(new Date().toISOString()))}</p>
            <table><tbody>${rows([['Reference', r.code], ['Client', [r.clientName, r.clientFirm].filter(Boolean).join(', ')], ['Your reference', r.clientReference],
                ['Case number', r.caseNumber], ['Court', r.court], ['Service', r.tier], ['Add-ons', (r.addons || []).join(', ')],
                ['Amount paid', r.amountPaid], ['Date paid', fmtDate(r.paidAt)], ['Paid through', 'Stripe (card details are never seen by this site)']])}</tbody></table>`);
    }

    // Nick's dispute evidence pack: the record's own facts, laid out for a card dispute or a court question.
    function printEvidencePack(p) {
        const list = (items, cols) => items.length ? items.map(i => `<tr>${cols.map(c => `<td${c === 'sha256' ? ' class="mono"' : ''}>${esc(typeof c === 'function' ? c(i) : (i[c] ?? ''))}</td>`).join('')}</tr>`).join('')
            : `<tr><td colspan="${cols.length}" style="color:#566860">None recorded</td></tr>`;
        const o = p.order;
        const activity = Array.isArray(p.client_activity) ? p.client_activity : [];
        printPage(`Evidence pack ${o.code}`, `<h1>Evidence pack: ${esc(o.code)}</h1>
            <p style="margin-top:0;color:#566860;font-size:13px">Generated ${esc(fmtDate(p.generated_at))} from the service record. Nothing here is added or edited by hand.</p>
            <h2>Request</h2><table><tbody>${rows([['Client', [o.client.name, o.client.firm].filter(Boolean).join(', ')], ['Client email', o.client.email],
                ['Case number', o.case_number], ['Court', o.court], ['Client reference', o.client_reference], ['Person served', o.recipient], ['Document', o.document],
                ['Service', [o.tier, ...(o.addons || [])].filter(Boolean).join(' + ')], ['Requested', fmtDate(o.created_at)], ['Status', o.status], ['Served', o.served_at ? fmtDate(o.served_at) : '']])}</tbody></table>
            <h2>Client's confirmation when submitting</h2><table><thead><tr><th>When</th><th>Entry</th><th>Details</th></tr></thead><tbody>${list(p.attestation, [i => fmtDate(i.created_at), 'title', 'detail'])}</tbody></table>
            <h2>Payment</h2><table><tbody>${rows([['Amount', p.payment.amount_due], ['Paid at', p.payment.paid_at ? fmtDate(p.payment.paid_at) : 'Not paid'], ['Stripe checkout session', p.payment.stripe_session_id]])}</tbody></table>
            <table><thead><tr><th>When</th><th>Payment entry</th><th>Details</th></tr></thead><tbody>${list(p.payment.entries, [i => fmtDate(i.created_at), 'title', 'detail'])}</tbody></table>
            <h2>Service attempts</h2><table><thead><tr><th>Logged</th><th>Attempt</th><th>Details</th><th>Shown to client</th></tr></thead><tbody>${list(p.attempts, [i => fmtDate(i.created_at), 'title', 'detail', i => i.shown_to_client ? 'Yes' : 'No'])}</tbody></table>
            <h2>Client activity on the tracking page</h2>${activity.length || !p.client_activity?.unavailable ? `<table><thead><tr><th>When</th><th>Action</th><th>Details</th><th>Network (hashed)</th></tr></thead><tbody>${list(activity, [i => fmtDate(i.created_at), 'action', 'detail', 'network'])}</tbody></table>` : `<p>${esc(p.client_activity.unavailable)}</p>`}
            <h2>Files and SHA-256 fingerprints</h2><table><thead><tr><th>File</th><th>Type</th><th>Stored</th><th>SHA-256 (taken when stored)</th></tr></thead><tbody>${list(p.files, ['filename', 'kind', i => fmtDate(i.stored_at), 'sha256'])}</tbody></table>
            <h2>Timeline seal</h2><p class="mono">${esc(p.timeline_seal?.verified ? 'Verified' : 'DOES NOT VERIFY')} · ${esc(String(p.timeline_seal?.entries || 0))} entries · ${esc(p.timeline_seal?.head || '')}</p>
            <p style="font-size:11px;color:#566860;margin-top:20px">Network addresses are stored only as SHA-256 hashes (first 12 characters shown). Each file's fingerprint can be recomputed from the file itself (for example "shasum -a 256" on a Mac).</p>`);
    }

    return {
        esc, post, get, onChange, fileMeta, checkFiles, uploadAll, stripPhotoBytes,
        verifyFileSha256, printChainOfCustody, printReceipt, printEvidencePack, printPage,
        money, fmtDate, fmtSize,
    };
})();
