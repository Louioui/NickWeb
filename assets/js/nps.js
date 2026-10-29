// Shared browser helpers for the request form (index.html), the client tracking page (track.html) and Nick's dashboard (admin.html).
// Files never pass through our server: the API hands back one-time upload links and the browser sends each file straight to private storage.
const NPS = (() => {
    const TYPE_BY_EXT = {
        pdf: 'application/pdf', doc: 'application/msword',
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

    // Some phones leave file.type empty for HEIC photos; fall back to the extension so storage accepts them.
    const typeFor = (file) => file.type || TYPE_BY_EXT[file.name.split('.').pop().toLowerCase()] || '';
    const fileMeta = (file) => ({ name: file.name, size: file.size, type: typeFor(file) });

    // Returns an error message for the first problem with the chosen files, or '' when they are fine.
    function checkFiles(files) {
        if (files.length > MAX_FILES) return `Please attach at most ${MAX_FILES} files.`;
        for (const f of files) {
            if (!typeFor(f)) return `${f.name}: only PDF, Word, JPG, PNG or HEIC files can be uploaded.`;
            if (f.size > MAX_BYTES) return `${f.name} is larger than 25 MB.`;
            if (f.size === 0) return `${f.name} is empty.`;
        }
        return '';
    }

    async function uploadOne(upload, file) {
        const body = new FormData();
        body.append('cacheControl', '3600');
        body.append('', new File([file], file.name, { type: typeFor(file) }));
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

    const money = (cents) => '$' + ((cents || 0) / 100).toFixed(2);
    const fmtDate = (iso, withTime = true) => {
        if (!iso) return '';
        const d = new Date(iso.length === 10 ? iso + 'T12:00:00' : iso);   // bare dates are calendar days, not midnight UTC
        return d.toLocaleString('en-US', withTime
            ? { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }
            : { month: 'short', day: 'numeric', year: 'numeric' });
    };
    const fmtSize = (bytes) => bytes >= 1048576 ? (bytes / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(bytes / 1024)) + ' KB';

    return { esc, post, get, onChange, fileMeta, checkFiles, uploadAll, money, fmtDate, fmtSize };
})();
