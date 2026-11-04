// Small, dependency-free ZIP writer for a printable evidence page and its source JSON.
// Store-only ZIP entries keep the exported bytes inspectable with ordinary archive tools.
const enc = new TextEncoder();
const crcTable = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let i = 0; i < 8; i++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
});
const crc32 = bytes => {
    let c = 0xffffffff;
    for (const byte of bytes) c = crcTable[(c ^ byte) & 255] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
};
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const table = (headers, rows) => `<table><thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(row => `<tr>${row.map(v => `<td>${esc(v)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;

export function evidenceHtml(pack) {
    const { order, payment, attestation, attempts, downloads, files, chain, client_activity: activity = [] } = pack;
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(order.code)} Dispute Evidence</title>
<style>body{font:14px/1.5 system-ui,sans-serif;max-width:950px;margin:35px auto;padding:0 20px;color:#15261c}h1,h2{color:#0d422e}h2{margin-top:30px;border-bottom:1px solid #bbb;padding-bottom:5px}table{border-collapse:collapse;width:100%;margin:10px 0 20px}th,td{border:1px solid #bbb;padding:7px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#edf3ef}p{overflow-wrap:anywhere}.mono{font-family:ui-monospace,monospace;font-size:12px}@media print{body{margin:0;max-width:none}h2{break-after:avoid}tr{break-inside:avoid}}</style></head><body>
<h1>Dispute evidence pack · ${esc(order.code)}</h1><p>Generated ${esc(pack.exported_at)}. Review this record and the source JSON before submitting it anywhere.</p>
<h2>Request and payment</h2>${table(['Field','Value'], [['Reference',order.code],['Client',order.client_name],['Recipient',order.recipient_name],['Case number',order.case_number],['Court',order.court],['Service tier',order.tier],['Stripe session',payment.stripe_session_id],['Amount due (cents)',payment.amount_due_cents],['Paid at',payment.paid_at],['Legal attestation at',attestation?.created_at || 'Not recorded']])}
<h2>Attempt log</h2>${table(['Logged at','Outcome','Detail'],attempts.map(a => [a.created_at,a.title,a.detail]))}
<h2>Client downloads</h2>${table(['Downloaded at','File'],downloads.map(d => [d.created_at,d.filename || d.file_id || 'Unknown file']))}
<h2>Client activity on the tracking page</h2>${table(['When','Action','Detail','Network (hashed)'],activity.map(a => [a.created_at,a.action,a.detail || '',a.network || '']))}
<h2>File fingerprints</h2>${table(['File','Kind','SHA-256'],files.map(f => [f.filename,f.kind,f.sha256 || 'Pending']))}
<h2>Sealed timeline</h2><p>Verification: ${chain.verified ? 'verified' : 'FAILED'} · ${esc(chain.entries)} events</p><p class="mono">Head hash: ${esc(chain.head || 'Unavailable')}</p>
</body></html>`;
}

export function zipEvidencePack(pack) {
    const entries = [
        ['evidence.html', enc.encode(evidenceHtml(pack))],
        ['evidence.json', enc.encode(JSON.stringify(pack, null, 2))],
    ];
    const locals = [], centrals = [];
    let offset = 0;
    const dosTime = 0, dosDate = 33; // 1980-01-01; generated_at in the content is authoritative.
    for (const [name, data] of entries) {
        const nameBytes = enc.encode(name), crc = crc32(data);
        const local = new Uint8Array(30 + nameBytes.length);
        const l = new DataView(local.buffer);
        l.setUint32(0, 0x04034b50, true); l.setUint16(4, 20, true); l.setUint16(6, 0x0800, true);
        l.setUint16(10, dosTime, true); l.setUint16(12, dosDate, true); l.setUint32(14, crc, true);
        l.setUint32(18, data.length, true); l.setUint32(22, data.length, true); l.setUint16(26, nameBytes.length, true);
        local.set(nameBytes, 30);
        locals.push(local, data);
        const central = new Uint8Array(46 + nameBytes.length);
        const c = new DataView(central.buffer);
        c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true);
        c.setUint16(8, 0x0800, true); c.setUint16(12, dosTime, true); c.setUint16(14, dosDate, true);
        c.setUint32(16, crc, true); c.setUint32(20, data.length, true); c.setUint32(24, data.length, true);
        c.setUint16(28, nameBytes.length, true); c.setUint32(42, offset, true); central.set(nameBytes, 46);
        centrals.push(central);
        offset += local.length + data.length;
    }
    const centralSize = centrals.reduce((n, b) => n + b.length, 0);
    const end = new Uint8Array(22), e = new DataView(end.buffer);
    e.setUint32(0, 0x06054b50, true); e.setUint16(8, entries.length, true); e.setUint16(10, entries.length, true);
    e.setUint32(12, centralSize, true); e.setUint32(16, offset, true);
    const out = new Uint8Array(offset + centralSize + end.length);
    let at = 0;
    for (const b of [...locals, ...centrals, end]) { out.set(b, at); at += b.length; }
    return out;
}
