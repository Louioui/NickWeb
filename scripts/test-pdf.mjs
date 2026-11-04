// Small valid PDFs with a real page tree for upload and billing regression tests.
export function testPdf(pageCount = 1, catalogExtra = '') {
    const pages = Array.from({ length: pageCount }, (_, i) => `${i + 3} 0 R`).join(' ');
    const objects = [`<< /Type /Catalog /Pages 2 0 R ${catalogExtra} >>`, `<< /Type /Pages /Kids [${pages}] /Count ${pageCount} >>`,
        ...Array.from({ length: pageCount }, () => `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>`)];
    let body = '%PDF-1.7\n';
    const offsets = objects.map((obj, i) => { const offset = body.length; body += `${i + 1} 0 obj\n${obj}\nendobj\n`; return offset; });
    const xref = body.length;
    body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map(at => `${String(at).padStart(10, '0')} 00000 n \n`).join('')}`;
    body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    return Buffer.from(body, 'latin1');
}
