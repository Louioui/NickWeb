// Parse the actual PDF page tree, including cross-reference and object streams.
// A textual /Type /Page count can include stale or hidden objects and is not a billing source.
import { getDocument } from 'pdfjs-dist/legacy/build/pdf.mjs';

// Opens the PDF with pdf.js. Returns { pages, unsafe }:
//   unsafe: true   JavaScript actions (document or page level, including inside object streams) or attached files
//   pages: n       the page tree's real page count
//   pages: null    pdf.js could not read the file (unsafe is then false: not being able to parse it is not proof of harm)
export async function inspectPdf(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 16 || bytes.length > 25 * 1024 * 1024) return { pages: null, unsafe: false };
    let task;
    try {
        task = getDocument({ data: new Uint8Array(bytes), useSystemFonts: false, isEvalSupported: false,
            stopAtErrors: true, disableFontFace: true });
        const pdf = await task.promise;
        const count = pdf.numPages;
        if (!Number.isSafeInteger(count) || count < 1 || count > 100000) return { pages: null, unsafe: false };
        if (await pdf.hasJSActions() || await pdf.getAttachments()) return { pages: null, unsafe: true };
        // Page-level additional actions can be stored away from the catalog, including in object streams.
        for (let pageNumber = 1; pageNumber <= count; pageNumber++) {
            const page = await pdf.getPage(pageNumber);
            if (await page.getJSActions()) return { pages: null, unsafe: true };
        }
        return { pages: count, unsafe: false };
    } catch {
        return { pages: null, unsafe: false };
    } finally {
        await task?.destroy().catch(() => {});
    }
}

// The page count when pdf.js can read the PDF and it is safe; null otherwise.
export async function countPdfPages(bytes) {
    const { pages, unsafe } = await inspectPdf(bytes);
    return unsafe ? null : pages;
}

export function printingSummary(files) {
    const pdfs = (files || []).filter(f => f.kind !== 'proof' && String(f.filename || '').toLowerCase().endsWith('.pdf'));
    const counted = pdfs.filter(f => Number.isSafeInteger(f.page_count) && f.page_count > 0);
    const pages = counted.reduce((sum, f) => sum + f.page_count, 0);
    return { pages, feeCents: Math.max(0, pages - 100) * 15, complete: counted.length === pdfs.length,
        pdfs: pdfs.length, countedPdfs: counted.length };
}
