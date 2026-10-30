// Server copy of the browser's photo cleaner (assets/js/nps.js), so a photo uploaded without the site's own page (for
// example straight to its signed storage link) still loses its GPS location and other hidden metadata. Keep the two in
// step: scripts/check-photo-metadata.mjs runs both on the same photos and fails if their output ever differs.
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

export { stripPhotoBytes };

const PHOTO_TYPES = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', heic: 'image/heic', heif: 'image/heif' };
export const photoType = (filename) => PHOTO_TYPES[String(filename || '').split('.').pop().toLowerCase()] || null;
