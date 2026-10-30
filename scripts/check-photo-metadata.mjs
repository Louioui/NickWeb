// Loads the real browser helper (assets/js/nps.js) and checks that photo metadata (GPS, EXIF, XMP, text) is removed
// from JPEG, PNG, WebP and HEIC files before upload, while the image data itself is left as it was.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../assets/js/nps.js', import.meta.url), 'utf8');
const context = { window: {}, TextDecoder, TextEncoder, DataView, Uint8Array, File, fetch: () => {} };
vm.runInNewContext(`${source}\nthis.NPS = NPS;`, context);
const { stripPhotoBytes } = context.NPS;

let passed = 0;
const check = (name, fn) => { fn(); passed++; console.log(`PASS ${name}`); };
const bytes = (...parts) => {
    const out = [];
    for (const p of parts) out.push(...(typeof p === 'string' ? [...p].map(c => c.charCodeAt(0)) : p));
    return new Uint8Array(out);
};
const u32be = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const u32le = (n) => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255];
const u16le = (n) => [n & 255, (n >>> 8) & 255];
const text = (b) => String.fromCharCode(...b);
const GPS_TEXT = 'GPS 37.9577N 121.2908W';

// PNG: signature, IHDR, a text chunk and an eXIf chunk holding "GPS…", IDAT, IEND (CRCs aren't checked by the stripper).
const chunk = (type, data) => bytes(u32be(data.length), type, data, [0, 0, 0, 0]);
const png = bytes([0x89], 'PNG\r\n\x1a\n', chunk('IHDR', bytes(new Array(13).fill(1))), chunk('tEXt', bytes(`Comment\0${GPS_TEXT}`)),
    chunk('eXIf', bytes(GPS_TEXT)), chunk('IDAT', bytes('pixels')), chunk('IEND', bytes('')));
check('PNG: text and EXIF chunks are removed, image chunks kept', () => {
    const out = text(stripPhotoBytes(png, 'image/png'));
    assert.ok(!out.includes('GPS') && !out.includes('tEXt') && !out.includes('eXIf'));
    assert.ok(out.includes('IHDR') && out.includes('IDAT') && out.includes('pixels') && out.includes('IEND'));
});

// WebP: VP8X with EXIF + XMP flags set, VP8 image data, EXIF and XMP chunks.
const riff = (id, data) => bytes(id, u32le(data.length), data, data.length % 2 ? [0] : []);
const webpBody = bytes('WEBP', riff('VP8X', bytes([0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0])), riff('VP8 ', bytes('frame!')),
    riff('EXIF', bytes(GPS_TEXT)), riff('XMP ', bytes(`<x:xmpmeta>${GPS_TEXT}</x:xmpmeta>`)));
const webp = bytes('RIFF', u32le(webpBody.length), webpBody);
check('WebP: EXIF and XMP chunks removed, flags cleared, RIFF size fixed', () => {
    const out = stripPhotoBytes(webp, 'image/webp');
    const s = text(out);
    assert.ok(!s.includes('GPS') && !s.includes('EXIF') && !s.includes('XMP ') && s.includes('frame!'));
    assert.equal(new DataView(out.buffer).getUint32(4, true), out.length - 8);
    assert.equal(out[20] & 0x0C, 0);   // VP8X flags byte: EXIF (0x08) and XMP (0x04) bits off
});

// HEIC: ftyp box, then an Exif block (little-endian TIFF) whose IFD0 points to a GPS IFD with a latitude
// (RATIONAL x3 = 24 bytes stored out of line), then an XMP packet, then image data.
const tiff = [];
tiff.push(...bytes('II'), ...u16le(42), ...u32le(8));                         // header, IFD0 at 8
tiff.push(...u16le(1), ...u16le(0x8825), ...u16le(4), ...u32le(1), ...u32le(26), ...u32le(0));   // IFD0: GPSInfo -> 26
tiff.push(...u16le(1), ...u16le(0x0002), ...u16le(5), ...u32le(3), ...u32le(44), ...u32le(0));   // GPS IFD: latitude -> 44
tiff.push(...[37, 0, 0, 0, 1, 0, 0, 0, 57, 0, 0, 0, 1, 0, 0, 0, 77, 0, 0, 0, 1, 0, 0, 0]);          // 37/1 57/1 77/1
const heic = bytes(u32be(24), 'ftypheic', [0, 0, 0, 0], 'mif1heic', 'Exif\0\0', tiff,
    `<x:xmpmeta><exif:GPSLatitude>${GPS_TEXT}</exif:GPSLatitude></x:xmpmeta>`, 'mdat-image-bytes');
check('HEIC: GPS section and XMP blanked in place, size and image data unchanged', () => {
    const out = stripPhotoBytes(heic, 'image/heic');
    assert.equal(out.length, heic.length);
    const t = 24 + 6;   // ftyp box (24) + "Exif\0\0" (6) -> TIFF starts here; GPS IFD at TIFF+26, values at TIFF+44
    assert.equal(text(heic.subarray(t, t + 2)), 'II', 'test offsets are wrong');
    assert.ok(out.subarray(t + 44, t + 68).every(b => b === 0), 'latitude values still present');
    assert.equal(out[t + 26] | (out[t + 27] << 8), 0, 'GPS IFD still lists entries');
    const s = text(out);
    assert.ok(!s.includes('GPSLatitude') && !s.includes(GPS_TEXT) && s.includes('mdat-image-bytes') && s.includes('ftypheic'));
});

// HEIC Exif items can also start with a 4-byte offset and then the TIFF header directly (no "Exif\0\0" prefix).
const heicNoPrefix = bytes(u32be(24), 'ftypheic', [0, 0, 0, 0], 'mif1heic', [0, 0, 0, 0], tiff, 'mdat-image-bytes');
check('HEIC: GPS is also blanked when the EXIF block has no "Exif\\0\\0" prefix', () => {
    const out = stripPhotoBytes(heicNoPrefix, 'image/heic');
    const t = 24 + 4;
    assert.equal(text(heicNoPrefix.subarray(t, t + 2)), 'II', 'test offsets are wrong');
    assert.ok(out.subarray(t + 44, t + 68).every(b => b === 0), 'latitude values still present');
    assert.equal(out[t + 26] | (out[t + 27] << 8), 0, 'GPS IFD still lists entries');
});
check('HEIC: bytes that only look like a TIFF header (in image data) are left untouched', () => {
    const noise = bytes(u32be(24), 'ftypheic', [0, 0, 0, 0], 'mif1heic', 'mdat', 'II*\0', [8, 0, 0, 0, 0xFF, 0xFF, 0x25, 0x88, 9, 9, 9, 9], 'MM\0*', new Array(40).fill(7));
    assert.deepEqual([...stripPhotoBytes(noise, 'image/heic')], [...noise]);
});

// JPEG: APP1 (EXIF) and COM segments removed, image segments kept.
const seg = (marker, data) => bytes([0xFF, marker, ((data.length + 2) >> 8) & 255, (data.length + 2) & 255], data);
const jpeg = bytes([0xFF, 0xD8], seg(0xE0, bytes('JFIF\0')), seg(0xE1, bytes(`Exif\0\0${GPS_TEXT}`)), seg(0xFE, bytes(GPS_TEXT)),
    [0xFF, 0xDA], bytes('scan-data'), [0xFF, 0xD9]);
check('JPEG: EXIF and comment segments removed, image data kept', () => {
    const s = text(stripPhotoBytes(jpeg, 'image/jpeg'));
    assert.ok(!s.includes('GPS') && s.includes('JFIF') && s.includes('scan-data'));
});

check('Unexpected structure uploads the original instead of a damaged file', () => {
    assert.equal(stripPhotoBytes(bytes('not a png at all'), 'image/png'), null);
    assert.equal(stripPhotoBytes(bytes('RIFF\x04\0\0\0XXXX'), 'image/webp'), null);
});

console.log(`${passed} photo metadata checks passed`);
