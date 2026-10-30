// Focused chaos checks against the real payment and crypto helpers with a controllable Supabase boundary.
import assert from 'node:assert/strict';
import { mock } from 'node:test';
import { randomUUID } from 'node:crypto';
import { createFakeSupabase } from './fake-supabase.mjs';
import { stripPhotoBytes } from '../api/_lib/photo-metadata.mjs';

const database = createFakeSupabase();
mock.module('@supabase/supabase-js', { namedExports: { createClient: () => database } });
mock.module('stripe', { defaultExport: class {} });
Object.assign(process.env, { SUPABASE_SERVICE_ROLE_KEY: 'test-service-role', APP_SECRET: 'test-app-secret' });
delete process.env.VERCEL_ENV;

const core = await import('../api/_lib/core.mjs');
const { markPaid } = await import('../api/_lib/orders.mjs');
let passed = 0;
async function check(name, fn) {
    await fn();
    passed++;
    console.log(`PASS ${name}`);
}
const order = () => {
    const value = { id: randomUUID(), code: 'NP-345678', status: 'awaiting_payment', paid_at: null,
        stripe_session_id: 'cs_test_chaos123', amount_due_cents: 7500, legal_hold: false };
    (database.__state.tables.orders ||= []).push(value);
    return value;
};
const paymentEvents = (id) => (database.__state.tables.order_events || []).filter(e => e.order_id === id && e.kind === 'payment' && e.title.startsWith('Payment received:'));

await check('ten simultaneous payment confirmations change the order and timeline once', async () => {
    database.__reset(); const target = order();
    const outcomes = await Promise.all(Array.from({ length: 10 }, () => markPaid(target.id, 7500, target.stripe_session_id)));
    assert.equal(outcomes.filter(Boolean).length, 1);
    assert.ok(target.paid_at);
    assert.equal(paymentEvents(target.id).length, 1);
});

await check('a timeline insert failure cannot leave a paid order without its event', async () => {
    database.__reset(); const target = order();
    database.__state.failEventInsert = true;
    await assert.rejects(markPaid(target.id, 7500, target.stripe_session_id));
    assert.equal(target.paid_at, null);
    assert.equal(paymentEvents(target.id).length, 0);
});

await check('tampered AES-GCM envelopes and wrong purposes fail closed', async () => {
    const secret = core.encryptSecret('sample secret');
    const parts = secret.split('.');
    assert.equal(core.decryptSecret(secret), 'sample secret');
    assert.throws(() => core.decryptSecret(secret, 'other-purpose'));
    for (const index of [1, 2, 3]) {
        const altered = [...parts];
        altered[index] = (altered[index][0] === 'A' ? 'B' : 'A') + altered[index].slice(1);
        assert.throws(() => core.decryptSecret(altered.join('.')));
    }
    assert.throws(() => core.decryptSecret(parts.slice(0, 3).join('.')));
});

await check('rotating a tracking token invalidates its old unlock token', async () => {
    const id = randomUUID();
    const old = core.signToken('track-unlock-v1', `${id}|old-token`, 3600);
    assert.ok(core.checkToken('track-unlock-v1', `${id}|old-token`, old));
    assert.equal(core.checkToken('track-unlock-v1', `${id}|new-token`, old), false);
});

await check('ten parallel email-code and TOTP replays each have one winner', async () => {
    database.__reset();
    const email = 'nicksprocessservices@outlook.com';
    const hash = core.sha256(`${email}:12345678`);
    (database.__state.tables.admin_codes ||= []).push({ email, code_hash: hash, used: false, attempts: 0,
        expires_at: new Date(Date.now() + 300000).toISOString(), created_at: new Date().toISOString() });
    (database.__state.tables.admin_totp ||= []).push({ email, last_used_step: 0 });
    const codeResults = await Promise.all(Array.from({ length: 10 }, () => database.rpc('use_admin_code', { p_email: email, p_hash: hash })));
    assert.equal(codeResults.filter(r => r.data === true).length, 1);
    const totpResults = await Promise.all(Array.from({ length: 10 }, () => database.rpc('use_admin_totp_step', { p_email: email, p_step: 42 })));
    assert.equal(totpResults.filter(r => r.data === true).length, 1);
});

await check('hostile file signatures, deep PDF actions and malformed photo metadata fail closed', async () => {
    const payloads = [
        [Buffer.from('MZ' + 'x'.repeat(30)), 'summons.pdf.exe'],
        [Buffer.from('%PDF-1.7\n' + 'x'.repeat(500000) + '\n/JavaScript\n%%EOF'), 'summons.pdf'],
        [Buffer.alloc(0), 'empty.pdf'],
        [Buffer.alloc(25 * 1024 * 1024 + 1), 'huge.pdf'],
        [Buffer.from('PK\x03\x04word/document.xml vbaProject.bin'), 'complaint.docx'],
    ];
    for (const [bytes, filename] of payloads) assert.equal(core.verifyFileMagic(bytes, filename), false, filename);
    assert.equal(stripPhotoBytes(Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0xff, 0xff]), 'image/jpeg'), null);
    const heic = Buffer.from([0, 0, 0, 24, ...Buffer.from('ftypheic'), 0, 0, 0, 0, ...Buffer.from('mif1heic'),
        ...Buffer.from('II*\0'), 0xff, 0xff, 0, 0, 0x25, 0x88]);
    assert.equal(stripPhotoBytes(heic, 'image/heic'), null);
});

console.log(`${passed} chaos and edge-case checks passed`);
