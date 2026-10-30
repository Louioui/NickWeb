// In-memory stand-in for the parts of supabase-js the API uses, so tests can run the REAL handlers in api/
// (scripts/mock-api.mjs is a separate re-implementation and can't catch bugs in the real code).
// Like supabase-js, every call resolves to { data, error } and never throws.
import { randomUUID } from 'node:crypto';

const PRIMARY_KEY = { admin_settings: 'email', client_preferences: 'email', client_security_settings: 'email', track_unlock_codes: 'order_id', admin_totp: 'email', admin_sessions: 'token_hash', client_trusted_devices: 'token_hash', webauthn_credentials: 'credential_id' };

export function createFakeSupabase() {
    const state = {
        tables: {},
        storage: new Map(),          // path -> Uint8Array
        failDownload: new Set(),     // paths whose download returns an error
        failExists: new Set(),       // paths whose info() fails with an auth error (storage unusable, not "missing")
        noBucket: new Set(),         // paths whose info() fails with "Bucket not found"
        failUpdate: new Set(),       // paths whose update() (store a cleaned photo back) fails
        rateHits: new Map(),
        otp: new Map(),              // email -> code accepted by auth.verifyOtp
        linkHashes: new Map(),       // token hash from admin.generateLink -> email (single use)
        users: new Map(),            // email -> user
        sessions: new Map(),         // access token -> email
        pairs: new Map(),            // access token -> its refresh token (one Supabase session)
        refreshTokens: new Map(),    // refresh token -> email
        revoked: [],
    };
    const rows = (t) => (state.tables[t] ||= []);

    class Query {
        constructor(table) { this.table = table; this.filters = []; this.op = 'select'; this.wantRows = false; this.limitN = null; this.orderBy = null; }
        select(_cols, opts = {}) { if (this.op === 'select') this.head = !!opts.head; this.countOpt = opts.count; this.wantRows = true; return this; }
        insert(v) { this.op = 'insert'; this.payload = Array.isArray(v) ? v : [v]; return this; }
        upsert(v) { this.op = 'upsert'; this.payload = Array.isArray(v) ? v : [v]; return this; }
        update(v) { this.op = 'update'; this.payload = v; return this; }
        delete() { this.op = 'delete'; return this; }
        eq(c, v) { this.filters.push(r => r[c] === v); return this; }
        neq(c, v) { this.filters.push(r => r[c] !== v); return this; }
        lt(c, v) { this.filters.push(r => r[c] < v); return this; }
        gt(c, v) { this.filters.push(r => r[c] > v); return this; }
        gte(c, v) { this.filters.push(r => r[c] >= v); return this; }
        in(c, list) { this.filters.push(r => list.includes(r[c])); return this; }
        is(c, v) { this.filters.push(r => (r[c] ?? null) === v); return this; }
        order(c, { ascending = true } = {}) { (this.orderBy ||= []).push({ c, ascending }); return this; }
        limit(n) { this.limitN = n; return this; }
        range(from, to) { this.offsetN = from; this.limitN = to - from + 1; return this; }
        single() { this.one = 'single'; return this; }
        maybeSingle() { this.one = 'maybe'; return this; }
        then(resolve, reject) { return Promise.resolve().then(() => this.run()).then(resolve, reject); }
        run() {
            const all = rows(this.table);
            const match = all.filter(r => this.filters.every(f => f(r)));
            let out;
            if (this.op === 'insert' || this.op === 'upsert') {
                // Like Postgres, a plain insert of an existing primary key fails with 23505 and writes nothing.
                const key = PRIMARY_KEY[this.table];
                if (this.op === 'insert' && key && this.payload.some(p => all.some(r => r[key] === p[key]))) {
                    return { data: null, error: { code: '23505', message: 'duplicate key value violates unique constraint' } };
                }
                out = this.payload.map(p => {
                    const key = PRIMARY_KEY[this.table] || 'id';
                    const existing = this.op === 'upsert' && all.find(r => r[key] === p[key]);
                    if (existing) return Object.assign(existing, p);
                    const row = { id: randomUUID(), created_at: new Date().toISOString(), ...p };
                    all.push(row);
                    return row;
                });
            } else if (this.op === 'update') {
                match.forEach(r => Object.assign(r, this.payload));
                out = match;
            } else if (this.op === 'delete') {
                state.tables[this.table] = all.filter(r => !match.includes(r));
                out = match;
            } else {
                out = match.slice();
                if (this.orderBy) {
                    out.sort((a, b) => {
                        for (const { c, ascending } of this.orderBy) {
                            const d = (a[c] < b[c] ? -1 : a[c] > b[c] ? 1 : 0) * (ascending ? 1 : -1);
                            if (d) return d;
                        }
                        return 0;
                    });
                }
                if (this.offsetN) out = out.slice(this.offsetN);
                if (this.limitN != null) out = out.slice(0, this.limitN);
                if (this.head) return { data: null, count: match.length, error: null };
            }
            const data = out.map(r => ({ ...r }));
            if (this.op !== 'select' && !this.wantRows) return { data: null, error: null, count: this.countOpt ? match.length : null };
            if (this.one === 'single') return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { message: 'not one row' } };
            if (this.one === 'maybe') return { data: data[0] ?? null, error: null };
            return { data, error: null, count: data.length };
        }
    }

    const rpcs = {
        // Same fixed window as the SQL function, stored in rate_limits so code that reads the table sees it.
        hit_rate_limit: ({ p_bucket, p_window_seconds }) => {
            const w = new Date(Math.floor(Date.now() / 1000 / p_window_seconds) * p_window_seconds * 1000).toISOString();
            let r = rows('rate_limits').find(x => x.bucket === p_bucket && x.window_start === w);
            if (!r) rows('rate_limits').push(r = { bucket: p_bucket, window_start: w, hits: 0 });
            return ++r.hits;
        },
        verify_order_chain: ({ p_order }) => [{ ok: true, head: 'f'.repeat(64), entries: rows('order_events').filter(e => e.order_id === p_order).length }],
        admin_codes_last_hour: () => 0,
        use_admin_code: ({ p_email, p_hash }) => {
            const r = rows('admin_codes').filter(c => c.email === p_email && !c.used && c.expires_at > new Date().toISOString())
                .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))[0];
            if (!r || (r.attempts || 0) >= 5) return false;
            r.attempts = (r.attempts || 0) + 1;
            r.used = r.code_hash === p_hash;
            return r.used;
        },
        use_admin_recovery_code: ({ p_email, p_hash }) => {
            const r = rows('admin_recovery_codes').find(c => c.email === p_email && c.code_hash === p_hash && !c.used);
            if (!r) return false;
            r.used = true;
            return true;
        },
        // Same steps as public.firm_remove_member (supabase/migrations/20261031120000_field_ops_prefs_firms.sql).
        firm_remove_member: ({ p_firm, p_email, p_actor }) => {
            const members = rows('firm_members').filter(m => m.firm_id === p_firm && !m.removed_at);
            const email = String(p_email).toLowerCase().trim();
            if (!members.some(m => m.email === String(p_actor).toLowerCase().trim() && m.role === 'admin')) throw new Error('Only an admin of this firm can remove staff.');
            const target = members.find(m => m.email === email);
            if (target?.role === 'admin' && members.filter(m => m.role === 'admin').length <= 1) throw new Error('The last admin of a firm cannot be removed.');
            if (!target) throw new Error('That person is not a current member of this firm.');
            target.removed_at = new Date().toISOString();
            state.tables.client_trusted_devices = rows('client_trusted_devices').filter(d => d.email !== email);
            state.tables.webauthn_credentials = rows('webauthn_credentials').filter(c => !(c.owner_kind === 'client' && c.owner_email === email));
            for (const [access, e] of [...state.sessions]) if (e === email) { state.sessions.delete(access); state.refreshTokens.delete(state.pairs.get(access)); }
            return rows('orders').filter(o => o.firm_id === p_firm && o.client_email === email && !['served', 'closed', 'cancelled'].includes(o.status))
                .map(o => { o.track_token = randomUUID().replace(/-/g, '') + randomUUID().replace(/-/g, '').slice(0, 11); return { order_id: o.id, code: o.code, track_token: o.track_token }; });
        },
        use_admin_totp_step: ({ p_email, p_step }) => {
            const r = rows('admin_totp').find(t => t.email === p_email);
            if (!r || (r.last_used_step || 0) >= p_step) return false;
            r.last_used_step = p_step;
            return true;
        },
    };

    const bucket = {
        // Error shapes as storage-js builds them from the storage server's JSON (StorageApiError: status, statusCode, code).
        info: async (p) => {
            if (state.failExists.has(p)) return { data: null, error: { message: 'invalid signature', status: 400, statusCode: '403', code: 'InvalidJWT' } };
            if (state.noBucket.has(p)) return { data: null, error: { message: 'Bucket not found', status: 400, statusCode: '404', code: 'NoSuchBucket' } };
            if (!state.storage.has(p)) return { data: null, error: { message: 'Object not found', status: 400, statusCode: '404', code: 'not_found' } };
            return { data: { name: p, size: state.storage.get(p).length }, error: null };
        },
        download: async (p) => {
            if (state.failDownload.has(p) || !state.storage.has(p)) return { data: null, error: { message: 'download failed' } };
            return { data: new Blob([state.storage.get(p)]), error: null };
        },
        update: async (p, body) => {
            if (state.failUpdate?.has(p)) return { data: null, error: { message: 'write failed', status: 500 } };
            state.storage.set(p, new Uint8Array(body)); return { data: { path: p }, error: null };
        },
        remove: async (paths) => { paths.forEach(p => state.storage.delete(p)); return { data: [], error: null }; },
        createSignedUploadUrl: async (p) => ({ data: { signedUrl: `https://storage.test/upload/${p}` }, error: null }),
        createSignedUrl: async (p) => ({ data: { signedUrl: `https://storage.test/download/${p}` }, error: null }),
    };

    const authError = (message, code) => ({ message, code, status: 401 });
    const client = {
        from: (t) => new Query(t),
        rpc: async (name, args) => { try { return { data: rpcs[name](args), error: null }; } catch (e) { return { data: null, error: { message: e.message } }; } },
        storage: { from: () => bucket },
        auth: {
            signInWithOtp: async () => ({ data: {}, error: null }),
            verifyOtp: async ({ email, token, token_hash, type }) => {
                if (token_hash !== undefined) {
                    email = type === 'magiclink' ? state.linkHashes.get(token_hash) : undefined;
                    state.linkHashes.delete(token_hash);
                    if (!email) return { data: {}, error: authError('Token has expired or is invalid', 'otp_expired') };
                } else if (state.otp.get(email) !== token) return { data: {}, error: authError('Token has expired or is invalid', 'otp_expired') };
                const user = state.users.get(email);
                const access = `access-${randomUUID()}`, refresh = `refresh-${randomUUID()}`;
                state.sessions.set(access, email);
                state.refreshTokens.set(refresh, email);
                state.pairs.set(access, refresh);
                return { data: { user, session: { access_token: access, refresh_token: refresh } }, error: null };
            },
            getUser: async (access) => {
                const email = state.sessions.get(access);
                return email ? { data: { user: state.users.get(email) }, error: null } : { data: { user: null }, error: authError('invalid JWT', 'bad_jwt') };
            },
            refreshSession: async ({ refresh_token }) => {
                const email = state.refreshTokens.get(refresh_token);
                if (!email) return { data: {}, error: authError('refresh failed', 'refresh_token_not_found') };
                state.refreshTokens.delete(refresh_token);
                const access = `access-${randomUUID()}`, refresh = `refresh-${randomUUID()}`;
                state.sessions.set(access, email); state.refreshTokens.set(refresh, email); state.pairs.set(access, refresh);
                return { data: { user: state.users.get(email), session: { access_token: access, refresh_token: refresh } }, error: null };
            },
            // Like Supabase: signing a session out also revokes its refresh token; scope 'global' signs out every session
            // of that user.
            // Like Supabase, a magic link for an unknown email quietly creates that user.
            admin: { getUserById: async (id) => {
                const user = [...state.users.values()].find(u => u.id === id);
                return user ? { data: { user }, error: null } : { data: { user: null }, error: { message: 'User not found', code: 'user_not_found', status: 404 } };
            }, generateLink: async ({ type, email }) => {
                if (type !== 'magiclink') return { data: {}, error: { message: 'bad type', status: 400 } };
                if (!state.users.has(email)) client.__addUser(email);
                const hashed = randomUUID().replace(/-/g, '');
                state.linkHashes.set(hashed, email);
                return { data: { user: state.users.get(email), properties: { hashed_token: hashed } }, error: null };
            }, signOut: async (access, scope = 'global') => {
                const email = state.sessions.get(access);
                const targets = scope === 'global' && email ? [...state.sessions].filter(([, e]) => e === email).map(([a]) => a) : [access];
                for (const a of targets) {
                    state.refreshTokens.delete(state.pairs.get(a)); state.pairs.delete(a);
                    state.sessions.delete(a); state.revoked.push(a);
                }
                return { data: null, error: null };
            } },
        },
    };

    // Test helpers
    client.__state = state;
    client.__reset = () => {
        state.tables = {};
        for (const k of ['storage', 'failDownload', 'failExists', 'noBucket', 'failUpdate', 'rateHits', 'otp', 'linkHashes', 'users', 'sessions', 'refreshTokens', 'pairs']) state[k].clear();
        state.revoked = [];
    };
    client.__addUser = (email) => {
        const user = { id: randomUUID(), email, email_confirmed_at: new Date().toISOString(), user_metadata: {} };
        state.users.set(email, user);
        return user;
    };
    client.__sessionFor = (email) => { const access = `access-${randomUUID()}`; state.sessions.set(access, email); return access; };
    client.__refreshFor = (email) => { const refresh = `refresh-${randomUUID()}`; state.refreshTokens.set(refresh, email); return refresh; };
    return client;
}
