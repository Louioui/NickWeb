// In-memory stand-in for the parts of supabase-js the API uses, so tests can run the REAL handlers in api/
// (scripts/mock-api.mjs is a separate re-implementation and can't catch bugs in the real code).
// Like supabase-js, every call resolves to { data, error } and never throws.
import { randomUUID } from 'node:crypto';

const PRIMARY_KEY = { client_security_settings: 'email', track_unlock_codes: 'order_id', admin_totp: 'email', admin_sessions: 'token_hash' };

export function createFakeSupabase() {
    const state = {
        tables: {},
        storage: new Map(),          // path -> Uint8Array
        failDownload: new Set(),     // paths whose download returns an error
        failExists: new Set(),       // paths whose info() fails with an auth error (storage unusable, not "missing")
        noBucket: new Set(),         // paths whose info() fails with "Bucket not found"
        rateHits: new Map(),
        otp: new Map(),              // email -> code accepted by auth.verifyOtp
        users: new Map(),            // email -> user
        sessions: new Map(),         // access token -> email
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
        order(c, { ascending = true } = {}) { this.orderBy = { c, ascending }; return this; }
        limit(n) { this.limitN = n; return this; }
        single() { this.one = 'single'; return this; }
        maybeSingle() { this.one = 'maybe'; return this; }
        then(resolve, reject) { return Promise.resolve().then(() => this.run()).then(resolve, reject); }
        run() {
            const all = rows(this.table);
            const match = all.filter(r => this.filters.every(f => f(r)));
            let out;
            if (this.op === 'insert' || this.op === 'upsert') {
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
                    const { c, ascending } = this.orderBy;
                    out.sort((a, b) => (a[c] < b[c] ? -1 : a[c] > b[c] ? 1 : 0) * (ascending ? 1 : -1));
                }
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
        remove: async (paths) => { paths.forEach(p => state.storage.delete(p)); return { data: [], error: null }; },
        createSignedUploadUrl: async (p) => ({ data: { signedUrl: `https://storage.test/upload/${p}` }, error: null }),
        createSignedUrl: async (p) => ({ data: { signedUrl: `https://storage.test/download/${p}` }, error: null }),
    };

    const authError = (message, code) => ({ message, code, status: 401 });
    const client = {
        from: (t) => new Query(t),
        rpc: async (name, args) => ({ data: rpcs[name](args), error: null }),
        storage: { from: () => bucket },
        auth: {
            signInWithOtp: async () => ({ data: {}, error: null }),
            verifyOtp: async ({ email, token }) => {
                if (state.otp.get(email) !== token) return { data: {}, error: authError('Token has expired or is invalid', 'otp_expired') };
                const user = state.users.get(email);
                const access = `access-${randomUUID()}`;
                state.sessions.set(access, email);
                return { data: { user, session: { access_token: access, refresh_token: `refresh-${randomUUID()}` } }, error: null };
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
                state.sessions.set(access, email); state.refreshTokens.set(refresh, email);
                return { data: { user: state.users.get(email), session: { access_token: access, refresh_token: refresh } }, error: null };
            },
            admin: { signOut: async (access) => { state.sessions.delete(access); state.revoked.push(access); return { data: null, error: null }; } },
        },
    };

    // Test helpers
    client.__state = state;
    client.__reset = () => {
        state.tables = {};
        for (const k of ['storage', 'failDownload', 'failExists', 'noBucket', 'rateHits', 'otp', 'users', 'sessions', 'refreshTokens']) state[k].clear();
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
