# Review: client messages and package boundaries (2026-11-03)

Scope: the uncommitted work on `codex/security-stress-hardening` (always-open Aura client messages, Origin/Nexus static
packages, ADR-001). Local repository and in-memory fakes only. No production API, database, Stripe, email or domain
was touched.

## Release condition: apply the migration before deploying the code

`api/admin.mjs` now calls `list_order_client_replied`, and `api/track.mjs` writes `client_message` events, which the
old `order_events_kind_check` rejects. If the code ships first, Nick's dashboard `list` fails and client messages
fail. Apply `20261102103000_client_messages.sql` first, then deploy. The currently deployed code does not depend on
the migration, so applying it early is safe.

## Findings and fixes

| ID | Sev | Finding | Fix | Regression test |
| --- | --- | --- | --- | --- |
| R-01 | High | `withClientReplied` sent up to 500 order ids in a PostgREST `.in()` URL filter (~18 KB; gateways reject past ~8 KB, about 216 orders), so a full dashboard `list` would fail. Its global `.limit(5000)` also hid older orders' latest event, so `client_replied` read false. | New `list_order_client_replied` RPC (ids in the POST body, `distinct on (order_id)` in the database). | `a full 500-order dashboard loads and flags replies…`. The fake now returns 414 for an oversized `.in()`. |
| R-02 | Medium | Migration `20261030060000` (already committed in 39abb6b, likely applied) was edited in place. That causes schema drift, and production's partial index would miss `client_message` (a performance issue only). | Edit reverted. The index is dropped and recreated in `20261102103000`. | Not testable without a real Postgres (see "Not verified"). |
| R-03 | Medium | The replacement `list_order_contact_dates` (SECURITY DEFINER) changed `search_path` from `''` to `public` and dropped `stable`, a hardening regression. It also returned NULL for orders with no exchange; `admin.js` already falls back to `created_at`, so users saw nothing, but it broke the API contract. (`CREATE OR REPLACE` keeps the existing `service_role` grant, so nothing was revoked.) | Restored `search_path`, `stable` and `coalesce`. The grant is re-stated explicitly. `client_message` still counts as contact. | `a client message advances last contact; an order with no exchange still counts from its submission`. |
| R-04 | Medium | Mock/real drift: `fake-supabase.mjs` and the `mock-api.mjs` admin list ignored `client_message`, so the suite could not see R-01/R-03. | Both updated. | Covered by the tests above. |
| R-05 | Low | The email marker was renamed `Reply emailed` → `Client reply emailed`. Legacy orders would re-email Nick on their next `respond-finish`. | Both titles are accepted (real handler and mock). | `a reply already emailed under the pre-message marker title…`. Mutation-checked: fails without the fix. |
| R-06 | Low | The package scan didn't look for links to `track.html`, `admin.html` or `account.html`, or for `APP_SECRET`, Resend, webhook, passkey or source-map references. | Patterns added to `check-package-boundaries.mjs`. | Origin and Nexus pass. |

## Decisions recorded

- **Notify-then-mark (at-least-once).** `order_events` is append-only (`order_events_protect_trg`), so a claim
  marker can't be rolled back after a failed send. Two concurrent `respond-finish` calls, or a partial Resend
  failure followed by a client retry, can email an admin twice. A duplicate is preferred over a lost notification.
  The duplicate is bounded by the `track-write` rate limit (10 per token per 15 min).
- **Messages on any status.** A client with a valid tracking token (and unlock, when the request is locked) can
  message Nick and attach `action_upload` files on served, closed or cancelled orders. Address and access edits
  remain limited to `action_required`. Whether cancelled or legally held orders should take new files is an open
  product decision for Nick.

## Requirement gap (not fixed)

- The Origin and Nexus artifacts ship with `form-action 'none'` and no JavaScript, so they have no working contact
  form, validation or abuse protection. The Origin requirement calls for those. A contact backend for the static
  packages needs a decision (mailto, a hosted form provider, or a minimal function) before it is built.

## Evidence

- `npm test`: every suite green (150 + 35 + 11 suites/3568 assertions + 68 + 11 + 77 + 34 + 6, plus both package
  scans).
- `npm audit --omit=dev`: 0 vulnerabilities.
- New tests were first seen failing against the pre-fix code (2 failures), then passing.

## Not verified

- **Migrations against real Postgres.** A disposable local Postgres could not start inside the sandbox (`shmget`
  blocked). Before deploying, apply the migration on a Supabase staging branch, or run this outside the sandbox
  (it uses a throwaway database in /tmp):

  ```bash
  D=/tmp/nickweb-pg && rm -rf $D && mkdir -p $D/sock && initdb -D $D/data -U postgres -A trust >/dev/null && pg_ctl -D $D/data -o "-c listen_addresses='' -k $D/sock" -l $D/log -w start && psql -h $D/sock -U postgres -v ON_ERROR_STOP=1 -c "create role anon; create role authenticated; create role service_role;" && for f in supabase/migrations/*.sql; do psql -h $D/sock -U postgres -v ON_ERROR_STOP=1 -q -f "$f" >/dev/null || { echo "FAILED $f"; break; }; done; pg_ctl -D $D/data stop
  ```
- Live Stripe, live email, the production API and the production database.
- Timed load, spike and soak profiles (only the existing in-process concurrency checks ran).
- HawkScan DAST (no `HAWK_API_KEY`).
- Browser rendering of the new message panel on `track.html`.
