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

## Second pass (independent re-verification, same day)

Four independent reviewers re-checked f856774 against the code, mutation tests, a real PGlite (Postgres 18)
apply of every migration, and both sites' Stripe webhooks. Their probes contradicted one claim in the first
version of this report, the "notify-then-mark is at-least-once" decision. Corrected below.

| ID | Sev | Finding | Fix | Regression test |
| --- | --- | --- | --- | --- |
| R-07 | Medium | `sendEmail` returns `false` instead of throwing, and `respond-finish` ignored the result. A Resend failure still wrote the "Client reply emailed" marker, so Nick was never told and no retry happened. | The marker is written only when every recipient accepts (`sent.every(Boolean)`). | `a failed notification is not recorded as sent…` |
| R-08 | Medium | The dedupe was check-then-act with the marker written after the send. 12 concurrent `respond-finish` calls sent 9 emails for one message. | An atomic claim per reply (`hit_rate_limit('reply-email:<reply id>', 120)`; the real SQL is `insert … on conflict do update … returning`), so only the first concurrent call sends. | `twelve concurrent respond-finish calls… exactly once` |
| R-09 | Low | Markers were matched by timestamp (`>=`), so a new message with the same timestamp as the previous marker was never emailed. | A marker's detail names the reply id it covers. The timestamp comparison is kept only for older markers without an id. Recent events also sort by `seq` after `created_at`, so a tie resolves to the newest row, as it does in the database. | `a new message sharing a timestamp…` |
| R-10 | Low | `build-package.mjs` resolved the output path before checking it was absolute, so a relative path wrote the package inside this repository. | The raw argument is checked first, and output inside the repository is refused. | Negative cases in `check-package-boundaries.mjs` |
| R-11 | Low | No test covered a PWM-Dev sale arriving on NickWeb's webhook (one shared Stripe account). | Test added. The existing behavior was already correct: 200, no data change, no email. | `a PWM-Dev sale on the shared Stripe account…` |

Each R-07, R-08 and R-09 test was mutation-checked in a scratch copy: removing the fix makes exactly that test fail.

## Decisions recorded

- **Notification is best effort, deduplicated per reply.** The reply itself is saved first and flags the job on
  Nick's dashboard, which is the durable signal. The email is sent at most once per reply while the 120-second
  claim lasts. If delivery fails, no marker is written, and a later `respond-finish` can send it after the claim
  expires. Nothing retries automatically. A call that crosses a claim-window boundary can, rarely, send a second
  email.
- **Messages on any status.** A client with a valid tracking token (and unlock, when the request is locked) can
  message Nick and attach `action_upload` files on served, closed or cancelled orders. Address and access edits
  remain limited to `action_required`. Whether cancelled or legally held orders should take new files is an open
  product decision for Nick.

## Reported, not fixed (need a decision)

- **Nick's notes don't clear the "client replied" badge.** `list_order_client_replied` counts action, status,
  attempt, payment and proof (the same set as before), but not `note`. Adding `note` would be wrong, because the
  system's own "files added" and "Client reply emailed" notes would clear the badge. The fix needs a decision on
  which of Nick's actions count as a reply.
- **Disputes on Nick's payments reach the wrong inbox.** NickWeb's webhook ignores `charge.dispute.created` and
  fraud warnings entirely. PWM-Dev's webhook emails its owner about every dispute on the shared Stripe account,
  NickWeb's included. Nick is never alerted. The fix belongs in NickWeb (handle disputes for orders with
  `metadata.order_id`). PWM-Dev should not start ignoring them.
- **PWM-Dev `/thanks` says "Payment received" without checking `session_id`.** It shows for direct visits and for
  delayed payments that are still pending. It grants nothing, but it's misleading.
- **Mock drift that predates this work:** the mock admin list computes `last_contact_at` for every order (the real
  one only for active orders), and the mock doesn't apply the `track-write` rate limit.

## Requirement gap (not fixed)

- The Origin and Nexus artifacts ship with `form-action 'none'` and no JavaScript, so they have no working contact
  form, validation or abuse protection. The Origin requirement calls for those. A contact backend for the static
  packages needs a decision (mailto, a hosted form provider, or a minimal function) before it is built.

## Evidence

- `npm test`: every suite green (150 + 35 + 11 suites/3568 assertions + 68 + 11 + 81 + 34 + 6, plus both package
  scans and the build-path refusal check).
- `npm audit --omit=dev`: 0 vulnerabilities.
- New tests were first seen failing against the pre-fix code (2 failures), then passing.

## Not verified

- **Migrations against real Supabase.** Native Postgres could not start inside the sandbox (`shmget` blocked).
  On the second pass, all 23 migrations applied cleanly in order on PGlite (Postgres 18.6, WASM), with only
  `storage.buckets` hand-stubbed. That run checked the constraint, the index, both functions (`stable`, empty
  `search_path`, `service_role`-only execute), the `seq` tiebreak and the append-only and seal triggers. It is
  not Supabase itself. The migration uses a plain `create function`, so running it twice by hand fails (normal for
  a tracked migration). Before deploying, apply it on a Supabase staging branch, or run this outside the sandbox
  (it uses a throwaway database in /tmp):

  ```bash
  D=/tmp/nickweb-pg && rm -rf $D && mkdir -p $D/sock && initdb -D $D/data -U postgres -A trust >/dev/null && pg_ctl -D $D/data -o "-c listen_addresses='' -k $D/sock" -l $D/log -w start && psql -h $D/sock -U postgres -v ON_ERROR_STOP=1 -c "create role anon; create role authenticated; create role service_role;" && for f in supabase/migrations/*.sql; do psql -h $D/sock -U postgres -v ON_ERROR_STOP=1 -q -f "$f" >/dev/null || { echo "FAILED $f"; break; }; done; pg_ctl -D $D/data stop
  ```
- Live Stripe, live email, the production API and the production database.
- Timed load, spike and soak profiles (only the existing in-process concurrency checks ran).
- HawkScan DAST (no `HAWK_API_KEY`).
- Browser rendering of the new message panel on `track.html`.
