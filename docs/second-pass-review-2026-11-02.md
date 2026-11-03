# Second-pass security review: 2026-11-02

Branch `claude/nick-web-project-setup-8f912a`, base `d0558b8`. This work used only local code, the in-memory fake Supabase and a fake Stripe. Nothing was pushed, deployed or migrated, and no live service was called. The prompts asked for a lot of work; the boundary between what was run and what was not is listed in section 6.

## 1. Baseline (before any change)

| Command | Result |
|---|---|
| `npm test` (8 suites) | All pass: 150 input, 25 client-account, 11 stress suites (3,566 assertions), 68 two-step/hold, 8 photo, 91 real-handler, 34 passkey, 11 chaos |
| `npm run build` | Passes. It rewrote `index.html` (see L-02) |
| `npm audit --omit=dev` | 0 vulnerabilities |
| lint / typecheck | No such scripts exist in `package.json` |

## 2. Findings

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| M-01 | Medium | `api/_lib/orders.mjs` `sendDailyDigests`, `/api/keepalive` | The daily digest had no once-per-day guard. Until `CRON_SECRET` is set, `/api/keepalive` is public with a limit of 4 runs per hour, so anyone could send every opted-in client up to 96 digest emails a day. A Vercel Cron retry also sent a duplicate. | **Fixed.** An atomic `hit_rate_limit('daily-digest-run', 86400)` lets one run per UTC day send. Test R-01 reproduced 4 digests from 4 runs before the fix and gets 1 after. Residual risk: the digest looks back a fixed 24 hours, but the guard counts per UTC day. If someone takes the day's slot early (possible only while `CRON_SECRET` is unset), events between that run and the next one are never digested. A stored watermark would close this gap; that is a product choice. |
| M-02 | Medium | `/api/stripe-webhook` | `charge.refunded` and `charge.dispute.created` were ignored. A refunded or disputed order kept showing as paid, and Nick was never told. | **Fixed.** The webhook reads the order id from the PaymentIntent metadata, writes a private timeline entry, and emails Nick once per Stripe event. That holds for retries that arrive one after another; two deliveries of the same event at the same moment can both pass the "already flagged" read. The existing `flagUnappliedPayment` has the same pattern. It never changes `paid_at` or the status automatically. If the email fails, the call throws so Stripe retries. Test R-03. **This needs a user action**: tick both event types on the webhook endpoint in Stripe. |
| L-01 | Low | `/api/track` `renew-payment` | When two renewals ran at once, both wrote a permanent "New payment link created" entry, and the losing Stripe session stayed open and payable. | **Fixed.** The guarded update now checks which rows it changed. The loser expires its own session, unless Stripe's idempotency returned the same session to both calls, and writes no event. Tests R-02 (distinct sessions) and R-02b (Stripe's idempotency returns one shared session, which must stay open). The fake Stripe now models idempotency keys. Related, now fixed: the key was bucketed by minute but `expires_at` changed every second, so two calls a few seconds apart in one minute sent different parameters under the same key, and Stripe refuses that (a 500 for the client). The expiry is now rounded to the same minute (test R-02c; the fake Stripe now refuses a reused key with different parameters). |
| T-01 | Medium (test gap) | `track.mjs`, `orders.mjs` | Mutation testing found three security guards whose removal left all 8 suites green: (a) cross-order file download scope in `fileForOrder`, (b) the doc-lock gate on downloads, (c) the `metadata.order_id` match in `confirm-payment`. The code was correct, but nothing would have caught a regression. | **Fixed.** Tests R-04, R-05 and R-06 now fail when each guard is removed. |
| T-02 | High (test gap) | `admin.mjs` `requireAdmin`, `firms.mjs` `requireRole`, `client.mjs` `list` | A second mutation pass found five critical guards whose removal left every suite green: the admin `ADMIN_EMAILS` re-check, admin session expiry, the 12-hour idle timeout, the firm role check, and the client list's `client_email` filter (cross-client exposure). | **Fixed.** Tests R-07, R-08 and R-09. |
| L-02 | Low | `index.html` build | The CSS committed in `index.html` was stale against `npm run build`. The difference is two rules used only by `feedback.html` (`.mx-5`, `.min-h-[44px]`), so there is no visible effect. | Reverted, not committed. Rebuilding pages before each commit, or a CI check, would stop the drift. |
| R-01 | Low (residual) | `/api/lookup` | The response is the same text either way, but it takes longer when the code and email match, because the email is sent inline. Exploiting this needs both values, and it is limited to 3 tries per email per 15 minutes. | Accepted. Padding the response would slow every legitimate call. |
| R-02 | Medium (config) | `/api/keepalive`, `/api/safewalk` | With `CRON_SECRET` unset, both endpoints are public but rate-limited. Making them refuse in production would silently stop Safe-Walk emergency alerts if the variable is missing, so the code was left as it is. | **Release condition**: set `CRON_SECRET` in Vercel. |

## 3. Mutation results (after the fixes)

Each guard was removed in turn, all 8 suites were run separately, then the file was restored with `cp` from a backup.

| Guard removed | Caught by |
|---|---|
| `markPaid` `.is('paid_at', null)` | real-handlers, chaos |
| confirm-payment order match | real-handlers (new R-06) |
| `readJson` Origin check | inputs, security-stress, real-handlers |
| `fileForOrder` order scope | real-handlers (new R-04) |
| `canMarkPaid` underpayment | security-stress, real-handlers |
| download doc-lock gate | real-handlers (new R-05) |
| digest once-a-day (new) | real-handlers (R-01) |
| renewal loser expiry (new) | real-handlers (R-02) |
| renewal: expiring the shared session | real-handlers (new R-02b) |
| admin `ADMIN_EMAILS` re-check | real-handlers (new R-07) |
| admin session expiry | real-handlers (new R-07) |
| admin idle timeout | real-handlers (new R-07) |
| legal-hold unlock step-up | real-handlers, chaos |
| legal-hold status rollback | chaos |
| firm removed-member filter | real-handlers |
| firm role check | real-handlers (new R-08) |
| client list own-orders filter | real-handlers (new R-09) |
| client `checkPin` | real-handlers, passkeys |

All 18 mutations are caught. Five were not caught before this review.

## 4. Verified by reading (not changed)

- **Rate limits** are an atomic `insert … on conflict do update hits = hits + 1` in SQL, so they are race-safe.
- **Raw-code paths are blocked.** `vercel.json` redirects `/docs/*`, `/api/_lib/*`, `/scripts/*`, `/supabase/*`, `/build/*` and the config files.
- **Payment application** (`canMarkPaid`, `markPaid`) is idempotent and checks the session id, amount and order. Unapplied payments are flagged once.
- **Request bodies.** `readJson` requires the JSON content type, rejects a cross-origin Origin header when one is present (it does not require the header), caps the body size, and blocks prototype keys.
- **Mock parity.** `scripts/mock-api.mjs` has no webhook or digest path, and its `renew-payment` is a stub that always answers 409, so these fixes create no drift there. The fake Stripe in the real-handler suite used to ignore idempotency keys; it now models them (R-02b).

## 5. Product tiers (Origin $550 / Nexus $2,800 / Aura $4,500)

**Not implemented.** The repository is one site that already includes everything the prompts assign to Aura: admin, client accounts, payments, files and audit. No separate Origin or Nexus build, feature flag, or entitlement model exists, and no implementation file mentions Nexus or Aura. Building it is a product decision (separate deployments versus one codebase with build-time tiers), so it was not invented here.

## 6. Not run

These were not run: load, stress, spike and soak tests against real infrastructure; chaos tests against real Supabase, Stripe or Resend; live Stripe or email; the production database or migrations; RLS tests against a real Postgres; full line-by-line reviews of `admin.mjs` (891 lines), `client.mjs`, `request.mjs` (the public, unauthenticated order and pricing endpoint), `_lib/passkeys.mjs`, `_lib/clients.mjs`, `_lib/photos.mjs`, `_lib/surveys.mjs`, `_lib/safewalk.mjs` and `_lib/firms.mjs`, beyond the guards mutated above; browser and accessibility testing. The existing suites' "stress" and "chaos" checks run in-process against fakes. They do not measure production capacity.

## 7. Third pass: order form and admin step-ups

I ran 13 more mutations against the public order form (`request.mjs`), pricing (`estimate`) and the admin step-up gates.

| Guard removed | Caught by |
|---|---|
| passkey register / remove step-up | passkeys |
| recovery-code generation step-up | real-handlers, chaos |
| authenticator setup step-up | real-handlers |
| delete refused under legal hold | chaos |
| **delete step-up** | **nothing before this pass**; now real-handlers (R-10) |
| unknown tier / add-on `hasOwn` | inputs, security-stress |
| **Terms must be accepted** | **nothing before this pass**; now real-handlers (R-11) |
| documents locked by default on new orders | real-handlers |
| **`finish` only within an hour of creation** | **nothing before this pass**; now real-handlers (R-12) |
| new atomic confirmation guard | real-handlers (R-12) |

**L-03 (Low, fixed).** `/api/request` `finish` checked "already emailed?" and wrote the marker in two separate steps. Three `finish` calls at the same moment sent the client three confirmation emails (reproduced in R-12). An atomic `hit_rate_limit('request-confirm:<order>', 86400)` now lets only one call send. If that counter is removed, R-12 fails.

## 8. Recommendation

**Ready for local review.** Production approval still needs: `CRON_SECRET` set; the webhook subscribed to `charge.refunded` and `charge.dispute.created`; a real-infrastructure load test; and an independent review of `admin.mjs`.
