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
| M-01 | Medium | `api/_lib/orders.mjs` `sendDailyDigests`, `/api/keepalive` | The daily digest had no once-per-day guard. Until `CRON_SECRET` is set, `/api/keepalive` is public with a limit of 4 runs per hour, so anyone could send every opted-in client up to 96 digest emails a day. A Vercel Cron retry also sent a duplicate. | **Fixed.** An atomic `hit_rate_limit('daily-digest-run', 86400)` lets one run per UTC day send. Test R-01 reproduced 4 digests from 4 runs before the fix and gets 1 after. |
| M-02 | Medium | `/api/stripe-webhook` | `charge.refunded` and `charge.dispute.created` were ignored. A refunded or disputed order kept showing as paid, and Nick was never told. | **Fixed.** The webhook reads the order id from the PaymentIntent metadata, writes a private timeline entry, and emails Nick once per Stripe event. It never changes `paid_at` or the status automatically. If the email fails, the call throws so Stripe retries. Test R-03. **This needs a user action**: tick both event types on the webhook endpoint in Stripe. |
| L-01 | Low | `/api/track` `renew-payment` | When two renewals ran at once, both wrote a permanent "New payment link created" entry, and the losing Stripe session stayed open and payable. | **Fixed.** The guarded update now checks which rows it changed. The loser expires its own session, unless Stripe's idempotency returned the same session to both calls, and writes no event. Test R-02. |
| T-01 | Medium (test gap) | `track.mjs`, `orders.mjs` | Mutation testing found three security guards whose removal left all 8 suites green: (a) cross-order file download scope in `fileForOrder`, (b) the doc-lock gate on downloads, (c) the `metadata.order_id` match in `confirm-payment`. The code was correct, but nothing would have caught a regression. | **Fixed.** Tests R-04, R-05 and R-06 now fail when each guard is removed. |
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

## 4. Verified by reading (not changed)

- **Rate limits** are an atomic `insert … on conflict do update hits = hits + 1` in SQL, so they are race-safe.
- **Raw-code paths are blocked.** `vercel.json` redirects `/docs/*`, `/api/_lib/*`, `/scripts/*`, `/supabase/*`, `/build/*` and the config files.
- **Payment application** (`canMarkPaid`, `markPaid`) is idempotent and checks the session id, amount and order. Unapplied payments are flagged once.
- **Request bodies.** `readJson` enforces the JSON content type, a same-origin Origin header, a byte cap, and blocks prototype keys.
- **Mock parity.** `scripts/mock-api.mjs` has no renew, webhook or digest paths, so these fixes create no drift there.

## 5. Product tiers (Origin $550 / Nexus $2,800 / Aura $4,500)

**Not implemented.** The repository is one site that already includes everything the prompts assign to Aura: admin, client accounts, payments, files and audit. No separate Origin or Nexus build, feature flag, or entitlement model exists, and no file mentions Nexus or Aura. Building it is a product decision (separate deployments versus one codebase with build-time tiers), so it was not invented here.

## 6. Not run

These were not run: load, stress, spike and soak tests against real infrastructure; chaos tests against real Supabase, Stripe or Resend; live Stripe or email; the production database or migrations; RLS tests against a real Postgres; full reviews of `admin.mjs` (891 lines), `client.mjs` and `firms.mjs` beyond the paths above; browser and accessibility testing. The existing suites' "stress" and "chaos" checks run in-process against fakes. They do not measure production capacity.

## 7. Recommendation

**Ready for local review.** Production approval still needs: `CRON_SECRET` set; the webhook subscribed to `charge.refunded` and `charge.dispute.created`; a real-infrastructure load test; and an independent review of `admin.mjs`.
