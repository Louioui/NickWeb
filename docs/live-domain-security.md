# Live-domain security checklist: status of every item in "Live Domain Security Recommendations"

Checked 2026-10-29 against the code, the 4 test suites (`npm test`: 150 + 24 + 3,557 + 58 checks) and the live Supabase
database. The notes repeat several sections two or three times; each item appears here once.

**Status key**
- **Done**: built and verified before this pass.
- **Fixed**: an earlier version had a real hole, now closed.
- **Finished**: was half-built, now complete.
- **Changed**: built differently from the note, and why.
- **Declined**: not built, and why.
- **Needs Nick**: changes what clients see or how he works.
- **Needs you**: an account or DNS step.

## Part 1: code and database

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | Check the real file contents (magic bytes) | Done | `verifyFileMagic` in `confirmUploads`. A mismatched file is deleted from storage and refused. |
| 2 | Pin email links to the real domain | Done | Uses `siteOrigin(request)` everywhere, including client sign-in links. |
| 3 | Constant-time `CRON_SECRET` check; rate-limit `finish` | Done | `timingSafeMatch` in keepalive; `finish` has its own limit. |
| 4 | Admin session cap and pruning | Done | Expired sessions are removed at each login. At most 5 devices; the oldest is dropped. |
| 5 | SQL CHECK constraints | Done | Migration `20261029092747_strict_check_constraints` (applied live). |

## Part 2: domain and outside services

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | SPF, DKIM and DMARC `p=reject` | **Needs you** | No email records exist today, so anyone can send mail as the domain (see "DNS records to add" below). |
| 2 | Cloudflare Turnstile | **Needs Nick** | Adds a check to the public request form, which is visible to clients. Per-IP and per-email limits plus the Vercel firewall rule cover most abuse until then. |
| 3 | Stripe webhook signing secret | Done (code) / **Needs you** (secret) | The signature check is built. Set `STRIPE_WEBHOOK_SECRET` when the webhook endpoint is added. |

## The "6 more" and "6 final" protections

| Item | Status | Notes |
|---|---|---|
| Scripts hidden inside PDFs or images (polyglots) | Done | Scans the start and end of each file for script and HTML patterns. |
| Per-email limit on tracking-link recovery | Done | `lookup-email:<hash>` alongside the per-IP limit. |
| Append-only admin audit log; limits on destructive actions | Done | `admin_audit_logs` can't be edited (database trigger). Per-admin limits on delete, export, payment links and codes. |
| Stripe link 24-hour expiry and duplicate-click guard | Done | `expires_at` and an idempotency key in `createCheckout`. |
| Wipe the dashboard on sign-out | Done | Drafts are kept only in memory. Sign-out clears session storage, dashboard storage and the app cache. |
| COOP / CORP headers | Done | In `vercel.json`. |
| Refuse `.docm`, macros and disguised `.zip` | Done | Looks inside `.docx` files: must be real Word documents, with no `vbaProject.bin` and no executables. |
| `markPaid`: right Stripe session and full amount only | Done | `canMarkPaid`. |
| Per-email limits on client sign-in and new orders | Done | |
| Per-link write limit and a cap on files per order | Done | |
| Old rate-limit rows pruned daily | Done | |
| Wipe the client portal on sign-out | Done | |

## Pillar 1: two-step sign-in

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | Nick: email code + authenticator app | **Fixed + Finished** | Secrets were stored as plain text; now encrypted (AES-256-GCM, server-only key). Each code works once. A failed lookup now refuses sign-in instead of skipping 2FA. The login screen never asked for the second code, so turning 2FA on would have locked Nick out; now it asks. Setup uses a QR code. |
| 2 | Step-up code before risky actions | **Fixed** | Guesses are now rate-limited. Changing the authenticator needed no code at all (a stolen session could switch 2FA off); now it needs the current one, and the old phone keeps working until the new one is confirmed. |
| 3 | Client second step to unlock documents | **Fixed + Finished** | The unlock never expired; it's now a signed 12-hour token. A locked page could still change the address; now blocked. Clients had no way to unlock; the tracking page now has an unlock box. |
| 4 | Rotate a private link | **Fixed** | Rotating revoked the old link but never sent the new one, locking the client out. It's now emailed. |
| 5 | Client PIN | **Fixed** | Plain SHA-256 of a 6-digit PIN can be cracked in under a second; now scrypt with a salt. Wrong PINs on the tracking page now count toward the lockout. |
| 6 | Lockout and alerts after failed attempts | Done | 5 failures cancel pending codes and email Nick. The database also caps wrong guesses at 25 an hour across all of his codes. |
| – | Recovery codes | **Changed** | Now hashed with a server-only key, so they can't be cracked from a database copy. With 2FA on, a recovery code replaces the authenticator code, never the email code. |

## Pillar 2: protecting Nick legally

| # | Item | Status | Notes |
|---|---|---|---|
| 7 | Chain-of-custody record | **Finished + Changed** | The printout never opened (`noopener` made `window.open` return nothing). It now opens, and it describes only what the system really does. |
| 8 | Legal hold on served orders | **Fixed** | Was enforced by a flag anyone could send. Now the database itself refuses to delete, roll back or rewrite a held order or remove its proofs. Unlocking needs a fresh code, or the typed reference without 2FA, and it's logged and emailed. Verified live. |
| 9 | Client attestation and submission fingerprint | **Fixed** | Every new request would have failed: the database didn't allow the `attestation` entry type. Now allowed and stored. |
| 10 | Append-only attempts | **Changed** | All timeline entries are append-only, not only attempts, enforced by a database trigger and verified live. Corrections are added as new entries. |
| 11 | Hash chain over the timeline | **Fixed** | The "seal" was recalculated from the current data each time, so an edit would simply produce a new, valid-looking seal. Now each entry is chained with SHA-256 by the database when it's written, `verify_order_chain` detects any later change (verified live with a forged entry), and the seal is emailed to the client with the proof, as an outside copy. Plain SHA-256, not HMAC: the emailed copy is what anchors it. |
| 12 | Stamp late client changes | Done | A reply records the attempt count at that moment. |
| 13 | Deadline and best-efforts terms on the receipt | Done | In the confirmation email. The terms text itself is Nick's to approve. |

## Pillar 3: sessions and devices

| # | Item | Status | Notes |
|---|---|---|---|
| 14 | 15-minute auto-lock | **Changed** | A browser-side "memory wipe" mostly looks secure without being secure, and 15 minutes would sign Nick out constantly in the field. Instead the **server** signs out a device after 12 hours without activity. |
| 15 | Client "sign out all devices" | Done | |
| 16 | Sign-in and security-change alerts | Done | Every sign-in, 2FA change, recovery-code use, new codes and legal-hold unlock emails Nick. |
| 17 | Bind sessions to the browser identifier | **Declined** (removed) | It logs everyone out after each browser update, and anyone who steals a cookie can copy the identifier too. The cookies are already HttpOnly, Secure and SameSite=Strict. |
| 18 | Mask details on locked tracking pages | Done | The street number, full name and documents are hidden until the page is unlocked. |
| 19 | 60-second download links, logged | Done | |

## Pillar 4: trust features

| # | Item | Status | Notes |
|---|---|---|---|
| 20 | Check a file's fingerprint in the browser | Done (helper) | `NPS.verifyFileSha256`. Not on client pages yet: **Needs Nick**. |
| 21 | "Enterprise Security" panel | **Declined as written** / **Needs Nick** | Claims like "TLS 1.3", "Zero-Trust", "malware screening" and "device-bound sessions" aren't true of this site. Accurate wording could be drafted for Nick to approve. |
| 22 | `security.txt` | **Fixed** | Business name corrected, `www` canonical, expiry under one year, broken policy link removed. Check it on a Preview: the local server can't serve `/.well-known/`. |
| 23 | Printable vendor security brief | **Declined** (removed) | Same unverifiable claims as #21, and it was never linked anywhere. |
| 24 | Strip location data from client photos | Done | Removes EXIF and GPS from JPEGs before upload. |
| 25 | Client request to purge documents | Done | Logged and emailed to Nick, who decides using the existing delete tool. Held orders can't be deleted. |

## Also found and fixed in this pass
- **Unapproved front-page change:** the other session had added a "Client Login" link to the front page's top bar without Nick's approval. It's removed; the client portal still works at `/account.html`.
- **Migration file names** now match the versions the live database recorded, so a future `supabase db push` won't re-run them.
- **Live database:** all four pending migrations are applied, plus a small one for the pending authenticator secret. Supabase's security advisor reports 0 issues.
- **A broken page caught during testing:** the shared browser script lost three helpers in an edit during this pass. `npm test` now loads that script for real, not only syntax-checks it.

## DNS records to add (need your OK; DNS is in Vercel → Domains → nicksprocessservices.dev)
Nothing sends email from this domain yet, so these are safe to add now, and they block spoofing at once:

| Type | Name | Value |
|---|---|---|
| TXT | `@` | `v=spf1 -all` |
| TXT | `_dmarc` | `v=DMARC1; p=reject; adkim=r; aspf=r` |
| MX | `@` | `0 .` (a "null MX": this domain receives no mail; replies go to Outlook) |

When Resend is set up later, add the records Resend shows (a DKIM TXT at `resend._domainkey`, plus SPF and MX on `send`).
Its mail passes DMARC through DKIM, so these three records don't need changing.

## Questions for you and Nick
- **`nicksprocessservices.com` is live**, on Squarespace or Google DNS. Is it Nick's? If so, it needs the same three records,
  or should redirect to the `.dev` site.
- **Client accounts (`account.html`)** were built by the other session without a decision from you and Nick. While they
  exist, Supabase sign-ups must stay **on**, so ignore the earlier advice to turn them off. Decide whether to keep them
  before launch.
- **Turnstile, the in-browser file check (#20) and any trust panel (#21)** all change client-facing pages, so they need
  Nick's OK.

## Not tested yet
None of this has run against real Supabase Auth, Stripe, Resend or Vercel. Everything above ran against the local mock,
the real server helpers, and the live database through SQL. The Preview checklist in `docs/HANDOFF.md` still applies.
