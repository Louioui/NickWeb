# Demo UI/UX review — 28 October 2026

## Scope and release state

This pass improves the existing dashboard and client tracking experience. Changes are local to the working branch: no push, production deploy, database mutation, real email or real payment was performed. The homepage design and business wording are unchanged; its generated CSS was refreshed with `npm run build`.

The local server is `node scripts/dev-server.mjs 8877`. It reported MOCK mode and uses in-memory sample orders. `/__mock` provides sample tracking links and login instructions. Sample state resets when this server restarts. Do not enter real case details into a demo.

## Findings addressed

| Finding | Result |
| --- | --- |
| The deadline summary opened every active job | A dedicated Due soon filter matches the count and includes overdue jobs. Calendar-day comparisons do not depend on the current hour. |
| Notes and selected proof files disappeared when switching actions/jobs | Unsaved drafts are retained in memory for each job/action in the current tab. Discard clears the current draft. Leaving the page warns about unsaved work. Nothing is persisted to local storage. |
| Slow responses could show the wrong selected job | Opening requests uses a sequence guard; late responses from earlier selections are ignored. |
| Saves had little confirmation | Success feedback identifies the completed action. Partial proof uploads produce a warning instead of silent success. Saving blocks changes to that action until the response returns. |
| Search and list failures lacked recovery | Result counts, useful empty states, Show all requests, a refresh button and a last-updated indicator provide a route forward. Failed refreshes preserve the last list. |
| Tracking treated a connection failure like a broken private link | Retryable failures have a Try Again button. Invalid links retain the separate email-link recovery path. |
| A successful client reply had no acknowledgement | A reply confirmation explains that Nick will review the response. Failed file uploads are named. |
| Phone tracking stages were only numbers | All four stage labels remain visible with an accessible current-step indicator. |
| Long company names/actions widened the phone dashboard | Grid items can shrink, headings wrap, recap details stack, and action/filter controls scroll horizontally. |
| Background refresh could redraw a form after typing began | Both pages check the current draft/sending state again after asynchronous reads complete. |

## Verification

- `npm test`: existing 88 input/security checks passed.
- `npm run build` and `git diff --check` passed.
- Browser: local Chromium-based in-app browser; desktop and 390 × 844 phone viewport.
- Urgent summary: 1 urgent sample returned exactly 1 request, rather than all 4 active requests.
- Note draft survived switching actions and jobs, then saved to the mock timeline with confirmation.
- Selected proof file survived switching actions; Discard removed it.
- Two intercepted case requests were released in reverse order; the later-selected case remained visible.
- Network failure was simulated for both manual refreshes and the initial tracking load; existing content remained, retry recovered, and no invalid-link message was shown for a connection problem.
- Client reply was sent through the mock API and confirmed; a manual refresh during typing preserved the draft.
- Empty search recovered via Show all requests.
- A long company name fit within the phone viewport without horizontal page overflow.
- Axe WCAG A/AA checks: no violations in the dashboard and tracking states scanned. This is an automated scan, not a complete accessibility certification.

Temporary network interception/offline emulation is cleared after testing. Test files and screenshots stay outside the repository.

## Connected service observations

- Supabase project `wlbmtcrgftermdtwnbgb` reported ACTIVE_HEALTHY, with no security advisories. This was read-only.
- The Vercel connection could not access `devteam-1898`; its authorization-recovery call returned Team not found, and its team list was empty. No deployment was attempted.

## Recommended next work, in order

1. **A complete test-mode rehearsal with Nick.** Submit documents, review/ask for missing information, receive the reply, send a Stripe test payment link, record attempts, upload proof and download it as the client. Local mocks verify the interface; they do not prove real email delivery, Stripe webhooks or storage integration. Include his actual iPhone and Safari.
2. **Make Nick's field workflow effortless.** Validate whether the most-used actions are Log attempt, Directions, Call client and Upload proof; prioritize those based on his actual use. Any further public homepage/content changes should be reviewed with Nick.
3. **Secure login and installation.** Add passkeys and recovery after the Phase 1 integration is proven, then an installable dashboard with an offline shell. Keep confidential case details and API responses out of offline caches.
4. **Polish failure cases in the request wizard.** In particular, if final notification retries fail after an order is created, make the confirmation precise about what succeeded and retain the private tracking link. Validate before changing the public flow.

Drafts in this pass are deliberately tab-memory only. Closing the tab does not save them. Real iOS Safari, actual email delivery, actual Stripe payment flows and production backend integration were not tested in this pass.
