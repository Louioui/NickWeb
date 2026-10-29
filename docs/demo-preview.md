# Isolated Vercel demo preview

Deployment: `dpl_DaU6WBnizQBpq9B637hxk8inH1am`  
Preview: https://nickweb-6y7786jit-devteam-1898.vercel.app/demo.html  
Project: `devteam-1898/nickweb`  
Environment: Preview. No production promotion, domain reassignment, Git push, Supabase write, email or card charge.

The deployment includes the current local UI/UX changes based on `c82f230`; these source changes remain uncommitted. A separate static package was uploaded through the CLI. The production target was compared before and after and was unchanged.

## How the demo works

- `scripts/build-demo.mjs` copies the four current pages and assets to a separate empty directory, injects a browser-only runtime, and generates a demo hub and simulated checkout.
- `scripts/demo-browser-runtime.js` runs the existing mock API and pricing/status rules inside the browser. It has no real database, email or payment credentials. It uses IndexedDB to keep sample requests and test files across pages and reloads in that browser. Supported browsers use a Web Lock to serialize changes across tabs.
- API calls are intercepted locally. The hosted package has **no API functions**. Direct HTTP requests to `/api/admin` and `/api/request` returned 404, as did `/.env.local`.
- The generated CSP restricts connections to the preview's own origin. Supabase, Resend and Stripe are not contacted. Map tile image requests are still allowed.
- Demo emails are suppressed. The sample login code is `12345678` for `nicksprocessservices@outlook.com`; it grants access only to browser-local sample data, not Nick's actual account.
- The hub links to sample tracking pages for each state. Links from one device do not access the other device's local samples. Use the hub on each device to get that device's links.
- The demo banner says to use test documents only. The Reset sample workspace button clears that browser's demo data after confirmation.

## Rebuild and preview

```sh
npm test
npm run build
node scripts/build-demo.mjs /absolute/path/to/a/new-empty-directory
```

Inspect the resulting package before deploying. It should contain only assets, HTML pages and the demo `vercel.json`; no `api/`, source secrets, database migrations or source videos. Use **Preview** explicitly with the existing project. Never promote this demo to production or point the live domain at it.

Vercel sign-in protection remains enabled. An expiring deployment-scoped review link was created for the user (23 hours); its access parameter is not committed here. The temporary project-wide automation bypass automatically created by `vercel curl` was revoked after verification, and its generated environment variable was confirmed removed.

## Verified

- Build and 103 automated checks pass (88 existing and 15 client-account checks); `git diff --check` passes.
- Local static demo: login and session across reload; complete new request to confirmation/tracking; client reply; simulated payment across page reload; proof upload, served status and file persistence across reload.
- Hosted preview: hub loads through the review link; login; urgency filter returns exactly the one urgent job; simulated payment reaches Paid; client reply receives confirmation.
- Hosted hub fits a 390 × 844 viewport with no horizontal page overflow. Resource inspection showed no requests to real Supabase, Resend, Stripe or API endpoints.
- No production deployment or real backend/payment integration was tested or changed. Actual iPhone Safari remains to be checked by Nick or the user.

This is a UI review environment. It does not verify real email delivery, Supabase integration, Stripe webhooks or production authentication.

## Client-account addition

The preview now includes account.html, the homepage Client Login entry, passwordless demo signup/sign-in, My requests with search/status filters, sign-out and contact prefill on New request. Demo code: 123456. See client-accounts.md for real Supabase setup and the exact boundary between mock validation and production integration.

Verified locally: wrong-code error, signup with five sample requests, reload persistence, second client with zero requests, sign-out, returning sign-in, search, completed filter and new-request prefill. Signup and My requests have zero axe WCAG A/AA violations in the exercised states. Mobile checks at 390 × 844 had no page overflow.

Final hosted account preview: signup with the demo code succeeds and shows five sample requests. Request links open the correct tracking page. The manual-refresh/reply race was exercised with a deliberately delayed demo response: the status says “Update paused while you reply. Your draft is kept.” and the typed draft remains. CodeRabbit completed its review of tracked changes; one valid minor tracking message issue was fixed. Its missing-account-page finding was dismissed because the new page exists in the workspace and was verified on the hosted preview (new files were not included in that review).
