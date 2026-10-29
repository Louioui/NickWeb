# Client accounts (demo first)

Clients use the same website: homepage Client Login → account.html → Create account → verify email → My requests. Nick keeps his separate staff login. No new domain is required.

## Current implementation

- Passwordless email verification with Supabase Auth; profile name and optional firm are display-only.
- api/client.mjs provides send-code, verify-code, session callback, me, list and logout actions. Production session tokens stay in a Secure (HTTPS), HttpOnly, SameSite=Strict cookie scoped to /api/client. No production tokens in localStorage.
- The server validates the user with Supabase Auth and requires email confirmation. Request summaries are queried using exact equality against the verified email; body email, user IDs and editable metadata cannot select another client's requests or grant staff access. Existing order intake normalizes emails to lowercase.
- My requests shows the latest 100 matching requests with search, active/completed filters and links to existing private tracking pages. Old tracking links remain usable. New request fills name, verified email and firm into empty form fields.
- No schema or RLS changes were needed. Requests are read through the existing server-only database client. Service credentials are never shipped to the browser.

## Demo

The separate static preview simulates account verification in the browser only, with IndexedDB persistence. It never calls Supabase, sends email, or creates real accounts. Client test code: 123456. Create an account with paralegal@example.com to see five sample requests; another test address starts with zero. Staff demo code remains 12345678 and uses a separate session.

Run npm test (88 existing checks plus 15 client-account checks), npm run build, then package with scripts/build-demo.mjs into a new empty directory. Deploy only that package to Vercel Preview.

## Before enabling real accounts

These steps have NOT been applied to production:

1. Configure SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in the intended server environment. Begin with a separate test project/data set; never put the service key in frontend assets.
2. Enable Supabase email authentication/signups. Configure custom SMTP for real recipient delivery. Include {{ .Token }} in the relevant signup/confirmation and magic-link email templates so both new and returning clients receive the numeric code. The page also accepts implicit-flow access/refresh callbacks; use the correct redirect settings for that flow.
3. Allowlist the exact test /account.html callback URL in Supabase Auth. Set the intended Site URL. Add the production callback only when the release is approved. Avoid broad redirect wildcards.
4. Verify actual email delivery, invalid/expired codes, single-use codes, cookie refresh and logout with two separate test inboxes. Verify accounts never see each other's requests, and cannot open Nick's dashboard. Provider rate limits and server-side send/verify/list rate limits apply.
5. Confirm whether a shared firm email is intended to grant access to every request submitted with that address. This implementation groups by verified email; it does not implement per-person firm membership, invitations, or delegated access.
6. Test actual iPhone Safari and complete the existing payment/upload/proof flow in the test environment before a separately approved release.

Production Supabase integration, real email delivery and real session expiry/revocation have not been exercised by the browser-only demo or mock tests.

References checked: https://supabase.com/docs/guides/auth/auth-email-passwordless and https://supabase.com/docs/reference/javascript/auth-verifyotp .
