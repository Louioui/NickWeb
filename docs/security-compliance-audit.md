# Security & compliance audit: Nick's Process Services

Audit date: 2026-10-29. Branch `claude/nick-website-vercel-deploy-597e80`.
This is an engineering review, not legal advice. Items marked "for a lawyer" need a professional's sign-off.

**Scope of the site.** A public website with a service-request form, a private tracking page for each client
(no client accounts, just a private link), and a dashboard for Nick (8-digit emailed login code). It is hosted on Vercel,
not Netlify, with Supabase for the database and files, Stripe for one-time card payments and Resend for email.

| # | Item | Status |
|---|------|--------|
| 1 | Traffic and cost protection | Code done; 2 dashboard settings for you |
| 2 | Keyboard access and alt text | Fixed; 0 automated violations |
| 3 | Database row-level security and policies | Fixed and verified from outside |
| 4 | SMS (TCPA) and email (CAN-SPAM) | Not applicable today; email footer added |
| 5 | Infinite loops and recursion | Checked; nothing unbounded |
| 6 | Tracking pixels and cookie banner | Not applicable: there are no trackers |
| 7 | Children (COPPA) and age gate | Not applicable: no sign-ups; privacy text added |
| 8 | Self-hosted fonts | Fonts already local; icons and map library now local too |
| 9 | Session replay | Not applicable: none installed |
| 10 | Auto-renewal (California ROSCA) | Not applicable: one-time payments only |
| 11 | DMCA agent | Not needed today; when it would be is noted below |
| 12 | Data export and deletion | Built into Nick's dashboard |
| 13 | Dependency audit | 0 vulnerabilities |

---

## 1. Traffic and cost protection

**Done in code**
- `vercel.json` → `functions`: every API call is capped at **10 seconds**, so a stuck or abused request can't build up
  compute time.
- `vercel.json` → `headers`: self-hosted fonts and libraries are cached for a year (`immutable`), so repeat visits and
  Vercel's edge serve them without using origin bandwidth. Pages were already served from Vercel's edge cache
  (`x-vercel-cache: HIT`).
- Each IP is rate-limited in the database: 8 requests an hour, 6 tracking-link lookups per 15 minutes, 5 login-code
  emails per 15 minutes, and 120 tracking-page calls per 10 minutes. Vercel overwrites the IP headers, so a visitor
  can't fake their IP to dodge the limits.
- Vercel's platform DDoS mitigation is on for every project and costs nothing extra.

**You need to do this in the Vercel dashboard (account settings; I didn't change these)**
1. **Settings → Billing → Spend Management:** set a monthly limit and turn on *Pause production deployment* when it's
   reached. This is the "circuit breaker" that guarantees no surprise bill.
2. ~~Project → Firewall rate-limit rule~~ **Done 2026-10-29:** "Rate limit /api/ requests" (path starts with `/api/`,
   60 requests per 60 seconds per IP, fixed window; over the limit, deny for 15 minutes). Vercel charges $0.50 per
   million requests it lets through; blocked requests are free. If the site is ever flooded, turn on
   **Attack Challenge Mode** on the same page.
3. Optional: add a bot check to the request form (Cloudflare Turnstile or Vercel BotID). That stops automated
   submissions that per-IP limits can't.

## 2. Keyboard access and alt text

- **Fixed:** the form's 1-2-3 step indicator was clickable with a mouse only. Its steps are now real buttons that work
  with Tab and Enter (`index.html`).
- **Fixed:** moving to the next step puts focus on that step's first field. Opening a job in the dashboard focuses
  its title (`index.html`, `admin.html`).
- **Fixed:** a field that fails validation is marked `aria-invalid`, so screen readers announce it (`index.html`).
- **Fixed:** the decorative animated canvas is now `aria-hidden` (`index.html`).
- **Already correct:**
  - every `<img>` has alt text: the logo is described, the decorative running-man strip has `alt=""`;
  - pop-ups keep focus inside, close with Escape and return focus to where it was;
  - focus rings are visible everywhere (`:focus-visible`, 2px);
  - all close buttons are labelled.
- **Verified:** axe-core 4.10.2 (WCAG 2.0, 2.1 and 2.2 A/AA) found **0 violations** on:
  - the homepage, each form step, the tracker, the Terms and Privacy pop-ups, and the mobile menu;
  - the tracking page in its Served and Action-required states;
  - the dashboard list and all 7 job tabs.

  I also checked with real keystrokes: Enter on a step button, Tab staying inside a pop-up, and Escape closing it and
  returning focus.

  Automated tools catch about half of accessibility problems. A screen-reader pass (VoiceOver) by a person is still
  worth doing before launch.

## 3. Database row-level security and policies

**Found:** RLS was on for all 6 tables, with no policies, which means "deny all". But Supabase also gives the public
`anon` and `authenticated` roles full table privileges by default, so RLS was the only lock.

**Fixed** (migration `20261029050000_deny_public_roles_defense_in_depth.sql`, applied to the live database):
- Took all table, sequence and function privileges away from `anon` and `authenticated`, now and for tables created
  later (default privileges).
- Added a **restrictive** `deny public roles` policy on every table (`using (false) with check (false)`). Restrictive
  policies combine with AND, so even a permissive policy added by mistake later can't open a table.
- The site's server uses the `service_role`, which still has full access and bypasses RLS by design. The key lives
  only in Vercel environment variables, never in the browser.

**Verified from outside** with the public key:
- Reading or inserting into `orders`, `order_files` or `admin_sessions` returns **permission denied (42501)**.
- Storage uploads are refused, and the `case-files` bucket is private.
- Supabase's security advisor reports **0 issues**.

**You:** in Supabase → Authentication, turn off "Allow new users to sign up". The site doesn't use Supabase Auth.

## 4. SMS (TCPA) and email (CAN-SPAM)

- **SMS:** the site sends **no text messages**. There's no SMS provider in the code, and the phone number is used only
  so Nick can call clients himself. *If automated texts are ever added:* add an unchecked opt-in checkbox with the exact
  consent wording, store the consent with a timestamp, and honor STOP. That's one for a lawyer.
- **Email:** every email the site sends is **transactional**: confirmations, status updates, payment requests and
  login codes for a request the person made. CAN-SPAM's unsubscribe requirement applies to commercial and marketing
  email, and the site sends none.
  - Each email now ends with a footer: "You're receiving this because a service request was made … with this email
    address. It's about that request only; we don't send marketing emails. If you didn't make this request, reply and
    let us know." (`api/_lib/orders.mjs`, in both the HTML and plain-text versions.)
  - Web addresses typed into the form are stripped from emails, so the form can't be used to send scam links.
  - *If marketing email is ever added:* use a separate sending stream with a one-click unsubscribe (`List-Unsubscribe`
    and `List-Unsubscribe-Post` headers) and Nick's postal address.

## 5. Infinite loops and recursion

There are no recursive functions. Every loop has a fixed upper bound:
- **Browser:**
  - `goToStep` runs at most 2 steps, and a bad number stops it immediately;
  - the tracking page refreshes every 20 seconds and the dashboard every 30, and both pause while the tab is hidden;
  - updates between open tabs come from changes only, never from reads, so two tabs can't trigger each other forever;
  - the request form retries its last step **once**.
- **Animations** (`requestAnimationFrame`) run only on screen and stop when the visitor prefers reduced motion. They
  run in the visitor's browser and cost the server nothing.
- **Server:**
  - creating a request retries a clashing reference number up to 4 times;
  - at most 10 files per request;
  - the daily cleanup handles at most 100 files per run;
  - every API call is capped at 10 seconds (item 1).
- There is no React or `useEffect`, so render loops can't happen.

## 6. Tracking pixels and cookie banner

There's nothing to gate:
- The code has **no** Meta or Google tags, analytics, heatmaps or marketing scripts. I searched for gtag, GTM, fbq,
  Hotjar, Clarity, Segment, PostHog and others.
- The public site sets **no cookies** and uses no local storage. The only cookie is Nick's dashboard login, which is
  essential, HttpOnly, and scoped to `/api/admin`.
- A cookie banner isn't needed. Adding one with nothing behind it would only mislead visitors.
- The privacy policy now says all of this plainly.
- *If analytics are ever added:* load them only after an explicit "Accept" click, and update the privacy policy.

## 7. Children (COPPA) and age gate

- There are no public accounts or sign-ups. Clients submit a request and get a private link, and the only login is
  Nick's.
- The site is for adults and legal professionals and isn't directed to children.
- The privacy policy now says so, and explains that information about a minor appears only when it's part of the legal
  documents being served (custody papers, for example).
- An age gate wouldn't protect anyone here, so none was added.

## 8. Self-hosted fonts

- The site's fonts (Libre Caslon and Montserrat) were **already self-hosted** under `assets/fonts`, and nothing loads
  from Google Fonts.
- **Fixed:** Font Awesome 6.5.1 (the icons) and Leaflet 1.9.4 (the map) were loaded from Cloudflare's CDN on every
  visit, which shared visitors' IP addresses with a third party.
  - Both now live in `assets/vendor/`, with their licenses included.
  - They came from the official npm packages. The Font Awesome file is byte-for-byte identical to what the site used
    before (its SRI hash matches).
- **One remaining third party:** the coverage map's background images come from OpenStreetMap's tile servers. The
  privacy policy now discloses this.
  - To remove it completely, the map could load only after the visitor taps "Show map", or be replaced with a static
    image. That's your call, since it changes how the page works.
- The browser lockdown (`Content-Security-Policy`) now allows only the site's own scripts and styles. On the homepage,
  OpenStreetMap is allowed for map images only.

## 9. Session replay

None is installed: no PostHog, FullStory, LogRocket, Hotjar or Clarity. *If one is ever added:* mask all inputs, and
record nothing on `track.html` or `admin.html`.

## 10. Auto-renewal (California ROSCA)

The site has **no subscriptions or recurring billing**. Every payment is a one-time Stripe Checkout for one request.
The amount and "Payment must be sent to effectuate service" appear right next to the Pay button. Nothing renews, so
there's nothing to cancel.

## 11. DMCA agent

- Clients' uploads are **private court documents** that only Nick can see. The site doesn't publish user content.
- The reviews on the homepage are reproduced from Google with names shortened, and each one links back to Google.
- The DMCA safe harbor (17 U.S.C. § 512(c)) protects *service providers that store and display content* for users, so
  a registered agent isn't needed today.
- *Register an agent if the site ever publishes uploads from users:* through the U.S. Copyright Office's DMCA
  Designated Agent Directory (dmca.copyright.gov). The fee is $6, and the registration must be renewed every 3 years.
  For a lawyer.
- **Worth checking with Google's terms:** whether reproducing the review text is allowed, or whether to embed it or
  link to it instead.

## 12. Data export and deletion

**Built.** This workflow is semi-automated, as the checklist asks:
1. A client asks by email or phone. The privacy policy now explains how: "To get a copy of the information we hold
   about your requests, or to have it deleted, email … or call …"
2. Nick searches the client's **email** in the dashboard. The search now covers email, and lists every request of
   theirs.
3. On each request, a new **Privacy** tab offers:
   - **Download all data (file):** a JSON file with the request details, the full timeline (including what was shown
     to the client) and the list of files. Secret keys such as the tracking code and payment link are left out.
   - **Delete permanently:** Nick types the reference number to confirm. The server removes every stored document
     first, and stops if that fails, so no file is ever left orphaned. It then closes any unpaid Stripe link and deletes
     the request together with its timeline and file records. Afterwards the client's tracking link stops working.
     Implemented in `exportOrder` and `deleteOrder` in `api/admin.mjs`.

**Tested** in the browser:
- the export contains the personal data and none of the secret keys;
- a wrong confirmation is refused and nothing is deleted;
- the right one deletes the request, and the client's link then returns "not found".

**Not deleted by this tool:**
- payment records in Stripe, which keeps them for tax and fraud reasons;
- delivery logs in Resend;
- server logs in Vercel, which no longer contain tracking codes.

**For a lawyer:** how long a registered process server must keep proofs of service. The tool warns Nick to check
before deleting.

## 13. Dependency audit

| Package | Version | Result |
|---|---|---|
| @supabase/supabase-js | 2.118.0 | 0 known vulnerabilities |
| stripe | 23.0.1 | 0 |
| tailwindcss (build only) | 3.4.17 | 0. Version 4 exists but is a full rewrite; it runs only at build time and never reaches visitors, so it stays put |
| Font Awesome (self-hosted) | 6.5.1 | 0 (checked separately; npm audit doesn't see vendored files) |
| Leaflet (self-hosted) | 1.9.4 | 0 (latest stable) |

`npm test` runs 88 checks on the server's input handling.

---

## Files changed in this pass

| File | Change |
|---|---|
| `index.html` | Step buttons work by keyboard; focus moves between steps; `aria-invalid`; canvas hidden from screen readers; icons and map self-hosted; privacy policy rewritten |
| `track.html`, `admin.html` | Icons self-hosted; dashboard focuses the opened job; search by email; Privacy tab (export and delete) |
| `api/admin.mjs` | `export` and `delete` actions; client email added to the job list |
| `api/_lib/orders.mjs` | "Why you got this email" footer in HTML and plain text |
| `scripts/mock-api.mjs` | Same export and delete in the local test server |
| `vercel.json` | 10-second limit on API calls; long caching for fonts and libraries; stricter lockdown with no CDN allowed; `/docs` not served |
| `assets/vendor/` | Font Awesome 6.5.1 and Leaflet 1.9.4, with licenses |
| `supabase/migrations/20261029050000_…sql` | Public roles' privileges removed; restrictive deny policies |
| `docs/security-compliance-audit.md` | This report |

## Still to confirm on a Vercel Preview before going live

- The same-site request check works on Vercel's real domain.
- Vercel accepts the redirect patterns that block internal files.
- The full lockdown header is the one actually sent on `track.html` and `admin.html`.
- The Stripe webhook is set up, and a test payment completes the return trip.
