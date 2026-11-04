# Website packages: Origin, Nexus, Aura

`npm run build:tiers` builds three packages from the one source page into `dist/`. `dist/` is gitignored, so Vercel never serves it, and the live site is unchanged. `scripts/check-tiers.mjs` runs as part of `npm test`. It rebuilds the three packages and checks each one.

| Package | Price | What's in it | What's left out |
|---|---|---|---|
| **Origin** | $550 | The public landing page, static: hero, services, how it works, the coverage ZIP checker and map, service fees, reviews, FAQ, legal dialogs, and a **Contact Nick** section with call, text and email | The motion layer, every CSS animation, and the whole private platform |
| **Nexus** | $2,800 | Origin plus the motion layer: the rosette canvas, parallax, scroll reveal, the running-logo sprite and the CSS effects, all of which respect reduced motion | The private platform |
| **Aura** | $4,500 | The live site exactly: Origin, Nexus, the online request form with uploads and payments, order tracking, client accounts, Nick's dashboard and the `api/` functions | Nothing |

## How it works

`scripts/build-tiers.mjs` cuts sections out of `index.html`, using exact text from the page as anchors. Each anchor must match exactly once. If the page changes so that an anchor no longer matches, the build fails and nothing gets shipped half-stripped.

Origin and Nexus are built from a list of allowed files. They get no `api/`, no private pages, no `sw.js` and no `vercel.json`.

## What the checks prove

- Aura's page is the live `index.html`, byte for byte.
- Origin and Nexus contain no `/api/` calls, Stripe or Supabase code, request form, tracking or private-page links.
- Every inline handler in Origin and Nexus calls a function the page defines.
- Every `#` link in Origin and Nexus points at an element that exists.
- The contact section uses only CSS classes the page's stylesheet defines.
- Nexus keeps the motion layer and its reduced-motion branch.
- Origin has no motion code, no canvas, and CSS animations switched off.

Disabling a single cut in the build (the tracking dialogs) makes 4 checks fail.

## Checked in a browser (local static server)

- **Origin and Nexus:** no console errors, no sideways scrolling at desktop or phone width, and no hidden sections.
- **Origin's plan buttons** scroll to the contact section.
- **The ZIP checker** works.
- **The contact buttons** are 236 by 48 pixels on a phone.

## How a customer buys and upgrades

**Buying.** The customer pays on the owner's site, partnershipwithmedia-dev.com, through the owner's Stripe account. The link to send is `https://partnershipwithmedia-dev.com/buy/<origin|nexus|aura>?site=<their domain>`. It shows the package and price for their site. Stripe only opens when they press Buy. The owner gets an email naming the package, the buyer and the website. The website comes from the link, so check the buyer's email matches the client.

**Delivery and upgrades are done by the owner, by hand.** Payment does not change the client's site by itself. Each package is a different deployed site, and Aura also needs its own database, keys and Stripe setup.

| Step | Origin or Nexus | Aura |
|---|---|---|
| Build | `npm run build:tiers` | same |
| Deploy | Upload `dist/<tier>/` to the client's Vercel project with `vercel deploy --prod` from that folder, or the dashboard | Deploy the repo, then set up Supabase (apply `supabase/migrations/`), the Vercel environment variables, the client's own Stripe keys and webhook, Resend and `CRON_SECRET` (see `docs/HANDOFF.md`) |
| Domain | Point the client's domain at that project | same |
| Time | Minutes | About an hour, plus verifying the email domain |

**Upgrading** (for example Origin to Nexus or Aura): the client pays the new package, or the difference if you offer upgrade credit. You then deploy the bigger package to their project, or move their domain to it. Their old deployment stays in Vercel, so going back is just moving the domain back.

**Why it isn't automatic.** A payment could trigger a Vercel deploy hook. That's only practical for Origin and Nexus, and the website on the buy link is unverified, so an automatic deploy could change a site its buyer doesn't own. Aura can't be automated at all: it needs a database and the client's own payment keys. Delivering by hand also gives a check that the payment is real and matches the client.

**Nick (2026-11-03):** bought Origin. `nicksprocessservices.dev` now serves `dist/origin/` from Vercel project `nickweb-origin`. The full site is still in project `nickweb`, without a domain. The Stripe webhook for his old payments was removed from the owner's account.

## Open questions for Nick and the owner

1. **Privacy policy (done 2026-11-03).** The Origin and Nexus builds now get their own privacy policy: no online collection, what Nick receives by phone, text or email, Vercel hosting and OpenStreetMap map images. Aura keeps the full policy. `check-tiers` fails if the Origin or Nexus policy mentions Supabase, Stripe, Resend, uploads or the tracking page. Nick should still read it over, since it's his legal text.
2. **The coverage map (decided: keep it).** It stays in Origin as coverage information, alongside the ZIP checker. Only the motion layer goes.
3. **A contact form for Origin.** Origin has call, text and email links but no form. A form needs a server endpoint and spam protection. Decide whether Origin should include one.
4. **Selling the packages.** The Origin, Nexus and Aura pricing section described in the UI brief is for selling these packages to clients. It is not part of Nick's own page and was not added.
5. **Deploying a package.** Each `dist/<tier>/` folder is a static site, except Aura, which deploys like today. Hosting for an Origin or Nexus customer is not set up.
