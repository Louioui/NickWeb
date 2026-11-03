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

## Open questions for Nick and the owner

1. **Privacy policy and Terms.** In Origin and Nexus, the privacy policy still says requests are stored with Supabase and card payments go through Stripe. Those packages no longer collect anything online. This is Nick's legal copy, so it needs his rewrite; it was not edited here.
2. **The coverage map.** It is interactive, so it could be argued to belong to Nexus. It was kept in Origin because it is information, not motion. Say if Origin should get a plain list of counties instead.
3. **A contact form for Origin.** Origin has call, text and email links but no form. A form needs a server endpoint and spam protection. Decide whether Origin should include one.
4. **Selling the packages.** The Origin, Nexus and Aura pricing section described in the UI brief is for selling these packages to clients. It is not part of Nick's own page and was not added.
5. **Deploying a package.** Each `dist/<tier>/` folder is a static site, except Aura, which deploys like today. Hosting for an Origin or Nexus customer is not set up.
