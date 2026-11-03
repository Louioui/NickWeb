# ADR-001: Enforce Origin, Nexus, and Aura at the delivery boundary

**Status:** Accepted

**Date:** 2026-11-02

**Deciders:** Nick’s Process Services platform owner and engineering team

## Context

NickWeb is the live operational site for one process-service business. It already contains a customer-facing service-request flow and, in its full form, an Aura-grade private platform: client accounts, tracking, protected documents, payments, Nick’s dashboard, security controls, audit logs, and server-side APIs.

The commercial packages called **Origin**, **Nexus**, and **Aura** are packages sold *to a website client*. They are not service tiers selected by Nick’s process-service customers. Treating an individual process-service order as an Origin/Nexus/Aura subscription would conflate two unrelated domains and could deny a legitimate process-service client access to their own receipt, documents, or tracking page.

The risk to avoid is delivering the full Aura source, APIs, account pages, or private routes to an Origin or Nexus website buyer while merely hiding UI controls. A hidden button, a CSS rule, or a client-side feature flag is not a security boundary.

## Decision

Package separation is enforced at the build and deployment boundary:

| Package | Delivered scope | Must not be delivered |
| --- | --- | --- |
| Origin ($550) | Static responsive landing page and contact capability | `api/`, admin, tracking, client accounts, private documents, payment portal, Aura scripts and environment configuration |
| Nexus ($2,800) | Origin plus enhanced visual and interaction layer, including reduced-motion support | Every Aura private route, API, server secret, account or payment workflow |
| Aura ($4,500) | Origin + Nexus + the full protected operational platform | Nothing is hidden only in the browser; private behavior remains server-authorized |

The current repository is the **Aura source project**. An Origin or Nexus customer receives a deliberately reduced static build, not this repository with selected pages hidden.

## Options considered

### Option A — Hide Aura controls in the frontend

| Dimension | Assessment |
| --- | --- |
| Complexity | Low initially |
| Security | Unacceptable |
| Upgrade safety | Poor |
| Maintainability | Poor |

This fails because any copied URL, browser modification, or directly called endpoint can expose functionality that was only visually hidden.

### Option B — Store Origin/Nexus/Aura on process-service orders

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Security | Misaligned domain model |
| Upgrade safety | Poor |
| Maintainability | Poor |

This fails because process-service service tiers and web-development packages are different products with different owners, billing, and access rules.

### Option C — Produce package-specific deployment artifacts

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Security | Strong |
| Upgrade safety | Strong |
| Maintainability | Strong |

This is the chosen design. Origin and Nexus artifacts are static and do not contain Aura backend code. Aura is deployed with its APIs, database migrations, and secure environment configuration.

## Consequences

- An Origin or Nexus buyer cannot discover or call Aura API routes because they are not delivered with that build.
- Upgrading means replacing the package artifact with a verified Aura deployment and applying the associated migration and environment checklist; it is not unlocking a browser-only flag.
- The existing NickWeb repository remains Aura-first and must keep server-side authorization on every protected operation.
- The exact files delivered by each package become a testable release artifact.

## Required implementation and release checks

1. Build package-specific artifacts from clean source.
2. Assert Origin and Nexus artifacts have no `api/`, Supabase, Stripe, admin, tracking, account, or private-document code.
3. Assert Nexus includes the approved interactive layer and honors reduced-motion preferences.
4. Assert Aura includes all required API routes, migrations, and security checks.
5. Run the static artifact scan before delivery.
6. Deliver no `.env`, secret, database dump, source credentials, or service-role key with any package.
7. Use a separate staging deployment and test data before an Aura upgrade goes live.

## Open business decision

Upgrade pricing, crediting the $550 Origin purchase, deposits, refund policy, and ownership/hosting terms are commercial decisions. They must be recorded in a signed proposal or order form; they must not be inferred from browser state or stored only in frontend code.
