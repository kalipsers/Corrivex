# Corrivex — Dual License

Corrivex is offered under **two** licenses. You choose the one that fits how
you intend to use it.

| You are… | License you use | What you must do |
|---|---|---|
| A homelab / personal user | AGPL v3 | Use, modify and share freely. If you redistribute or expose Corrivex over a network, your modifications must also be AGPL. |
| A company using it for **internal** infrastructure | AGPL v3 | Same as above. **Internal use without external network exposure does not trigger the source-disclosure clause** of section 13, but the moment you let users (your customers, partners, the public) interact with a Corrivex-powered service over a network, you must publish your modifications under AGPL v3. |
| An MSP, SaaS provider, or any third party offering Corrivex (or a derivative) as a hosted/managed service | AGPL v3 | The AGPL "Remote Network Interaction" clause (section 13) requires you to make the **complete corresponding source** of the running system — including any private modifications — available to every user. |
| A vendor embedding Corrivex (or a derivative) inside a closed-source product, or any user who cannot accept the AGPL terms | **Commercial license** (contact the author) | Keep your modifications private, embed in proprietary products, ship without copyleft obligations. |

## Why dual licensing?

This model — pioneered by MongoDB, GitLab, and Grafana — keeps Corrivex
genuinely open for the community while funding ongoing development through
commercial licensing for parties that can't or won't comply with AGPL.

## Use-case matrix

| User type | Use it | Modify privately | Sell as service | Embed in product |
|---|---|---|---|---|
| Homelaber | ✅ | ✅ | — | — |
| Company internal | ✅ | ✅ | ❌ — publish required | ❌ — risky |
| MSP / SaaS provider | ✅ | ❌ — publish required | ❌ — publish required | ❌ — risky |
| Pays for commercial license | ✅ | ✅ | ✅ | ✅ |

## Buying a commercial license

Contact the maintainer (see GitHub repository). Commercial licenses are
typically structured per-deployment or per-seat; quotes available on
request. A commercial license grants:

- Permission to keep your modifications proprietary
- Permission to redistribute or host Corrivex-derived services without
  publishing source under AGPL
- Optional support, prioritised bug fixes, and feature roadmap input
  (terms vary)

## Default

If you have not negotiated a commercial license, **AGPL v3 applies** — see
the `LICENSE` file in this repository. Contributions made under
pull-requests are accepted under the AGPL v3 unless explicitly noted
otherwise; the maintainer reserves the right to relicense the project's own
code (not third-party contributions without permission) for commercial
distribution.
