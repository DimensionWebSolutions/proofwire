# Proofwire — the plan

> Positioning, pricing, and distribution. Written to be argued with.
> Regulatory dates below need re-verifying before they go in any customer-facing
> material — AI Act implementation timelines have already slipped once and
> several provisions are in flux.

---

## The one-sentence version

**Certificate Transparency for AI agents.** Free, open, and verifiable for
everyone; the neutral witness network and compliance layer are the business.

---

## Why now, specifically

Three things have to be true at once for this to work. In 2026 they are.

**1. Agents took the write path.** Through 2025 most production agents read.
They now refund, provision, email customers, merge pull requests, and move
money. The moment an agent acquired write access, "what did it do?" stopped
being a debugging question and became a liability question.

**2. The first incidents landed.** Every company running agents at scale has
now had at least one *our agent did what?* morning. The universal response is
to check the logs, and the universal discovery is that the logs are a text file
that anyone with production access can edit, held by the party with the
strongest motive to edit them.

**3. The regulatory floor is rising.** EU AI Act obligations phase in through
2026–2027 with record-keeping and human-oversight requirements attached. NIST
AI RMF and ISO/IEC 42001 both want demonstrable action records. SOC 2 auditors
have started asking how agent actions are evidenced. None of these mandate
Proofwire specifically — but all of them create a buyer whose job is to produce
evidence, and who currently has nothing to produce.

**The insurance angle is the sleeper.** AI liability cover is being written
now. Underwriters price what they can verify. A company that can hand an
insurer a witnessed, machine-checkable record of every agent action and every
guardrail that fired is a categorically better risk than one that cannot — and
that premium difference is a harder ROI number than any compliance pitch.

---

## The wedge

Not "buy our compliance platform." Nobody buys a compliance platform on a
Tuesday afternoon.

The wedge is a developer who is nervous. They install `proofwire`, wrap one MCP
server, and within a minute see their agent get blocked from running
`DELETE FROM customers`. That is a demo that survives being retold at standup.

```
BLOCKED  ops.query   destructive SQL from an agent is never permitted
```

This is the Sentry playbook: an individual engineer adopts it to sleep better,
and two quarters later someone in risk discovers it is already deployed and
asks who owns the contract.

**Why it spreads:** the failure it prevents is embarrassing, the integration is
one line, and the output is screenshot-shaped.

---

## Open vs. paid

The line is drawn on a principle, not on feature-gating: **evidence you cannot
verify without a vendor's permission is not evidence.**

| Always free, Apache-2.0 | Paid |
| --- | --- |
| Receipt format and spec | Hosted witness network |
| Verifier (`pw check`) | Managed log with retention and search |
| Policy engine | Compliance exports (AI Act / SOC 2 / ISO 42001) |
| MCP proxy, CLI, dashboard | SSO, RBAC, multi-tenant policy management |
| Self-hosted log | Approval workflows (Slack / Teams / PagerDuty) |
| Client SDKs | KMS/HSM signing, key rotation, BYOK |

The verifier must stay open or the whole proposition collapses. An auditor who
needs our SaaS to check a proof is trusting us, which is the exact thing the
product exists to avoid.

### The witness network is the real moat

Anyone can fork the code. Nobody can fork *independence*. A witness is only
worth anything if it is run by a party with no incentive to collude with the
log's owner — so the network's value rises with the number of mutually
distrusting participants in it, and that is a classic two-sided network effect
that a fork cannot replicate on day one.

Target witness operators: audit firms, cyber insurers, industry consortia, and
eventually regulators themselves. Each is a distribution channel as much as a
node.

---

## Pricing

| Tier | Price | For |
| --- | --- | --- |
| **Open** | Free | Self-hosted, self-witnessed. Complete and unlimited. |
| **Team** | $99/mo | 3 hosted witnesses, 1M receipts/mo, 1yr retention, Slack approvals |
| **Business** | $999/mo | 5 witnesses across orgs, 25M receipts, 7yr retention, compliance exports, SSO |
| **Enterprise** | from $60k/yr | BYOK/HSM, private witnesses, custom retention, audit support, SLA |
| **Witness operator** | Revenue share | Audit firms and insurers running nodes |

Metering on **receipts** rather than seats: it scales with the risk being
covered, the customer can predict it, and it does not punish adding teammates.

Rough unit economics: a receipt is ~1KB, one signature to write, one to
witness. Storage and compute are rounding errors against $999/mo at 25M
receipts. Gross margin should sit above 90% — this is a trust business, not an
infrastructure business, and the cost base should reflect that.

---

## Go to market

**Months 0–3 — earn the right to be believed.**
Ship the OSS. Publish the spec and the threat model, gaps included. Get a real
cryptographer to review the Merkle implementation and publish the review
unedited, findings and all. Credibility here is the product; a single "their
consistency proof is wrong" thread would be fatal.

Launch content, in order of expected reach:
1. *"Your AI agent's audit log is a text file. Here's what that costs you."*
2. *"We tried four ways to tamper with our own logs. Here's what caught each."*
3. *"Certificate Transparency, but for agents"* — for the infrastructure crowd.

Target: HN front page, 5k GitHub stars, 50 production deployments.

**Months 3–9 — meet the buyer.**
Launch the hosted witness network. Sign two audit firms and one cyber insurer
as witness operators — they bring distribution and credibility that no amount
of marketing buys. Publish an AI Act evidence-mapping guide that is genuinely
useful whether or not you use the product.

Target: 200 paying teams, $50k MRR, one named insurer partnership.

**Months 9–24 — become the format.**
Submit the receipt format as an IETF Internet-Draft. Get it referenced in one
procurement checklist or audit framework. The goal is that "Proofwire receipts"
becomes the noun, the way "SBOM" did — at which point the hosted network is the
default place to get them witnessed.

Target: $1M ARR, format cited in at least one standard or framework.

---

## Who else is in this

| Category | Examples | Why this is different |
| --- | --- | --- |
| LLM observability | LangSmith, Braintrust, Helicone | Optimised for debugging quality. Mutable stores; no adversarial integrity model; no enforcement. |
| Agent gateways | Various MCP gateways, AI firewalls | Some enforce. None produce third-party-verifiable evidence. |
| Transparency logs | Sigstore, Rekor, CT | Right primitives, wrong domain. Built for artifacts, not for runtime actions with policy and approvals. |
| GRC platforms | Vanta, Drata | Sell to the same buyer, but collect attestations *about* controls rather than evidence *from* them. Natural integration partners, not competitors. |

**The honest competitive risk:** an observability vendor bolts on signing and
calls it done. The defense is that the hard part is not the signature — it is
the append-only proof structure, the failure-mode discipline, the erasure
story, and a witness network of parties who distrust each other. Signing is a
weekend. Independence takes years.

---

## What would make this fail

Listed because a plan without this section is marketing.

1. **Nobody feels the pain yet.** The buyer for "prove what your agent did"
   may not have a budget line until after a public incident in their own
   industry. *Test:* do inbound requests mention audit and compliance unprompted
   within 90 days of launch? If every conversation has to be educated from
   zero, the wedge is wrong.

2. **The platforms absorb it.** If Anthropic, OpenAI, or the major clouds ship
   signed action logs natively, the standalone case narrows sharply. *Hedge:*
   be the neutral, cross-vendor format they can point at rather than a
   competitor to it. A customer running agents from three vendors needs one
   evidence trail, and no single vendor can credibly be the neutral witness.

3. **Verification stays theoretical.** If nobody ever actually runs
   `pw check`, this is elaborate logging with good marketing. *Test:* are
   auditors and counterparties running the verifier, or only the customers who
   wrote the logs?

4. **Cryptographic error.** One real bug in the consistency proof destroys the
   only thing being sold. *Mitigation:* exhaustive property tests (already
   covering every tree size to 64 and every consistency pair to 48), external
   review before any paid tier, and a published, funded bug bounty.

5. **Enforcement creates outages.** A policy that blocks something legitimate
   during an incident makes Proofwire the thing that gets removed first.
   *Mitigation:* ship a monitor-only mode, make policies testable against
   recorded traffic, and make removal obviously safe so the tool never becomes
   the outage.

---

## First five things to build next

1. **Hosted witness service** — the revenue mechanism and the moat. Scoped in
   [`docs/WITNESS-SERVICE.md`](docs/WITNESS-SERVICE.md): what already exists
   and is reusable, what's net-new, and which decisions (domain, hosting
   budget, billing provider, key custody) are business calls this repo can't
   make for you.
2. **Python SDK** — most agent frameworks are Python; the proxy covers MCP but
   the library needs to meet people where they are.
3. **Monitor-only mode** — removes the adoption objection entirely.
   *Built:* `pw proxy --monitor`. Receipts record what the policy would have
   done without claiming it did.
4. **Policy test harness** — `pw policy test` against recorded traffic, so
   policies get the same treatment as code.
   *Built:* `pw policy test [file] --fail-on-change` replays the log and lists
   every verdict the new policy would change.
5. **Compliance export** — AI Act Article 12 / SOC 2 evidence packs, generated
   from receipts. This is what turns a developer tool into a line item.
