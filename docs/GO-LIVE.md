# Is it ready, and how do we take it live?

**Short answer: the standalone tool is ready to launch. The hosted hub is not
ready to hold anyone else's data yet, and the gap is four specific things.**

This document is deliberately blunt about what is and is not done. A product
whose entire value proposition is "you don't have to take our word for it"
cannot ship a readiness assessment that asks you to take its word for it.

---

## What was actually measured

Run `node --no-warnings=ExperimentalWarning packages/server/test/load.js` to
reproduce. Numbers below are from a 4-core i5-10210U laptop — a floor, not a
ceiling, and a server will be several times better.

| | Measured | Read as |
| --- | --- | --- |
| Receipt signing (agent side) | 5,900/s | 0.17 ms added per tool call. Invisible next to any real tool. |
| Ingest, batched 200 | 2,300/s | ~200M receipts/day per process |
| Ingest, 16 concurrent agents | 1,660/s | No lock contention, no errors |
| Inclusion proof | 9,500/s | Proof-on-demand is free |
| Evidence bundle, 4,000 receipts | 109 ms | Exports are interactive |
| Self-audit, 4,000 receipts | 1.1 s | ~4.5 min per million — a background job, not a request |
| Storage | 2.5 KB/receipt | 1M receipts ≈ 2.3 GB |
| Cold tree rebuild, 4,000 leaves | 29 ms | Restart cost is negligible |
| Dependencies | **0** | 5 workspace packages, nothing from the registry |

Capacity is not the constraint. A single hub process comfortably handles far
more agent traffic than any early customer will generate.

> **One caveat on these numbers:** bundle generation was originally 41 seconds
> for 4,000 receipts — an O(n²) mistake in proof generation that only a load
> test would ever surface. It is now 109 ms. Assume there are others that
> haven't been provoked yet; that is what design partners are for.

---

## Blocking: hosted service

Four things. Nothing here is research — all four are known work.

### 1. The hub's signing keys live in its database

Today `server_keys` holds the hub's and witness's private keys as PEM. Anyone
who obtains the database file can sign checkpoints as the hub.

**What it does *not* allow:** forging receipts. Agents hold those keys and the
hub never sees them. This is the design paying off — the worst case is bounded.

**What it does allow:** signing a checkpoint over a history the hub never held.
Independent witnesses catch this, which is precisely why they exist — but
defence-in-depth is not a substitute for key management.

*Fix:* a KMS/HSM signer interface. The format only ever needs a `sign(bytes)`
operation, so this is an adapter, not a redesign. **Estimate: days.**

### 2. Nobody independent has reviewed the cryptography

I wrote the Merkle implementation, the receipt format, and the tests that check
them. The tests are thorough — every tree size to 128, every consistency pair
to 48, byte-identical cross-checks between the fast and reference proof paths —
but they test what I thought to test. That is exactly the blind spot an
external reviewer exists to cover.

For a product sold on cryptographic assurance, shipping unreviewed to paying
customers would be selling the thing we haven't verified.

*Fix:* commission a review of `packages/core` (roughly 1,500 lines, the part
that matters) and **publish it unedited, findings and all**. That publication
is also the strongest marketing asset this product can have.
**Estimate: 3–6 weeks, mostly calendar time.**

### 3. Backup and restore is untested

`docs/HUB.md` says to back up the SQLite file. Nobody has actually restored
one and confirmed the result verifies.

There is a subtlety that makes this more than a checkbox: **a restore from a
backup that predates some receipts is indistinguishable, from the evidence
alone, from malicious truncation.** An auditor holding a later checkpoint sees
exactly the same failure either way. The runbook has to cover re-pushing from
each agent's local log — and that path needs to be exercised, not just written
down.

*Fix:* automated backup, a tested restore runbook, and a drill.
**Estimate: days.**

### 4. No password reset or invite flow

Users are created by an admin with a password set inline. There is no reset, no
email, no invitation. That is fine for a bootstrap and unworkable for a real
team the first time someone is locked out.

*Fix:* invite tokens and password reset. **Estimate: days.**

---

## Needed soon, not blocking a launch

- **High availability.** A hub outage doesn't stop agents — they keep running
  and keep recording locally, by design. But it does stop *approvals*, and
  escalations fail closed, so agents block on escalated actions. That is
  correct behaviour and still an availability problem worth engineering.
- **SSO (SAML/OIDC).** The first enterprise buyer will ask on the first call.
- **A metrics endpoint.** Structured JSON logs exist; Prometheus does not.
- **Incremental self-audit.** 4.5 minutes per million receipts is fine now and
  won't be at 100M.
- **Retention and archival.** Logs grow forever by design. Customers will want
  cold storage with proofs intact.
- **`node:sqlite` is still flagged experimental upstream.** Stable in practice,
  small API surface here, but worth tracking — and worth a Postgres backend
  before anyone bets a compliance programme on it.

---

## The staged path

The key insight: **these stages carry very different risk, and the first two
carry almost none.** Don't gate a launch on hosted-service requirements.

### Stage 0 — dogfood (now, 1 week)

Run it against your own agents. `pw init`, wrap one real MCP server, leave it a
week. You will find things no test does.

Ship nothing. Fix what you find.

### Stage 1 — open-source launch, standalone only (2–4 weeks)

Publish the repo and the npm package. **No hosted service, so no customer data
and no liability.** Every claim in the README is checkable by the person
reading it.

- [ ] Repo public, `npm publish` the CLI
- [ ] `docs/THREAT-MODEL.md` prominent — leading with limits is the credibility play
- [ ] Launch posts: *"Your agent's audit log is a text file"* → *"We attacked our own log four ways"*
- [ ] CI running the full suite on every push

**Success looks like:** HN front page, stars, and — more important — people
actually running `pw verify`. Track that.

### Stage 2 — self-hosted hub with design partners (4–8 weeks)

Three to five teams run their *own* hub. They hold their own data; you hold
none. Blockers #3 and #4 apply here (#1 and #2 do not, because they operate
their own keys and accept their own risk knowingly).

- [ ] Backup/restore runbook, drilled
- [ ] Invite and password reset
- [ ] Monitor-only mode — removes the "what if it blocks something real"
      objection entirely, and it is the single highest-leverage adoption fix
- [ ] Weekly contact with every partner

**This is where you learn whether anyone verifies anything.** If no auditor
ever runs `pw check`, the premise is wrong and better to know now.

### Stage 3 — hosted service (3–6 months)

All four blockers closed, security review published, a witness network with at
least one operator who isn't you.

Only now does the business model in `BUSINESS.md` switch on.

---

## What is genuinely solid

Not everything is a caveat. These are done and tested, not aspirational:

- **The cryptography.** RFC 6962 Merkle with exhaustive verification, RFC 8785
  canonicalization, Ed25519, domain separation against second-preimage
  splicing. 152 tests.
- **The enforcement path.** Policy evaluates before the call is forwarded; a
  denied call provably never reaches the tool.
- **Tenant isolation.** Every row names its org; cross-tenant access is refused
  by id, by slug, and by filter. Tested from all three directions.
- **The failure modes.** Escalation without an approver denies. A typo'd
  operator is a load error. A budget nothing can compute warns at startup.
  Every one of these was chosen so the unsafe direction is the one that breaks
  loudly.
- **The trust model.** The hub cannot forge a receipt and cannot stop an agent
  working. That is what makes "self-hosted first, hosted later" a real strategy
  rather than a retreat.

---

## The honest one-line answer

**Standalone: ship it in two weeks.** **Hosted: three to six months, gated on a
published security review.** The order matters — the open-source launch is what
earns the right to run the hosted one, and it is not a delay.
