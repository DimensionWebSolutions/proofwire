# Is it ready, and how do we take it live?

> **Status: the four blockers below are closed.** What remains is the one
> thing that cannot be self-certified — an external review — plus the
> operational items in "needed soon". See the resolution notes under each.

**The standalone tool is ready to launch. The hosted hub is ready for design
partners running their own instance; a hosted service still waits on a
published external review.**

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
| Tests | **207** | Including published RFC 6962 and RFC 8032 vectors |

Capacity is not the constraint. A single hub process comfortably handles far
more agent traffic than any early customer will generate.

> **One caveat on these numbers:** bundle generation was originally 41 seconds
> for 4,000 receipts — an O(n²) mistake in proof generation that only a load
> test would ever surface. It is now 109 ms. Assume there are others that
> haven't been provoked yet; that is what design partners are for.

---

## The four blockers, and how each was closed

Three were fixable outright. The second was not, by definition — so the work
there was to make the review cheap and to reduce the risk it covers in the
meantime.

### 1. The hub's signing keys live in its database

Today `server_keys` holds the hub's and witness's private keys as PEM. Anyone
who obtains the database file can sign checkpoints as the hub.

**What it does *not* allow:** forging receipts. Agents hold those keys and the
hub never sees them. This is the design paying off — the worst case is bounded.

**What it does allow:** signing a checkpoint over a history the hub never held.
Independent witnesses catch this, which is precisely why they exist — but
defence-in-depth is not a substitute for key management.

**CLOSED.** `packages/server/src/signer.js` puts signing behind a three-member
interface — `{ kid, publicKey, async sign(digest) }` — with three backends:
`local` (unchanged default), `command` (a KMS CLI, a PKCS#11 tool, `vault
write` — anything that reads a digest on stdin), and `http` (a signing
sidecar). Configured with `PROOFWIRE_SIGNER`, per role, so the witness key can
live in different custody from the log key — which is what an independent
witness *should* do.

Three decisions worth noting:

- **A misconfigured signer disables signing; it never falls back to a local
  key.** Quietly minting a key nobody asked for would defeat the entire point
  of moving to a KMS.
- **Startup runs a real self-test** — a signature over a random digest,
  verified against the configured public key. That catches a missing command,
  a denied grant, the wrong key wired up, and an unexpected output encoding,
  all at boot rather than at the first checkpoint hours later.
- **A dead signer stops checkpoints and never stops ingest.** Receipts keep
  being accepted and verified; only the tree-head signature pauses.

Key rotation retires the old key and keeps it forever, so a checkpoint signed
last year still verifies. `/.well-known/proofwire` publishes every key,
retired ones included.

*Remaining:* the vendor-specific wrapper scripts (AWS KMS, GCP KMS, Azure Key
Vault) are one-file examples, not written yet.

### 2. Nobody independent has reviewed the cryptography

I wrote the Merkle implementation, the receipt format, and the tests that check
them. The tests are thorough — every tree size to 128, every consistency pair
to 48, byte-identical cross-checks between the fast and reference proof paths —
but they test what I thought to test. That is exactly the blind spot an
external reviewer exists to cover.

For a product sold on cryptographic assurance, shipping unreviewed to paying
customers would be selling the thing we haven't verified.

**STILL OPEN — and it cannot be closed from the inside.** What was done
instead:

**External ground truth.** `packages/core/test/vectors.test.js` now pins the
implementation to published values rather than to itself:

- The **RFC 6962 Certificate Transparency reference tree** — eight leaves of
  increasing length, all nine prefix roots, with inclusion and consistency
  proofs verified against those roots. Plus two anchors derivable from the
  spec text with nothing to misremember: `MTH({}) = SHA-256("")` and
  `MTH({""}) = SHA-256(0x00)`.
- **RFC 8032 Ed25519 TEST 1 and TEST 2**, pinning the *signature bytes* — not
  merely that sign-then-verify round-trips, which passes even when both halves
  are wrong the same way. This also exercises the hand-assembled DER SPKI
  header, the one place raw DER is built by hand.
- **RFC 8785** ordering, number and escape rules.
- **Randomized differential testing** across three structurally different
  implementations of the same tree.

This matters because every other test checks the implementation against
itself, which catches inconsistency but not a shared misreading of the spec.
It now provably produces the same bytes as every other RFC 6962 implementation
— the property an auditor running someone else's verifier depends on.

**A review brief.** [`AUDIT-BRIEF.md`](AUDIT-BRIEF.md) scopes the work to
~1,500 lines, states the six falsifiable claims, and names the six places I am
least confident — including the trailing-ones loop in `verifyConsistency` and
whether the new cached-proof equivalence is total or merely true for the sizes
tested. Naming them is the point: a reviewer should not spend their budget
rediscovering my own doubts.

**A disclosure policy.** [`SECURITY.md`](../SECURITY.md), with the in-scope
claims and the documented non-issues stated up front.

*Remaining:* commission the review and **publish it unedited**.
**3–6 weeks, mostly calendar time.**

### 3. Backup and restore is untested

`docs/HUB.md` says to back up the SQLite file. Nobody has actually restored
one and confirmed the result verifies.

There is a subtlety that makes this more than a checkbox: **a restore from a
backup that predates some receipts is indistinguishable, from the evidence
alone, from malicious truncation.** An auditor holding a later checkpoint sees
exactly the same failure either way. The runbook has to cover re-pushing from
each agent's local log — and that path needs to be exercised, not just written
down.

**CLOSED**, and the exercise turned up something that had been stated
imprecisely in the previous version of this document.

`packages/server/src/backup.js` plus four commands: `backup` (via
`VACUUM INTO`, so it is consistent without stopping writes and without the WAL
sidecars that make a naive `cp` subtly wrong), `verify-backup`, `restore`, and
`reconcile`. Scheduled backups with retention run in `serve`.

**The finding:** a restored hub *cannot detect its own staleness*. Not an
oversight and not fixable — the proof that the log once reached 18 entries
lived in the data the restore discarded. A hub rolled back to 10 is perfectly
self-consistent and has no way to know otherwise. Only a party holding later
evidence can see it: the **agent**, whose local log is longer, or a **witness
or auditor** holding a later checkpoint.

So `reconcile` now reports `selfReferential` and says plainly that a clean
result proves internal consistency and not currency, accepts
`--against <checkpoints.json>` for external evidence, and distinguishes a
**recoverable** gap (re-push from the agent — idempotent, and it self-heals)
from a **divergent** one (the history was rewritten; no re-push fixes that).
A restore is recorded in the hub's own hash-chained trail, which makes the
claim contemporaneous without ever excusing the gap.

Three other bugs the exercise found: `verifyBackup` opened backups read-write,
running migrations and breaking the very digest that proved them intact;
restores clobbered the previous database instead of moving it aside; WAL
sidecars were left beside a restored file.

### 4. No password reset or invite flow

Users are created by an admin with a password set inline. There is no reset, no
email, no invitation. That is fine for a bootstrap and unworkable for a real
team the first time someone is locked out.

**CLOSED.** One table serves both, because they are the same object — a
single-use, expiring capability to establish a credential — and two
near-identical implementations would mean two places to get consumption wrong.

Four rules, each closing a specific hole:

- **The token is never stored, only its hash.** A database leak does not hand
  over a working reset link for every account.
- **Consumption is atomic**, so two racing submissions cannot both succeed.
- **Issuing a reset invalidates outstanding ones**, so a link an attacker
  already holds dies when the user asks for a new one.
- **Setting a password revokes every session.** A reset exists because the
  account may already be in someone else's hands.

Requesting a reset answers identically whether or not the address exists.
An invited account holds a membership an admin can see but cannot be signed
in to. Delivery is a webhook (`PROOFWIRE_NOTIFY_URL`) rather than built-in
SMTP, and the link is returned to the caller either way, so an admin is never
stuck behind a mail integration.

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

### Stage 2 — self-hosted hub with design partners (ready now)

Three to five teams run their *own* hub. They hold their own data; you hold
none. Blockers #3 and #4 apply here (#1 and #2 do not, because they operate
their own keys and accept their own risk knowingly).

- [x] Backup/restore runbook, drilled
- [x] Invite and password reset
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

**Standalone: ship it.** **Self-hosted hub: ready for design partners.**
**Hosted service: gated on one thing — a published external review**, which is
calendar time rather than engineering time.

The order still matters. The open-source launch is what earns the right to run
the hosted one, and it is not a delay.
