# Scoping the hosted witness service

> Written before any of it is built, per `BUSINESS.md`'s own priority order
> (item 1 of "first five things to build next"). This is a scope, not a
> commitment — the parts marked **your call** are business or spending
> decisions this session cannot make.

---

## What this is, precisely

Not a new product. A witness is exactly what `packages/server` already does
when it's asked to `/v1/witness/cosign` instead of hosting a log — the
Dockerfile, the auth model, the split-view refusal, all of it already exist
and are tested (`packages/server/test/hub.test.js` covers the refusal logic;
this session's Docker work exercised it end to end across two real,
separately-bootstrapped containers with genuinely independent org/key state).

What doesn't exist is the *service* around that: something publicly
reachable, with keys a customer can trust, that someone gets billed for and
someone is paged for. That's four different kinds of work, and they don't
have to ship together.

---

## What's already there — reusable, not rebuilt

| Piece | Where | Status |
| --- | --- | --- |
| Split-view refusal (won't sign two roots at one size, won't sign a shrink, requires a consistency proof to grow) | `packages/server/src/app.js` → `/v1/witness/cosign` | Done, tested, exercised across two real containers this session |
| Witness identity / external signer (local, command, HTTP-to-KMS) | `packages/server/src/signer.js` | Done — the KMS/HSM path already exists, unused so far |
| Per-org, per-log witness state, durable via the same `VACUUM INTO` backup as everything else | `packages/server/src/db.js` (`witness_state` table), `packages/server/src/backup.js` | Done, with one caveat below |
| A witness-scoped credential (`witness:sign` + `logs:read`, nothing else) | `packages/server/src/auth.js` | Done — minted one by hand this session (login, `POST /v1/keys`, same-origin CSRF check and all) |
| A witness client, self-hosted side | `pw cosign --remote <name>`, `pw remote add` | Done |
| Docker image, health-checked, read-only rootfs, non-root, built and smoke-tested in CI | `Dockerfile`, `.github/workflows/ci.yml`'s `docker` job | Done |
| Witness-only mode and per-customer key issuance (Phase 0 below) | `PROOFWIRE_WITNESS_ONLY`, `WITNESS_ONLY_ROUTES` in `app.js`, `proofwire-hub witness-key` | Done — CI runs the image as a hub *and* as a separate witness-only node, co-signs the hub's checkpoint on the witness and verifies it with the witness key pinned |

**Nothing above needs to be rewritten.** The gap is entirely in what sits
around it.

---

## What's net-new

### 1. A witness-only deployment mode

`docker-compose.yml`'s `witness` service was the *whole hub image* — every
route (`/v1/logs`, `/v1/keys`, `/v1/approvals`, the console UI, org
creation) live, just unused by convention. That's fine self-hosted; it is
not fine as a thing Proofwire runs publicly and gets attacked. A node whose
only job is `/v1/witness/cosign`, `/v1/witness/key`, `/health` and `/ready`
should not also be exposing org/key administration.

**Done.** `PROOFWIRE_WITNESS_ONLY=1` keeps six routes — those four, plus
`/.well-known/proofwire` (which then publishes only the witness key) and
`/v1/me` (which `pw remote add` needs to prove a credential) — and 404s the
rest. The allowlist is one constant, `WITNESS_ONLY_ROUTES`, applied to the
route table after it's built, so a route added to the hub later is excluded
from a witness by default rather than exposed by default; the test that
checks it derives the list of routes that must be gone from a full hub's own
route table, for the same reason. A witness-only node creates no hub key at
all. `docker-compose.yml`'s witness service now sets the flag.

Keys can't be minted over HTTP on a witness-only node, so there's a host-side
command for it: `proofwire-hub witness-key <customer>` creates that
customer's organization and a key scoped to `witness:sign` + `logs:read`,
and prints the witness's own public key for the customer to pin. That is
Phase 1's "API keys issued by hand," made into one command instead of the
login-and-`curl` sequence this session used the first time.

### 2. Self-serve account and key issuance

There is currently no way to get a witness API key without someone running
`bootstrap` on a shell, or logging into the console and minting one by hand —
which is what this session did, manually, to prove the mechanism works.
There is no public signup at all: no `POST /v1/orgs`, no billing-gated key
issuance.

**Work:** a signup flow (email verification at minimum), and a key-issuance
path that's either free (beta) or gated on a Stripe subscription
(post-beta). This is the biggest net-new engineering piece and the one most
worth *not* over-building before Phase 1 proves anyone wants it — see the
phased plan below.

### 3. Public key transparency

This is the one that isn't optional, because it's the entire premise the
product is selling. A witness's public key served over its own API is a
witness vouching for itself — exactly the failure mode `verifyBundle`'s
witness-pinning exists to prevent (`docs/HUB.md`: "a bundle's own keyring
comes from the party whose honesty is in question, so it cannot vouch for
witnesses"). A customer needs to obtain
Proofwire's witness key from *somewhere other than the witness*, the same
way `docs/HUB.md` already insists on for self-run witnesses.

**Work:** publish each witness node's key where it can't be quietly changed
without it being noticed — committed to this git repository (so the commit
history is the audit trail), shown on the site next to a fingerprint, and
ideally submitted to a real transparency log (Sigstore's Rekor is the
obvious one — it's free, it's exactly this primitive, and using it instead
of reinventing it is consistent with `BUSINESS.md`'s own read on Sigstore
as "right primitives, wrong domain" — the domain matches here). A key
rotation needs a public, dated record, not a silent swap.

### 4. Billing and metering

`BUSINESS.md` prices per receipt, not per seat. The hub already meters
receipts per org per day (`usage_daily`) — but that's *hub* usage, and a
hosted witness needs its own metering: checkpoints witnessed, not receipts
ingested, since a witness never sees a receipt, only a root.

**Work:** a `usage_daily`-shaped table on the witness side (trivial,
same pattern), a Stripe integration for the Team/Business tiers'
subscription + overage, and — because `BUSINESS.md`'s Enterprise tier is
"from $60k/yr," clearly a sales conversation, not a self-serve checkout —
an invoicing path that doesn't assume everyone pays by card.

### 5. Witness-specific operational hardening

Three things that are true of a witness and not obviously true of a hub:

- **A witness's restore-from-backup problem is a security problem, not just
  an availability one.** `packages/server/src/backup.js`'s own documentation
  is explicit that a hub restored from a stale backup is "indistinguishable
  from malicious truncation" for *the log*. For a *witness*, the equivalent
  failure is worse: restored from a backup taken before it last saw size N,
  a witness could accept a checkpoint that shrinks relative to what it
  actually witnessed live, believing it's merely resuming from size N−k.
  The refusal logic checks the witness's *stored* state, not its true
  history — a restore silently rewrites that state. This needs a real
  decision, not a shipped assumption: one option is a rule that a witness
  never restores from backup at all, only rebuilds empty and refuses
  everything until it has independently re-synced enough state to trust
  itself again; another is a harder guarantee, with state replicated
  synchronously rather than backed up periodically. Neither is implemented
  or decided yet — this is a design gap, not a documented policy.
- **The witness didn't check the log's own signature — now it binds.** Found
  while building Phase 0: `/v1/witness/cosign` signed any well-formed
  checkpoint body that extended what it last saw for that organization and
  log name, so a witness's memory of a log belonged to whoever reached it
  first with a well-formed body. **Done:** the first request for a log must
  name its signing key (`logPublicKey`) and be signed by it; the witness binds
  the log to that key, in the same transaction that claims the position, and
  refuses any later checkpoint not signed by it. A rotation is rebound only on
  the host (`proofwire-hub witness-rebind`), recorded in the audit trail, and
  keeps the recorded position, so a new key has to extend what was attested
  rather than start over. Positions from before the change bind on their next
  successful co-signing. What's still first-use: the *first* key to reach the
  witness for a log name wins, which is why per-customer organizations stay.
  And it's a wire change: `pw` 0.2.0 doesn't send `logPublicKey`, so it
  can't start witnessing a new log against a 0.3.0 witness; `pw` 0.3.0 does.
- **Key custody.** A self-hosted operator can accept a local key file; a
  service Proofwire operates and charges money for should not have its
  witness key sitting in a container's SQLite file. `signer.js`'s
  `command`/`http` external-signer interface already exists for exactly
  this — the work is standing up a real KMS (cloud KMS, or a proper HSM for
  Enterprise-tier credibility) and wiring it in, not writing new code.

### 6. The partner-witness onboarding path

This is `BUSINESS.md`'s actual moat — "Nobody can fork *independence*,"
run by audit firms and insurers, not Proofwire itself, echoing
`docker-compose.yml`'s own instruction for the witness service: "run this
somewhere the hub's operator does not control." Technically this is close
to free: the software a partner runs *is* the
same open-source witness-only image from item 1, self-hosted by them,
their key published the same way (item 3). The work here is almost entirely
non-engineering — an onboarding doc, a directory page on the site listing
trusted witness operators, and a business-development conversation with the
first two firms, per `BUSINESS.md`'s Month 3–9 target.

---

## The honest problem this doesn't solve by itself

A witness node Proofwire operates, for a hub Proofwire doesn't operate, is
a different operator than the log's owner — which clears the *minimum* bar
(`docker-compose.yml`'s own comment on the witness service: "a witness on
the same host as the log it witnesses proves nothing about that log that
the log could not have claimed itself"). It does not clear the bar
`docs/HUB.md` sets a few lines further into that same file's Witnessing
section: "three witnesses on infrastructure the log operator controls
provide one witness's worth of assurance." Three Proofwire-run witnesses
are still one operator's worth of assurance if that operator is Proofwire. The Team
tier's "3 hosted witnesses" is honestly marketed as convenience and
redundancy, not as the independence story — that story is item 6, and it
runs on a much slower, partner-relationship clock than the engineering does.
Selling the Team tier without being clear about that distinction, even
internally, is how a credible product turns into an overclaim.

---

## Decisions that are yours, not this session's

I can write and test code; I can't provision paid infrastructure, pick a
cloud bill, or sign up for a billing provider on your behalf — and some of
these are genuinely business calls, not engineering ones:

- **A domain.** Everything today is `proofwire.github.io` (or
  `dimensionwebsolutions.github.io` before the org transfer). A witness node
  needs a real, stable hostname — `witness1.proofwire.<tld>` or similar —
  which means owning a domain, which nobody has bought yet.
- **Where it runs, and who pays for it.** Any cloud provider works; the
  unit economics in `BUSINESS.md` assume near-zero marginal cost, which is
  true for compute but not for zero — something has a bill attached.
- **A billing provider.** Stripe is the default assumption; worth confirming
  before code gets written against its API specifically.
- **Legal.** A paid service with an uptime-adjacent value proposition
  ("we'll catch a split view") wants terms of service that say what happens
  if the witness itself is down when it mattered, and a privacy policy for
  whatever the signup flow collects. Not blocking Phase 1 if Phase 1 is a
  free beta with no signed agreement, but blocking anything billed.
- **Key custody model and budget.** A real KMS/HSM is a recurring cost and
  a vendor relationship, not a code change.

---

## A phased path

**Phase 0 — witness-only mode. Done** (item 1): the flag, the route
allowlist, `witness-key`, `docker-compose.yml` using it, and a CI job that
runs the image as a separate witness-only node and verifies a real co-signed
checkpoint with the witness key pinned.

**Phase 1 — one node, free, manual.** One Proofwire-operated witness,
running Phase 0's image, on whatever infrastructure and domain get decided
above. No self-serve signup — API keys issued by hand, the way this session
minted one, the same way `bootstrap` already works. Free, explicitly
labelled beta. Key published in this repo and on the site (item 3, minus
Rekor for now — that can follow). This is enough to replace the pricing
page's "Get notified" waitlist with something real for the first cohort,
and enough to start Month 3–9's actual goal: proving anyone uses it before
building billing for it.

**Phase 2 — billed, multiple nodes.** Self-serve signup, Stripe metering,
the second and third nodes the Team tier promises, a public status page,
the backup/restore question in item 5 actually resolved rather than noted.

**Phase 3 — partner witnesses.** Item 6. Mostly business development with
a documentation checklist behind it; the software side is already what
Phase 0 built.

With Phase 0 and the log-key binding done, what's left before Phase 1 isn't
code: it's a domain and somewhere to run the node — plus a 0.3.0 release, so
the `pw` on npm speaks the binding. The next engineering candidate that needs
none of those decisions is publishing the witness key into this repository as
a dated, append-only record (item 3's first half), ready for the day there's a
real node's key to put in it.
