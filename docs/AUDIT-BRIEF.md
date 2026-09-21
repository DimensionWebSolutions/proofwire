# Audit brief

**For a cryptographic reviewer.** This document exists to make a review cheap,
fast, and pointed — scope stated, ground truth identified, and the places I am
least sure about named rather than left to be found.

It is written in the knowledge that **I wrote both the implementation and its
tests**, which is exactly why an outside review is needed: the tests check what
their author thought to check.

---

## What to review

**~1,500 lines.** Everything else is plumbing around it.

| File | Lines | Why it matters |
| --- | ---: | --- |
| `packages/core/src/merkle.js` | ~330 | RFC 6962 tree, inclusion and consistency proofs. **The highest-value target.** |
| `packages/core/src/canonical.js` | ~110 | RFC 8785. If two parties disagree on bytes, every signature is arguable. |
| `packages/core/src/receipt.js` | ~330 | What is signed, what is chained, the salted commitments |
| `packages/core/src/hash.js` | ~76 | Domain separation |
| `packages/core/src/keys.js` | ~157 | Ed25519, and a hand-assembled DER SPKI header |
| `packages/core/src/checkpoint.js` | ~185 | Signed tree heads, witness co-signatures |
| `packages/server/src/store.js` → `ingest()` | ~120 | The four admission checks |
| `packages/server/src/app.js` → `/v1/witness/cosign` | ~100 | Split-view refusal, and its transaction boundary |

Out of scope unless you want to: the console, the CLI, the policy engine
(security-relevant but not cryptographic), backups.

## Running it

```bash
npm install          # zero external dependencies; installs 5 workspace links
npm test             # 207 tests
node --no-warnings=ExperimentalWarning packages/server/test/load.js
npm run demo         # attacks a real log four ways
```

No build step. Node ≥ 22.13 (where `node:sqlite` stopped needing a flag); the core needs
only ≥ 20.11 and has no dependencies at all.

---

## The claims, stated so they can be falsified

1. **A receipt cannot be altered undetectably.** Signed over its RFC 8785
   canonical form with Ed25519.
2. **An entry cannot be removed or reordered undetectably.** Hash chain plus
   sequence numbers.
3. **History cannot be rewritten undetectably once checkpointed** — even by an
   attacker holding the signing key, who can re-sign every receipt. The
   consistency proof against a published root is what closes this.
4. **A log operator cannot show two histories** to two auditors, given at least
   one honest witness.
5. **A receipt reveals nothing about its payload** beyond size and a redacted
   preview, and destroying salts makes payloads permanently unopenable while
   leaving every proof intact.
6. **The hub cannot forge a receipt**, because it never holds an agent's key.

Break any of these and the product is wrong. Claims 3 and 4 are the interesting
ones.

---

## External ground truth already checked

`packages/core/test/vectors.test.js` pins the implementation to published
values rather than to itself:

- **RFC 6962** — the Certificate Transparency reference tree (eight leaves of
  increasing length), all nine prefix roots, plus inclusion and consistency
  proofs verified against those roots.
- Two anchors derivable from the spec text with nothing to misremember:
  `MTH({}) = SHA-256("")` and `MTH({""}) = SHA-256(0x00)`.
- **RFC 8032** — Ed25519 TEST 1 and TEST 2, pinning the *signature bytes*, not
  merely that sign-then-verify round-trips. This also exercises the
  hand-assembled SPKI header in `publicKeyObject`, which is the one place raw
  DER is constructed by hand.
- **RFC 8785** — key ordering by UTF-16 code unit, `-0` normalisation,
  exponent forms, escape minimality.

Please check those constants against the source documents. A known-answer test
whose answers are wrong is worse than none.

---

## Where I would look first

Ordered by where I think a bug is most likely to be, not by severity.

### 1. `verifyConsistency` — the trailing-ones loop

```js
while ((fn & 1) === 1) { fn >>>= 1; sn >>>= 1; }
if (proof.length === 0) return false;
let i = 0;
if (fn !== 0) { fr = proof[i]; sr = proof[i]; i++; } else { fr = firstRoot; sr = firstRoot; }
```

This is the densest code in the project and the least self-evident. It is
exercised exhaustively for every `(m, n)` pair to n=48 and randomly beyond, but
exhaustive testing of a correct-looking implementation does not prove the
*rejection* side is tight. **Specifically: is there a proof shape that verifies
against a root it should not?** Length confusion and the `sn !== 0` terminal
check are where I would attack it.

### 2. The cached-level fast path in `inclusionProof`

Recently added to fix an O(n²) blow-up. It is asserted byte-identical to the
recursive reference for every tree size to 128 and randomly beyond — but the
equivalence of "pair adjacent, promote the odd one" to RFC 6962's
"split at the largest power of two" is an argument I made, not one I can cite.
**Is that equivalence actually total, or only for the sizes tested?**

### 3. Two-phase receipts and budget accounting

An allowed action writes an `intent` receipt before the call and an `outcome`
receipt after. Budgets aggregate over `intent` and skip `outcome`
(`History._relevant`). **Is there an interleaving where a budget is
double-counted or bypassed?** This fixed a real TOCTOU where pipelined calls
all evaluated against an empty ledger.

### 4. The witness transaction boundary

`/v1/witness/cosign` validates and *claims* the position inside one
transaction, then signs outside it, because signing may be a KMS round-trip.
The intended property: two concurrent requests offering different roots at the
same size cannot both be signed. **Is the claim actually atomic against SQLite's
isolation, and is failing-after-claim genuinely the safe direction?**

### 5. Salted commitments

`sha256(salt || canonical(value))`, salt 16 bytes, stored outside the signed
body. **Is 16 bytes enough, and is anything about the construction length-
extendable or otherwise weak given an attacker who knows the plaintext
distribution?** Note `preview` is stored in the clear and is best-effort
redaction — I treat that as a known, documented leak, not a defence.

### 6. `normalizeSignature`

Accepts hex, base64 and base64url from an external signer. **Can a crafted
string be coerced into 64 bytes that are not the signature the KMS produced?**

---

## Known limitations — no need to rediscover these

Documented in `docs/THREAT-MODEL.md`; repeated here so review time is not spent
confirming them:

- An attacker with the signing key can write **new** false receipts going
  forward. The chain proves consistency, not truthfulness.
- Proofwire records only what passes through it. An unwrapped path to the same
  API leaves no receipt.
- Timestamps come from the signing host. A uniformly wrong clock is not
  detectable from the log alone.
- Redaction is pattern-based and will not catch a secret shaped like prose.
- Witnesses are only as independent as the deployment makes them.
- A restored hub **cannot detect its own staleness** — the evidence was in the
  data the restore discarded. Only an outside party holding a later checkpoint
  can see it.

---

## Threat model in one paragraph

The adversary is **the operator of the log**, possibly holding the signing key,
with full write access to storage. They want to remove or alter a record of
something an AI agent did, after the fact, without an auditor detecting it. The
defender is a third party — an auditor, insurer, regulator, or opposing counsel
— who holds a bundle and at most one previously published root, and who
distrusts everyone involved.

## Publishing

The review will be **published unedited, findings and all**, including anything
you find that I got wrong. That is a condition of the engagement, not a
concession: a security product whose audit is summarised by its vendor has not
been audited in any sense a buyer should care about.

Findings can also be reported privately, under the policy in
[`SECURITY.md`](../SECURITY.md), through GitHub's private vulnerability
reporting.
