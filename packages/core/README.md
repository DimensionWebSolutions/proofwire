# @proofwire/core

Signed, hash-chained, Merkle-anchored receipts for AI agent actions.
**Zero dependencies** — Node's standard library only.

[![CI](https://github.com/proofwire/proofwire/actions/workflows/ci.yml/badge.svg)](https://github.com/proofwire/proofwire/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)

```bash
npm install @proofwire/core
```

```js
import { ProofLog, Policy, History } from '@proofwire/core';

const log = ProofLog.open('.proofwire');
const decision = policy.decide(
  { kind: 'payment', target: 'stripe.refund', params, metrics: { amount_usd: 45 }, actor },
  new History(log.entries),
);

if (decision.outcome !== 'allow') {
  log.append({ actor, action, decision, result: null });
  throw new Error(decision.reason);
}

const result = await stripe.refunds.create(params);
log.append({ actor, action, decision, result: { status: 'ok', payload: result } });
```

## What is in here

| | |
| --- | --- |
| `canonical.js` | RFC 8785 deterministic JSON — two parties must produce identical bytes or every signature is arguable |
| `merkle.js` | RFC 6962 tree, inclusion and consistency proofs |
| `receipt.js` | The signed record, and salted payload commitments |
| `checkpoint.js` | Signed tree heads and witness co-signatures |
| `log.js` | Append-only file-backed log, audit, evidence bundles |
| `policy.js` | Declarative rules, budgets, rate limits |
| `redact.js` | Secret and PII detection |

## Verified against published vectors

Not only against itself. The **RFC 6962 Certificate Transparency reference
tree** (all nine roots, with proofs checked against them) and **RFC 8032**
Ed25519 test vectors, pinning signature bytes rather than round-trips.

## Part of Proofwire

| Package | What it is |
| --- | --- |
| [`proofwire`](https://npmjs.com/package/proofwire) | The `pw` CLI — start here |
| [`@proofwire/core`](https://npmjs.com/package/@proofwire/core) | Receipts, Merkle log, policy engine. Zero dependencies. |
| [`@proofwire/proxy`](https://npmjs.com/package/@proofwire/proxy) | The MCP proxy and the hub client |
| [`@proofwire/server`](https://npmjs.com/package/@proofwire/server) | The multi-tenant hub |
| [`@proofwire/dashboard`](https://npmjs.com/package/@proofwire/dashboard) | Local read-only dashboard |

Full documentation: **https://github.com/proofwire/proofwire**

Apache-2.0. The format, the verifier and the CLI are open and stay open:
evidence you cannot verify without a vendor's permission is not evidence.
