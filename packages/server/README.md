# @proofwire/server

The Proofwire hub: a multi-tenant transparency log, policy registry, approvals
inbox, and witness service.

[![CI](https://github.com/DimensionWebSolutions/proofwire/actions/workflows/ci.yml/badge.svg)](https://github.com/DimensionWebSolutions/proofwire/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)

```bash
npx @proofwire/server bootstrap
npx @proofwire/server serve
```

## The hub cannot forge a receipt

It never holds a signing key. Agents sign locally; the hub verifies every
receipt on arrival and stores only what it can verify. That leaves it able to
do exactly three dishonest things, each with a defence:

| What a malicious hub could try | What stops it |
| --- | --- |
| Alter a receipt | The signature fails |
| Drop or reorder receipts | The chain breaks; consistency proofs expose the gap |
| Show two customers two histories | Witness countersignatures |

And it is not load-bearing either: an agent whose hub is unreachable keeps
running, keeps recording locally, and ships the backlog when it returns.

## Also

- Keys can live in a KMS or HSM rather than the database (`PROOFWIRE_SIGNER`)
- Backups, verification, restore and reconcile
- Invitations and password resets
- Its own hash-chained audit trail for every administrative action

Deployment guide: https://github.com/DimensionWebSolutions/proofwire/blob/main/docs/HUB.md

## Part of Proofwire

| Package | What it is |
| --- | --- |
| [`proofwire`](https://npmjs.com/package/proofwire) | The `pw` CLI — start here |
| [`@proofwire/core`](https://npmjs.com/package/@proofwire/core) | Receipts, Merkle log, policy engine. Zero dependencies. |
| [`@proofwire/proxy`](https://npmjs.com/package/@proofwire/proxy) | The MCP proxy and the hub client |
| [`@proofwire/server`](https://npmjs.com/package/@proofwire/server) | The multi-tenant hub |
| [`@proofwire/dashboard`](https://npmjs.com/package/@proofwire/dashboard) | Local read-only dashboard |

Full documentation: **https://github.com/DimensionWebSolutions/proofwire**

Apache-2.0. The format, the verifier and the CLI are open and stay open:
evidence you cannot verify without a vendor's permission is not evidence.
