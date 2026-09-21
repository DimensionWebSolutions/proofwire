# @proof_wire/proxy

A transparent MCP proxy that enforces policy and writes tamper-evident
receipts, plus the client that ships them to a Proofwire hub.

[![CI](https://github.com/proofwire/proofwire/actions/workflows/ci.yml/badge.svg)](https://github.com/proofwire/proofwire/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)

Most people want the [`proofwire`](https://npmjs.com/package/proofwire) CLI
instead — this is the library underneath it.

```js
import { McpProxy } from '@proof_wire/proxy';
import { RemoteSink, hubApprover } from '@proof_wire/proxy/remote';
```

It speaks MCP to both sides, so adopting it changes one line of config.
Everything that is not a `tools/call` is forwarded untouched — MCP gains
methods faster than any proxy can track, and one that only forwards what it
recognises breaks on the next release.

**A denied call never reaches the upstream server**, and the denial itself
becomes a receipt — which is the record that matters most, because it is proof
the guardrail existed and fired.

## Part of Proofwire

| Package | What it is |
| --- | --- |
| [`proofwire`](https://npmjs.com/package/proofwire) | The `pw` CLI — start here |
| [`@proof_wire/core`](https://npmjs.com/package/@proof_wire/core) | Receipts, Merkle log, policy engine. Zero dependencies. |
| [`@proof_wire/proxy`](https://npmjs.com/package/@proof_wire/proxy) | The MCP proxy and the hub client |
| [`@proof_wire/server`](https://npmjs.com/package/@proof_wire/server) | The multi-tenant hub |
| [`@proof_wire/dashboard`](https://npmjs.com/package/@proof_wire/dashboard) | Local read-only dashboard |

Full documentation: **https://github.com/proofwire/proofwire**

Apache-2.0. The format, the verifier and the CLI are open and stay open:
evidence you cannot verify without a vendor's permission is not evidence.
