# @proofwire/dashboard

A local, read-only dashboard over a Proofwire log.

[![CI](https://github.com/proofwire/proofwire/actions/workflows/ci.yml/badge.svg)](https://github.com/proofwire/proofwire/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)

```bash
pw dash --port 7788
```

Read-only and loopback-only, both deliberately: this process can see the log
directory, which on a live machine sits next to the signing key.

Shows the receipt timeline, decisions and reasons, redacted argument previews,
and the inclusion proof for any entry.

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
