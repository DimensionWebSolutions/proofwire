# Proofwire

**Tamper-evident receipts for AI agent actions.**

Your agents spend money, send mail, and touch customer data. When something
goes wrong, "our logs say it didn't" is not an answer — your logs are a text
file you can edit.

Proofwire makes every agent action **policy-gated before it runs** and
**cryptographically provable afterwards**. One line of config. No code change.

Run it standalone on one machine, or as a **hub** your whole organisation
writes to — with shared policy, an approvals inbox, tenant isolation, and
independent witnesses that make a hosted log worth believing.

```bash
npm install -g proofwire
pw init
```

Then wrap any MCP server:

```jsonc
// .mcp.json — before
{ "command": "npx", "args": ["-y", "@acme/mcp-crm"] }

// after
{ "command": "pw", "args": ["proxy", "--namespace", "crm", "--", "npx", "-y", "@acme/mcp-crm"] }
```

That is the whole integration. Every tool call now hits your policy first, and
every decision — allowed, blocked, or escalated to a human — lands in an
append-only log that an outside party can verify without trusting you.

---

## See it in one command

```bash
git clone https://github.com/proofwire/proofwire && cd proofwire
npm install
npm run demo
```

The demo runs a real agent session through a real proxy, then attacks the
resulting log four ways and shows each attack being caught:

```
1. An agent works through a queue of tasks
  ran      ops.query        a harmless read
  ran      ops.refund       $45 refund — inside budget
  ran      ops.refund       $30 refund — $75 committed
  BLOCKED  ops.refund       $90 refund — would reach $165
           budget refunds.daily would be exceeded: 75 already committed plus 90 proposed…
  BLOCKED  ops.query        destructive SQL
  ran      ops.send_email   outbound mail            (approved by dana@acme.test)
  BLOCKED  ops.query        a live credential in the args

3. Four ways to cover your tracks, and what each one costs
  Edit a receipt in place    ✓ caught — signature does not verify
  Delete a receipt           ✓ caught — expected seq 6, found 8
  Re-sign the whole chain    ✓ caught — checkpoint covers 11 entries, log holds 8
  Truncate the log           ✓ caught — entries have been removed
```

---

## For teams: the hub

```bash
docker compose up -d
docker compose exec hub node packages/server/src/bin.js bootstrap
```

```bash
pw remote add --url https://hub.acme.com --token <agent token>
pw proxy --namespace crm -- npx -y @acme/mcp-crm
```

The proxy now fetches your organisation's active policy at startup, enforces
it, records locally, and streams receipts to the hub — where an operator sees
this:

```
Acme Financial                                          ✓ verified
  11 receipts · 30d      3 actions blocked      1 log      11 entries

  RECENTLY BLOCKED
  48s   ops.query    DENY   arguments contain anthropic_key; policy forbids sending these to a tool
  48s   ops.refund   DENY   budget refunds.daily would be exceeded: 45 already committed plus 90
                            proposed, against a cap of 100 per 24h
  1m    ops.query    DENY   destructive SQL from an agent is never permitted
```

What the hub adds:

| | |
| --- | --- |
| **Shared policy** | Versioned, immutable, rolled back by version. Agents fetch the active one and record its hash in every receipt. |
| **Approvals inbox** | Escalations reach a human in the console. Undecided requests expire into a denial — never into an approval. |
| **Tenant isolation** | Every row names its org. A credential cannot reach another organisation's data by any route, including by guessing an id. |
| **Witness service** | Counter-signs roots, and refuses two roots at one size. This is what defeats a split view. |
| **Its own audit trail** | Every administrative action is hash-chained. We ask you to trust a tamper-evident record, so ours is one too. |

**The hub is not trusted and does not need to be.** It never holds a signing
key, so it cannot forge a receipt — and it is not load-bearing either: an agent
whose hub is unreachable keeps running, keeps recording locally, and ships the
backlog when it returns.

Full deployment and operations guide: [`docs/HUB.md`](docs/HUB.md).

---

## Why this is different

Everyone is building agent **observability** — dashboards that show you what
your agent did, which you have to take on faith. Proofwire builds agent
**evidence**: a record whose integrity a third party can check independently,
using nothing but the file you hand them.

|                                | Observability tools | Proofwire |
| ------------------------------ | ------------------- | --------- |
| Shows what the agent did       | ✅                  | ✅        |
| Blocks the action before it runs| ❌                  | ✅        |
| Survives an insider with DB access | ❌              | ✅        |
| Verifiable by someone who distrusts you | ❌         | ✅        |
| Erasure without breaking the audit trail | ❌        | ✅        |
| Survives the *vendor* being the adversary | ❌       | ✅        |

The distinction matters the day a regulator, an insurer, or opposing counsel
asks *"prove it."* A dashboard is a claim. A signed, witnessed Merkle root is
evidence.

---

## How it works

### 1. Policy runs first

```jsonc
{
  "version": 1,
  "rules": [
    { "id": "deny.destructive-sql",
      "when": { "params.sql": { "matches": "(?i)\\b(drop|truncate|delete\\s+from)\\b" } },
      "then": "deny",
      "reason": "destructive SQL from an agent is never permitted" },

    { "id": "escalate.customer-mail",
      "when": { "target": "*.send_email" },
      "then": "escalate" }
  ],

  "budgets": [
    { "id": "refunds.daily", "match": { "target": "*.refund" },
      "field": "metrics.amount_usd", "limit": 1000, "window": "24h", "then": "escalate" }
  ],

  "egress": { "denySecrets": true }
}
```

Three defaults chosen so the failure modes are safe:

- **A typo is a load error, not a skipped rule.** A misspelled operator in a
  `deny` rule must never quietly read as "allow".
- **`escalate` with no approver resolves to `deny`.** A system that degrades
  into "allow everything" under stress is worse than no system.
- **Budgets commit at decision time, not on completion.** Otherwise three
  pipelined refunds all evaluate against an empty ledger and every one passes a
  cap they collectively blow through.

### 2. Every action gets a receipt

```jsonc
{
  "v": 1, "log": "lg_14b9c3dd", "seq": 7, "prev": "3fa4a544…",
  "ts": "2026-09-20T17:19:00.057Z", "phase": "intent",
  "actor": { "agent": "claude-opus-5", "principal": "ops@acme.test", … },
  "action": {
    "kind": "tool_call", "target": "ops.refund",
    "metrics": { "amount_usd": 45 },
    "params": { "hash": "74155b6d…", "size": 42, "preview": { "order": "ord_8821", … } }
  },
  "decision": { "outcome": "allow", "policy": "8ab2e528…", "rules": ["refunds.under-cap"] },
  "attest": { "alg": "ed25519", "kid": "pw106d7bf7…", "sig": "…" }
}
```

Four properties, each because a specific dispute is foreseeable:

- **Signed** — Ed25519, deterministic, key never leaves the runtime.
- **Chained** — each receipt commits to its predecessor's hash. Delete or
  reorder one entry and everything after it breaks.
- **Tree-anchored** — RFC 6962 Merkle log, the same construction Certificate
  Transparency uses. Inclusion proofs tie one receipt to a published root;
  consistency proofs prove the log only ever grew.
- **Sealed** — arguments are stored as *salted commitments* plus a redacted
  preview, never as raw payloads.

### 3. Nothing sensitive is in the log

The log holds `sha256(salt ‖ payload)` and a preview with secrets masked. Salts
live in a separate file. So:

- **A receipt is publishable as written.** No "sanitise before exporting" step
  to forget.
- **Erasure and audit stop being in conflict.** `pw shred --before 2026-01-01`
  destroys the salts. Those payloads become permanently unopenable — by you,
  by a court, by whoever steals the directory in 2029 — while every signature,
  chain link and inclusion proof still verifies. That is a real GDPR Article 17
  erasure that does not gut your audit trail.

### 4. Witnesses close the last hole

A log signing its own root can show two different histories to two auditors —
the classic split-view attack, and the one thing a self-hosted log cannot
defend against alone. Independent witnesses only counter-sign a root that
extends the last one they saw, so a split view requires every witness to
collude.

```bash
pw witness keygen               # on the witness's machine
pw trust pw1a4f… <publicKey>    # on the log's machine
pw check evidence.json --witnesses 2
```

---

## Commands

```
Setup
  pw init                        create a log, a starter policy, and a config

Run
  pw proxy -- <cmd...>           wrap an MCP server; enforce policy, write receipts
    --namespace <ns>             prefix tool names in receipts
    --principal <id>             who the agent is acting for
    --approve tty|webhook|deny   how escalations get resolved

Inspect
  pw log                         recent receipts  [--tail N --denied --target X --json]
  pw stats                       totals, spend, busiest tools
  pw dash                        browsable dashboard  [--port 7788]

Prove
  pw verify                      audit the local log end to end
  pw prove <seq>                 inclusion proof for one receipt
  pw export [file]               evidence bundle for a third party
  pw check <file>                verify a bundle with nothing but itself

Hub
  pw remote add --url <hub> --token <key>   connect this machine
  pw push                        ship local receipts the hub is missing
  pw remote-verify <log>         verify a hosted log from outside
  pw policy push|pull|list       manage the org's shared policy
  pw cosign                      have a witness counter-sign your latest root

Govern
  pw keys                        public keys to publish for verifiers
  pw witness keygen              create an independent witness identity
  pw trust <kid> <pubkey>        trust a witness or another signer
  pw shred --before <date>       destroy payload commitments, keep the audit trail
```

`pw verify` exits non-zero when a log has been altered — put it in CI.

---

## Library use

Not on MCP? The core is a small, dependency-free ES module.

```js
import { ProofLog, Policy } from '@proofwire/core';

const log = ProofLog.open('.proofwire');
const policy = Policy.parse(await readFile('proofwire.policy.json', 'utf8'));

const decision = policy.decide({
  kind: 'payment',
  target: 'stripe.refund',
  params: { order, amount },
  metrics: { amount_usd: amount / 100 },
  actor,
}, new History(log.entries));

if (decision.outcome !== 'allow') {
  log.append({ actor, action, decision, result: null });
  throw new Error(decision.reason);
}

const result = await stripe.refunds.create({ ... });
log.append({ actor, action, decision, result: { status: 'ok', payload: result } });
```

---

## What it does not do

Stated plainly, because a security tool that overstates its guarantees is worse
than none:

- **It cannot prove an action it never saw.** Proofwire records what passes
  through it. An agent with a second, unwrapped path to the same API leaves no
  receipt. Route tools through the proxy and treat unwrapped credentials as the
  hole they are.
- **A hub's own signing keys live in its database** in `0.2.0`. A KMS/HSM
  backend is the next piece of work; until then, treat that database as key
  material.
- **It cannot stop an attacker with the signing key from writing false
  receipts going forward.** It *can* stop them rewriting the past, once a
  checkpoint has been witnessed. Keep the key in a KMS or HSM in production.
- **Witnesses are only as independent as you make them.** Three witnesses on
  infrastructure you control are one witness.
- **Redaction is best-effort.** The detectors catch known credential formats
  and common PII. They will not catch a secret shaped like prose. Commitments,
  not redaction, are what keep payloads out of the log.

See [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for the full analysis.

---

## Status

`0.2.0` — cryptography, policy engine, proxy, CLI, and the multi-tenant hub are
complete and covered by **145 tests**: exhaustive Merkle proof verification for
every tree size up to 64 and every `(m, n)` consistency pair up to 48, plus
end-to-end tests that run a real agent through a real proxy against a real hub
over HTTP.

```bash
npm test
```

Wire format and policy schema are versioned (`"v": 1`) and will be migrated,
not broken.

## License

Apache-2.0. The format, the verifier, and the CLI are open and will stay open:
evidence you cannot verify without a vendor's permission is not evidence.
