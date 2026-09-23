# Changelog

All five packages — `proofwire` and `@proof_wire/{core,proxy,dashboard,server}` —
release together at the same version.

## Unreleased

### Security

- **`pw dash` refuses requests whose `Host` is not its own**, which closes DNS
  rebinding: a web page could previously point its own domain at `127.0.0.1`
  and read the local dashboard's receipts. The page is also served with a CSP
  that allows only its own inline script, by hash, and forbids framing. Internal
  errors no longer echo their message, which could include file paths.
- **Hub sign-in no longer reveals which emails have accounts.** An unknown
  address now costs the same scrypt as a wrong password.
- **Failed sign-ins are limited per account**, as well as per address: ten, then
  one more every 90 seconds (`accountLoginRate`). A throttled account is
  refused before its password is checked (`429 too_many_attempts`, or a notice
  on the console sign-in page). `/forgot` now falls under the strict auth limit.
- **`pw remote add` refuses a plain `http://` hub URL** unless it is on this
  machine or `--insecure` is given, so an API key is not sent unencrypted by
  accident.
- **CI hardening:** every GitHub Action is pinned to a commit SHA, workflows
  default to a read-only token, and CodeQL and Dependabot are configured.
  `scripts/repo-hygiene.mjs` blocks keys, salts, environment and database files,
  and token-shaped strings in CI and in the release preflight.

### Fixed

- **`pw proxy` no longer triggers Node's DEP0190 warning on Windows** when it
  wraps a bare command such as `npx` or `node`. The shell now gets one
  already-quoted command line with no separate args. Quoting is unchanged.

### Changed

- **`pw check --witness-keys` skips list entries that carry `revokedAt`**, and
  says which. A revoked witness key could "witness" anything; a retired one
  (`retiredAt`) is still pinned, since what it signed before stays good.

### Added

- **`pw policy test [policy-file]`** replays the local log against a policy and
  lists every call whose verdict would change, such as `deny → allow`, with the
  rule responsible. Each call is judged at its recorded time, against only what
  the new policy would have let through, so budgets and rate limits behave as
  they would have live. Monitored calls are compared on what the policy would
  have done. Options: `--since`, `--session`, `--target`, `--json`, `--all`, and
  `--fail-on-change` (exit 1 if anything differs, for CI). Calls whose logged
  arguments were partly masked are marked approximate. No hub is needed.
- **Monitor mode: `pw proxy --monitor`**, or `"monitor": true` in
  `proofwire.config.json` (`--enforce` overrides it). The policy is evaluated
  as usual but every call is forwarded, and escalations never reach an
  approver. Each receipt written in this mode carries `decision.enforced:
  false`. A call the policy would have stopped is recorded as `allow` (it ran)
  with `decision.wouldBe: "deny" | "escalate"` and a reason that says it was
  not enforced. These fields are signed, and monitored calls count toward
  budgets. `pw log --would-block` lists them, `pw stats` tallies them by rule,
  and the dashboard and hub console label them "would deny". `McpProxy` takes
  `monitor: true`.
- **`witnesses/keys.json`**, the published record of Proofwire-operated
  witness keys — empty until there is a real node. Append-only, enforced by
  replaying its git history in CI; `pw check --witness-keys` reads it directly.

## 0.3.0 — 2026-09-22

### Breaking

- **A witness binds each log to its signing key.** The first request to
  co-sign a log must name the key its checkpoints are signed with
  (`logPublicKey`) and carry a valid `log` signature from it; every later
  checkpoint must be signed by that key. A first request naming no key is
  `400 missing_log_key`, another key `409 log_key_mismatch`, a missing or
  invalid signature `422 bad_log_signature`. **`pw` 0.2.0 does not send
  `logPublicKey`**, so it cannot start witnessing a new log against a 0.3.0
  witness — upgrade the CLI. Logs a witness recorded under 0.2.0 bind on their
  next successful co-signing.
- **`buildReceipt` throws on a missing `actor.principal`, `actor.agent`,
  `actor.session`, `action.kind`, `action.target` or `decision.outcome`**,
  and `verifyReceipt` reports them (plus `ts` and `phase`) as format issues.
  Such receipts used to verify and then crash a hub's ingest with a raw
  SQLite error; they are now refused cleanly, before they are signed.
- **Keys and signatures must be canonical base64url.** A string whose final
  character carries non-zero unused bits — `QB`, where `QA` is the canonical
  encoding of the same byte — is rejected, in both the CLI's verifier and the
  browser's. Every encoder in
  common use emits the canonical form, so this only rejects hand-made input.

### Added

- **Witness-only mode** (`PROOFWIRE_WITNESS_ONLY=1`): the hub answers six
  routes — health, readiness, `/.well-known/proofwire`, `/v1/me`, the witness
  key and co-signing — and 404s everything else. No console, no log ingest, no
  key management over HTTP, no hub key. `docker-compose.yml`'s witness uses it.
- **`proofwire-hub witness-key <customer>`** — gives a customer their own
  organization and a witness-scoped key, and prints the witness's public key
  for them to pin.
- **`proofwire-hub witness-rebind <customer> <log> <public key>`** — the only
  way to change a log's binding after a key rotation. Host-only, recorded in
  the audit trail, and it keeps the recorded position: a new key must extend
  what the witness already attested to.
- **`pw cosign`** sends the log's key, shows the binding, and explains a key
  mismatch.

### Fixed

- A hub fed a malformed-but-validly-signed receipt answered 500; it now
  answers `422 receipt_rejected` (see *Breaking*).
- Version strings reported by `pw --version`, the hub banner,
  `/.well-known/proofwire` and the proxy's receipts (`actor.runtime`) are read
  from the package, not typed into source. 0.2.0's all said `0.2.0` by hand.

### Infrastructure

- The Dockerfile is built on every push and driven end to end — as a hub and
  as a separate witness-only node that co-signs the hub's checkpoint, verified
  with the witness key pinned.

## 0.2.0 — 2026-09-22

First release on npm.
