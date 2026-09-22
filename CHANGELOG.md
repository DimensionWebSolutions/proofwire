# Changelog

All five packages — `proofwire` and `@proof_wire/{core,proxy,dashboard,server}` —
release together at the same version.

## Unreleased

### Changed

- **`pw check --witness-keys` skips list entries that carry `revokedAt`**, and
  says which. A revoked witness key could "witness" anything; a retired one
  (`retiredAt`) is still pinned, since what it signed before stays good.

### Added

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
