# Running the Proofwire hub

The hub is the multi-tenant half of Proofwire: a transparency log your whole
organisation writes to, a policy registry your agents read from, an approvals
inbox your people work out of, and a witness service that makes any of it worth
believing.

---

## The trust model, first

Everything else follows from one property:

> **The hub cannot forge a receipt, because it never holds a signing key.**

Agents sign locally with keys that never leave the machine. The hub verifies
every receipt on arrival and stores what it can verify. That leaves it able to
do exactly three dishonest things, and each has a defence:

| What a malicious hub could try | What stops it |
| --- | --- |
| Alter a receipt | The signature fails. Ingest rejects it; so does any later audit. |
| Drop or reorder receipts | The chain breaks at the next entry, and consistency proofs against a published checkpoint expose the gap. |
| Show two customers two histories | Witness countersignatures. A witness signs only roots that extend the last one it saw, and refuses two roots at one size. |

The corollary matters as much: **the hub is optional.** An agent whose hub is
unreachable keeps running and keeps recording locally, and ships the backlog
when the hub returns. An audit service that could halt production would be
removed from production after its first outage.

---

## Quick start

```bash
docker compose up -d
docker compose exec hub node packages/server/src/bin.js bootstrap
```

`bootstrap` prints an admin password and two API keys, once:

```
  org        acme  org_c8139b3e88ae61b955f1d961
  admin      admin@example.com
  password   kR2mFqXt9

  API keys  (shown once — they are not stored in recoverable form)
  agent      pwk_5f28cece….tZXYRJZMDLgFPpHM…
             receipts:write logs:write logs:read policies:read
  auditor    pwk_72f15eec….2wARtiM9Uq3AwURZ…
             read-only: the credential to hand an outside firm
```

Point an agent at it:

```bash
pw remote add --url https://hub.acme.com --token <agent token>
pw proxy --namespace crm -- npx -y @acme/mcp-crm
```

From that moment the proxy fetches the org's active policy at startup, enforces
it, records every decision locally, and streams the receipts to the hub.

---

## Configuration

Environment only. A config file that anyone who can reach the filesystem can
edit is one more thing to get wrong in a container.

| Variable | Default | Notes |
| --- | --- | --- |
| `PROOFWIRE_PORT` | `8787` | |
| `PROOFWIRE_HOST` | `0.0.0.0` | |
| `PROOFWIRE_DB` | `./data/proofwire.db` | Put this on a durable volume. |
| `PROOFWIRE_TRUST_PROXY` | `0` | Set to `1` **only** behind a proxy you control. |
| `PROOFWIRE_CHECKPOINT_EVERY` | `500` | Receipts between automatic checkpoints. |
| `PROOFWIRE_SELFCHECK_MINUTES` | `60` | Re-verify every stored log on this interval. |
| `PROOFWIRE_APPROVAL_TTL` | `900` | Seconds before an undecided escalation expires. |
| `PROOFWIRE_ACCESS_LOG` | on | Set `off` to silence per-request JSON logs. |
| `PROOFWIRE_INSECURE_COOKIES` | unset | Drops `Secure` on session cookies. Local development only. |

### On `PROOFWIRE_TRUST_PROXY`

`X-Forwarded-For` is a header any client can set. With no proxy in front,
honouring it lets anyone evade the per-address rate limit by inventing an
address. Turn it on only when something you operate is guaranteed to overwrite
it.

---

## Credentials

### API keys — machines

Scoped and, for agents, pinned to a single log. A key pinned to `payments`
cannot read or write `support`, which contains a leaked agent credential to the
blast radius of the one runtime that held it.

| Scope | For |
| --- | --- |
| `receipts:write` | An agent runtime pushing receipts |
| `receipts:read` | Auditors, dashboards, CI verification |
| `logs:write` / `logs:read` | Registering logs; reading their state |
| `policies:read` | Agents fetching the active policy at startup |
| `policies:write` | Whoever is allowed to change the rules |
| `approvals:read` / `approvals:write` | The escalation inbox |
| `witness:sign` | A client asking the witness to counter-sign |
| `admin` | Members, keys, org settings |

An agent needs `receipts:write logs:write logs:read policies:read`. Nothing more.
Giving it `receipts:read` lets a compromised agent read back the entire
organisation's history of what other agents did.

### Sessions — people

Console users get scopes from their role, not from a list, because a person's
authority changes when their job does:

| Role | Can |
| --- | --- |
| `owner` | Everything, including minting keys |
| `admin` | Everything except ownership transfer |
| `operator` | Read, and resolve escalations |
| `auditor` | **Read everything, change nothing** |

`auditor` is the role to hand an outside firm. It cannot alter what it is
auditing, which is the point.

---

## Witnessing

A hub signing its own roots proves very little — it can sign two. Independent
witnesses are what close that.

```bash
# On the witness's own infrastructure, run a second hub:
docker compose up -d witness

# From the agent's machine:
pw remote add --name witness --url https://witness.example.org --token <key>
pw cosign --remote witness
```

The witness enforces two rules and returns a signature only if both hold:

1. **Never sign two different roots at the same size.** This is the split-view
   refusal, returned as `409 split_view`.
2. **Never sign a larger root without a consistency proof** that it extends the
   last root this witness saw. Returned as `409 not_an_extension`.

A refusal on either ground is not a transient error. It means the history the
witness was shown does not match the history it saw before.

**Witnesses are only as independent as you make them.** Three witnesses on
infrastructure the log operator controls provide one witness's worth of
assurance. They should be run by whoever would be harmed by a split view — the
auditor, the insurer, the counterparty — not by the log's owner.

Auditors then demand the signatures:

```bash
pw check evidence.json --witnesses 2
```

---

## Operating it

### Health

- `GET /health` — the process is up.
- `GET /ready` — the database answers. This is the one to put in a load
  balancer, so a hub with a wedged disk leaves rotation instead of serving
  errors.
- `GET /.well-known/proofwire` — the hub's and witness's public keys, served
  **without credentials**. A verifier that must authenticate to obtain the key
  it verifies with is not independent.

### Verifying the hub against itself

```bash
docker compose exec hub node packages/server/src/bin.js check
```

Re-derives every log from stored receipts — signatures, chain links, inclusion
proofs, and every checkpoint replayed — and exits non-zero on any failure. The
server also does this on `PROOFWIRE_SELFCHECK_MINUTES` and logs
`selfcheck.failed`. **Alert on that line.**

A hosted log that only ever checks its customers' data and never its own is
asking to be taken at its word.

### Backups

Back up `PROOFWIRE_DB`. SQLite in WAL mode needs the `-wal` and `-shm`
sidecars too, or use `sqlite3 proofwire.db ".backup out.db"` for a consistent
copy.

A restore from a backup that predates some receipts looks *exactly* like
malicious truncation to any auditor holding a later checkpoint — because from
the evidence alone it is indistinguishable. Agents still hold their local logs,
so re-run `pw push` from each to refill the gap.

### Scaling

`0.2.0` is single-writer per process. SQLite in WAL mode handles concurrent
readers comfortably, and ingest is a few hundred microseconds of verification
plus one transaction. For more than one hub process, shard by organisation —
each log has exactly one writer by design, so sharding is natural and needs no
coordination.

---

## The API

All endpoints are tenant-scoped by credential. There is deliberately no way to
address a log by id across an organisation boundary.

```
POST   /v1/logs                          register a log (slug, canonical, kid, publicKey)
GET    /v1/logs                          list
GET    /v1/logs/:log                     state: size, head, root
GET    /v1/logs/:log/head                resync point for a reconnecting agent
POST   /v1/logs/:log/receipts            append a verified batch  { receipts, batchId }
GET    /v1/logs/:log/receipts/:seq       one receipt
GET    /v1/receipts                      query across logs  [?denied&target&session&since]
GET    /v1/logs/:log/proof/:seq          inclusion proof
GET    /v1/logs/:log/consistency?from=   consistency proof
GET    /v1/logs/:log/audit               the hub re-verifies its own storage
GET    /v1/logs/:log/bundle              evidence bundle for a third party
POST   /v1/logs/:log/checkpoint          sign the current root
GET    /v1/logs/:log/checkpoints

POST   /v1/witness/cosign                counter-sign  { checkpoint, consistencyProof }
GET    /v1/witness/key

GET    /v1/policies                      versions
GET    /v1/policies/:slug                the active one — what agents fetch
POST   /v1/policies/:slug                publish a new version
POST   /v1/policies/:slug/activate       roll back to a version

POST   /v1/approvals                     raise an escalation
GET    /v1/approvals                     the inbox  [?status]
GET    /v1/approvals/:id?wait=30         long-poll for a decision
POST   /v1/approvals/:id/decide          { approved, note }

GET    /v1/keys · POST /v1/keys · DELETE /v1/keys/:id
GET    /v1/members · POST /v1/members
GET    /v1/events                        the hub's own hash-chained audit trail
GET    /v1/usage
```

### Ingest semantics

A batch is accepted whole or rejected whole. Four checks, any failure rejecting
everything:

1. Signature verifies against the key bound to the log at registration.
2. The receipt names the log it is being sent to (the *signed* identifier).
3. Sequence numbers continue from the hub's current size.
4. `prev` equals the hub's current head.

Rejecting the batch rather than its valid prefix is deliberate: a partial accept
leaves the client's head and the hub's silently diverged, and the next batch
fails for a reason unrelated to what actually went wrong.

Pass a `batchId` and retries are idempotent — the hub recognises a resubmission
and returns the original result rather than replaying it.

On `409 sequence_gap` the error carries the sequence to resume from. The
`RemoteSink` handles this automatically.

---

## Hardening checklist

- [ ] TLS terminated in front; `PROOFWIRE_TRUST_PROXY=1` only then
- [ ] `PROOFWIRE_DB` on a durable, backed-up volume
- [ ] Container runs read-only except `/data`, as non-root (the shipped
      compose file does both)
- [ ] Agent keys pinned to one log each, with no `receipts:read`
- [ ] At least one witness run by someone other than you
- [ ] Alerting on `selfcheck.failed` and on `split_view` refusals
- [ ] The hub and witness public keys published somewhere auditors can reach
      independently of the hub
- [ ] Bootstrap admin password rotated

---

## Known limits in 0.2.0

Stated plainly, because a security product that hides its edges is selling
confidence rather than evidence.

1. **Single-writer per log.** By design — a chain has one author. Multiple
   agents use multiple logs.
2. **Keys are bound to a log for its lifetime.** Rotation means registering a
   new log. A chain signed by two keys over its life is one whose validity
   depends on knowing exactly when the swap happened, which the log cannot
   itself establish.
3. **The hub's own keys live in the database.** A KMS/HSM backend is the next
   piece of work. Until then, the database is as sensitive as a signing key.
4. **Timestamps come from the signing host.** A backdated entry is flagged when
   it contradicts its neighbours; a uniformly wrong clock is not detectable
   from the log alone.
5. **No SSO yet.** Sessions are email plus password. SAML/OIDC is planned.
6. **`node:sqlite` is still marked experimental** upstream. It is stable in
   practice and the API surface used here is small, but it is worth knowing.
