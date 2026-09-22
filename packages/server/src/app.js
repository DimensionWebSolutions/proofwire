import http from 'node:http';
import { EventEmitter } from 'node:events';
import {
  Policy,
  canonicalize,
  verifyCheckpoint,
  checkpointDigest,
  sign as signBytes,
  unhex,
  hex,
  verifyConsistency,
} from '@proof_wire/core';
import { openDatabase, newId, now, transact } from './db.js';
import { Store, StoreError } from './store.js';
import { signerFor, selfTest, disabledSigner } from './signer.js';
import { Auth, Tokens, requireScope, requireLog, scopesForRole, verifyPassword, SCOPES, ROLES } from './auth.js';
import {
  Router,
  RateLimiter,
  readBody,
  redirect,
  sendJson,
  sendHtml,
  parseCookies,
  clientAddress,
  newRequestId,
  errorResponse,
} from './http.js';
import { renderConsole } from './console.js';

/**
 * The Proofwire hub.
 *
 * Read the route table below as the product: agents push signed receipts,
 * humans resolve escalations, auditors pull proofs, witnesses counter-sign.
 * Everything else is plumbing around those four jobs.
 */

export const DEFAULT_CONFIG = {
  port: 8787,
  host: '0.0.0.0',
  database: './data/proofwire.db',
  /** 8 MB is ~8,000 receipts in one batch; well past any sane client. */
  maxBodyBytes: 8 * 1024 * 1024,
  maxBatchReceipts: 1000,
  /** Ingest is bursty by nature — an agent session flushes in a clump. */
  ingestRate: { capacity: 600, refillPerSec: 120 },
  apiRate: { capacity: 120, refillPerSec: 20 },
  authRate: { capacity: 10, refillPerSec: 0.2 },
  trustProxy: false,
  approvalTtlSeconds: 900,
  /** Auto-checkpoint after this many new receipts. 0 disables. */
  checkpointEvery: 500,
  publicUrl: '',
  /** Serve only `WITNESS_ONLY_ROUTES`. For a node whose one job is co-signing. */
  witnessOnly: false,
};

/**
 * Everything a witness-only node answers. Anything else is a plain 404.
 *
 * A witness that is also a full hub exposes org creation, key management, the
 * console and log ingest to the internet for no reason: none of it is needed
 * to co-sign a checkpoint, all of it is attack surface, and a witness is the
 * one component whose compromise defeats the split-view defence outright.
 *
 * `/v1/me` stays because `pw remote add` uses it to prove a credential works
 * before storing it. Keys are minted with `proofwire-hub witness-key` on the
 * host, not over HTTP.
 */
export const WITNESS_ONLY_ROUTES = Object.freeze([
  'GET /health',
  'GET /ready',
  'GET /.well-known/proofwire',
  'GET /v1/me',
  'GET /v1/witness/key',
  'POST /v1/witness/cosign',
]);

export class Hub {
  /** @param {Partial<typeof DEFAULT_CONFIG>} [config] */
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.db = openDatabase(this.config.database);
    this.store = new Store(this.db);
    this.auth = new Auth(this.store);
    this.tokens = new Tokens(this.auth);

    // Signing goes through a `Signer`, which for a KMS or HSM backend holds no
    // key material at all. `local` remains the default so nothing breaks for an
    // existing self-hosted deployment.
    //
    // A witness-only node has no hub role, so it gets no hub key at all — not
    // an unused one sitting in the database, where it would also trip the
    // "a signing key is stored in this database" warning on a node whose real
    // key is in a KMS.
    this.hubSigner = this.config.witnessOnly
      ? disabledSigner('this is a witness-only node; it signs no checkpoints of its own')
      : signerFor(this.store, 'hub', config.env ?? process.env);
    this.witnessSigner = signerFor(this.store, 'witness', config.env ?? process.env);

    // Kept for compatibility with callers that want the identity shape.
    this.hubIdentity = { kid: this.hubSigner.kid, publicKey: this.hubSigner.publicKey };
    this.witnessIdentity = { kid: this.witnessSigner.kid, publicKey: this.witnessSigner.publicKey };

    this.limiters = {
      ingest: new RateLimiter(this.config.ingestRate),
      api: new RateLimiter(this.config.apiRate),
      auth: new RateLimiter(this.config.authRate),
    };

    /** Wakes long-polling approval waiters the moment a human decides. */
    this.approvalBus = new EventEmitter();
    this.approvalBus.setMaxListeners(0);

    /** @type {number} */
    this._sinceCheckpoint = 0;
    this.startedAt = now();

    this.router = new Router();
    this._routes();
    if (this.config.witnessOnly) this._restrictToWitness();
  }

  /**
   * Drop every route not in `WITNESS_ONLY_ROUTES`.
   *
   * Filtering the one route table, rather than guarding each handler, keeps
   * the whole public surface of a witness in a single list someone can audit —
   * and means a route added to `_routes()` later is excluded by default instead
   * of exposed by default.
   */
  _restrictToWitness() {
    const keyOf = (route) => `${route.method} ${route.raw}`;
    const allowed = new Set(WITNESS_ONLY_ROUTES);
    const kept = this.router.routes.filter((route) => allowed.has(keyOf(route)));

    // A route renamed in `_routes()` would otherwise leave a witness quietly
    // unable to do its job while claiming to be up.
    const missing = WITNESS_ONLY_ROUTES.filter((k) => !kept.some((route) => keyOf(route) === k));
    if (missing.length) {
      throw new Error(`witness-only mode names routes that do not exist: ${missing.join(', ')}`);
    }
    this.router.routes = kept;
  }

  // ── principal resolution ──────────────────────────────────────────────

  /**
   * Work out who is calling.
   *
   * A bearer token is a machine and carries its own scopes. A session cookie
   * is a person, whose scopes come from their role in the org they have
   * selected — and selecting an org they are not a member of resolves to no
   * principal at all, not to an error that would confirm the org exists.
   *
   * @param {import('node:http').IncomingMessage} req
   * @param {URL} url
   * @returns {import('./auth.js').Principal|null}
   */
  _principal(req, url) {
    const header = req.headers.authorization;
    if (typeof header === 'string' && header.startsWith('Bearer ')) {
      const key = this.auth.keyForToken(header.slice(7).trim());
      if (!key) return null;
      this.auth.touchKey(key.id);
      return {
        kind: 'key',
        id: key.id,
        orgId: key.orgId,
        label: `${key.name} (${key.id})`,
        scopes: key.scopes,
        logId: key.logId,
      };
    }

    const cookies = parseCookies(req.headers.cookie);
    const user = this.auth.userForSession(cookies.pw_session);
    if (!user) return null;

    const wanted = url.searchParams.get('org') ?? cookies.pw_org ?? null;
    const orgs = this.auth.orgsFor(user.id);
    if (orgs.length === 0) return null;

    const org = wanted ? orgs.find((o) => o.id === wanted || o.slug === wanted) : orgs[0];
    if (!org) return null;

    return {
      kind: 'user',
      id: user.id,
      orgId: org.id,
      label: user.email,
      scopes: scopesForRole(org.role),
      logId: null,
      role: org.role,
      user,
      org,
    };
  }

  /**
   * Resolve a `:log` path segment, which may be an id or a slug, within the
   * caller's org and no other.
   *
   * @param {import('./auth.js').Principal} principal
   * @param {string} ref
   */
  _log(principal, ref) {
    const log =
      this.store.log(principal.orgId, ref) ?? this.store.logBySlug(principal.orgId, ref);
    if (!log) throw new StoreError(404, 'no_such_log', `no log "${ref}" in this organization`);
    requireLog(principal, log.id);
    return log;
  }

  // ── routes ────────────────────────────────────────────────────────────

  _routes() {
    const r = this.router;

    // ── health ──────────────────────────────────────────────────────────
    r.get('/health', () => ({ status: 'ok', startedAt: this.startedAt }));

    r.get('/ready', () => {
      // Readiness means the database answers, not merely that we are running.
      this.db.prepare('SELECT 1').get();
      return { status: 'ready' };
    });

    /**
     * Everything a verifier needs to check this hub's signatures, served
     * without credentials. A verifier that has to authenticate to get the key
     * it verifies with is not independent.
     */
    r.get('/.well-known/proofwire', () => {
      // Every key that has ever signed here, including retired ones. A
      // signature made before a rotation stays verifiable; without this, a
      // rotation would quietly invalidate the history it was meant to protect.
      const keys = this.store.serverKeys().map((k) => ({
        kid: k.kid,
        role: k.role,
        publicKey: k.public_key,
        retiredAt: k.retired_at,
      }));

      // A witness publishes its witness key and nothing that could be mistaken
      // for it. An auditor pinning a witness copies a key from here; offering
      // a second, unrelated key on the same page invites pinning the wrong one.
      if (this.config.witnessOnly) {
        return {
          service: 'proofwire-witness',
          version: '0.2.0',
          witness: { kid: this.witnessSigner.kid, publicKey: this.witnessSigner.publicKey },
          keys: keys.filter((k) => k.role === 'witness'),
          receiptVersion: 1,
        };
      }
      return {
        service: 'proofwire-hub',
        version: '0.2.0',
        hub: { kid: this.hubSigner.kid, publicKey: this.hubSigner.publicKey },
        witness: { kid: this.witnessSigner.kid, publicKey: this.witnessSigner.publicKey },
        keys,
        receiptVersion: 1,
      };
    });

    // ── auth ────────────────────────────────────────────────────────────
    r.post('/v1/auth/login', async (ctx) => {
      const { email, password } = ctx.body ?? {};
      const user = email ? this.auth.userByEmail(String(email)) : null;
      const ok = user && password && verifyPasswordSafe(String(password), user.password_hash);
      if (!ok) {
        // One message for both "no such user" and "wrong password": the
        // difference tells an attacker which emails are registered.
        throw new StoreError(401, 'invalid_credentials', 'email or password is incorrect');
      }
      const session = this.auth.createSession(user.id);
      this.db.prepare('UPDATE users SET last_seen_at = ? WHERE id = ?').run(now(), user.id);
      const orgs = this.auth.orgsFor(user.id);

      ctx.res.setHeader('set-cookie', [
        cookie('pw_session', session.token, { maxAge: 14 * 86400 }),
        ...(orgs[0] ? [cookie('pw_org', orgs[0].id, { maxAge: 14 * 86400 })] : []),
      ]);
      return { user: { id: user.id, email: user.email, name: user.name }, orgs };
    });

    r.post('/v1/auth/logout', (ctx) => {
      const cookies = parseCookies(ctx.req.headers.cookie);
      if (cookies.pw_session) this.auth.revokeSession(cookies.pw_session);
      ctx.res.setHeader('set-cookie', [
        cookie('pw_session', '', { maxAge: 0 }),
        cookie('pw_org', '', { maxAge: 0 }),
      ]);
      return { ok: true };
    });

    r.get('/v1/me', (ctx) => {
      requireScope(ctx.principal, 'logs:read');
      return {
        kind: ctx.principal.kind,
        label: ctx.principal.label,
        org: { id: ctx.principal.orgId, ...pick(this.store.org(ctx.principal.orgId), ['slug', 'name', 'plan']) },
        scopes: ctx.principal.scopes,
        role: ctx.principal.role ?? null,
        pinnedLog: ctx.principal.logId,
      };
    });

    // ── logs ────────────────────────────────────────────────────────────
    r.post('/v1/logs', (ctx) => {
      requireScope(ctx.principal, 'logs:write');
      const { slug, kid, publicKey, name, canonical } = ctx.body ?? {};
      if (!slug || !kid || !publicKey) {
        throw new StoreError(400, 'missing_fields', 'slug, kid and publicKey are required');
      }
      const log = this.store.createLog({
        orgId: ctx.principal.orgId,
        slug: String(slug),
        canonical: canonical ? String(canonical) : undefined,
        kid: String(kid),
        publicKey: String(publicKey),
        name: name ? String(name) : undefined,
      });
      this.store.recordEvent({
        orgId: ctx.principal.orgId,
        actor: ctx.principal.label,
        actorKind: ctx.principal.kind,
        action: 'log.register',
        subject: log.slug,
        meta: { kid: log.kid },
      });
      return publicLog(log);
    });

    r.get('/v1/logs', (ctx) => {
      requireScope(ctx.principal, 'logs:read');
      return { logs: this.store.logs(ctx.principal.orgId).map(publicLog) };
    });

    r.get('/v1/logs/:log', (ctx) => {
      requireScope(ctx.principal, 'logs:read');
      return publicLog(this._log(ctx.principal, ctx.params.log));
    });

    /**
     * The resync endpoint. A proxy that crashed mid-flush asks where the hub
     * thinks the log is, and replays from there — which is why a chain gap is
     * a recoverable condition rather than a broken log.
     */
    r.get('/v1/logs/:log/head', (ctx) => {
      requireScope(ctx.principal, 'logs:read');
      const log = this._log(ctx.principal, ctx.params.log);
      return { log: log.slug, size: log.size, head: log.head, root: log.root };
    });

    r.post('/v1/logs/:log/receipts', (ctx) => {
      requireScope(ctx.principal, 'receipts:write');
      const log = this._log(ctx.principal, ctx.params.log);

      const receipts = ctx.body?.receipts;
      if (!Array.isArray(receipts)) {
        throw new StoreError(400, 'missing_receipts', 'body must be { receipts: [...] }');
      }
      if (receipts.length > this.config.maxBatchReceipts) {
        throw new StoreError(
          413,
          'batch_too_large',
          `at most ${this.config.maxBatchReceipts} receipts per batch`,
        );
      }

      const result = this.store.ingest({
        orgId: ctx.principal.orgId,
        logId: log.id,
        receipts,
        batchId: ctx.body?.batchId ? String(ctx.body.batchId) : undefined,
      });

      if (!result.duplicate) {
        this._sinceCheckpoint += result.accepted;
        if (this.config.checkpointEvery > 0 && this._sinceCheckpoint >= this.config.checkpointEvery) {
          this._sinceCheckpoint = 0;
          // A checkpoint is an optimisation of detection, not a precondition
          // for storing receipts — and with an external signer it is a network
          // call. Never make an ingest wait for one, and never fail one over it.
          this.store.checkpoint(ctx.principal.orgId, log.id, this.hubSigner).catch((err) => {
            console.error(
              JSON.stringify({ level: 'warn', event: 'checkpoint.failed', log: log.slug, message: err.message }),
            );
          });
        }
      }
      return result;
    });

    r.get('/v1/logs/:log/receipts/:seq', (ctx) => {
      requireScope(ctx.principal, 'receipts:read');
      const log = this._log(ctx.principal, ctx.params.log);
      const row = this.store.receipt(ctx.principal.orgId, log.id, Number(ctx.params.seq));
      if (!row) throw new StoreError(404, 'no_such_entry', 'no such entry in this log');
      return { receipt: JSON.parse(row.body), receivedAt: row.received_at };
    });

    r.get('/v1/receipts', (ctx) => {
      requireScope(ctx.principal, 'receipts:read');
      const q = Object.fromEntries(ctx.query);
      if (ctx.principal.logId) q.logId = ctx.principal.logId;
      const { entries, total } = this.store.receipts(ctx.principal.orgId, q);
      return {
        total,
        entries: entries.map((e) => ({ ...e, metrics: JSON.parse(e.metrics), body: undefined })),
      };
    });

    r.get('/v1/logs/:log/proof/:seq', (ctx) => {
      requireScope(ctx.principal, 'receipts:read');
      const log = this._log(ctx.principal, ctx.params.log);
      return this.store.proof(ctx.principal.orgId, log.id, Number(ctx.params.seq));
    });

    r.get('/v1/logs/:log/consistency', (ctx) => {
      requireScope(ctx.principal, 'receipts:read');
      const log = this._log(ctx.principal, ctx.params.log);
      const from = Number(ctx.query.get('from'));
      const to = ctx.query.get('to') ? Number(ctx.query.get('to')) : undefined;
      if (!Number.isInteger(from)) {
        throw new StoreError(400, 'bad_range', '?from=<size> is required');
      }
      return this.store.consistency(ctx.principal.orgId, log.id, from, to);
    });

    r.get('/v1/logs/:log/audit', (ctx) => {
      requireScope(ctx.principal, 'receipts:read');
      const log = this._log(ctx.principal, ctx.params.log);
      return this.store.audit(ctx.principal.orgId, log.id);
    });

    r.get('/v1/logs/:log/bundle', (ctx) => {
      requireScope(ctx.principal, 'receipts:read');
      const log = this._log(ctx.principal, ctx.params.log);
      const bundle = this.store.bundle(ctx.principal.orgId, log.id, {
        since: ctx.query.get('since') ?? undefined,
        until: ctx.query.get('until') ?? undefined,
        session: ctx.query.get('session') ?? undefined,
      });
      this.store.recordEvent({
        orgId: ctx.principal.orgId,
        actor: ctx.principal.label,
        actorKind: ctx.principal.kind,
        action: 'evidence.export',
        subject: log.slug,
        meta: { entries: bundle.entries.length, partial: bundle.partial },
      });
      return bundle;
    });

    // ── checkpoints & witnessing ────────────────────────────────────────
    r.post('/v1/logs/:log/checkpoint', async (ctx) => {
      requireScope(ctx.principal, 'logs:write');
      const log = this._log(ctx.principal, ctx.params.log);
      return this.store.checkpoint(ctx.principal.orgId, log.id, this.hubSigner);
    });

    r.get('/v1/logs/:log/checkpoints', (ctx) => {
      requireScope(ctx.principal, 'logs:read');
      const log = this._log(ctx.principal, ctx.params.log);
      return { checkpoints: this.store.checkpoints(ctx.principal.orgId, log.id) };
    });

    /**
     * The witness endpoint.
     *
     * This is the part that cannot be faked by the log operator, so it is the
     * part that has to be strictest: a witness signs a root only if it extends
     * the last root it signed for that log, and never signs a second, different
     * root at a size it has already seen. Those two rules are what make a split
     * view impossible without the witness's complicity.
     */
    r.post('/v1/witness/cosign', async (ctx) => {
      requireScope(ctx.principal, 'witness:sign');
      const checkpoint = ctx.body?.checkpoint;
      const proof = ctx.body?.consistencyProof;
      if (!checkpoint?.body) {
        throw new StoreError(400, 'missing_checkpoint', 'body must be { checkpoint: {...} }');
      }

      const { body } = checkpoint;
      const logKey = `${ctx.principal.orgId}:${body.log}`;

      // Validate and *claim* the position in one transaction, then sign
      // outside it.
      //
      // Signing may be a network call to a KMS. If validation and the claim
      // were not atomic, two concurrent requests offering different roots at
      // the same size could both pass validation while the other was still
      // signing, and the witness would attest to two histories — the precise
      // thing it exists to refuse. Claiming first also fails in the safe
      // direction: if signing then errors, the position is already taken, so a
      // later *different* root at that size is still refused.
      transact(this.db, () => {
        const prior = this.db
          .prepare('SELECT * FROM witness_state WHERE witness_kid = ? AND log_id = ?')
          .get(this.witnessSigner.kid, logKey);

        if (prior) {
          if (body.size < prior.size) {
            throw new StoreError(
              409,
              'log_shrank',
              `this witness last saw ${body.log} at size ${prior.size}; it cannot shrink to ${body.size}`,
            );
          }
          if (body.size === prior.size && body.root !== prior.root) {
            throw new StoreError(
              409,
              'split_view',
              `this witness already signed a different root at size ${body.size} — refusing to ` +
                `attest to two histories of the same log`,
              { seen: prior.root, offered: body.root },
            );
          }
          if (body.size > prior.size) {
            // Growth must be proven, not asserted. Without this the witness is
            // just a second rubber stamp on whatever it is handed.
            if (!Array.isArray(proof)) {
              throw new StoreError(
                400,
                'missing_consistency_proof',
                `extending ${prior.size} → ${body.size} requires a consistency proof`,
              );
            }
            const ok = verifyConsistency({
              firstSize: prior.size,
              secondSize: body.size,
              firstRoot: unhex(prior.root),
              secondRoot: unhex(body.root),
              proof: proof.map((h) => unhex(String(h))),
            });
            if (!ok) {
              throw new StoreError(
                409,
                'not_an_extension',
                `the offered root at size ${body.size} does not extend the root this witness ` +
                  `signed at size ${prior.size} — history was rewritten`,
              );
            }
          }
        }

        this.db
          .prepare(
            `INSERT INTO witness_state(witness_kid, log_id, size, root, updated_at)
             VALUES(?, ?, ?, ?, ?)
             ON CONFLICT(witness_kid, log_id) DO UPDATE SET
               size = excluded.size, root = excluded.root, updated_at = excluded.updated_at`,
          )
          .run(this.witnessSigner.kid, logKey, body.size, body.root, now());
      });

      const sig = {
        role: /** @type {const} */ ('witness'),
        kid: this.witnessSigner.kid,
        sig: await this.witnessSigner.sign(checkpointDigest(body)),
        ts: now(),
      };

      try {
        const local = this.store.logBySlug(ctx.principal.orgId, body.log);
        if (local) {
          this.store.addWitnessSignature(ctx.principal.orgId, local.id, body.size, sig);
        }
      } catch {
        // Witnessing a log this hub does not itself host is a legitimate
        // case — the signature is still returned to the caller.
      }

      return {
        signature: sig,
        witness: { kid: this.witnessSigner.kid, publicKey: this.witnessSigner.publicKey },
      };
    });

    r.get('/v1/witness/key', () => ({
      kid: this.witnessSigner.kid,
      publicKey: this.witnessSigner.publicKey,
      backend: this.witnessSigner.kind,
    }));

    // ── policies ────────────────────────────────────────────────────────
    r.get('/v1/policies', (ctx) => {
      requireScope(ctx.principal, 'policies:read');
      return {
        policies: this.db
          .prepare(
            `SELECT slug, version, hash, note, created_at, created_by, active
             FROM policies WHERE org_id = ? ORDER BY slug, version DESC`,
          )
          .all(ctx.principal.orgId),
      };
    });

    /** What an agent fetches at startup. */
    r.get('/v1/policies/:slug', (ctx) => {
      requireScope(ctx.principal, 'policies:read');
      const row = this.db
        .prepare(
          `SELECT * FROM policies WHERE org_id = ? AND slug = ? AND active = 1
           ORDER BY version DESC LIMIT 1`,
        )
        .get(ctx.principal.orgId, ctx.params.slug);
      if (!row) throw new StoreError(404, 'no_such_policy', `no active policy "${ctx.params.slug}"`);
      return {
        slug: row.slug,
        version: row.version,
        hash: row.hash,
        policy: JSON.parse(row.doc),
      };
    });

    r.post('/v1/policies/:slug', (ctx) => {
      requireScope(ctx.principal, 'policies:write');
      const doc = ctx.body?.policy;
      if (!doc) throw new StoreError(400, 'missing_policy', 'body must be { policy: {...} }');

      // Compile before storing. A policy that fails to load is one an agent
      // would fetch and then refuse to start with — better to reject it here,
      // where a human is watching, than at 3am on a deploy.
      let policy;
      try {
        policy = new Policy(doc);
      } catch (err) {
        throw new StoreError(422, 'invalid_policy', err.message);
      }

      return transact(this.db, () => {
        const last = this.db
          .prepare('SELECT max(version) AS v FROM policies WHERE org_id = ? AND slug = ?')
          .get(ctx.principal.orgId, ctx.params.slug);
        const version = (last?.v ?? 0) + 1;
        const activate = ctx.body?.activate !== false;

        if (activate) {
          this.db
            .prepare('UPDATE policies SET active = 0 WHERE org_id = ? AND slug = ?')
            .run(ctx.principal.orgId, ctx.params.slug);
        }

        this.db
          .prepare(
            `INSERT INTO policies(id, org_id, slug, version, doc, hash, note, created_at, created_by, active)
             VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            newId('policy'), ctx.principal.orgId, ctx.params.slug, version,
            canonicalize(doc), policy.hash, String(ctx.body?.note ?? ''), now(),
            ctx.principal.label, activate ? 1 : 0,
          );

        this.store.recordEvent({
          orgId: ctx.principal.orgId,
          actor: ctx.principal.label,
          actorKind: ctx.principal.kind,
          action: activate ? 'policy.publish' : 'policy.draft',
          subject: `${ctx.params.slug}@${version}`,
          meta: { hash: policy.hash, rules: policy.rules.length },
        });

        return { slug: ctx.params.slug, version, hash: policy.hash, active: activate };
      });
    });

    r.post('/v1/policies/:slug/activate', (ctx) => {
      requireScope(ctx.principal, 'policies:write');
      const version = Number(ctx.body?.version);
      const row = this.db
        .prepare('SELECT * FROM policies WHERE org_id = ? AND slug = ? AND version = ?')
        .get(ctx.principal.orgId, ctx.params.slug, version);
      if (!row) throw new StoreError(404, 'no_such_policy', `no version ${version} of "${ctx.params.slug}"`);

      return transact(this.db, () => {
        this.db
          .prepare('UPDATE policies SET active = 0 WHERE org_id = ? AND slug = ?')
          .run(ctx.principal.orgId, ctx.params.slug);
        this.db.prepare('UPDATE policies SET active = 1 WHERE id = ?').run(row.id);
        this.store.recordEvent({
          orgId: ctx.principal.orgId,
          actor: ctx.principal.label,
          actorKind: ctx.principal.kind,
          action: 'policy.activate',
          subject: `${ctx.params.slug}@${version}`,
          meta: { hash: row.hash },
        });
        return { slug: ctx.params.slug, version, active: true };
      });
    });

    // ── approvals ───────────────────────────────────────────────────────
    r.post('/v1/approvals', (ctx) => {
      requireScope(ctx.principal, 'receipts:write');
      const b = ctx.body ?? {};
      if (!b.target) throw new StoreError(400, 'missing_target', 'target is required');
      const log = this._log(ctx.principal, String(b.log ?? ctx.principal.logId ?? ''));

      const id = newId('approval');
      const expiresAt = new Date(Date.now() + this.config.approvalTtlSeconds * 1000).toISOString();

      this.db
        .prepare(
          `INSERT INTO approvals(id, org_id, log_id, target, params, reason, rules,
             principal, agent, session, status, requested_at, expires_at)
           VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
        )
        .run(
          id, ctx.principal.orgId, log.id, String(b.target),
          canonicalize(b.params ?? {}), String(b.reason ?? ''),
          canonicalize(b.rules ?? []), String(b.principal ?? ''), String(b.agent ?? ''),
          String(b.session ?? ''), now(), expiresAt,
        );

      return { id, status: 'pending', expiresAt };
    });

    r.get('/v1/approvals', (ctx) => {
      requireScope(ctx.principal, 'approvals:read');
      const status = ctx.query.get('status') ?? 'pending';
      return {
        approvals: this.db
          .prepare(
            `SELECT a.*, l.slug AS log_slug FROM approvals a JOIN logs l ON l.id = a.log_id
             WHERE a.org_id = ? AND a.status = ? ORDER BY a.requested_at DESC LIMIT 200`,
          )
          .all(ctx.principal.orgId, status)
          .map(publicApproval),
      };
    });

    /**
     * Poll, optionally long. `?wait=30` holds the connection until a human
     * decides or the deadline passes — which keeps an agent's escalation
     * latency at human speed rather than poll-interval speed.
     */
    r.get('/v1/approvals/:id', async (ctx) => {
      requireScope(ctx.principal, 'approvals:read');
      const read = () =>
        this.db
          .prepare('SELECT * FROM approvals WHERE org_id = ? AND id = ?')
          .get(ctx.principal.orgId, ctx.params.id);

      let row = read();
      if (!row) throw new StoreError(404, 'no_such_approval', 'no such approval request');

      const wait = Math.min(Number(ctx.query.get('wait') ?? 0), 55);
      if (row.status === 'pending' && wait > 0) {
        row = await this._awaitDecision(ctx.params.id, wait * 1000, read);
      }
      if (row.status === 'pending' && row.expires_at <= now()) {
        return publicApproval({ ...row, status: 'expired' });
      }
      return publicApproval(row);
    });

    r.post('/v1/approvals/:id/decide', (ctx) => {
      requireScope(ctx.principal, 'approvals:write');
      const approved = ctx.body?.approved === true;
      const note = String(ctx.body?.note ?? '');

      const row = this.db
        .prepare('SELECT * FROM approvals WHERE org_id = ? AND id = ?')
        .get(ctx.principal.orgId, ctx.params.id);
      if (!row) throw new StoreError(404, 'no_such_approval', 'no such approval request');
      if (row.status !== 'pending') {
        throw new StoreError(409, 'already_decided', `this request was already ${row.status}`);
      }
      if (row.expires_at <= now()) {
        throw new StoreError(410, 'expired', 'this request expired before it was decided');
      }

      const status = approved ? 'approved' : 'denied';
      this.db
        .prepare('UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, note = ? WHERE id = ?')
        .run(status, now(), ctx.principal.label, note, row.id);

      this.store.recordEvent({
        orgId: ctx.principal.orgId,
        actor: ctx.principal.label,
        actorKind: ctx.principal.kind,
        action: `approval.${status}`,
        subject: row.target,
        meta: { approval: row.id, note },
      });

      this.approvalBus.emit(row.id);
      return { id: row.id, status, decidedBy: ctx.principal.label };
    });

    // ── admin ───────────────────────────────────────────────────────────
    r.get('/v1/keys', (ctx) => {
      requireScope(ctx.principal, 'admin');
      return { keys: this.auth.keys(ctx.principal.orgId) };
    });

    r.post('/v1/keys', (ctx) => {
      requireScope(ctx.principal, 'admin');
      const { name, scopes, log } = ctx.body ?? {};
      if (!name || !Array.isArray(scopes)) {
        throw new StoreError(400, 'missing_fields', 'name and scopes are required');
      }
      const pinned = log ? this._log(ctx.principal, String(log)).id : undefined;
      const key = this.auth.createKey({
        orgId: ctx.principal.orgId,
        name: String(name),
        scopes,
        logId: pinned,
        createdBy: ctx.principal.label,
        expiresAt: ctx.body?.expiresAt,
      });
      this.store.recordEvent({
        orgId: ctx.principal.orgId,
        actor: ctx.principal.label,
        actorKind: ctx.principal.kind,
        action: 'key.create',
        subject: key.id,
        meta: { name, scopes, log: pinned ?? null },
      });
      return { ...key, warning: 'the token is shown once and is not recoverable' };
    });

    r.delete('/v1/keys/:id', (ctx) => {
      requireScope(ctx.principal, 'admin');
      this.auth.revokeKey(ctx.principal.orgId, ctx.params.id);
      this.store.recordEvent({
        orgId: ctx.principal.orgId,
        actor: ctx.principal.label,
        actorKind: ctx.principal.kind,
        action: 'key.revoke',
        subject: ctx.params.id,
      });
      return { id: ctx.params.id, revoked: true };
    });

    /**
     * Invite someone. Returns the link rather than sending it: mail delivery
     * is an integration, and a hub that silently depends on SMTP being right
     * fails in a way nobody sees until an invitation never arrives.
     */
    r.post('/v1/invites', (ctx) => {
      requireScope(ctx.principal, 'admin');
      const { email, role } = ctx.body ?? {};
      if (!email || !role) {
        throw new StoreError(400, 'missing_fields', 'email and role are required');
      }
      if (!ROLES.includes(String(role))) {
        throw new StoreError(400, 'bad_role', `role must be one of ${ROLES.join(', ')}`);
      }

      const user =
        this.auth.userByEmail(String(email)) ?? this.auth.createUser({ email: String(email) });

      // The membership is created now, not on redemption, so an admin can see
      // who has been invited and to what. It grants nothing on its own: the
      // account has no password, so it cannot be signed in to, and the
      // invitation link is the only way to set one.
      this.auth.addMember(ctx.principal.orgId, user.id, String(role));

      const issued = this.tokens.issue({
        kind: 'invite',
        userId: user.id,
        orgId: ctx.principal.orgId,
        role: String(role),
        createdBy: ctx.principal.label,
      });

      this.store.recordEvent({
        orgId: ctx.principal.orgId,
        actor: ctx.principal.label,
        actorKind: ctx.principal.kind,
        action: 'member.invite',
        subject: user.email,
        meta: { role, expiresAt: issued.expiresAt },
      });

      const link = `${this._publicUrl(ctx)}/accept?token=${encodeURIComponent(issued.token)}`;
      this._deliver({ kind: 'invite', email: user.email, link, expiresAt: issued.expiresAt });

      return {
        email: user.email,
        role,
        expiresAt: issued.expiresAt,
        link,
        note: 'this link is shown once and grants account access — send it over a channel you trust',
      };
    });

    /**
     * Ask for a password reset.
     *
     * Always answers the same way, whether or not the address exists. A
     * different response for an unknown address turns this endpoint into an
     * account enumeration oracle.
     */
    r.post('/v1/auth/reset', (ctx) => {
      const email = String(ctx.body?.email ?? '');
      const user = email ? this.auth.userByEmail(email) : null;

      if (user) {
        const issued = this.tokens.issue({ kind: 'reset', userId: user.id });
        const link = `${this._publicUrl(ctx)}/reset?token=${encodeURIComponent(issued.token)}`;
        this._deliver({ kind: 'reset', email: user.email, link, expiresAt: issued.expiresAt });

        const orgs = this.auth.orgsFor(user.id);
        for (const org of orgs) {
          this.store.recordEvent({
            orgId: org.id,
            actor: user.email,
            actorKind: 'user',
            action: 'password.reset-requested',
            subject: user.email,
          });
        }
      }

      return { ok: true, note: 'if that address has an account, a reset link has been issued' };
    });

    /** Consume an invite or reset token and set a password. */
    r.post('/v1/auth/redeem', (ctx) => {
      const { token, password } = ctx.body ?? {};
      if (!token) throw new StoreError(400, 'missing_token', 'token is required');

      const { user, orgId } = this.tokens.redeem({
        token: String(token),
        password: String(password ?? ''),
      });

      for (const org of this.auth.orgsFor(user.id)) {
        this.store.recordEvent({
          orgId: org.id,
          actor: user.email,
          actorKind: 'user',
          action: 'password.set',
          subject: user.email,
        });
      }

      const session = this.auth.createSession(user.id);
      ctx.res.setHeader('set-cookie', [
        cookie('pw_session', session.token, { maxAge: 14 * 86400 }),
        ...(orgId ? [cookie('pw_org', orgId, { maxAge: 14 * 86400 })] : []),
      ]);
      return { ok: true, email: user.email };
    });

    r.get('/v1/members', (ctx) => {
      requireScope(ctx.principal, 'admin');
      return { members: this.auth.members(ctx.principal.orgId), roles: ROLES };
    });

    r.post('/v1/members', (ctx) => {
      requireScope(ctx.principal, 'admin');
      const { email, role, password } = ctx.body ?? {};
      if (!email || !role) throw new StoreError(400, 'missing_fields', 'email and role are required');
      const user =
        this.auth.userByEmail(String(email)) ??
        this.auth.createUser({ email: String(email), password: password ? String(password) : undefined });
      this.auth.addMember(ctx.principal.orgId, user.id, String(role));
      this.store.recordEvent({
        orgId: ctx.principal.orgId,
        actor: ctx.principal.label,
        actorKind: ctx.principal.kind,
        action: 'member.add',
        subject: user.email,
        meta: { role },
      });
      return { id: user.id, email: user.email, role };
    });

    r.get('/v1/events', (ctx) => {
      requireScope(ctx.principal, 'admin');
      return {
        events: this.store.events(ctx.principal.orgId, Number(ctx.query.get('limit') ?? 100)),
        integrity: this.store.auditEvents(ctx.principal.orgId),
      };
    });

    r.get('/v1/usage', (ctx) => {
      requireScope(ctx.principal, 'logs:read');
      return {
        daily: this.db
          .prepare('SELECT day, receipts, denials FROM usage_daily WHERE org_id = ? ORDER BY day DESC LIMIT 90')
          .all(ctx.principal.orgId),
        logs: this.store.logs(ctx.principal.orgId).length,
      };
    });

    // ── console ─────────────────────────────────────────────────────────
    for (const page of [
      '/', '/logs/:log', '/approvals', '/policies', '/settings', '/events',
      '/login', '/forgot', '/accept', '/reset',
    ]) {
      r.get(page, (ctx) => renderConsole(this, ctx, page));
    }

    // Both flows post here. The page decides its own wording; the handler is
    // the same, because setting a password from a capability is one operation.
    for (const route of ['/accept', '/reset']) {
      r.post(route, (ctx) => {
        const token = String(ctx.body?.token ?? '');
        const password = String(ctx.body?.password ?? '');
        const confirm = String(ctx.body?.confirm ?? '');

        if (password !== confirm) {
          return { __redirect: `${route}?token=${encodeURIComponent(token)}&e=mismatch` };
        }
        try {
          const { user, orgId } = this.tokens.redeem({ token, password });
          for (const org of this.auth.orgsFor(user.id)) {
            this.store.recordEvent({
              orgId: org.id, actor: user.email, actorKind: 'user',
              action: 'password.set', subject: user.email, meta: { via: 'console' },
            });
          }
          const session = this.auth.createSession(user.id);
          return {
            __redirect: '/',
            cookies: [
              cookie('pw_session', session.token, { maxAge: 14 * 86400 }),
              ...(orgId ? [cookie('pw_org', orgId, { maxAge: 14 * 86400 })] : []),
            ],
          };
        } catch (err) {
          const code = err instanceof StoreError ? err.code : 'invalid_token';
          return { __redirect: `${route}?token=${encodeURIComponent(token)}&e=${code}` };
        }
      });
    }

    r.post('/forgot', (ctx) => {
      const email = String(ctx.body?.email ?? '');
      const user = email ? this.auth.userByEmail(email) : null;
      if (user) {
        const issued = this.tokens.issue({ kind: 'reset', userId: user.id });
        const link = `${this._publicUrl(ctx)}/reset?token=${encodeURIComponent(issued.token)}`;
        this._deliver({ kind: 'reset', email: user.email, link, expiresAt: issued.expiresAt });
      }
      // Same page either way: the response must not reveal whether the
      // address is registered.
      return { __redirect: '/forgot?sent=1' };
    });

    r.post('/login', (ctx) => {
      const email = String(ctx.body?.email ?? '');
      const password = String(ctx.body?.password ?? '');
      const user = email ? this.auth.userByEmail(email) : null;
      if (!user || !verifyPasswordSafe(password, user.password_hash)) {
        return { __redirect: '/login?e=1' };
      }
      const session = this.auth.createSession(user.id);
      this.db.prepare('UPDATE users SET last_seen_at = ? WHERE id = ?').run(now(), user.id);
      const orgs = this.auth.orgsFor(user.id);
      return {
        __redirect: '/',
        cookies: [
          cookie('pw_session', session.token, { maxAge: 14 * 86400 }),
          ...(orgs[0] ? [cookie('pw_org', orgs[0].id, { maxAge: 14 * 86400 })] : []),
        ],
      };
    });

    r.post('/logout', (ctx) => {
      const cookies = parseCookies(ctx.req.headers.cookie);
      if (cookies.pw_session) this.auth.revokeSession(cookies.pw_session);
      return {
        __redirect: '/login',
        cookies: [cookie('pw_session', '', { maxAge: 0 }), cookie('pw_org', '', { maxAge: 0 })],
      };
    });

    r.post('/approvals/:id/decide', (ctx) => {
      requireScope(ctx.principal, 'approvals:write');
      const approved = String(ctx.body?.approved ?? '') === '1';
      const row = this.db
        .prepare('SELECT * FROM approvals WHERE org_id = ? AND id = ?')
        .get(ctx.principal.orgId, ctx.params.id);
      if (!row) throw new StoreError(404, 'no_such_approval', 'no such approval request');
      if (row.status !== 'pending' || row.expires_at <= now()) {
        return { __redirect: '/approvals' };
      }

      const status = approved ? 'approved' : 'denied';
      this.db
        .prepare('UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, note = ? WHERE id = ?')
        .run(status, now(), ctx.principal.label, '', row.id);
      this.store.recordEvent({
        orgId: ctx.principal.orgId,
        actor: ctx.principal.label,
        actorKind: ctx.principal.kind,
        action: `approval.${status}`,
        subject: row.target,
        meta: { approval: row.id, via: 'console' },
      });
      this.approvalBus.emit(row.id);
      return { __redirect: '/approvals' };
    });

    r.post('/settings/keys/:id/revoke', (ctx) => {
      requireScope(ctx.principal, 'admin');
      this.auth.revokeKey(ctx.principal.orgId, ctx.params.id);
      this.store.recordEvent({
        orgId: ctx.principal.orgId,
        actor: ctx.principal.label,
        actorKind: ctx.principal.kind,
        action: 'key.revoke',
        subject: ctx.params.id,
        meta: { via: 'console' },
      });
      return { __redirect: '/settings' };
    });
  }

  /**
   * Block until an approval is decided, or the deadline passes.
   *
   * Event-driven with a timer as a backstop: the event fires when a human
   * clicks, and the timer covers a decision made by another process against
   * the same database.
   *
   * @param {string} id
   * @param {number} ms
   * @param {() => any} read
   */
  _awaitDecision(id, ms, read) {
    return new Promise((resolve) => {
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        clearInterval(poll);
        clearTimeout(timer);
        this.approvalBus.off(id, onDecided);
        resolve(read());
      };
      const onDecided = () => finish();

      this.approvalBus.once(id, onDecided);
      const poll = setInterval(() => {
        const row = read();
        if (row && row.status !== 'pending') finish();
      }, 1000);
      const timer = setTimeout(finish, ms);
    });
  }

  /**
   * The base URL to put in an invitation or reset link.
   *
   * Configured first, because behind a proxy the Host header is whatever the
   * proxy passes through and a link built from it can point somewhere useless.
   *
   * @param {import('./http.js').Ctx} ctx
   * @returns {string}
   */
  _publicUrl(ctx) {
    if (this.config.publicUrl) return this.config.publicUrl.replace(/\/+$/, '');
    const host = ctx.req.headers.host ?? `localhost:${this.config.port}`;
    return `http${process.env.PROOFWIRE_INSECURE_COOKIES === '1' ? '' : 's'}://${host}`;
  }

  /**
   * Hand a link to whatever actually sends mail.
   *
   * Deliberately a webhook rather than built-in SMTP: every organisation
   * already has a way to send transactional mail, and a hub that ships its own
   * is one more thing to configure, monitor, and get onto an allowlist. A
   * delivery failure is logged and never fails the request — the link is
   * returned to the caller either way, so an admin is never stuck.
   *
   * @param {{ kind: string, email: string, link: string, expiresAt: string }} payload
   */
  _deliver(payload) {
    const url = process.env.PROOFWIRE_NOTIFY_URL;
    if (!url) return;

    fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(process.env.PROOFWIRE_NOTIFY_TOKEN
          ? { authorization: `Bearer ${process.env.PROOFWIRE_NOTIFY_TOKEN}` }
          : {}),
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10_000),
    }).catch((err) => {
      console.error(
        JSON.stringify({ level: 'warn', event: 'notify.failed', kind: payload.kind, message: err.message }),
      );
    });
  }

  /**
   * Whether a state-changing request originated from this hub's own pages.
   *
   * `Origin` is set by the browser on every POST and cannot be forged by page
   * script. `Referer` is the fallback for the handful of cases that omit
   * Origin. A request carrying neither is refused rather than trusted: for a
   * cookie-authenticated write, absence of evidence is not evidence of
   * innocence.
   *
   * @param {import('node:http').IncomingMessage} req
   * @returns {boolean}
   */
  _sameOrigin(req) {
    const host = req.headers.host;
    if (!host) return false;

    const stated = req.headers.origin ?? req.headers.referer;
    if (typeof stated !== 'string' || stated === '') return false;

    try {
      return new URL(stated).host === host;
    } catch {
      return false;
    }
  }

  // ── request pipeline ──────────────────────────────────────────────────

  /**
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   */
  async handle(req, res) {
    const requestId = newRequestId();
    res.setHeader('x-request-id', requestId);
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');
    // Suppressed alongside Secure cookies, because a local HTTP development
    // hub that pins the browser to HTTPS for a year is a foot-gun.
    if (process.env.PROOFWIRE_INSECURE_COOKIES !== '1') {
      res.setHeader('strict-transport-security', 'max-age=31536000; includeSubDomains');
    }

    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const started = Date.now();
    let status = 500;

    try {
      const matched = this.router.match(req.method ?? 'GET', url.pathname);
      if (!matched) {
        throw new StoreError(404, 'not_found', `no route for ${req.method} ${url.pathname}`);
      }

      const principal = this._principal(req, url);

      // Cross-site request forgery.
      //
      // Only cookie-authenticated requests are exposed: a browser will never
      // attach an Authorization header to a cross-site request, so the API is
      // structurally immune and the console is not. SameSite=Lax already
      // withholds the cookie on a cross-site POST in current browsers, but
      // that is one mechanism in one layer, and "the browser will protect us"
      // is not a control an auditor can inspect. An explicit origin check is.
      if (
        principal?.kind === 'user' &&
        !['GET', 'HEAD', 'OPTIONS'].includes(req.method ?? 'GET') &&
        !this._sameOrigin(req)
      ) {
        throw new StoreError(
          403,
          'cross_origin',
          'this request did not come from the console; state-changing requests must be same-origin',
        );
      }

      // Rate limit by credential where we have one, by address otherwise. A
      // per-address limit alone would throttle every agent behind one NAT
      // together; a per-key limit alone would let unauthenticated floods past.
      const isIngest = url.pathname.endsWith('/receipts') && req.method === 'POST';
      const isAuth = url.pathname.startsWith('/v1/auth/') || url.pathname === '/login';
      const limiter = isIngest ? this.limiters.ingest : isAuth ? this.limiters.auth : this.limiters.api;
      const bucketKey = principal
        ? `${principal.kind}:${principal.id}`
        : `ip:${clientAddress(req, this.config.trustProxy)}`;

      const allowed = limiter.take(bucketKey);
      if (!allowed.ok) {
        res.setHeader('retry-after', String(allowed.retryAfter));
        throw new StoreError(
          429,
          'rate_limited',
          `too many requests; retry in ${allowed.retryAfter}s`,
        );
      }

      const body =
        req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH'
          ? await readBody(req, this.config.maxBodyBytes)
          : null;

      /** @type {import('./http.js').Ctx} */
      const ctx = {
        req, res, url,
        params: matched.params,
        query: url.searchParams,
        body,
        principal,
        requestId,
        store: this.store,
        auth: this.auth,
        config: this.config,
        hub: this,
      };

      const out = await matched.handler(ctx);
      if (res.writableEnded) return;

      if (out && typeof out === 'object' && out.__redirect !== undefined) {
        status = 303;
        redirect(res, out.__redirect, out.cookies);
      } else if (out && typeof out === 'object' && out.__html !== undefined) {
        status = out.status ?? 200;
        sendHtml(res, status, out.__html, out.headers ?? {});
      } else {
        status = 200;
        sendJson(res, status, out ?? { ok: true });
      }
    } catch (err) {
      const { status: s, body, internal } = errorResponse(err, requestId);
      status = s;
      if (internal) {
        console.error(
          JSON.stringify({
            level: 'error', requestId, path: url.pathname,
            message: internal.message, stack: internal.stack,
          }),
        );
      }
      if (!res.writableEnded) sendJson(res, status, body);
    } finally {
      if (process.env.PROOFWIRE_ACCESS_LOG !== 'off') {
        console.log(
          JSON.stringify({
            level: status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info',
            requestId,
            method: req.method,
            path: url.pathname,
            status,
            ms: Date.now() - started,
          }),
        );
      }
    }
  }

  /**
   * @param {number} [port]
   * @returns {Promise<{ url: string, server: import('node:http').Server }>}
   */
  listen(port = this.config.port) {
    this.server = http.createServer((req, res) => this.handle(req, res));
    return new Promise((resolve, reject) => {
      this.server.on('error', reject);
      this.server.listen(port, this.config.host, () => {
        const addr = /** @type {import('node:net').AddressInfo} */ (this.server.address());
        resolve({ url: `http://${this.config.host}:${addr.port}`, server: this.server });
      });
    });
  }

  async close() {
    if (this.server) await new Promise((r) => this.server.close(r));
    this.db.close();
  }
}

// ── helpers ─────────────────────────────────────────────────────────────

/**
 * A user with no password set (invited but never activated) must not be able
 * to sign in with an empty one.
 *
 * @param {string} password
 * @param {string|null} hash
 */
function verifyPasswordSafe(password, hash) {
  if (!hash) return false;
  return verifyPassword(password, hash);
}

/**
 * @param {string} name
 * @param {string} value
 * @param {{ maxAge: number }} opts
 */
function cookie(name, value, opts) {
  return (
    `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${opts.maxAge}` +
    (process.env.PROOFWIRE_INSECURE_COOKIES === '1' ? '' : '; Secure')
  );
}

/** @param {object} log */
function publicLog(log) {
  return {
    id: log.id,
    slug: log.slug,
    canonical: log.canonical,
    name: log.name,
    kid: log.kid,
    publicKey: log.public_key,
    size: log.size,
    head: log.head,
    root: log.root,
    createdAt: log.created_at,
    lastSeenAt: log.last_seen_at,
    archivedAt: log.archived_at,
  };
}

/** @param {object} row */
function publicApproval(row) {
  return {
    id: row.id,
    log: row.log_slug ?? row.log_id,
    target: row.target,
    params: JSON.parse(row.params),
    reason: row.reason,
    rules: JSON.parse(row.rules),
    principal: row.principal,
    agent: row.agent,
    session: row.session,
    status: row.status,
    requestedAt: row.requested_at,
    expiresAt: row.expires_at,
    decidedAt: row.decided_at,
    decidedBy: row.decided_by,
    note: row.note,
  };
}

/**
 * @param {object|null} obj
 * @param {string[]} keys
 */
function pick(obj, keys) {
  /** @type {Record<string, unknown>} */
  const out = {};
  if (!obj) return out;
  for (const k of keys) out[k] = obj[k];
  return out;
}

export { SCOPES, ROLES };
