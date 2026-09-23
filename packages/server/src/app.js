import http from 'node:http';
import { createRequire } from 'node:module';
import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';
import {
  Policy,
  canonicalize,
  checkpointDigest,
  verify as verifyBytes,
  identityFromPublicKey,
  unhex,
  verifyConsistency,
} from '@proof_wire/core';
import { openDatabase, newId, now, transact } from './db.js';
import { Store, StoreError } from './store.js';
import { signerFor, disabledSigner } from './signer.js';
import { Auth, Tokens, requireScope, requireLog, scopesForRole, verifyPassword, hashPassword, SCOPES, ROLES } from './auth.js';
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
import {
  SLACK_HOSTS,
  verifySlackSignature,
  slackUrlProblem,
  approvalMessage,
  decidedMessage,
  slackActor,
} from './slack.js';

/**
 * The Proofwire hub.
 *
 * Read the route table below as the product: agents push signed receipts,
 * humans resolve escalations, auditors pull proofs, witnesses counter-sign.
 * Everything else is plumbing around those four jobs.
 */

/** This package's version, as published — read, not typed, so it cannot drift. */
export const VERSION = createRequire(import.meta.url)('../package.json').version;

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
  /**
   * Failed sign-ins per account, from anywhere. The per-address limit above
   * does nothing against credential stuffing spread over thousands of
   * addresses; this one does. Ten wrong guesses, then one more every 90s.
   */
  accountLoginRate: { capacity: 10, refillPerSec: 1 / 90 },
  trustProxy: false,
  approvalTtlSeconds: 900,
  /** Auto-checkpoint after this many new receipts. 0 disables. */
  checkpointEvery: 500,
  publicUrl: '',
  /** Serve only `WITNESS_ONLY_ROUTES`. For a node whose one job is co-signing. */
  witnessOnly: false,
  /** Hosts a Slack webhook or response URL may be on. Tests point this at a fake. */
  slackHosts: SLACK_HOSTS,
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
      account: new RateLimiter(this.config.accountLoginRate),
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
    const user = this.auth.userForSession(cookies.get('pw_session'));
    if (!user) return null;

    const wanted = url.searchParams.get('org') ?? cookies.get('pw_org') ?? null;
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
          version: VERSION,
          witness: { kid: this.witnessSigner.kid, publicKey: this.witnessSigner.publicKey },
          keys: keys.filter((k) => k.role === 'witness'),
          receiptVersion: 1,
        };
      }
      return {
        service: 'proofwire-hub',
        version: VERSION,
        hub: { kid: this.hubSigner.kid, publicKey: this.hubSigner.publicKey },
        witness: { kid: this.witnessSigner.kid, publicKey: this.witnessSigner.publicKey },
        keys,
        receiptVersion: 1,
      };
    });

    // ── auth ────────────────────────────────────────────────────────────
    r.post('/v1/auth/login', async (ctx) => {
      const { email, password } = ctx.body ?? {};
      const attempt = this._checkLogin(ctx, email, password);
      if (attempt.throttled) {
        ctx.res.setHeader('retry-after', String(attempt.throttled));
        throw new StoreError(429, 'too_many_attempts', 'too many failed sign-ins for this account; try again later');
      }
      const user = attempt.user;
      if (!user) {
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
      if (cookies.get('pw_session')) this.auth.revokeSession(cookies.get('pw_session'));
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
      if (row.pruned_at) {
        // Gone by the organisation's own retention. Its hash is still in the
        // tree, so an inclusion proof for it works; the content is with the
        // agent's local log, or an export taken before.
        throw new StoreError(410, 'pruned', `entry ${row.seq} was pruned by retention on ${row.pruned_at}`, {
          seq: row.seq,
          hash: row.hash,
          ts: row.ts,
          prunedAt: row.pruned_at,
        });
      }
      return { receipt: JSON.parse(row.body), receivedAt: row.received_at };
    });

    // ── retention ───────────────────────────────────────────────────────
    r.get('/v1/settings/retention', (ctx) => {
      requireScope(ctx.principal, 'admin');
      return this.store.retention(ctx.principal.orgId);
    });

    r.put('/v1/settings/retention', (ctx) => {
      requireScope(ctx.principal, 'admin');
      const raw = ctx.body?.days;
      const days = raw === null || raw === 'forever' ? null : Number(raw);
      if (days !== null && (!Number.isInteger(days) || days < 1 || days > 36_500)) {
        throw new StoreError(400, 'bad_retention', 'days must be a whole number from 1 to 36500, or null to keep forever');
      }
      const { capDays } = this.store.retention(ctx.principal.orgId);
      if (capDays !== null && (days === null || days > capDays)) {
        throw new StoreError(
          400,
          'over_cap',
          `this organization's plan keeps receipts at most ${capDays} days on the hub; choose ${capDays} or fewer`,
          { capDays },
        );
      }
      this.store.setRetention(ctx.principal.orgId, { days });
      this.store.recordEvent({
        orgId: ctx.principal.orgId,
        actor: ctx.principal.label,
        actorKind: ctx.principal.kind,
        action: 'retention.set',
        subject: days === null ? 'forever' : `${days} days`,
        meta: { days },
      });
      const result = this.store.retention(ctx.principal.orgId);
      if (result.effectiveDays !== null && result.effectiveDays < 183) {
        return {
          ...result,
          warning:
            'Shorter than six months: logs of high-risk AI systems must be kept at least that long under ' +
            'the EU AI Act (Arts. 19 and 26(6)). The hub will prune sooner; keep the agents\' local logs or ' +
            'exported evidence packs for the full period.',
        };
      }
      return result;
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
     *
     * And it only takes a log's checkpoints from the log. The first request
     * for a log names the key its checkpoints are signed with
     * (`logPublicKey`); the witness checks that signature and binds the log to
     * that key. From then on a checkpoint must carry a valid `log` signature
     * from the bound key, or it is refused before its position is even looked
     * at. Without this, a witness's memory of a log belongs to whoever reaches
     * it first with a well-formed body. A key rotation is rebound on the host
     * (`proofwire-hub witness-rebind`), never over this endpoint.
     */
    r.post('/v1/witness/cosign', async (ctx) => {
      requireScope(ctx.principal, 'witness:sign');
      const checkpoint = ctx.body?.checkpoint;
      const proof = ctx.body?.consistencyProof;
      if (!checkpoint?.body) {
        throw new StoreError(400, 'missing_checkpoint', 'body must be { checkpoint: {...} }');
      }

      /** @type {{ kid: string, publicKey: string }|null} */
      let offered = null;
      if (ctx.body?.logPublicKey !== undefined && ctx.body?.logPublicKey !== null) {
        try {
          offered = identityFromPublicKey(String(ctx.body.logPublicKey));
        } catch {
          throw new StoreError(
            400,
            'bad_log_key',
            'logPublicKey must be the log signer\'s raw 32-byte Ed25519 public key, canonical base64url',
          );
        }
      }

      const { body } = checkpoint;
      const logKey = `${ctx.principal.orgId}:${body.log}`;
      const witnessKid = this.witnessSigner.kid;
      /** @type {{ kid: string, bound_at: string, bound_by: string }} */
      let binding;
      let newlyBound = false;

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
      //
      // The key binding is read, checked and — on first use — written inside
      // the same transaction, for the same reason: two first requests naming
      // different keys must not both bind.
      transact(this.db, () => {
        const bound = this.store.witnessBinding(witnessKid, logKey);
        if (bound && offered && offered.kid !== bound.kid) {
          throw new StoreError(
            409,
            'log_key_mismatch',
            `this witness has ${body.log} bound to ${bound.kid}, not ${offered.kid}. If the log's ` +
              `key was rotated on purpose, the witness operator rebinds it: ` +
              `proofwire-hub witness-rebind <customer> ${body.log} <new public key>`,
            { bound: bound.kid, offered: offered.kid },
          );
        }
        if (!bound && !offered) {
          throw new StoreError(
            400,
            'missing_log_key',
            `this witness has not co-signed for ${body.log} before, so the request must name the key ` +
              `its checkpoints are signed with: { checkpoint, logPublicKey }. (pw 0.2.0 does not ` +
              `send it; upgrade the CLI.)`,
          );
        }
        const key = bound ? { kid: bound.kid, publicKey: bound.public_key } : offered;

        // Checked before the position, so a checkpoint the log never signed
        // cannot move, or even probe, what the witness remembers.
        const logSig = Array.isArray(checkpoint.sigs)
          ? checkpoint.sigs.find((s) => s && s.role === 'log' && s.kid === key.kid)
          : undefined;
        if (
          !logSig ||
          typeof logSig.sig !== 'string' ||
          !verifyBytes(key.publicKey, checkpointDigest(body), logSig.sig)
        ) {
          throw new StoreError(
            422,
            'bad_log_signature',
            `the checkpoint carries no valid log signature from ${key.kid}` +
              (bound ? `, the key this witness has ${body.log} bound to` : ''),
          );
        }

        const prior = this.store.witnessPosition(witnessKid, logKey);

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
          .run(witnessKid, logKey, body.size, body.root, now());

        // A position recorded before bindings existed is bound here too, on its
        // next co-signing — the same first-use rule, applied late.
        binding = bound ?? this.store.bindWitnessLogKey({
          witnessKid, positionKey: logKey, kid: key.kid, publicKey: key.publicKey, by: 'first-use',
        });
        newlyBound = !bound;
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
        logKey: { kid: binding.kid, boundAt: binding.bound_at, boundBy: binding.bound_by, newlyBound },
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

      this._notifySlack(ctx, {
        id,
        target: String(b.target),
        log: log.slug,
        params: b.params ?? {},
        reason: String(b.reason ?? ''),
        rules: Array.isArray(b.rules) ? b.rules.map(String) : [],
        principal: String(b.principal ?? ''),
        agent: String(b.agent ?? ''),
        expiresAt,
      });
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
      const res = this._decideApproval(ctx.principal.orgId, ctx.params.id, {
        approved: ctx.body?.approved === true,
        by: ctx.principal.label,
        byKind: ctx.principal.kind,
        note: String(ctx.body?.note ?? ''),
        via: 'api',
      });
      if (res.outcome === 'missing') throw new StoreError(404, 'no_such_approval', 'no such approval request');
      if (res.outcome === 'already') {
        throw new StoreError(409, 'already_decided', `this request was already ${res.row.status}`);
      }
      if (res.outcome === 'expired') {
        throw new StoreError(410, 'expired', 'this request expired before it was decided');
      }
      return { id: res.row.id, status: res.status, decidedBy: ctx.principal.label };
    });

    // ── integrations: Slack approvals ───────────────────────────────────
    r.get('/v1/integrations/slack', (ctx) => {
      requireScope(ctx.principal, 'admin');
      const found = this.store.integration(ctx.principal.orgId, 'slack');
      if (!found) return { configured: false };
      // The webhook URL and signing secret are credentials: report that they
      // are set, never what they are.
      return {
        configured: true,
        webhookHost: new URL(found.config.webhookUrl).host,
        approvers: found.config.approvers,
        interactionsUrl: `${this._publicUrl(ctx)}/v1/integrations/slack/interactions`,
        updatedAt: found.updatedAt,
      };
    });

    r.put('/v1/integrations/slack', (ctx) => {
      requireScope(ctx.principal, 'admin');
      const b = ctx.body ?? {};
      const problem = slackUrlProblem(String(b.webhookUrl ?? ''), this.config.slackHosts);
      if (problem) throw new StoreError(400, 'bad_webhook_url', `webhookUrl ${problem}`);
      // Slack signing secrets are 32 lowercase hex characters.
      if (!/^[0-9a-f]{32}$/.test(String(b.signingSecret ?? ''))) {
        throw new StoreError(400, 'bad_signing_secret', 'signingSecret must be the 32-character hex secret from the Slack app');
      }
      const approvers = Array.isArray(b.approvers) ? b.approvers.map(String) : [];
      const badApprover = approvers.find((id) => !/^[UW][A-Z0-9]{2,20}$/.test(id));
      if (badApprover !== undefined) {
        throw new StoreError(400, 'bad_approver', `"${badApprover}" is not a Slack user ID (like U024BE7LH)`);
      }

      this.store.setIntegration(ctx.principal.orgId, 'slack', {
        webhookUrl: String(b.webhookUrl),
        signingSecret: String(b.signingSecret),
        approvers,
      });
      this.store.recordEvent({
        orgId: ctx.principal.orgId,
        actor: ctx.principal.label,
        actorKind: ctx.principal.kind,
        action: 'integration.slack.set',
        subject: 'slack',
        meta: { webhookHost: new URL(String(b.webhookUrl)).host, approvers },
      });
      return {
        configured: true,
        approvers,
        interactionsUrl: `${this._publicUrl(ctx)}/v1/integrations/slack/interactions`,
      };
    });

    r.delete('/v1/integrations/slack', (ctx) => {
      requireScope(ctx.principal, 'admin');
      const removed = this.store.deleteIntegration(ctx.principal.orgId, 'slack');
      if (removed) {
        this.store.recordEvent({
          orgId: ctx.principal.orgId,
          actor: ctx.principal.label,
          actorKind: ctx.principal.kind,
          action: 'integration.slack.removed',
          subject: 'slack',
        });
      }
      return { configured: false, removed };
    });

    /** A plain message, so an admin can see the webhook works before relying on it. */
    r.post('/v1/integrations/slack/test', async (ctx) => {
      requireScope(ctx.principal, 'admin');
      const found = this.store.integration(ctx.principal.orgId, 'slack');
      if (!found) throw new StoreError(404, 'not_configured', 'Slack is not connected for this organization');
      const res = await this._postToSlack(found.config.webhookUrl, {
        text: `Proofwire is connected. Escalated agent actions for this organization will appear here, with Approve and Deny buttons.`,
      });
      if (!res.ok) throw new StoreError(502, 'slack_error', `Slack answered: ${res.error}`);
      return { sent: true };
    });

    /**
     * Button clicks, from Slack. No API key: Slack proves it sent the request
     * by signing the raw body with the app's signing secret, and a request
     * that doesn't verify changes nothing.
     */
    r.post('/v1/integrations/slack/interactions', async (ctx) => {
      let payload;
      try {
        payload = JSON.parse(String(ctx.body?.payload ?? ''));
      } catch {
        throw new StoreError(400, 'bad_payload', 'expected a Slack interaction payload');
      }
      const action = Array.isArray(payload?.actions) ? payload.actions[0] : null;
      const approvalId = typeof action?.value === 'string' ? action.value : '';
      const row = approvalId ? this.db.prepare('SELECT * FROM approvals WHERE id = ?').get(approvalId) : null;
      const slack = row ? this.store.integration(row.org_id, 'slack') : null;

      // One answer for "no such approval", "no Slack for that org" and "bad
      // signature", so an unsigned request learns nothing about which ids exist.
      const verified =
        slack &&
        verifySlackSignature({
          signingSecret: slack.config.signingSecret,
          timestamp: ctx.req.headers['x-slack-request-timestamp'],
          signature: ctx.req.headers['x-slack-signature'],
          rawBody: ctx.rawBody ?? '',
        });
      if (!verified) throw new StoreError(401, 'bad_signature', 'request signature did not verify');

      const by = slackActor(payload.user);
      const respond = (/** @type {object} */ message) => {
        const url = String(payload.response_url ?? '');
        if (slackUrlProblem(url, this.config.slackHosts)) return;
        this._postToSlack(url, message).catch(() => {});
      };

      const approvers = slack.config.approvers ?? [];
      if (approvers.length && !approvers.includes(String(payload.user?.id))) {
        this.store.recordEvent({
          orgId: row.org_id,
          actor: by,
          actorKind: 'slack',
          action: 'approval.refused',
          subject: row.target,
          meta: { approval: row.id, reason: 'not an approver' },
        });
        respond({
          response_type: 'ephemeral',
          replace_original: false,
          text: 'You are not on the list of people who can decide Proofwire approvals for this workspace.',
        });
        return {};
      }

      const res = this._decideApproval(row.org_id, row.id, {
        approved: action.action_id === 'proofwire_approve',
        by,
        byKind: 'slack',
        note: action.action_id === 'proofwire_approve' ? 'approved in Slack' : 'denied in Slack',
        via: 'slack',
      });
      if (res.outcome === 'decided') respond(decidedMessage(row, res.status, by));
      else if (res.outcome === 'already') respond(decidedMessage(row, res.row.status, res.row.decided_by, true));
      else if (res.outcome === 'expired') respond(decidedMessage(row, 'expired', ''));
      return {};
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
      const attempt = this._checkLogin(ctx, ctx.body?.email, ctx.body?.password);
      if (attempt.throttled) return { __redirect: '/login?e=2' };
      const user = attempt.user;
      if (!user) return { __redirect: '/login?e=1' };
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
      if (cookies.get('pw_session')) this.auth.revokeSession(cookies.get('pw_session'));
      return {
        __redirect: '/login',
        cookies: [cookie('pw_session', '', { maxAge: 0 }), cookie('pw_org', '', { maxAge: 0 })],
      };
    });

    r.post('/approvals/:id/decide', (ctx) => {
      requireScope(ctx.principal, 'approvals:write');
      const res = this._decideApproval(ctx.principal.orgId, ctx.params.id, {
        approved: String(ctx.body?.approved ?? '') === '1',
        by: ctx.principal.label,
        byKind: ctx.principal.kind,
        note: '',
        via: 'console',
      });
      if (res.outcome === 'missing') throw new StoreError(404, 'no_such_approval', 'no such approval request');
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
   * Decide a pending approval: the one path the API, the console and Slack
   * all take, so they can't drift apart in what they check or record.
   *
   * The update itself is conditional on the request still being pending and
   * unexpired, so two people clicking at once can't both decide it: exactly
   * one update lands, and the other caller is told who got there first.
   *
   * @param {string} orgId
   * @param {string} id
   * @param {{ approved: boolean, by: string, byKind: string, note: string, via: string }} d
   * @returns {{ outcome: 'decided' | 'already' | 'expired' | 'missing', status?: string, row?: any }}
   */
  _decideApproval(orgId, id, d) {
    const read = () => this.db.prepare('SELECT * FROM approvals WHERE org_id = ? AND id = ?').get(orgId, id);
    const row = read();
    if (!row) return { outcome: 'missing' };

    const status = d.approved ? 'approved' : 'denied';
    const at = now();
    const changed = this.db
      .prepare(
        `UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, note = ?
         WHERE id = ? AND status = 'pending' AND expires_at > ?`,
      )
      .run(status, at, d.by, d.note, id, at).changes;

    if (!changed) {
      const current = read();
      return current.status === 'pending' ? { outcome: 'expired', row: current } : { outcome: 'already', row: current };
    }

    this.store.recordEvent({
      orgId,
      actor: d.by,
      actorKind: d.byKind,
      action: `approval.${status}`,
      subject: row.target,
      meta: { approval: id, note: d.note, via: d.via },
    });
    this.approvalBus.emit(id);
    return { outcome: 'decided', status, row: read() };
  }

  /**
   * Post a new approval request to the organisation's Slack channel, if it
   * has one. Never awaited by the request that created the approval: an agent
   * escalating must not wait on, or fail because of, Slack.
   *
   * @param {import('./http.js').Ctx} ctx
   * @param {Parameters<typeof approvalMessage>[0]} approval
   */
  _notifySlack(ctx, approval) {
    const slack = this.store.integration(ctx.principal.orgId, 'slack');
    if (!slack) return;
    const message = approvalMessage(approval, `${this._publicUrl(ctx)}/approvals`);
    this._postToSlack(slack.config.webhookUrl, message).then((res) => {
      if (!res.ok) {
        console.error(
          JSON.stringify({ level: 'warn', event: 'slack.notify_failed', approval: approval.id, error: res.error }),
        );
      }
    });
  }

  /**
   * @param {string} url  Already checked against `slackHosts`.
   * @param {object} message
   * @returns {Promise<{ ok: boolean, error?: string }>}
   */
  async _postToSlack(url, message) {
    if (slackUrlProblem(url, this.config.slackHosts)) return { ok: false, error: 'URL not allowed' };
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(message),
        // A webhook URL is never a place to follow a redirect to.
        redirect: 'error',
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) return { ok: true };
      return { ok: false, error: `HTTP ${res.status} ${(await res.text()).slice(0, 100)}` };
    } catch (err) {
      return { ok: false, error: /** @type {Error} */ (err).message };
    }
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
    if (this.config.publicUrl) return trimSlashes(this.config.publicUrl);
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
   * Check a sign-in attempt, for both the API and the console form.
   *
   * Two things an attacker learns from a naive version, both closed here:
   *
   *   - Which emails exist. An unknown address used to return before scrypt
   *     ran, ~50ms faster than a known one; now every attempt pays for one
   *     scrypt, known user or not.
   *   - Unlimited guesses. The per-address limiter is useless against a
   *     botnet, so failures are also counted per account. A throttled account
   *     is refused *before* the password is checked, so even the right
   *     password does not get in until the window passes, and the same
   *     refusal is given for addresses that do not exist.
   *
   * @param {import('./http.js').Ctx} ctx
   * @param {unknown} email
   * @param {unknown} password
   * @returns {{ user: any, throttled: number }}
   */
  _checkLogin(ctx, email, password) {
    const address = String(email ?? '').trim();
    const key = `login:${address.toLowerCase()}`;
    const gate = this.limiters.account.peek(key);
    if (!gate.ok) {
      // To the operator's log, not the tenant audit chain: an attempt on an
      // address belongs to no organisation until it succeeds.
      console.error(
        JSON.stringify({
          level: 'warn',
          event: 'auth.login_throttled',
          email: address.slice(0, 200),
          from: clientAddress(ctx.req, this.config.trustProxy),
        }),
      );
      return { user: null, throttled: gate.retryAfter };
    }
    const user = address ? this.auth.userByEmail(address) : null;
    const ok = verifyPasswordSafe(String(password ?? ''), user?.password_hash ?? null) && Boolean(password);
    if (ok) return { user, throttled: 0 };
    this.limiters.account.take(key);
    return { user: null, throttled: 0 };
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
      const isAuth =
        url.pathname.startsWith('/v1/auth/') || url.pathname === '/login' || url.pathname === '/forgot';
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

      const { body, raw } =
        req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH'
          ? await readBody(req, this.config.maxBodyBytes)
          : { body: null, raw: null };

      /** @type {import('./http.js').Ctx} */
      const ctx = {
        req, res, url,
        params: matched.params,
        query: url.searchParams,
        body,
        rawBody: raw,
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
 * Drop trailing slashes from a URL. A loop rather than a `/+$` regex, which
 * backtracks quadratically on a long run of slashes followed by anything else.
 *
 * @param {string} s
 * @returns {string}
 */
function trimSlashes(s) {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47) end--;
  return s.slice(0, end);
}

/**
 * A user with no password set (invited but never activated) must not be able
 * to sign in with an empty one.
 *
 * @param {string} password
 * @param {string|null} hash
 */
function verifyPasswordSafe(password, hash) {
  if (!hash) {
    // Same cost as a real check, so the response time does not say whether
    // the account exists or has a password yet.
    dummyPasswordHash ??= hashPassword(randomBytes(32).toString('hex'));
    verifyPassword(password, dummyPasswordHash);
    return false;
  }
  return verifyPassword(password, hash);
}

/**
 * A hash no password matches in practice; only its cost matters. Made on
 * first use rather than at import, so a hub that never serves a sign-in (a
 * witness node) never pays for it.
 *
 * @type {string | undefined}
 */
let dummyPasswordHash;

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
