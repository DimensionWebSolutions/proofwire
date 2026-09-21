import { randomBytes, createHash, timingSafeEqual, scryptSync } from 'node:crypto';
import { newId, now } from './db.js';
import { StoreError } from './store.js';

/**
 * Identity and permission for the hub.
 *
 * Two kinds of caller, deliberately kept separate:
 *
 *   **API keys** are for machines — an agent runtime pushing receipts, a CI
 *   job checking a log, a witness signing a root. They carry explicit scopes
 *   and, for agent keys, are pinned to a single log.
 *
 *   **Sessions** are for humans in the console. Permission comes from their
 *   role in the org, not from a scope list, because a person's authority
 *   changes when their job does and enumerating scopes per user is how
 *   permissions quietly drift.
 */

/**
 * Scopes name an action, not a resource, because the resource is always the
 * caller's own org — tenancy is enforced separately and unconditionally.
 */
export const SCOPES = /** @type {const} */ ([
  'receipts:write',   // push receipts to a log
  'receipts:read',    // read receipts and proofs
  'logs:write',       // register and archive logs
  'logs:read',
  'policies:read',    // fetch the active policy (agents need this)
  'policies:write',
  'approvals:read',
  'approvals:write',  // resolve an escalation
  'witness:sign',     // counter-sign a checkpoint
  'admin',            // members, keys, org settings
]);

/**
 * What each role may do. `admin` is not a wildcard — it is listed explicitly
 * so that adding a scope later does not silently widen everyone's authority.
 */
const ROLE_SCOPES = {
  owner: [...SCOPES],
  admin: [
    'receipts:read', 'logs:read', 'logs:write', 'policies:read', 'policies:write',
    'approvals:read', 'approvals:write', 'admin',
  ],
  operator: [
    'receipts:read', 'logs:read', 'policies:read', 'approvals:read', 'approvals:write',
  ],
  // An auditor can read everything and change nothing. This is the role you
  // hand an outside firm, and it must not be able to alter what it is auditing.
  auditor: ['receipts:read', 'logs:read', 'policies:read', 'approvals:read'],
};

export const ROLES = Object.keys(ROLE_SCOPES);

/**
 * @param {string} role
 * @returns {string[]}
 */
export function scopesForRole(role) {
  return ROLE_SCOPES[role] ?? [];
}

/**
 * Hash a bearer secret. A plain SHA-256 is right here and scrypt would be
 * wrong: these are 256-bit random secrets, not passwords, so there is no
 * dictionary to slow down — and a deliberately slow hash on the ingest path
 * would be a self-inflicted denial of service at thousands of receipts a
 * second.
 *
 * @param {string} secret
 * @returns {string}
 */
function hashSecret(secret) {
  return createHash('sha256').update(secret, 'utf8').digest('hex');
}

/**
 * Passwords are a different problem and get scrypt.
 *
 * @param {string} password
 * @param {string} [salt]
 * @returns {string} `scrypt$<salt>$<hash>`
 */
export function hashPassword(password, salt) {
  const s = salt ?? randomBytes(16).toString('hex');
  const derived = scryptSync(password, s, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
  return `scrypt$${s}$${derived}`;
}

/**
 * @param {string} password
 * @param {string} stored
 * @returns {boolean}
 */
export function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  const [scheme, salt, expected] = stored.split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
  return safeEqual(actual, expected);
}

/**
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeEqual(a, b) {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}

export class Auth {
  /**
   * @param {import('./store.js').Store} store
   */
  constructor(store) {
    this.store = store;
    this.db = store.db;
  }

  // ── users ─────────────────────────────────────────────────────────────

  /**
   * @param {object} args
   * @param {string} args.email
   * @param {string} [args.name]
   * @param {string} [args.password]
   */
  createUser(args) {
    const email = args.email.trim().toLowerCase();
    const user = {
      id: newId('user'),
      email,
      name: args.name ?? email.split('@')[0],
      password_hash: args.password ? hashPassword(args.password) : null,
      created_at: now(),
    };
    this.db
      .prepare(
        'INSERT INTO users(id, email, name, password_hash, created_at) VALUES(?, ?, ?, ?, ?)',
      )
      .run(user.id, user.email, user.name, user.password_hash, user.created_at);
    return user;
  }

  /** @param {string} email */
  userByEmail(email) {
    return (
      this.db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim().toLowerCase()) ?? null
    );
  }

  /**
   * @param {string} orgId
   * @param {string} userId
   * @param {string} role
   */
  addMember(orgId, userId, role) {
    if (!ROLE_SCOPES[role]) {
      throw new StoreError(400, 'bad_role', `role must be one of ${ROLES.join(', ')}`);
    }
    this.db
      .prepare(
        `INSERT INTO memberships(org_id, user_id, role, created_at) VALUES(?, ?, ?, ?)
         ON CONFLICT(org_id, user_id) DO UPDATE SET role = excluded.role`,
      )
      .run(orgId, userId, role, now());
    return { orgId, userId, role };
  }

  /**
   * @param {string} orgId
   * @param {string} userId
   */
  membership(orgId, userId) {
    return (
      this.db
        .prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?')
        .get(orgId, userId) ?? null
    );
  }

  /** @param {string} orgId */
  members(orgId) {
    return this.db
      .prepare(
        `SELECT m.role, m.created_at, u.id, u.email, u.name, u.last_seen_at
         FROM memberships m JOIN users u ON u.id = m.user_id
         WHERE m.org_id = ? ORDER BY m.created_at ASC`,
      )
      .all(orgId);
  }

  /**
   * Orgs a user belongs to. The console uses this to pick a workspace.
   *
   * @param {string} userId
   */
  orgsFor(userId) {
    return this.db
      .prepare(
        `SELECT o.*, m.role FROM memberships m JOIN orgs o ON o.id = m.org_id
         WHERE m.user_id = ? ORDER BY o.created_at ASC`,
      )
      .all(userId);
  }

  // ── sessions ──────────────────────────────────────────────────────────

  /**
   * @param {string} userId
   * @param {number} [days]
   * @returns {{ token: string, expiresAt: string }}
   */
  createSession(userId, days = 14) {
    const token = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + days * 86_400_000).toISOString();
    this.db
      .prepare(
        `INSERT INTO sessions(id, user_id, token_hash, created_at, expires_at)
         VALUES(?, ?, ?, ?, ?)`,
      )
      .run(newId('session'), userId, hashSecret(token), now(), expiresAt);
    return { token, expiresAt };
  }

  /**
   * @param {string} token
   * @returns {object|null}
   */
  userForSession(token) {
    if (!token) return null;
    const row = this.db
      .prepare(
        `SELECT s.*, u.id AS uid, u.email, u.name FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.revoked_at IS NULL`,
      )
      .get(hashSecret(token));
    if (!row) return null;
    if (row.expires_at <= now()) return null;
    return { id: row.uid, email: row.email, name: row.name, sessionId: row.id };
  }

  /** @param {string} token */
  revokeSession(token) {
    this.db
      .prepare('UPDATE sessions SET revoked_at = ? WHERE token_hash = ?')
      .run(now(), hashSecret(token));
  }

  // ── api keys ──────────────────────────────────────────────────────────

  /**
   * Mint an API key. The secret is returned exactly once and never stored.
   *
   * @param {object} args
   * @param {string} args.orgId
   * @param {string} args.name
   * @param {string[]} args.scopes
   * @param {string} [args.logId]     Pin an agent key to one log.
   * @param {string} [args.createdBy]
   * @param {string} [args.expiresAt]
   * @returns {{ id: string, token: string, scopes: string[], logId: string|null }}
   */
  createKey(args) {
    const bad = args.scopes.filter((s) => !SCOPES.includes(s));
    if (bad.length) {
      throw new StoreError(400, 'bad_scope', `unknown scope(s): ${bad.join(', ')}`);
    }

    const id = newId('key');
    const secret = randomBytes(24).toString('base64url');
    // The id travels in the token so a lookup is a primary-key hit rather than
    // a scan that hashes every stored key.
    const token = `${id}.${secret}`;

    this.db
      .prepare(
        `INSERT INTO api_keys(id, org_id, name, secret_hash, scopes, log_id, created_at, created_by, expires_at)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id, args.orgId, args.name, hashSecret(secret), JSON.stringify(args.scopes),
        args.logId ?? null, now(), args.createdBy ?? null, args.expiresAt ?? null,
      );

    return { id, token, scopes: args.scopes, logId: args.logId ?? null };
  }

  /**
   * Resolve a bearer token to a principal.
   *
   * @param {string} token
   * @returns {object|null}
   */
  keyForToken(token) {
    if (typeof token !== 'string') return null;
    const dot = token.indexOf('.');
    if (dot < 1) return null;

    const id = token.slice(0, dot);
    const secret = token.slice(dot + 1);
    const row = this.db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id);
    if (!row) return null;
    if (!safeEqual(hashSecret(secret), row.secret_hash)) return null;
    if (row.revoked_at) return null;
    if (row.expires_at && row.expires_at <= now()) return null;

    return {
      id: row.id,
      orgId: row.org_id,
      name: row.name,
      scopes: JSON.parse(row.scopes),
      logId: row.log_id,
    };
  }

  /** @param {string} keyId */
  touchKey(keyId) {
    this.db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(now(), keyId);
  }

  /**
   * @param {string} orgId
   * @param {string} keyId
   */
  revokeKey(orgId, keyId) {
    const res = this.db
      .prepare('UPDATE api_keys SET revoked_at = ? WHERE org_id = ? AND id = ? AND revoked_at IS NULL')
      .run(now(), orgId, keyId);
    if (res.changes === 0) {
      throw new StoreError(404, 'no_such_key', 'no such active key in this organization');
    }
  }

  /** @param {string} orgId */
  keys(orgId) {
    return this.db
      .prepare(
        `SELECT id, name, scopes, log_id, created_at, created_by, last_used_at, expires_at, revoked_at
         FROM api_keys WHERE org_id = ? ORDER BY created_at DESC`,
      )
      .all(orgId)
      .map((k) => ({ ...k, scopes: JSON.parse(k.scopes) }));
  }
}

/**
 * The resolved caller for one request.
 *
 * @typedef {object} Principal
 * @property {'key'|'user'} kind
 * @property {string} id
 * @property {string} orgId
 * @property {string} label       For the audit trail.
 * @property {string[]} scopes
 * @property {string|null} logId  Non-null means this caller may touch only that log.
 * @property {string} [role]
 */

/**
 * Throw unless the caller holds the scope.
 *
 * @param {Principal|null} principal
 * @param {string} scope
 */
export function requireScope(principal, scope) {
  if (!principal) {
    throw new StoreError(401, 'unauthenticated', 'this endpoint requires credentials');
  }
  if (!principal.scopes.includes(scope)) {
    throw new StoreError(
      403,
      'insufficient_scope',
      `this credential lacks the "${scope}" scope`,
      { required: scope, held: principal.scopes },
    );
  }
}

/**
 * Throw unless the caller may act on this specific log.
 *
 * An agent key pinned to one log must not be able to write to a sibling, even
 * within the same org. This is the check that contains a leaked agent
 * credential to the blast radius of the one runtime that held it.
 *
 * @param {Principal|null} principal
 * @param {string} logId
 */
export function requireLog(principal, logId) {
  if (!principal) {
    throw new StoreError(401, 'unauthenticated', 'this endpoint requires credentials');
  }
  if (principal.logId && principal.logId !== logId) {
    throw new StoreError(
      403,
      'wrong_log',
      'this credential is pinned to a different log',
    );
  }
}
