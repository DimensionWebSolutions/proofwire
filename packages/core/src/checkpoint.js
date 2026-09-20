import { hashObject, CHECKPOINT_PREFIX } from './hash.js';
import { sign, verify } from './keys.js';

/**
 * Signed tree heads, and the witness co-signatures that make them binding.
 *
 * A log operator signing its own root proves very little: it can always sign a
 * second, different root for the same size and show each to a different
 * auditor. This "split view" is the one attack a self-hosted transparency log
 * cannot defend against alone.
 *
 * The fix is independent witnesses. A witness only ever counter-signs a root
 * that extends the last root it saw from that log, and it refuses to sign two
 * roots at the same size. A checkpoint carrying signatures from witnesses the
 * verifier chose forces the operator to show everyone the same history.
 */

/**
 * @typedef {object} CheckpointBody
 * @property {number} v
 * @property {string} log    Log identifier.
 * @property {number} size   Number of entries covered.
 * @property {string} root   Merkle root, hex.
 * @property {string} head   Hash of the last entry — ties the chain to the tree.
 * @property {string} ts
 */

/**
 * @typedef {object} Signature
 * @property {'log'|'witness'} role
 * @property {string} kid
 * @property {string} sig
 * @property {string} [ts]  When the witness signed, if later than the body.
 */

/**
 * @typedef {{ body: CheckpointBody, sigs: Signature[] }} Checkpoint
 */

export const CHECKPOINT_VERSION = 1;

/**
 * @param {object} args
 * @param {string} args.log
 * @param {number} args.size
 * @param {string} args.root
 * @param {string} args.head
 * @param {string} [args.ts]
 * @returns {CheckpointBody}
 */
export function buildCheckpoint(args) {
  return {
    v: CHECKPOINT_VERSION,
    log: args.log,
    size: args.size,
    root: args.root,
    head: args.head,
    ts: args.ts ?? new Date().toISOString(),
  };
}

/**
 * @param {CheckpointBody} body
 * @returns {Buffer}
 */
export function checkpointDigest(body) {
  return hashObject(CHECKPOINT_PREFIX, body);
}

/**
 * @param {import('./keys.js').Identity} identity
 * @param {CheckpointBody} body
 * @param {'log'|'witness'} [role='log']
 * @returns {Checkpoint}
 */
export function signCheckpoint(identity, body, role = 'log') {
  return {
    body,
    sigs: [{ role, kid: identity.kid, sig: sign(identity, checkpointDigest(body)) }],
  };
}

/**
 * Add a witness co-signature to an existing checkpoint.
 *
 * @param {Checkpoint} checkpoint
 * @param {import('./keys.js').Identity} witness
 * @returns {Checkpoint}
 */
export function cosign(checkpoint, witness) {
  const sig = sign(witness, checkpointDigest(checkpoint.body));
  const existing = checkpoint.sigs.filter((s) => s.kid !== witness.kid);
  return {
    body: checkpoint.body,
    sigs: [
      ...existing,
      { role: 'witness', kid: witness.kid, sig, ts: new Date().toISOString() },
    ],
  };
}

/**
 * @param {Checkpoint} checkpoint
 * @param {import('./receipt.js').Keyring} keyring
 * @param {object} [opts]
 * @param {number} [opts.minWitnesses=0]  Reject a checkpoint with fewer valid
 *   witness signatures than this. Set above zero to refuse to trust the
 *   operator's word alone.
 * @returns {{ ok: boolean, issues: string[], signers: string[], witnesses: number }}
 */
export function verifyCheckpoint(checkpoint, keyring, opts = {}) {
  /** @type {string[]} */
  const issues = [];
  /** @type {string[]} */
  const signers = [];
  let witnesses = 0;

  if (!checkpoint?.body || !Array.isArray(checkpoint.sigs)) {
    return { ok: false, issues: ['malformed checkpoint'], signers, witnesses };
  }
  if (checkpoint.body.v !== CHECKPOINT_VERSION) {
    issues.push(`unsupported checkpoint version ${checkpoint.body.v}`);
  }

  const digest = checkpointDigest(checkpoint.body);
  let hasLogSig = false;

  for (const s of checkpoint.sigs) {
    const pub = keyring[s.kid];
    if (!pub) {
      issues.push(`no public key for signer ${s.kid}`);
      continue;
    }
    if (!verify(pub, digest, s.sig)) {
      issues.push(`invalid ${s.role} signature from ${s.kid}`);
      continue;
    }
    signers.push(s.kid);
    if (s.role === 'witness') witnesses++;
    if (s.role === 'log') hasLogSig = true;
  }

  if (!hasLogSig) issues.push('checkpoint carries no valid log signature');

  const min = opts.minWitnesses ?? 0;
  if (witnesses < min) {
    issues.push(`only ${witnesses} valid witness signature(s), policy requires ${min}`);
  }

  return { ok: issues.length === 0, issues, signers, witnesses };
}
