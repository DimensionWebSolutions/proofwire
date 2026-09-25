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
 * Check a checkpoint's signatures.
 *
 * **Witnesses have to be pinned.** A checkpoint's `role` field is a label, not
 * something the signature covers, and a bundle's keyring is supplied by the same
 * party whose honesty is in question. So a witness count taken from the bundle's
 * own keyring proves nothing: an operator can invent as many witnesses as they
 * like by adding fresh keys. The verifier has to bring the witnesses' public
 * keys from somewhere else — `trustedWitnesses`, a map of kid to public key
 * obtained from the witness operators.
 *
 * With `trustedWitnesses`:
 *   - only `witness` signatures made by a pinned key are counted, and they are
 *     checked against the *pinned* key, never the bundle's;
 *   - a pinned witness's signature relabelled as the log's does not count as a
 *     log signature;
 *   - witness signatures from keys the verifier has never heard of are ignored
 *     rather than counted.
 *
 * Without it the count is informational only, and callers that demand witnesses
 * must not rely on it.
 *
 * @param {Checkpoint} checkpoint
 * @param {import('./receipt.js').Keyring} keyring
 * @param {object} [opts]
 * @param {number} [opts.minWitnesses=0]  Reject a checkpoint with fewer valid
 *   witness signatures than this.
 * @param {Record<string, string>} [opts.trustedWitnesses]  kid → public key
 *   (base64url), from outside the bundle.
 * @returns {{ ok: boolean, issues: string[], signers: string[], witnesses: number, pinned: boolean }}
 */
export function verifyCheckpoint(checkpoint, keyring, opts = {}) {
  /** @type {string[]} */
  const issues = [];
  /** @type {string[]} */
  const signers = [];
  let witnesses = 0;
  const trusted = opts.trustedWitnesses;
  const pinned = Boolean(trusted) && typeof trusted === 'object';
  const has = (obj, key) => obj != null && Object.prototype.hasOwnProperty.call(obj, key);

  if (!checkpoint?.body || !Array.isArray(checkpoint.sigs)) {
    return { ok: false, issues: ['malformed checkpoint'], signers, witnesses, pinned };
  }
  if (checkpoint.body.v !== CHECKPOINT_VERSION) {
    issues.push(`unsupported checkpoint version ${checkpoint.body.v}`);
  }

  const digest = checkpointDigest(checkpoint.body);
  let hasLogSig = false;
  // Each witness counts once, however many times its signature appears. A
  // signature is just bytes: without this, one witness's signature copied
  // three times satisfied a policy that asked for three witnesses. Keyed by
  // public key rather than kid, so one key pinned under two names is still
  // one witness.
  /** @type {Set<string>} */
  const counted = new Set();

  for (const s of checkpoint.sigs) {
    if (pinned && s?.role === 'witness') {
      if (!has(trusted, s.kid)) continue; // a witness we were not told to trust
      if (counted.has(trusted[s.kid])) continue;
      if (verify(trusted[s.kid], digest, s.sig)) {
        counted.add(trusted[s.kid]);
        signers.push(s.kid);
        witnesses++;
      } else {
        issues.push(`invalid witness signature from ${s.kid}`);
      }
      continue;
    }
    if (pinned && s?.role === 'log' && has(trusted, s.kid)) {
      issues.push(`signature from pinned witness ${s.kid} is labelled as the log's`);
      continue;
    }

    if (!has(keyring, s?.kid)) {
      issues.push(`no public key for signer ${s?.kid}`);
      continue;
    }
    if (!verify(keyring[s.kid], digest, s.sig)) {
      issues.push(`invalid ${s.role} signature from ${s.kid}`);
      continue;
    }
    if (s.role === 'witness') {
      if (counted.has(keyring[s.kid])) continue;
      counted.add(keyring[s.kid]);
      witnesses++; // unpinned: a claim, not evidence
    }
    signers.push(s.kid);
    if (s.role === 'log') hasLogSig = true;
  }

  if (!hasLogSig) issues.push('checkpoint carries no valid log signature');

  const min = opts.minWitnesses ?? 0;
  if (witnesses < min) {
    issues.push(`only ${witnesses} valid witness signature(s), policy requires ${min}`);
  }

  return { ok: issues.length === 0, issues, signers, witnesses, pinned };
}

/**
 * Sign a checkpoint with an async signer.
 *
 * The useful key stores — KMS, HSM, a Vault transit engine — are all network
 * or IPC calls, so the signing interface has to be async. This is the variant
 * the hub uses; `signCheckpoint` above remains for in-process keys.
 *
 * @param {{ kid: string, sign: (digest: Buffer) => Promise<string> }} signer
 * @param {CheckpointBody} body
 * @param {'log'|'witness'} [role='log']
 * @returns {Promise<Checkpoint>}
 */
export async function signCheckpointWith(signer, body, role = 'log') {
  const sig = await signer.sign(checkpointDigest(body));
  return { body, sigs: [{ role, kid: signer.kid, sig }] };
}

/**
 * Counter-sign an existing checkpoint with an async signer.
 *
 * @param {Checkpoint} checkpoint
 * @param {{ kid: string, sign: (digest: Buffer) => Promise<string> }} signer
 * @returns {Promise<Checkpoint>}
 */
export async function cosignWith(checkpoint, signer) {
  const sig = await signer.sign(checkpointDigest(checkpoint.body));
  return {
    body: checkpoint.body,
    sigs: [
      ...checkpoint.sigs.filter((s) => s.kid !== signer.kid),
      { role: /** @type {const} */ ('witness'), kid: signer.kid, sig, ts: new Date().toISOString() },
    ],
  };
}
