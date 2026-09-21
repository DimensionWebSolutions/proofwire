import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { canonicalize, canonicalBytes } from './canonical.js';
import { hex, unhex } from './hash.js';
import { MerkleTree, leafHash, verifyInclusion, verifyConsistency } from './merkle.js';
import { generateIdentity, identityFromPem, identityFromPublicKey } from './keys.js';
import {
  buildReceipt,
  signReceipt,
  entryHash,
  verifyChain,
  verifyReceipt,
  openSeal,
  GENESIS_PREV,
} from './receipt.js';
import { buildCheckpoint, signCheckpoint, verifyCheckpoint } from './checkpoint.js';

/**
 * A local, file-backed transparency log.
 *
 * Layout under the log directory:
 *
 *   config.json        log id, creation time, signing key id
 *   key.pem            Ed25519 private key — the one file that must not leave
 *   keyring.json       kid → public key, for every key that has ever signed here
 *   entries.jsonl      one canonical receipt per line, append-only
 *   checkpoints.jsonl  signed tree heads, append-only
 *   salts.jsonl        commitment salts — the only file holding anything
 *                      sensitive, and the one you delete to crypto-shred
 *
 * Writes are synchronous on purpose. An audit log that returns before the
 * record is durable will, on the one day it matters, be missing the record
 * that matters.
 */

const FILES = {
  config: 'config.json',
  key: 'key.pem',
  keyring: 'keyring.json',
  entries: 'entries.jsonl',
  checkpoints: 'checkpoints.jsonl',
  salts: 'salts.jsonl',
};

/**
 * @param {string} file
 * @returns {string[]} Non-empty lines.
 */
function readLines(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split('\n').filter((l) => l.trim() !== '');
}

export class ProofLog {
  /**
   * @param {string} dir
   * @param {object} state
   * @private
   */
  constructor(dir, state) {
    this.dir = dir;
    /** @type {{ log: string, created: string, kid: string }} */
    this.config = state.config;
    /** @type {import('./keys.js').Identity} */
    this.identity = state.identity;
    /** @type {import('./receipt.js').Keyring} */
    this.keyring = state.keyring;
    /** @type {import('./receipt.js').Receipt[]} */
    this.entries = state.entries;
    /** @type {MerkleTree} */
    this.tree = state.tree;
    /** @type {string} */
    this.head = state.head;
  }

  /**
   * Create a new log, generating a fresh signing identity.
   *
   * @param {string} dir
   * @param {object} [opts]
   * @param {string} [opts.logId]
   * @returns {ProofLog}
   */
  static create(dir, opts = {}) {
    if (fs.existsSync(path.join(dir, FILES.config))) {
      throw new Error(`a Proofwire log already exists at ${dir}`);
    }
    fs.mkdirSync(dir, { recursive: true });

    const { identity, privateKeyPem } = generateIdentity();
    const config = {
      log: opts.logId ?? 'lg_' + randomBytes(8).toString('hex'),
      created: new Date().toISOString(),
      kid: identity.kid,
    };

    fs.writeFileSync(path.join(dir, FILES.config), JSON.stringify(config, null, 2) + '\n');
    // 0600 is advisory on Windows but correct and enforced on POSIX.
    fs.writeFileSync(path.join(dir, FILES.key), privateKeyPem, { mode: 0o600 });
    fs.writeFileSync(
      path.join(dir, FILES.keyring),
      JSON.stringify({ [identity.kid]: identity.publicKey }, null, 2) + '\n',
    );
    fs.writeFileSync(path.join(dir, FILES.entries), '');
    fs.writeFileSync(path.join(dir, FILES.checkpoints), '');
    fs.writeFileSync(path.join(dir, FILES.salts), '', { mode: 0o600 });

    return ProofLog.open(dir);
  }

  /**
   * Open an existing log, rebuilding the Merkle tree from the entry file.
   *
   * @param {string} dir
   * @param {object} [opts]
   * @param {boolean} [opts.readOnly=false]  Skip loading the private key — the
   *   mode an auditor uses, and the mode that cannot accidentally append.
   * @returns {ProofLog}
   */
  static open(dir, opts = {}) {
    const configPath = path.join(dir, FILES.config);
    if (!fs.existsSync(configPath)) {
      throw new Error(`no Proofwire log at ${dir} (run \`pw init\` first)`);
    }
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    /** @type {import('./receipt.js').Keyring} */
    const keyring = JSON.parse(fs.readFileSync(path.join(dir, FILES.keyring), 'utf8'));

    let identity;
    if (opts.readOnly) {
      identity = identityFromPublicKey(keyring[config.kid]);
    } else {
      identity = identityFromPem(fs.readFileSync(path.join(dir, FILES.key), 'utf8'));
      if (identity.kid !== config.kid) {
        throw new Error(
          `key.pem does not match config: key is ${identity.kid}, config says ${config.kid}`,
        );
      }
    }

    /** @type {import('./receipt.js').Receipt[]} */
    const entries = [];
    const tree = new MerkleTree();
    let head = GENESIS_PREV;

    for (const [i, line] of readLines(path.join(dir, FILES.entries)).entries()) {
      let receipt;
      try {
        receipt = JSON.parse(line);
      } catch (err) {
        throw new Error(`entries.jsonl line ${i + 1} is not valid JSON: ${err.message}`);
      }
      entries.push(receipt);
      tree.append(leafHash(canonicalBytes(receipt)));
      head = entryHash(receipt);
    }

    return new ProofLog(dir, { config, identity, keyring, entries, tree, head });
  }

  /** @returns {number} */
  get size() {
    return this.entries.length;
  }

  /** @returns {string} Current Merkle root, hex. */
  get root() {
    return hex(this.tree.root);
  }

  /** @returns {string} */
  get logId() {
    return this.config.log;
  }

  /**
   * Record an action. Returns the signed, durable receipt.
   *
   * @param {object} args
   * @param {import('./receipt.js').Actor} args.actor
   * @param {{ kind: string, target: string, params: unknown }} args.action
   * @param {import('./receipt.js').Decision} args.decision
   * @param {null | { status: 'ok'|'error', code?: string, latencyMs?: number, payload?: unknown }} [args.result]
   * @param {'atomic'|'intent'|'outcome'} [args.phase]
   * @param {string} [args.ref]
   * @returns {import('./receipt.js').Receipt}
   */
  append(args) {
    if (!this.identity.privateKeyObject) {
      throw new Error('log is open read-only; cannot append');
    }
    const { body, salts } = buildReceipt({
      log: this.config.log,
      seq: this.entries.length,
      prev: this.head,
      ...args,
    });
    const receipt = signReceipt(this.identity, body);

    // Durable before in-memory: if the process dies mid-append we would rather
    // have an entry on disk that memory never saw than the reverse.
    fs.appendFileSync(path.join(this.dir, FILES.entries), canonicalize(receipt) + '\n');
    // Salts go to their own file so it can be destroyed independently. They
    // are written second: a receipt without its salt is merely unopenable, a
    // salt without its receipt is a dangling secret.
    fs.appendFileSync(
      path.join(this.dir, FILES.salts),
      canonicalize({ seq: receipt.seq, ...salts }) + '\n',
      { mode: 0o600 },
    );

    this.entries.push(receipt);
    this.tree.append(leafHash(canonicalBytes(receipt)));
    this.head = entryHash(receipt);
    return receipt;
  }

  /**
   * Sign and store the current tree head.
   *
   * @returns {import('./checkpoint.js').Checkpoint}
   */
  checkpoint() {
    const body = buildCheckpoint({
      log: this.config.log,
      size: this.size,
      root: this.root,
      head: this.head,
    });
    const cp = signCheckpoint(this.identity, body, 'log');
    fs.appendFileSync(path.join(this.dir, FILES.checkpoints), canonicalize(cp) + '\n');
    return cp;
  }

  /** @returns {import('./checkpoint.js').Checkpoint[]} */
  checkpoints() {
    return readLines(path.join(this.dir, FILES.checkpoints)).map((l) => JSON.parse(l));
  }

  /**
   * Attach a signature — normally a witness countersignature — to the stored
   * checkpoint at `size`.
   *
   * Obtaining a witness signature and not keeping it would be pointless: the
   * signature is the evidence, and it has to be in the file that gets exported.
   * The checkpoint body is unchanged, so every existing signature over it stays
   * valid; only the signature set grows.
   *
   * @param {number} size
   * @param {import('./checkpoint.js').Signature} signature
   * @returns {import('./checkpoint.js').Checkpoint}
   */
  addSignature(size, signature) {
    const file = path.join(this.dir, FILES.checkpoints);
    const all = this.checkpoints();
    const target = all.find((cp) => cp.body.size === size);
    if (!target) {
      throw new Error(`no checkpoint at size ${size} in this log`);
    }
    // Replacing by kid keeps this idempotent: re-witnessing the same root
    // updates the signature rather than accumulating duplicates.
    target.sigs = [...target.sigs.filter((s) => s.kid !== signature.kid), signature];

    fs.writeFileSync(file, all.map((cp) => canonicalize(cp)).join('\n') + '\n');
    return target;
  }

  /**
   * The commitment salts for one entry, if they still exist.
   *
   * @param {number} seq
   * @returns {{ params?: string, result?: string }}
   */
  saltsFor(seq) {
    for (const line of readLines(path.join(this.dir, FILES.salts))) {
      const row = JSON.parse(line);
      if (row.seq === seq) {
        const { seq: _drop, ...salts } = row;
        return salts;
      }
    }
    return {};
  }

  /**
   * Reveal a payload: confirm that `value` is what entry `seq` committed to.
   *
   * This is how a disclosure works in practice. You hand someone the receipt
   * (safe to publish) and, separately, the payload and its salt. They check
   * the commitment themselves. You never had to put the payload in the log.
   *
   * @param {number} seq
   * @param {'params'|'result'} which
   * @param {unknown} value
   * @returns {boolean}
   */
  reveal(seq, which, value) {
    const receipt = this.entries[seq];
    if (!receipt) return false;
    const sealed = which === 'params' ? receipt.action.params : receipt.result?.payload;
    if (!sealed) return false;
    return openSeal(sealed, this.saltsFor(seq)[which], value);
  }

  /**
   * Crypto-shred: destroy the salts, permanently, for matching entries.
   *
   * After this the commitments cannot be opened by us, by a court, or by a
   * future attacker who steals the whole directory — while every signature,
   * chain link and inclusion proof still verifies. An erasure request and an
   * immutable audit trail stop being in conflict.
   *
   * @param {(receipt: import('./receipt.js').Receipt) => boolean} predicate
   * @returns {number} How many entries were shredded.
   */
  shred(predicate) {
    const doomed = new Set(this.entries.filter(predicate).map((r) => r.seq));
    if (doomed.size === 0) return 0;
    const file = path.join(this.dir, FILES.salts);
    const kept = readLines(file).filter((l) => !doomed.has(JSON.parse(l).seq));
    fs.writeFileSync(file, kept.length ? kept.join('\n') + '\n' : '', { mode: 0o600 });
    return doomed.size;
  }

  /**
   * Register another party's public key so their signatures verify here.
   *
   * @param {string} kid
   * @param {string} publicKey  base64url
   */
  trustKey(kid, publicKey) {
    this.keyring = { ...this.keyring, [kid]: publicKey };
    fs.writeFileSync(
      path.join(this.dir, FILES.keyring),
      JSON.stringify(this.keyring, null, 2) + '\n',
    );
  }

  /**
   * A portable proof that entry `seq` is in the log at the current size.
   *
   * @param {number} seq
   * @returns {{ log: string, seq: number, treeSize: number, root: string, leaf: string, proof: string[] }}
   */
  proofFor(seq) {
    if (!Number.isInteger(seq) || seq < 0 || seq >= this.size) {
      throw new RangeError(`no entry ${seq} in a log of ${this.size}`);
    }
    return {
      log: this.config.log,
      seq,
      treeSize: this.size,
      root: this.root,
      leaf: hex(this.tree.leaves[seq]),
      proof: this.tree.inclusionProof(seq).map(hex),
    };
  }

  /**
   * Full local audit: signatures, chain links, tree consistency, and every
   * historical checkpoint replayed against the log as it stands now.
   *
   * @returns {{ ok: boolean, size: number, root: string, issues: import('./receipt.js').VerifyIssue[] }}
   */
  audit() {
    const chain = verifyChain(this.entries, this.keyring);
    const issues = [...chain.issues];

    // Every entry must actually sit where the tree says it does.
    for (let i = 0; i < this.entries.length; i++) {
      const ok = verifyInclusion({
        leafHash: this.tree.leaves[i],
        index: i,
        treeSize: this.size,
        proof: this.tree.inclusionProof(i),
        root: this.tree.root,
      });
      if (!ok) {
        issues.push({ seq: i, kind: 'chain', message: 'entry is not provably in the tree' });
      }
    }

    // Replay history: each past checkpoint must still describe a prefix of the
    // log we hold. This is what catches an edit made after a root was published.
    for (const cp of this.checkpoints()) {
      const sigCheck = verifyCheckpoint(cp, this.keyring);
      if (!sigCheck.ok) {
        for (const m of sigCheck.issues) {
          issues.push({ kind: 'signature', message: `checkpoint at size ${cp.body.size}: ${m}` });
        }
        continue;
      }
      if (cp.body.size > this.size) {
        issues.push({
          kind: 'chain',
          message:
            `a signed checkpoint covers ${cp.body.size} entries but the log holds ` +
            `only ${this.size} — entries have been removed`,
        });
        continue;
      }
      const ok = verifyConsistency({
        firstSize: cp.body.size,
        secondSize: this.size,
        firstRoot: unhex(cp.body.root),
        secondRoot: this.tree.root,
        proof: this.tree.consistencyProof(cp.body.size).map((b) => b),
      });
      if (!ok) {
        issues.push({
          kind: 'chain',
          message:
            `the log no longer extends the checkpoint signed at size ${cp.body.size} ` +
            `(${cp.body.ts}) — history was rewritten`,
        });
      }
    }

    return { ok: issues.length === 0, size: this.size, root: this.root, issues };
  }

  /**
   * An evidence bundle: everything an outside party needs to verify this log,
   * and nothing they need to trust us about.
   *
   * Receipts are publishable by construction — the salts live elsewhere and
   * are never included — so there is no "sanitise before sending" step here
   * to get wrong.
   *
   * @param {object} [opts]
   * @param {(r: import('./receipt.js').Receipt) => boolean} [opts.filter]
   * @returns {object}
   */
  bundle(opts = {}) {
    const selected = opts.filter ? this.entries.filter(opts.filter) : this.entries;
    const entries = selected;
    return {
      v: 1,
      kind: 'proofwire.bundle',
      log: this.config.log,
      exported: new Date().toISOString(),
      treeSize: this.size,
      root: this.root,
      head: this.head,
      keyring: this.keyring,
      checkpoints: this.checkpoints(),
      partial: selected.length !== this.entries.length,
      // Inclusion proofs let a filtered bundle still tie each entry to the
      // full-log root, so exporting a subset proves no selective omission
      // within it.
      entries: entries.map((receipt, i) => ({
        receipt,
        proof: this.tree.inclusionProof(selected[i].seq).map(hex),
      })),
    };
  }
}

/**
 * Verify an evidence bundle standing alone — no access to the original log.
 *
 * This is the function an auditor, regulator, or opposing counsel runs. It
 * deliberately takes nothing but the bundle and, optionally, a root they
 * obtained independently.
 *
 * @param {object} bundle
 * @param {object} [opts]
 * @param {string} [opts.expectRoot]  A root from a witness or a prior export.
 * @param {number} [opts.minWitnesses=0]
 * @returns {{ ok: boolean, issues: string[], checked: number }}
 */
export function verifyBundle(bundle, opts = {}) {
  /** @type {string[]} */
  const issues = [];

  if (bundle?.kind !== 'proofwire.bundle' || bundle.v !== 1) {
    return { ok: false, issues: ['not a Proofwire v1 bundle'], checked: 0 };
  }
  const keyring = bundle.keyring ?? {};
  let root;
  try {
    root = unhex(bundle.root);
  } catch {
    return { ok: false, issues: ['bundle root is not valid hex'], checked: 0 };
  }

  if (opts.expectRoot && opts.expectRoot !== bundle.root) {
    issues.push(
      `bundle root ${bundle.root.slice(0, 16)}… does not match the expected ` +
        `${opts.expectRoot.slice(0, 16)}… — you were shown a different history`,
    );
  }

  for (const cp of bundle.checkpoints ?? []) {
    const res = verifyCheckpoint(cp, keyring, { minWitnesses: opts.minWitnesses ?? 0 });
    if (!res.ok) {
      issues.push(`checkpoint at size ${cp.body?.size}: ${res.issues.join('; ')}`);
    }
  }

  let checked = 0;
  /** @type {import('./receipt.js').Receipt[]} */
  const receipts = [];

  for (const { receipt, proof } of bundle.entries ?? []) {
    receipts.push(receipt);
    const ok = verifyInclusion({
      leafHash: leafHash(canonicalBytes(receipt)),
      index: receipt.seq,
      treeSize: bundle.treeSize,
      proof: (proof ?? []).map(unhex),
      root,
    });
    if (!ok) {
      issues.push(`entry ${receipt.seq} is not provably part of the logged tree`);
    }
    checked++;
  }

  // A complete bundle must also form an unbroken chain. A filtered one cannot,
  // by construction, so inclusion proofs carry the weight there instead.
  if (!bundle.partial) {
    const chain = verifyChain(receipts, keyring);
    for (const i of chain.issues) issues.push(`entry ${i.seq}: ${i.message}`);
  } else {
    for (const receipt of receipts) {
      for (const i of verifyReceipt(receipt, keyring)) {
        issues.push(`entry ${i.seq}: ${i.message}`);
      }
    }
  }

  return { ok: issues.length === 0, issues, checked };
}
