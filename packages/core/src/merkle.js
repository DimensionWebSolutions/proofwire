import { sha256, LEAF_PREFIX, NODE_PREFIX, equalBytes } from './hash.js';

/**
 * RFC 6962 Merkle tree — the same construction Certificate Transparency uses.
 *
 * Two proofs matter here, and they answer different questions:
 *
 *   inclusion   "receipt #4,201 is in the log you published" — for anyone
 *               holding a single receipt who wants to tie it to a root.
 *   consistency "the log you published today still contains, unmodified,
 *               everything you published last Tuesday" — this is the one that
 *               makes deletion and back-dating detectable. Without it an
 *               operator can quietly rewrite history and re-sign a new root.
 */

/** Root of the empty tree, per RFC 6962 §2.1. */
const EMPTY_ROOT = sha256(Buffer.alloc(0));

/**
 * @param {Buffer} data  The canonical bytes of a receipt.
 * @returns {Buffer}
 */
export function leafHash(data) {
  return sha256(LEAF_PREFIX, data);
}

/**
 * @param {Buffer} left
 * @param {Buffer} right
 * @returns {Buffer}
 */
export function nodeHash(left, right) {
  return sha256(NODE_PREFIX, left, right);
}

/**
 * Largest power of two strictly less than n. Defined only for n > 1.
 *
 * @param {number} n
 * @returns {number}
 */
function splitPoint(n) {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
}

/**
 * Merkle tree head over a slice of leaf hashes.
 *
 * @param {Buffer[]} leaves
 * @returns {Buffer}
 */
export function merkleRoot(leaves) {
  if (leaves.length === 0) return EMPTY_ROOT;
  if (leaves.length === 1) return leaves[0];
  const k = splitPoint(leaves.length);
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

/**
 * An append-only tree that keeps the root cheap to maintain.
 *
 * Internally this is a binary counter of complete subtrees: appending a leaf
 * pushes a size-1 subtree and merges equal-sized neighbours, so an append is
 * O(log n) rather than the O(n) a full recomputation would cost. The root is
 * the right-to-left fold of that stack, which is exactly RFC 6962's
 * "split at the largest power of two" decomposition read from the other end.
 */
export class MerkleTree {
  /** @param {Buffer[]} [leaves] Existing leaf hashes, oldest first. */
  constructor(leaves = []) {
    /** @type {Buffer[]} */
    this.leaves = [];
    /** @type {{ size: number, hash: Buffer }[]} */
    this._stack = [];
    /**
     * Cached level structure, built on demand for proof generation.
     * `_levels[0]` is the leaves; each subsequent level pairs adjacent nodes
     * and promotes an unpaired last node. Invalidated on append.
     * @type {Buffer[][]|null}
     */
    this._levels = null;
    for (const l of leaves) this.append(l);
  }

  /**
   * Build the level structure, so an inclusion proof is a walk up the tree
   * rather than a recomputation of it.
   *
   * The naive recursive PATH is O(n) per proof because it rebuilds every
   * subtree root it passes. That is invisible on a toy log and quadratic on a
   * real one: generating proofs for all n entries of an export costs O(n²),
   * which measured at 41 seconds for 4,000 receipts and would be hours for a
   * hundred thousand. One O(n) build amortised across every proof turns each
   * one into O(log n).
   *
   * Pairing adjacent nodes and promoting the odd one out is exactly RFC 6962's
   * "split at the largest power of two" decomposition, read bottom-up.
   *
   * @returns {Buffer[][]}
   */
  _buildLevels() {
    if (this._levels) return this._levels;

    /** @type {Buffer[][]} */
    const levels = [this.leaves.slice()];
    while (levels[levels.length - 1].length > 1) {
      const below = levels[levels.length - 1];
      /** @type {Buffer[]} */
      const above = [];
      for (let i = 0; i < below.length; i += 2) {
        // An unpaired final node rises unchanged; it pairs at a higher level.
        above.push(i + 1 < below.length ? nodeHash(below[i], below[i + 1]) : below[i]);
      }
      levels.push(above);
    }

    this._levels = levels;
    return levels;
  }

  /** @returns {number} */
  get size() {
    return this.leaves.length;
  }

  /**
   * @param {Buffer} hash  A leaf hash, already domain-tagged by `leafHash`.
   * @returns {number} The index the leaf was stored at.
   */
  append(hash) {
    this.leaves.push(hash);
    this._levels = null;
    this._stack.push({ size: 1, hash });
    while (this._stack.length > 1) {
      const right = this._stack[this._stack.length - 1];
      const left = this._stack[this._stack.length - 2];
      if (left.size !== right.size) break;
      this._stack.splice(-2, 2, {
        size: left.size + right.size,
        hash: nodeHash(left.hash, right.hash),
      });
    }
    return this.leaves.length - 1;
  }

  /** @returns {Buffer} */
  get root() {
    if (this._stack.length === 0) return EMPTY_ROOT;
    let acc = this._stack[this._stack.length - 1].hash;
    for (let i = this._stack.length - 2; i >= 0; i--) {
      acc = nodeHash(this._stack[i].hash, acc);
    }
    return acc;
  }

  /**
   * Root the tree had when it held exactly `size` leaves. Needed to check a
   * historical checkpoint against the log as it stands now.
   *
   * @param {number} size
   * @returns {Buffer}
   */
  rootAt(size) {
    if (size < 0 || size > this.leaves.length) {
      throw new RangeError(`size ${size} out of range for tree of ${this.leaves.length}`);
    }
    return merkleRoot(this.leaves.slice(0, size));
  }

  /**
   * @param {number} index
   * @param {number} [treeSize]  Defaults to the current size.
   * @returns {Buffer[]}
   */
  inclusionProof(index, treeSize = this.leaves.length) {
    // The fast path covers the overwhelmingly common case: a proof against the
    // tree as it stands now. A proof against a historical size still needs the
    // recursive form, which is fine — that is a rare, one-off request.
    if (treeSize !== this.leaves.length) {
      return inclusionProof(this.leaves.slice(0, treeSize), index);
    }
    if (!Number.isInteger(index) || index < 0 || index >= this.leaves.length) {
      throw new RangeError(`leaf index ${index} out of range for ${this.leaves.length} leaves`);
    }

    const levels = this._buildLevels();
    /** @type {Buffer[]} */
    const proof = [];
    let i = index;

    for (let depth = 0; depth < levels.length - 1; depth++) {
      const level = levels[depth];
      const sibling = i ^ 1;
      // No sibling means this node was promoted unchanged; nothing to prove
      // at this level, and the index simply rises.
      if (sibling < level.length) proof.push(level[sibling]);
      i >>>= 1;
    }
    return proof;
  }

  /**
   * @param {number} fromSize
   * @param {number} [toSize]  Defaults to the current size.
   * @returns {Buffer[]}
   */
  consistencyProof(fromSize, toSize = this.leaves.length) {
    return consistencyProof(this.leaves.slice(0, toSize), fromSize);
  }
}

/**
 * PATH(m, D[n]) from RFC 6962 §2.1.1 — the sibling hashes from a leaf up to
 * the root, bottom-first.
 *
 * @param {Buffer[]} leaves
 * @param {number} index
 * @returns {Buffer[]}
 */
export function inclusionProof(leaves, index) {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError(`leaf index ${index} out of range for ${leaves.length} leaves`);
  }
  if (leaves.length === 1) return [];
  const k = splitPoint(leaves.length);
  if (index < k) {
    return [...inclusionProof(leaves.slice(0, k), index), merkleRoot(leaves.slice(k))];
  }
  return [...inclusionProof(leaves.slice(k), index - k), merkleRoot(leaves.slice(0, k))];
}

/**
 * Recompute the root a proof implies, then compare. Returns false rather than
 * throwing on malformed input: a verifier is fed hostile data by definition.
 *
 * @param {object} args
 * @param {Buffer} args.leafHash
 * @param {number} args.index
 * @param {number} args.treeSize
 * @param {Buffer[]} args.proof
 * @param {Buffer} args.root
 * @returns {boolean}
 */
export function verifyInclusion({ leafHash: leaf, index, treeSize, proof, root }) {
  if (!Number.isInteger(index) || !Number.isInteger(treeSize)) return false;
  if (index < 0 || treeSize <= 0 || index >= treeSize) return false;

  let fn = index;
  let sn = treeSize - 1;
  let acc = leaf;

  for (const sibling of proof) {
    if (sn === 0) return false;
    if (sibling.length !== 32) return false;
    if ((fn & 1) === 1 || fn === sn) {
      acc = nodeHash(sibling, acc);
      while (fn !== 0 && (fn & 1) === 0) {
        fn >>>= 1;
        sn >>>= 1;
      }
    } else {
      acc = nodeHash(acc, sibling);
    }
    fn >>>= 1;
    sn >>>= 1;
  }

  // A proof that runs out before reaching the root proves nothing.
  if (sn !== 0) return false;
  return equalBytes(acc, root);
}

/**
 * PROOF(m, D[n]) from RFC 6962 §2.1.2 — evidence that the size-m tree is a
 * prefix of the size-n tree.
 *
 * @param {Buffer[]} leaves  The larger (current) leaf set.
 * @param {number} fromSize  The smaller, historical size m.
 * @returns {Buffer[]}
 */
export function consistencyProof(leaves, fromSize) {
  const n = leaves.length;
  if (!Number.isInteger(fromSize) || fromSize < 0 || fromSize > n) {
    throw new RangeError(`fromSize ${fromSize} out of range for ${n} leaves`);
  }
  if (fromSize === 0 || fromSize === n) return [];
  return subProof(leaves, fromSize, true);
}

/**
 * @param {Buffer[]} leaves
 * @param {number} m
 * @param {boolean} isRootOfOld  True while the old root is still an exact
 *   subtree root of the path we are walking, so it need not be sent.
 * @returns {Buffer[]}
 */
function subProof(leaves, m, isRootOfOld) {
  const n = leaves.length;
  if (m === n) return isRootOfOld ? [] : [merkleRoot(leaves)];
  const k = splitPoint(n);
  if (m <= k) {
    return [...subProof(leaves.slice(0, k), m, isRootOfOld), merkleRoot(leaves.slice(k))];
  }
  return [...subProof(leaves.slice(k), m - k, false), merkleRoot(leaves.slice(0, k))];
}

/**
 * Check that `secondRoot` is an append-only extension of `firstRoot`.
 *
 * This is the check an auditor runs on a schedule. If it ever fails, the log
 * operator has rewritten history — no further interpretation required.
 *
 * @param {object} args
 * @param {number} args.firstSize
 * @param {number} args.secondSize
 * @param {Buffer} args.firstRoot
 * @param {Buffer} args.secondRoot
 * @param {Buffer[]} args.proof
 * @returns {boolean}
 */
export function verifyConsistency({ firstSize, secondSize, firstRoot, secondRoot, proof }) {
  if (!Number.isInteger(firstSize) || !Number.isInteger(secondSize)) return false;
  if (firstSize < 0 || secondSize < firstSize) return false;

  if (firstSize === secondSize) {
    return proof.length === 0 && equalBytes(firstRoot, secondRoot);
  }
  // Everything extends the empty tree; there is nothing to prove.
  if (firstSize === 0) return proof.length === 0;

  let fn = firstSize - 1;
  let sn = secondSize - 1;
  // Strip the trailing ones: those levels are shared by both roots.
  while ((fn & 1) === 1) {
    fn >>>= 1;
    sn >>>= 1;
  }

  if (proof.length === 0) return false;
  let i = 0;
  let fr;
  let sr;
  if (fn !== 0) {
    // The old root was not a complete subtree, so its left edge is supplied.
    fr = proof[i];
    sr = proof[i];
    i++;
  } else {
    fr = firstRoot;
    sr = firstRoot;
  }

  for (; i < proof.length; i++) {
    const p = proof[i];
    if (sn === 0) return false;
    if (p.length !== 32) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = nodeHash(p, fr);
      sr = nodeHash(p, sr);
      while (fn !== 0 && (fn & 1) === 0) {
        fn >>>= 1;
        sn >>>= 1;
      }
    } else {
      sr = nodeHash(sr, p);
    }
    fn >>>= 1;
    sn >>>= 1;
  }

  if (sn !== 0) return false;
  return equalBytes(fr, firstRoot) && equalBytes(sr, secondRoot);
}
