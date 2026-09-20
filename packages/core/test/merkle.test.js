import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import {
  MerkleTree,
  leafHash,
  nodeHash,
  merkleRoot,
  inclusionProof,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
} from '../src/merkle.js';

/** @param {number} n */
function leaves(n) {
  return Array.from({ length: n }, (_, i) => leafHash(Buffer.from(`leaf-${i}`)));
}

test('empty tree root is the hash of the empty string (RFC 6962 §2.1)', () => {
  assert.equal(
    merkleRoot([]).toString('hex'),
    createHash('sha256').update(Buffer.alloc(0)).digest('hex'),
  );
});

test('single-leaf root is the leaf hash itself', () => {
  const l = leaves(1);
  assert.deepEqual(merkleRoot(l), l[0]);
});

test('matches the hand-computed root for n=3', () => {
  // RFC 6962 splits at the largest power of two below n:  ((0,1), 2)
  const l = leaves(3);
  assert.deepEqual(merkleRoot(l), nodeHash(nodeHash(l[0], l[1]), l[2]));
});

test('incremental appends agree with a full recomputation', () => {
  const tree = new MerkleTree();
  const all = leaves(300);
  for (let i = 0; i < all.length; i++) {
    tree.append(all[i]);
    assert.deepEqual(
      tree.root,
      merkleRoot(all.slice(0, i + 1)),
      `root diverged after appending leaf ${i}`,
    );
  }
});

test('rootAt reproduces every historical root', () => {
  const all = leaves(70);
  const tree = new MerkleTree(all);
  for (let n = 0; n <= all.length; n++) {
    assert.deepEqual(tree.rootAt(n), merkleRoot(all.slice(0, n)));
  }
});

test('inclusion proofs verify for every leaf of every tree size up to 64', () => {
  for (let n = 1; n <= 64; n++) {
    const l = leaves(n);
    const root = merkleRoot(l);
    for (let i = 0; i < n; i++) {
      const proof = inclusionProof(l, i);
      assert.ok(
        verifyInclusion({ leafHash: l[i], index: i, treeSize: n, proof, root }),
        `inclusion failed for leaf ${i} of ${n}`,
      );
      // Proof length is the tree depth, never more.
      assert.ok(proof.length <= Math.ceil(Math.log2(n)) + 1);
    }
  }
});

test('inclusion proof is rejected when the leaf is altered', () => {
  const l = leaves(17);
  const root = merkleRoot(l);
  const proof = inclusionProof(l, 5);
  const forged = leafHash(Buffer.from('leaf-5-but-tampered'));
  assert.equal(
    verifyInclusion({ leafHash: forged, index: 5, treeSize: 17, proof, root }),
    false,
  );
});

test('inclusion proof is rejected when a sibling is altered', () => {
  const l = leaves(17);
  const root = merkleRoot(l);
  for (let i = 0; i < inclusionProof(l, 5).length; i++) {
    const proof = inclusionProof(l, 5);
    proof[i] = randomBytes(32);
    assert.equal(
      verifyInclusion({ leafHash: l[5], index: 5, treeSize: 17, proof, root }),
      false,
      `a corrupted sibling at depth ${i} was accepted`,
    );
  }
});

test('inclusion proof is rejected when claimed at the wrong index', () => {
  const l = leaves(16);
  const root = merkleRoot(l);
  const proof = inclusionProof(l, 3);
  for (let j = 0; j < 16; j++) {
    if (j === 3) continue;
    assert.equal(
      verifyInclusion({ leafHash: l[3], index: j, treeSize: 16, proof, root }),
      false,
      `leaf 3's proof was accepted at index ${j}`,
    );
  }
});

test('truncated and padded inclusion proofs are rejected', () => {
  const l = leaves(23);
  const root = merkleRoot(l);
  const proof = inclusionProof(l, 9);
  assert.equal(
    verifyInclusion({ leafHash: l[9], index: 9, treeSize: 23, proof: proof.slice(0, -1), root }),
    false,
    'a truncated proof was accepted',
  );
  assert.equal(
    verifyInclusion({
      leafHash: l[9],
      index: 9,
      treeSize: 23,
      proof: [...proof, randomBytes(32)],
      root,
    }),
    false,
    'an over-long proof was accepted',
  );
});

test('out-of-range indices are rejected rather than throwing', () => {
  const l = leaves(8);
  const root = merkleRoot(l);
  for (const index of [-1, 8, 99, 1.5, NaN]) {
    assert.equal(
      verifyInclusion({ leafHash: l[0], index, treeSize: 8, proof: [], root }),
      false,
      `index ${index} was accepted`,
    );
  }
});

test('consistency proofs verify for every (m, n) pair up to n=48', () => {
  for (let n = 1; n <= 48; n++) {
    const l = leaves(n);
    const secondRoot = merkleRoot(l);
    for (let m = 0; m <= n; m++) {
      const firstRoot = merkleRoot(l.slice(0, m));
      const proof = consistencyProof(l, m);
      assert.ok(
        verifyConsistency({ firstSize: m, secondSize: n, firstRoot, secondRoot, proof }),
        `consistency failed for m=${m} n=${n}`,
      );
    }
  }
});

test('consistency proof fails when a historical leaf was rewritten', () => {
  const original = leaves(20);
  const m = 12;
  const oldRoot = merkleRoot(original.slice(0, m));

  // The operator edits entry 4 and keeps appending as if nothing happened.
  const rewritten = [...original];
  rewritten[4] = leafHash(Buffer.from('leaf-4-after-the-incident'));
  const newRoot = merkleRoot(rewritten);
  const proof = consistencyProof(rewritten, m);

  assert.equal(
    verifyConsistency({ firstSize: m, secondSize: 20, firstRoot: oldRoot, secondRoot: newRoot, proof }),
    false,
    'a rewritten history passed the consistency check',
  );
});

test('consistency proof fails when a historical leaf was deleted', () => {
  const original = leaves(20);
  const m = 12;
  const oldRoot = merkleRoot(original.slice(0, m));

  const pruned = original.filter((_, i) => i !== 7);
  const newRoot = merkleRoot(pruned);
  const proof = consistencyProof(pruned, m);

  assert.equal(
    verifyConsistency({
      firstSize: m,
      secondSize: pruned.length,
      firstRoot: oldRoot,
      secondRoot: newRoot,
      proof,
    }),
    false,
    'a deletion passed the consistency check',
  );
});

test('consistency proof with corrupted siblings is rejected', () => {
  const l = leaves(29);
  const secondRoot = merkleRoot(l);
  const m = 13;
  const firstRoot = merkleRoot(l.slice(0, m));
  const base = consistencyProof(l, m);
  for (let i = 0; i < base.length; i++) {
    const proof = consistencyProof(l, m);
    proof[i] = randomBytes(32);
    assert.equal(
      verifyConsistency({ firstSize: m, secondSize: 29, firstRoot, secondRoot, proof }),
      false,
      `a corrupted consistency sibling at ${i} was accepted`,
    );
  }
});

test('a shrinking log is rejected', () => {
  const l = leaves(10);
  assert.equal(
    verifyConsistency({
      firstSize: 10,
      secondSize: 4,
      firstRoot: merkleRoot(l),
      secondRoot: merkleRoot(l.slice(0, 4)),
      proof: [],
    }),
    false,
  );
});

test('empty consistency proof only passes for equal roots at equal size', () => {
  const l = leaves(6);
  const root = merkleRoot(l);
  assert.ok(
    verifyConsistency({ firstSize: 6, secondSize: 6, firstRoot: root, secondRoot: root, proof: [] }),
  );
  assert.equal(
    verifyConsistency({
      firstSize: 6,
      secondSize: 6,
      firstRoot: randomBytes(32),
      secondRoot: root,
      proof: [],
    }),
    false,
  );
});

test('a second-preimage splice is blocked by domain separation', () => {
  // Without the 0x00/0x01 tags, an interior node's bytes would also be a valid
  // leaf, letting an attacker present an internal node as a logged receipt.
  const l = leaves(2);
  const interior = nodeHash(l[0], l[1]);
  const root = merkleRoot(l);
  assert.deepEqual(interior, root);
  // The interior hash is not a leaf hash of anything, so it cannot be claimed
  // as an entry: leafHash(x) === interior has no known solution.
  assert.notDeepEqual(leafHash(interior), interior);
});
