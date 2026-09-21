import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import {
  leafHash,
  nodeHash,
  merkleRoot,
  MerkleTree,
  inclusionProof,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
} from '../src/merkle.js';
import { canonicalize } from '../src/canonical.js';
import { identityFromPublicKey, publicKeyObject, sign, verify, keyIdFor, generateIdentity } from '../src/keys.js';

/**
 * Known-answer tests against **external** ground truth.
 *
 * Every other test in this repository checks this implementation against
 * itself: the reference proof path against the cached one, the tree against a
 * recomputation. That catches inconsistency but not a shared misreading of the
 * specification — if the construction is subtly wrong, it is wrong everywhere
 * at once and every internal test still passes.
 *
 * These vectors come from outside. If this file passes, the implementation
 * agrees with the same bytes every other RFC 6962 and RFC 8032 implementation
 * produces, which is the property that actually matters: an auditor running
 * someone else's verifier must reach the same answer.
 *
 * A reviewer should check the constants below against the source documents
 * rather than take them on faith — which is the whole point of a known-answer
 * test, and why the two independently derivable anchors are called out.
 */

// ── RFC 6962: the Certificate Transparency reference tree ────────────────

/**
 * Eight leaves of increasing length. This is the test tree used by the CT
 * reference implementations; any RFC 6962 tree must produce these roots.
 */
const CT_LEAVES = [
  '',
  '00',
  '10',
  '2021',
  '3031',
  '40414243',
  '5051525354555657',
  '606162636465666768696a6b6c6d6e6f',
].map((hex) => Buffer.from(hex, 'hex'));

/** Root of the tree for each prefix length, 0 through 8. */
const CT_ROOTS = [
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
];

test('the two anchors that need no reference at all', () => {
  // RFC 6962 §2.1: MTH({}) = SHA-256(). Derivable from the spec text plus the
  // definition of SHA-256, with nothing to misremember.
  assert.equal(
    merkleRoot([]).toString('hex'),
    createHash('sha256').update(Buffer.alloc(0)).digest('hex'),
  );
  assert.equal(merkleRoot([]).toString('hex'), CT_ROOTS[0]);

  // MTH({d0}) = SHA-256(0x00 || d0). With d0 empty, that is SHA-256 of a
  // single zero byte — another value checkable by hand.
  assert.equal(
    leafHash(Buffer.alloc(0)).toString('hex'),
    createHash('sha256').update(Buffer.from([0x00])).digest('hex'),
  );
  assert.equal(leafHash(Buffer.alloc(0)).toString('hex'), CT_ROOTS[1]);
});

test('every CT reference root matches, for all nine tree sizes', () => {
  const leaves = CT_LEAVES.map(leafHash);
  for (let n = 0; n <= 8; n++) {
    assert.equal(
      merkleRoot(leaves.slice(0, n)).toString('hex'),
      CT_ROOTS[n],
      `root diverged from the CT reference tree at n=${n}`,
    );
  }
});

test('the incremental tree reaches the same reference roots', () => {
  // The optimised append path has to agree with the reference vectors too,
  // not merely with the recursive implementation beside it.
  const tree = new MerkleTree();
  assert.equal(tree.root.toString('hex'), CT_ROOTS[0]);
  for (let n = 1; n <= 8; n++) {
    tree.append(leafHash(CT_LEAVES[n - 1]));
    assert.equal(tree.root.toString('hex'), CT_ROOTS[n], `append path diverged at n=${n}`);
  }
});

test('the hand-computed n=2 and n=3 shapes match the spec decomposition', () => {
  // Spelling out the structure catches a mistake the aggregate roots would
  // hide, such as swapping the two halves.
  const l = CT_LEAVES.map(leafHash);
  assert.equal(nodeHash(l[0], l[1]).toString('hex'), CT_ROOTS[2]);
  // n=3 splits at the largest power of two below 3, so ((0,1), 2).
  assert.equal(nodeHash(nodeHash(l[0], l[1]), l[2]).toString('hex'), CT_ROOTS[3]);
  // n=4 is balanced.
  assert.equal(
    nodeHash(nodeHash(l[0], l[1]), nodeHash(l[2], l[3])).toString('hex'),
    CT_ROOTS[4],
  );
});

test('proofs over the reference tree verify against the reference roots', () => {
  const leaves = CT_LEAVES.map(leafHash);
  for (let n = 1; n <= 8; n++) {
    const root = Buffer.from(CT_ROOTS[n], 'hex');
    for (let i = 0; i < n; i++) {
      assert.ok(
        verifyInclusion({
          leafHash: leaves[i],
          index: i,
          treeSize: n,
          proof: inclusionProof(leaves.slice(0, n), i),
          root,
        }),
        `inclusion against the reference root failed for leaf ${i} of ${n}`,
      );
    }
    for (let m = 0; m <= n; m++) {
      assert.ok(
        verifyConsistency({
          firstSize: m,
          secondSize: n,
          firstRoot: Buffer.from(CT_ROOTS[m], 'hex'),
          secondRoot: root,
          proof: consistencyProof(leaves.slice(0, n), m),
        }),
        `consistency against the reference roots failed for ${m} → ${n}`,
      );
    }
  }
});

// ── RFC 8032: Ed25519 ────────────────────────────────────────────────────

/**
 * RFC 8032 §7.1. These pin the signature bytes themselves, not merely that
 * sign-then-verify round-trips — a round-trip passes even if both halves are
 * wrong in the same way.
 */
const ED25519_VECTORS = [
  {
    name: 'TEST 1 (empty message)',
    secret: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    public: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    message: '',
    signature:
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' +
      '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  },
  {
    name: 'TEST 2 (one-byte message)',
    secret: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    public: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    message: '72',
    signature:
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da' +
      '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
  },
];

/** The fixed PKCS#8 prefix for a raw Ed25519 private key (RFC 8410). */
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

test('Ed25519 signatures match RFC 8032 byte for byte', () => {
  for (const v of ED25519_VECTORS) {
    const key = createPrivateKey({
      key: Buffer.concat([PKCS8_PREFIX, Buffer.from(v.secret, 'hex')]),
      format: 'der',
      type: 'pkcs8',
    });

    // The public key derived from the secret must be the published one.
    const jwk = createPublicKey(key).export({ format: 'jwk' });
    assert.equal(
      Buffer.from(/** @type {string} */ (jwk.x), 'base64url').toString('hex'),
      v.public,
      `${v.name}: derived public key does not match the vector`,
    );

    const identity = { kid: 'x', publicKey: jwk.x, privateKeyObject: key };
    const produced = Buffer.from(
      sign(/** @type {any} */ (identity), Buffer.from(v.message, 'hex')),
      'base64url',
    ).toString('hex');

    assert.equal(produced, v.signature, `${v.name}: signature bytes differ from RFC 8032`);
  }
});

test('the SPKI wrapping used for verification round-trips a published key', () => {
  // `publicKeyObject` hand-assembles a DER SPKI header around raw key bytes,
  // because Node has no raw importer. A mistake there would be invisible in a
  // self-consistent test: we would verify our own signatures happily while
  // rejecting everyone else's.
  for (const v of ED25519_VECTORS) {
    const raw = Buffer.from(v.public, 'hex').toString('base64url');
    const key = publicKeyObject(raw);
    const jwk = key.export({ format: 'jwk' });
    assert.equal(Buffer.from(/** @type {string} */ (jwk.x), 'base64url').toString('hex'), v.public);

    assert.ok(
      verify(raw, Buffer.from(v.message, 'hex'), Buffer.from(v.signature, 'hex').toString('base64url')),
      `${v.name}: a published signature did not verify through our wrapping`,
    );
  }
});

test('a key id is a pure function of the public key', () => {
  // Two parties must derive the same kid for the same key, or a keyring
  // lookup silently fails and every signature by that key looks unverifiable.
  for (const v of ED25519_VECTORS) {
    const raw = Buffer.from(v.public, 'hex');
    const expected = 'pw1' + createHash('sha256').update(raw).digest('hex').slice(0, 32);
    assert.equal(keyIdFor(raw), expected);
    assert.equal(identityFromPublicKey(raw.toString('base64url')).kid, expected);
  }
});

// ── RFC 8785: canonical JSON ─────────────────────────────────────────────

test('canonicalization sorts by UTF-16 code unit, not by locale', () => {
  // A locale-aware sort would order these differently in some environments,
  // and two parties would then hash the same object to different digests.
  assert.equal(canonicalize({ b: 1, a: 2, A: 3, '1': 4 }), '{"1":4,"A":3,"a":2,"b":1}');
  assert.equal(canonicalize({ 'é': 1, 'e': 2, 'z': 3 }), '{"e":2,"z":3,"é":1}');
  assert.equal(canonicalize({ 'é': 1, 'e': 2 }), '{"e":2,"é":1}');
});

test('canonical numbers follow ECMAScript, with -0 normalised', () => {
  assert.equal(canonicalize(0), '0');
  assert.equal(canonicalize(-0), '0', 'RFC 8785 requires -0 to serialize as 0');
  assert.equal(canonicalize(1e21), '1e+21');
  assert.equal(canonicalize(1e-7), '1e-7');
  assert.equal(canonicalize(0.1), '0.1');
  assert.equal(canonicalize(1 / 3), '0.3333333333333333');
  assert.equal(canonicalize(Number.MAX_SAFE_INTEGER), '9007199254740991');
  assert.throws(() => canonicalize(NaN), /non-finite/);
  assert.throws(() => canonicalize(Infinity), /non-finite/);
});

test('canonical strings use the shortest legal escapes', () => {
  assert.equal(canonicalize('\b\t\n\f\r"\\'), '"\\b\\t\\n\\f\\r\\"\\\\"');
  assert.equal(canonicalize(' '), '"\\u0000"');
  assert.equal(canonicalize(''), '"\\u001f"');
  // Everything at or above U+0020, apart from quote and backslash, is literal.
  assert.equal(canonicalize('é☃'), '"é☃"');
  assert.equal(canonicalize(''), '""');
});

test('the same object canonicalizes identically whatever order it was built in', () => {
  // The property every signature depends on.
  const a = { z: 1, m: { b: [1, 2], a: 'x' }, a: true };
  const b = { a: true, m: { a: 'x', b: [1, 2] }, z: 1 };
  assert.equal(canonicalize(a), canonicalize(b));
  assert.equal(canonicalize(JSON.parse(JSON.stringify(a))), canonicalize(b));
});

// ── randomized differential testing ──────────────────────────────────────

test('all three tree implementations agree over thousands of random trees', () => {
  // Three structurally different ways to reach a root:
  //   1. the recursive spec form (split at the largest power of two)
  //   2. the incremental binary-counter stack used on append
  //   3. the cached level structure used for proofs
  // A shared bug would have to be present in all three, written differently.
  let checked = 0;

  for (let trial = 0; trial < 400; trial++) {
    const n = 1 + Math.floor(Math.random() * 60);
    const leaves = Array.from({ length: n }, () => leafHash(randomBytes(1 + Math.floor(Math.random() * 40))));

    const recursive = merkleRoot(leaves);

    const incremental = new MerkleTree();
    for (const l of leaves) incremental.append(l);

    assert.deepEqual(incremental.root, recursive, `n=${n}: incremental root differs`);

    // The level structure is built lazily by asking for a proof.
    const i = Math.floor(Math.random() * n);
    const cached = incremental.inclusionProof(i);
    assert.deepEqual(cached, inclusionProof(leaves, i), `n=${n}, leaf=${i}: cached proof differs`);

    // And the proof, checked by the independent iterative verifier, must
    // reconstruct exactly that root.
    assert.ok(
      verifyInclusion({ leafHash: leaves[i], index: i, treeSize: n, proof: cached, root: recursive }),
      `n=${n}, leaf=${i}: proof did not reconstruct the root`,
    );
    checked++;
  }

  assert.equal(checked, 400);
});

test('random consistency proofs hold, and random forgeries do not', () => {
  for (let trial = 0; trial < 200; trial++) {
    const n = 2 + Math.floor(Math.random() * 50);
    const m = Math.floor(Math.random() * n);
    const leaves = Array.from({ length: n }, () => leafHash(randomBytes(8)));

    const firstRoot = merkleRoot(leaves.slice(0, m));
    const secondRoot = merkleRoot(leaves);
    const proof = consistencyProof(leaves, m);

    assert.ok(
      verifyConsistency({ firstSize: m, secondSize: n, firstRoot, secondRoot, proof }),
      `honest consistency ${m} → ${n} failed`,
    );

    // Alter one historical leaf. The proof for the altered tree must not
    // reconcile with the original root.
    if (m > 0) {
      const tampered = [...leaves];
      tampered[Math.floor(Math.random() * m)] = leafHash(randomBytes(8));
      assert.equal(
        verifyConsistency({
          firstSize: m,
          secondSize: n,
          firstRoot,
          secondRoot: merkleRoot(tampered),
          proof: consistencyProof(tampered, m),
        }),
        false,
        `a rewritten history passed consistency for ${m} → ${n}`,
      );
    }
  }
});

test('a random proof is never accepted', () => {
  // Sanity floor: if forged proofs pass, nothing above means anything.
  const leaves = Array.from({ length: 33 }, () => leafHash(randomBytes(8)));
  const root = merkleRoot(leaves);

  for (let trial = 0; trial < 300; trial++) {
    const index = Math.floor(Math.random() * 33);
    const length = 1 + Math.floor(Math.random() * 8);
    const proof = Array.from({ length }, () => randomBytes(32));
    assert.equal(
      verifyInclusion({ leafHash: leaves[index], index, treeSize: 33, proof, root }),
      false,
      'a randomly generated proof was accepted',
    );
  }
});

// ── strictness ───────────────────────────────────────────────────────────

test('keys and signatures must be canonical base64url', () => {
  // Node's own decoder accepts every one of these — padding, whitespace, the
  // standard alphabet — and would have verified them. A verifier that quietly
  // accepts malformed encodings can be argued into agreeing with something it
  // should have rejected, and two implementations can disagree about it.
  const v = ED25519_VECTORS[0];
  const key = Buffer.from(v.public, 'hex').toString('base64url');
  const sig = Buffer.from(v.signature, 'hex').toString('base64url');
  const msg = Buffer.from(v.message, 'hex');

  assert.ok(verify(key, msg, sig), 'the canonical encoding must still verify');

  for (const bad of [`${sig}=`, `${sig}\n`, ` ${sig}`, `${sig}!`, sig.slice(0, -1), '']) {
    assert.equal(verify(key, msg, bad), false, `accepted signature ${JSON.stringify(bad.slice(-8))}`);
  }
  for (const bad of [`${key}=`, `${key}\n`, ` ${key}`, key.slice(0, -1), '']) {
    assert.equal(verify(bad, msg, sig), false, `accepted key ${JSON.stringify(bad.slice(-8))}`);
    assert.throws(() => identityFromPublicKey(bad), undefined, `built an identity from ${JSON.stringify(bad.slice(-8))}`);
  }

  // The same signature spelled in the standard alphabet. Find one that has a
  // character where the two alphabets differ.
  let found = 0;
  for (let i = 0; i < 200 && found < 5; i++) {
    const id = generateIdentity().identity;
    const m = randomBytes(16);
    const s = sign(id, m);
    if (!/[-_]/.test(s)) continue;
    const standard = s.replace(/-/g, '+').replace(/_/g, '/');
    assert.ok(verify(id.publicKey, m, s));
    assert.equal(verify(id.publicKey, m, standard), false, 'accepted the standard base64 alphabet');
    found++;
  }
  assert.ok(found > 0, 'the search never produced a signature that exercises the alphabet check');
});
