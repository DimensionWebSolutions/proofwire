import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { sha256 } from './hash.js';

/**
 * Ed25519 identities.
 *
 * Ed25519 rather than ECDSA because signing is deterministic: no per-signature
 * nonce means no way to leak the private key by reusing one, which matters a
 * lot when the signer is an unattended agent runtime signing thousands of
 * receipts an hour.
 */

/**
 * @typedef {object} Identity
 * @property {string} kid   Key ID — `pw1` + first 16 bytes of the public key hash, hex.
 * @property {string} publicKey  Raw 32-byte Ed25519 public key, base64url.
 * @property {import('node:crypto').KeyObject} [privateKeyObject]  Present only for signing identities.
 */

/**
 * Decode base64url strictly.
 *
 * `Buffer.from(x, 'base64url')` is forgiving to the point of being a hazard for a
 * verifier: it accepts `=` padding, the standard `+` and `/` alphabet, and it
 * silently skips whitespace and any other character it does not recognise. A
 * signature or key that decodes fine but is not what the wire format says is one
 * more thing that two implementations can disagree about — and a verifier that
 * quietly accepts malformed encodings is one that can be argued into agreeing
 * with something it should have rejected.
 *
 * @param {string} s
 * @returns {Buffer}
 */
function decodeBase64url(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
    throw new TypeError('not base64url');
  }
  return Buffer.from(s, 'base64url');
}

/**
 * Raw public key bytes from a Node KeyObject, via JWK (`x` is base64url).
 *
 * @param {import('node:crypto').KeyObject} pub
 * @returns {Buffer}
 */
function rawPublicKey(pub) {
  const jwk = pub.export({ format: 'jwk' });
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new TypeError('expected an Ed25519 public key');
  }
  return Buffer.from(jwk.x, 'base64url');
}

/**
 * Derive the key ID. Truncating to 16 bytes keeps receipts small while leaving
 * 128 bits of collision resistance — far beyond what a key registry needs.
 *
 * @param {Buffer} rawPub
 * @returns {string}
 */
export function keyIdFor(rawPub) {
  return 'pw1' + sha256(rawPub).subarray(0, 16).toString('hex');
}

/**
 * Generate a fresh signing identity.
 *
 * @returns {{ identity: Identity, privateKeyPem: string }}
 */
export function generateIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = rawPublicKey(publicKey);
  return {
    identity: {
      kid: keyIdFor(raw),
      publicKey: raw.toString('base64url'),
      privateKeyObject: privateKey,
    },
    privateKeyPem: /** @type {string} */ (
      privateKey.export({ type: 'pkcs8', format: 'pem' })
    ),
  };
}

/**
 * Load a signing identity from a PKCS#8 PEM private key.
 *
 * @param {string} pem
 * @returns {Identity}
 */
export function identityFromPem(pem) {
  const privateKeyObject = createPrivateKey(pem);
  if (privateKeyObject.asymmetricKeyType !== 'ed25519') {
    throw new TypeError(
      `expected an Ed25519 private key, got ${privateKeyObject.asymmetricKeyType}`,
    );
  }
  const raw = rawPublicKey(createPublicKey(privateKeyObject));
  return {
    kid: keyIdFor(raw),
    publicKey: raw.toString('base64url'),
    privateKeyObject,
  };
}

/**
 * A verify-only identity, built from the public half alone. This is what an
 * auditor holds: enough to check every signature, never enough to forge one.
 *
 * @param {string} publicKeyB64u  Raw 32-byte key, base64url.
 * @returns {Identity}
 */
export function identityFromPublicKey(publicKeyB64u) {
  const raw = decodeBase64url(publicKeyB64u);
  if (raw.length !== 32) {
    throw new TypeError(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  }
  return { kid: keyIdFor(raw), publicKey: raw.toString('base64url') };
}

/**
 * Rebuild a Node public KeyObject from raw bytes by wrapping them in the
 * fixed 12-byte SPKI prefix for Ed25519 (RFC 8410) — Node has no raw importer.
 *
 * @param {string} publicKeyB64u
 * @returns {import('node:crypto').KeyObject}
 */
export function publicKeyObject(publicKeyB64u) {
  const raw = decodeBase64url(publicKeyB64u);
  if (raw.length !== 32) {
    throw new TypeError(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  }
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    raw,
  ]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

/**
 * @param {Identity} identity  Must carry a private key.
 * @param {Buffer} message
 * @returns {string} Signature, base64url.
 */
export function sign(identity, message) {
  if (!identity.privateKeyObject) {
    throw new Error(`identity ${identity.kid} is verify-only; cannot sign`);
  }
  return cryptoSign(null, message, identity.privateKeyObject).toString('base64url');
}

/**
 * @param {string} publicKeyB64u
 * @param {Buffer} message
 * @param {string} signatureB64u
 * @returns {boolean}
 */
export function verify(publicKeyB64u, message, signatureB64u) {
  let sig;
  try {
    sig = decodeBase64url(signatureB64u);
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  try {
    return cryptoVerify(null, message, publicKeyObject(publicKeyB64u), sig);
  } catch {
    return false;
  }
}
