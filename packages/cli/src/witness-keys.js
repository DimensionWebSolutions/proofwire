import fs from 'node:fs';

/**
 * The witnesses a verifier has chosen to trust.
 *
 * These have to come from outside the bundle. A bundle's own keyring is supplied
 * by the party whose honesty is in question, so it cannot vouch for witnesses:
 * an operator could add any number of fresh keys and "witness" their own
 * checkpoints. The auditor brings the public keys, obtained from the witness
 * operators directly, and only signatures from those keys count.
 *
 *     --witness-key kid=publicKey[,kid=publicKey…]
 *     --witness-keys witnesses.json      { "kid": "publicKey", … }
 *                                        or [ { "kid": …, "publicKey": … }, … ]
 *                                        (entries with `revokedAt` are skipped)
 *
 * @param {Record<string, any>} args
 * @returns {Record<string, string>|undefined}  undefined when none were given.
 */
export function witnessKeysFrom(args) {
  /** @type {Record<string, string>} */
  const keys = {};

  const inline = args['witness-key'];
  if (typeof inline === 'string') {
    for (const part of inline.split(/[,\s]+/).filter(Boolean)) {
      const eq = part.indexOf('=');
      if (eq < 1 || eq === part.length - 1) {
        throw new Error(`--witness-key expects kid=publicKey, got "${part}"`);
      }
      keys[part.slice(0, eq)] = part.slice(eq + 1);
    }
  }

  const file = args['witness-keys'];
  if (typeof file === 'string') {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    // The list form is also the format of the repository's published witness
    // record (witnesses/keys.json), which marks a compromised key `revokedAt`
    // rather than deleting it. A revoked key is never pinned: whoever holds it
    // could "witness" anything. A merely retired one still is — it stopped
    // signing, but what it signed before stays good.
    const revoked = Array.isArray(raw)
      ? raw.filter((w) => typeof w?.revokedAt === 'string' && w.revokedAt).map((w) => w.kid)
      : [];
    if (revoked.length) {
      process.stderr.write(`  not pinning ${revoked.length} revoked witness key(s) from ${file}: ${revoked.join(', ')}\n`);
    }
    const entries = Array.isArray(raw)
      ? raw.filter((w) => !revoked.includes(w?.kid)).map((w) => [w?.kid, w?.publicKey])
      : Object.entries(raw);
    for (const [kid, publicKey] of entries) {
      if (typeof kid !== 'string' || typeof publicKey !== 'string' || !kid || !publicKey) {
        throw new Error(`${file}: each witness needs a kid and a publicKey`);
      }
      keys[kid] = publicKey;
    }
  }

  return Object.keys(keys).length ? keys : undefined;
}
