/**
 * Deterministic JSON serialization (RFC 8785 / JCS).
 *
 * Two parties must produce byte-identical bytes for the same logical object,
 * or every signature we make is worthless. `JSON.stringify` does not promise
 * that: key order follows insertion order, so the same receipt built by two
 * different code paths can hash differently. JCS pins the order and the
 * number/string encodings.
 */

/** Characters that must be escaped, mapped to their shortest legal escape. */
const ESCAPES = {
  0x08: '\\b',
  0x09: '\\t',
  0x0a: '\\n',
  0x0c: '\\f',
  0x0d: '\\r',
  0x22: '\\"',
  0x5c: '\\\\',
};

/**
 * @param {string} s
 * @returns {string} JSON string literal, including surrounding quotes.
 */
function encodeString(s) {
  let out = '"';
  for (const ch of s) {
    const cp = /** @type {number} */ (ch.codePointAt(0));
    const esc = ESCAPES[cp];
    if (esc !== undefined) out += esc;
    else if (cp < 0x20) out += '\\u' + cp.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

/**
 * JCS numbers are ECMAScript `Number::toString` output, with the one carve-out
 * that -0 serializes as `0`. NaN and Infinity have no JSON form at all.
 *
 * @param {number} n
 * @returns {string}
 */
function encodeNumber(n) {
  if (!Number.isFinite(n)) {
    throw new TypeError(`cannot canonicalize non-finite number: ${n}`);
  }
  if (n === 0) return '0';
  return String(n);
}

/**
 * Canonicalize a JSON-compatible value to its RFC 8785 string form.
 *
 * `undefined` object properties are dropped (matching `JSON.stringify`), but
 * `undefined` inside an array becomes `null` — again matching stringify, so
 * round-tripping through `JSON.parse` is stable.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalize(value) {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return encodeNumber(value);
    case 'string':
      return encodeString(value);
    case 'bigint':
      throw new TypeError('cannot canonicalize bigint: no JSON representation');
    case 'undefined':
    case 'function':
    case 'symbol':
      throw new TypeError(`cannot canonicalize ${typeof value}`);
  }

  if (Array.isArray(value)) {
    const items = value.map((v) => (v === undefined ? 'null' : canonicalize(v)));
    return '[' + items.join(',') + ']';
  }

  if (value instanceof Date) return encodeString(value.toISOString());

  // Sort by UTF-16 code unit, which is what `Array.prototype.sort` does by
  // default on strings. Intl collation would be locale-dependent and wrong.
  const obj = /** @type {Record<string, unknown>} */ (value);
  const keys = Object.keys(obj).sort();
  const parts = [];
  for (const k of keys) {
    const v = obj[k];
    if (v === undefined) continue;
    parts.push(encodeString(k) + ':' + canonicalize(v));
  }
  return '{' + parts.join(',') + '}';
}

/**
 * Canonical form as UTF-8 bytes — what actually gets hashed and signed.
 *
 * @param {unknown} value
 * @returns {Buffer}
 */
export function canonicalBytes(value) {
  return Buffer.from(canonicalize(value), 'utf8');
}
