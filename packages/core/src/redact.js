/**
 * Detection and masking of secrets and personal data in tool arguments.
 *
 * This runs before anything is written to a receipt. The threat here is banal
 * but real: an agent passes an API key or a customer's card number as a tool
 * argument, and the audit log — the one artifact designed to be kept forever
 * and handed to third parties — becomes the worst breach in the building.
 */

/**
 * @typedef {object} Detector
 * @property {string} type
 * @property {RegExp} pattern
 * @property {'secret'|'pii'|'financial'} severity
 * @property {(m: string) => boolean} [confirm]  Extra check to cut false positives.
 */

/**
 * Luhn check, so we do not flag every 16-digit order number as a card.
 *
 * @param {string} s
 * @returns {boolean}
 */
function luhn(s) {
  const digits = s.replace(/[^0-9]/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/** @type {Detector[]} */
export const DEFAULT_DETECTORS = [
  { type: 'aws_access_key', severity: 'secret', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: 'github_token', severity: 'secret', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  // Anthropic first, and OpenAI's pattern excludes `sk-ant-`: both are `sk-`
  // prefixed, and a mislabelled finding sends an incident responder to the
  // wrong vendor's dashboard to rotate the wrong key.
  { type: 'anthropic_key', severity: 'secret', pattern: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g },
  { type: 'openai_key', severity: 'secret', pattern: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { type: 'stripe_key', severity: 'secret', pattern: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { type: 'slack_token', severity: 'secret', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: 'google_api_key', severity: 'secret', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { type: 'private_key_block', severity: 'secret', pattern: /-----BEGIN[ A-Z]*PRIVATE KEY-----/g },
  {
    type: 'jwt',
    severity: 'secret',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    type: 'bearer_token',
    severity: 'secret',
    pattern: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/g,
  },
  {
    type: 'credit_card',
    severity: 'financial',
    pattern: /\b(?:\d[ -]?){12,18}\d\b/g,
    confirm: luhn,
  },
  { type: 'us_ssn', severity: 'pii', pattern: /\b(?!000|666|9\d\d)\d{3}-\d{2}-\d{4}\b/g },
  { type: 'iban', severity: 'financial', pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g },
  {
    type: 'email',
    severity: 'pii',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    type: 'phone_e164',
    severity: 'pii',
    pattern: /(?<![\w.])\+[1-9]\d{7,14}(?![\w.])/g,
  },
];

/**
 * Replace a match with a stable, non-reversible tag. Keeping the last four
 * characters is deliberate: it is what lets a human recognise *which* card or
 * key an incident involved without the log containing the value.
 *
 * @param {string} type
 * @param {string} match
 * @returns {string}
 */
function mask(type, match) {
  const tail = match.replace(/[^A-Za-z0-9]/g, '').slice(-4);
  return `[redacted:${type}:…${tail}]`;
}

/**
 * @typedef {object} RedactionFinding
 * @property {string} path   JSON-pointer-ish location, e.g. `args.body.token`.
 * @property {string} type
 * @property {'secret'|'pii'|'financial'} severity
 */

/**
 * @typedef {object} RedactionResult
 * @property {unknown} value     Deep copy with matches masked.
 * @property {RedactionFinding[]} findings
 */

/**
 * Walk a value and mask anything a detector claims.
 *
 * @param {unknown} value
 * @param {object} [opts]
 * @param {Detector[]} [opts.detectors]
 * @param {string[]} [opts.denyKeys]  Keys whose value is masked outright,
 *   whatever it looks like — `password`, `authorization`, and friends.
 * @returns {RedactionResult}
 */
export function redact(value, opts = {}) {
  const detectors = opts.detectors ?? DEFAULT_DETECTORS;
  const denyKeys = (opts.denyKeys ?? [
    'password',
    'passwd',
    'secret',
    'token',
    'api_key',
    'apikey',
    'authorization',
    'auth',
    'credential',
    'credentials',
    'private_key',
    'client_secret',
    'session_key',
    'cvv',
    'cvc',
  ]).map((k) => k.toLowerCase());

  /** @type {RedactionFinding[]} */
  const findings = [];

  /**
   * @param {string} s
   * @param {string} path
   * @returns {string}
   */
  function scanString(s, path) {
    let out = s;
    for (const d of detectors) {
      // Fresh lastIndex each pass: these are /g regexes held in module scope.
      d.pattern.lastIndex = 0;
      out = out.replace(d.pattern, (m) => {
        if (d.confirm && !d.confirm(m)) return m;
        findings.push({ path, type: d.type, severity: d.severity });
        return mask(d.type, m);
      });
    }
    return out;
  }

  /**
   * @param {unknown} v
   * @param {string} path
   * @returns {unknown}
   */
  function walk(v, path) {
    if (typeof v === 'string') return scanString(v, path);
    if (Array.isArray(v)) return v.map((item, i) => walk(item, `${path}[${i}]`));
    if (v && typeof v === 'object') {
      /** @type {Record<string, unknown>} */
      const out = {};
      for (const [k, val] of Object.entries(v)) {
        const child = path ? `${path}.${k}` : k;
        if (denyKeys.includes(k.toLowerCase())) {
          findings.push({ path: child, type: `key:${k.toLowerCase()}`, severity: 'secret' });
          out[k] = '[redacted:by-key]';
          continue;
        }
        out[k] = walk(val, child);
      }
      return out;
    }
    return v;
  }

  return { value: walk(value, ''), findings };
}

/**
 * True if anything found would be a reportable disclosure on its own.
 *
 * @param {RedactionFinding[]} findings
 * @returns {boolean}
 */
export function hasSecrets(findings) {
  return findings.some((f) => f.severity === 'secret' || f.severity === 'financial');
}
