/**
 * Terminal output helpers.
 *
 * Colour is suppressed when stdout is not a TTY, when NO_COLOR is set, or when
 * TERM says dumb — because this CLI's output gets piped into files and CI logs
 * constantly, and escape codes in an audit artifact are noise at best.
 */

const enabled =
  process.stdout.isTTY &&
  !process.env.NO_COLOR &&
  process.env.TERM !== 'dumb';

/**
 * @param {number} code
 * @returns {(s: string) => string}
 */
const style = (code) => (s) => (enabled ? `[${code}m${s}[0m` : s);

export const c = {
  bold: style(1),
  dim: style(2),
  red: style(31),
  green: style(32),
  yellow: style(33),
  blue: style(34),
  magenta: style(35),
  cyan: style(36),
  grey: style(90),
};

/** @param {string} s */
export function out(s = '') {
  process.stdout.write(s + '\n');
}

/** @param {string} s */
export function err(s) {
  process.stderr.write(s + '\n');
}

export const ok = (s) => out(`${c.green('✓')} ${s}`);
export const bad = (s) => out(`${c.red('✗')} ${s}`);
export const warn = (s) => out(`${c.yellow('!')} ${s}`);
export const info = (s) => out(`${c.blue('·')} ${s}`);

/**
 * @param {string} title
 */
export function heading(title) {
  out('');
  out(c.bold(title));
  out(c.grey('─'.repeat(Math.min(title.length + 10, 64))));
}

/**
 * Render aligned key/value lines.
 *
 * @param {[string, string][]} rows
 * @param {number} [indent=2]
 */
export function kv(rows, indent = 2) {
  const width = Math.max(...rows.map(([k]) => k.length));
  for (const [k, v] of rows) {
    out(' '.repeat(indent) + c.grey(k.padEnd(width)) + '  ' + v);
  }
}

/**
 * A simple column table that does not wrap — audit output is read in wide
 * terminals and grepped in narrow ones, and truncation beats reflow for both.
 *
 * @param {string[]} headers
 * @param {string[][]} rows
 */
export function table(headers, rows) {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => stripAnsi(r[i] ?? '').length)),
  );
  out('  ' + headers.map((h, i) => c.grey(h.padEnd(widths[i]))).join('  '));
  for (const row of rows) {
    out(
      '  ' +
        row
          .map((cell, i) => cell + ' '.repeat(Math.max(0, widths[i] - stripAnsi(cell).length)))
          .join('  '),
    );
  }
}

/** @param {string} s */
function stripAnsi(s) {
  return s.replace(/\[\d+m/g, '');
}

/**
 * @param {string} outcome
 * @returns {string}
 */
export function outcomeBadge(outcome) {
  switch (outcome) {
    case 'allow':
      return c.green('allow');
    case 'deny':
      return c.red('DENY');
    case 'escalate':
      return c.yellow('escalate');
    default:
      return outcome;
  }
}

/**
 * Minimal flag parser. Supports `--flag`, `--key value`, `--key=value`, short
 * `-k`, and a `--` terminator after which everything is positional — which the
 * proxy command depends on to capture a full wrapped command line.
 *
 * @param {string[]} argv
 * @returns {{ _: string[], rest: string[], [k: string]: any }}
 */
export function parseArgs(argv) {
  /** @type {any} */
  const out = { _: [], rest: [] };
  let i = 0;
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      out.rest = argv.slice(i + 1);
      break;
    }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) {
        out[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (next === undefined || next.startsWith('-')) {
          out[a.slice(2)] = true;
        } else {
          out[a.slice(2)] = next;
          i++;
        }
      }
    } else if (a.startsWith('-') && a.length > 1) {
      out[a.slice(1)] = true;
    } else {
      out._.push(a);
    }
  }
  return out;
}
