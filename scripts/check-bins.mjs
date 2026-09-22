import fs from 'node:fs';
import path from 'node:path';

/**
 * Problems with the executables a set of packages declares, as messages.
 *
 * The one this exists for: a `#!/usr/bin/env node` line ending in CRLF. On
 * Linux and macOS the kernel then looks for a program called `node\r`, and the
 * installed command fails with "No such file or directory" — on every machine
 * except the Windows one it was published from. A Windows checkout produces
 * exactly that by default (`core.autocrlf=true`), and npm packs the working
 * copy, not the commit. 0.2.0 and 0.3.0 shipped clean LF shebangs by luck, not
 * by any check; this is the check.
 *
 * Also refused: a bin that does not exist, and one with no `#!` at the very
 * start of the file (a UTF-8 byte-order mark before it breaks it just as
 * surely).
 *
 * @param {string} root         Repository root.
 * @param {string[]} packageDirs Package directories, relative to `root`.
 * @returns {string[]}
 */
export function binProblems(root, packageDirs) {
  /** @type {string[]} */
  const problems = [];
  for (const rel of packageDirs) {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, rel, 'package.json'), 'utf8'));
    const bins = typeof pkg.bin === 'string' ? { [pkg.name]: pkg.bin } : (pkg.bin ?? {});

    for (const [name, target] of Object.entries(bins)) {
      const label = `${pkg.name}: bin "${name}" (${target})`;
      let bytes;
      try {
        bytes = fs.readFileSync(path.join(root, rel, target));
      } catch {
        problems.push(`${label} does not exist`);
        continue;
      }
      const end = bytes.indexOf(0x0a);
      const first = bytes.subarray(0, end === -1 ? bytes.length : end);
      if (first[0] !== 0x23 || first[1] !== 0x21) {
        problems.push(`${label} does not start with a #! line`);
      } else if (first.includes(0x0d)) {
        problems.push(`${label} has a CRLF #! line — on Linux and macOS it would run "node\\r" and fail`);
      }
    }
  }
  return problems;
}
