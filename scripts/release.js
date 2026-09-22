#!/usr/bin/env node
import { execFileSync, execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { binProblems } from './check-bins.mjs';

/**
 * Publish the workspace to npm, in dependency order, with the checks that
 * matter before something irreversible.
 *
 *     node scripts/release.js --dry-run    what would happen
 *     node scripts/release.js              do it
 *
 * npm is effectively write-once: `npm unpublish` is allowed for 72 hours and
 * the name is held forever either way. So everything that can be verified
 * beforehand is verified beforehand.
 */

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Dependency order. `@proof_wire/core` has no dependents above it; the CLI
 * depends on the proxy, so it goes last. Publishing out of order leaves a
 * package on the registry whose dependency does not exist yet — briefly
 * uninstallable, and not fixable by unpublishing.
 */
const ORDER = [
  'packages/core',
  'packages/proxy',
  'packages/dashboard',
  'packages/server',
  'packages/cli',
];

const B = (s) => `[1m${s}[0m`;
const DIM = (s) => `[90m${s}[0m`;
const GREEN = (s) => `[32m${s}[0m`;
const RED = (s) => `[31m${s}[0m`;
const YELLOW = (s) => `[33m${s}[0m`;
const CYAN = (s) => `[36m${s}[0m`;

const dryRun = process.argv.includes('--dry-run');
const skipTests = process.argv.includes('--skip-tests');
// With 2FA on (it should be), npm wants a one-time code per publish. Either pass
// one here, or leave it out and npm prompts, which needs the terminal attached.
const otp = process.argv.find((a) => a.startsWith('--otp='))?.slice('--otp='.length);

/**
 * Run a command, coping with Windows' `.cmd` shims.
 *
 * `npm` on Windows is a shim Node will not spawn without a shell — but passing
 * an argv *array* with `shell: true` is deprecated precisely because Node
 * concatenates it unescaped. So on Windows we build the one string ourselves,
 * quoting as we go; everywhere else argv is passed through untouched, which is
 * safer and needs no quoting at all.
 *
 * @param {string} cmd
 * @param {string[]} args
 * @param {object} [opts]
 */
function run(cmd, args, opts = {}) {
  const common = {
    cwd: ROOT,
    encoding: /** @type {const} */ ('utf8'),
    stdio: opts.inherit ? /** @type {const} */ ('inherit') : /** @type {const} */ ('pipe'),
    ...opts,
  };

  if (process.platform !== 'win32') {
    return execFileSync(cmd, args, common);
  }

  const quote = (a) => (/[\s"^&|<>()%!]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a);
  return execSync([cmd, ...args.map(quote)].join(' '), common);
}

/** @param {string} rel */
function manifest(rel) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, rel, 'package.json'), 'utf8'));
}

/**
 * Is this exact name@version already on the registry?
 *
 * @param {string} name
 * @param {string} version
 */
function alreadyPublished(name, version) {
  try {
    const out = run('npm', ['view', `${name}@${version}`, 'version']);
    return out.trim() === version;
  } catch {
    return false;
  }
}

function preflight() {
  console.log('');
  console.log(B('  Preflight'));
  console.log(DIM('  ─────────────────────────────────────────────────────────'));

  /** @type {string[]} */
  const blocking = [];

  // 1. Authenticated?
  let who = null;
  try {
    who = run('npm', ['whoami']).trim();
    console.log(`  ${GREEN('✓')} npm    authenticated as ${B(who)}`);
  } catch {
    console.log(`  ${RED('✗')} npm    not logged in`);
    blocking.push(
      'Run `npm login` first. Publishing needs credentials this script will not ask you for.',
    );
  }

  // 2. Does the scope exist and can this account write to it?
  if (who) {
    try {
      const orgs = JSON.parse(run('npm', ['org', 'ls', 'proof_wire', '--json']));
      console.log(
        `  ${GREEN('✓')} scope  @proof_wire reachable ${DIM(`(${Object.keys(orgs).length} member(s))`)}`,
      );
    } catch {
      console.log(`  ${YELLOW('!')} scope  cannot read the @proof_wire org`);
      blocking.push(
        'Create the free org at https://www.npmjs.com/org/create (name: proof_wire).\n' +
          '     Without it, the four @proof_wire/* packages cannot be published.\n' +
          '     The unscoped `proofwire` CLI depends on two of them, so it would be uninstallable.',
      );
    }
  }

  // 3. Clean tree — a publish should correspond to a commit.
  const dirty = run('git', ['status', '--porcelain']).trim();
  if (dirty) {
    console.log(`  ${YELLOW('!')} git    working tree is dirty`);
    for (const line of dirty.split('\n').slice(0, 10)) console.log(`           ${DIM(line)}`);
    blocking.push('Commit or stash first, so the published code matches a commit.');
  } else {
    console.log(`  ${GREEN('✓')} git    working tree clean`);
  }

  // 4. Versions consistent across the workspace.
  const versions = new Set(ORDER.map((r) => manifest(r).version));
  if (versions.size !== 1) {
    console.log(`  ${RED('✗')} vers   mismatched: ${[...versions].join(', ')}`);
    blocking.push('All packages should release at the same version.');
  } else {
    console.log(`  ${GREEN('✓')} vers   all at ${B([...versions][0])}`);
  }

  // 5. Executables that will actually run where they are installed.
  const bins = binProblems(ROOT, ORDER);
  if (bins.length) {
    console.log(`  ${RED('✗')} bins   ${bins.length} problem(s)`);
    for (const p of bins) console.log(`           ${p}`);
    blocking.push(
      'Fix the executables first. For a CRLF #! line, re-check the file out with the\n' +
        '     LF .gitattributes rule applied — `git checkout -- <file>`, once the tree is clean.',
    );
  } else {
    console.log(`  ${GREEN('✓')} bins   every #! line is LF`);
  }

  // 6. Tests. The last chance to find out before it is permanent.
  if (skipTests) {
    console.log(`  ${YELLOW('!')} tests  skipped`);
  } else {
    try {
      run('npm', ['test'], {
        env: { ...process.env, PROOFWIRE_ACCESS_LOG: 'off', PROOFWIRE_INSECURE_COOKIES: '1' },
      });
      console.log(`  ${GREEN('✓')} tests  passing`);
    } catch (err) {
      console.log(`  ${RED('✗')} tests  FAILING`);
      blocking.push('Do not publish a failing build.');
    }
  }

  return blocking;
}

async function main() {
  console.log('');
  console.log(B('  Proofwire release') + DIM(dryRun ? '  (dry run)' : ''));

  const blocking = preflight();

  if (blocking.length) {
    console.log('');
    console.log(RED(`  ${blocking.length} thing(s) to fix first:`));
    console.log('');
    for (const b of blocking) console.log(`  ${YELLOW('→')} ${b}`);
    console.log('');
    process.exitCode = 1;
    return;
  }

  const version = manifest(ORDER[0]).version;
  console.log('');
  console.log(B(`  Publishing ${version}`));
  console.log(DIM('  ─────────────────────────────────────────────────────────'));

  for (const rel of ORDER) {
    const { name } = manifest(rel);

    if (alreadyPublished(name, version)) {
      console.log(`  ${DIM('•')} ${name.padEnd(24)} ${DIM(`${version} already on the registry, skipping`)}`);
      continue;
    }

    if (dryRun) {
      console.log(`  ${CYAN('would publish')} ${name} ${version}`);
      continue;
    }

    try {
      // Attached to the terminal, not piped: a piped npm cannot ask for a 2FA code and
      // fails with EOTP, which is how the first attempt at this went.
      run('npm', ['publish', '--workspace', `./${rel}`, '--access', 'public', ...(otp ? [`--otp=${otp}`] : [])], { inherit: true });
      console.log(`  ${GREEN('✓')} ${name.padEnd(24)} ${version}`);
    } catch (err) {
      console.log(`  ${RED('✗')} ${name.padEnd(24)} ${String(err.stderr ?? err.message).trim().split('\n').slice(-2).join(' ')}`);
      console.log('');
      console.log(RED('  Stopped. Packages already published above are live and cannot be taken back.'));
      console.log(DIM('  Fix the cause and re-run — published versions are skipped automatically.'));
      process.exitCode = 1;
      return;
    }
  }

  if (dryRun) {
    console.log('');
    console.log(DIM('  Nothing was published. Drop --dry-run to do it for real.'));
    console.log('');
    return;
  }

  console.log('');
  console.log(GREEN(`  Published ${version}.`));
  console.log('');
  console.log(DIM('  Verify what the world now sees:'));
  console.log(`    ${CYAN('npx proofwire@latest --version')}`);
  console.log(`    ${CYAN(`npm view proofwire@${version}`)}`);
  console.log('');
  console.log(DIM('  Then tag the release:'));
  console.log(`    ${CYAN(`git tag -a v${version} -m "Proofwire ${version}" && git push --tags`)}`);
  console.log('');
}

await main();
