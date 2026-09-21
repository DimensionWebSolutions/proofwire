import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ProofLog, Policy, verifyBundle } from '@proofwire/core';
import { RemoteSink, fetchPolicy } from '@proofwire/proxy/remote';
import { c, out, ok, bad, warn, info, heading, kv, table } from './ui.js';

/**
 * Commands that connect a local log to a Proofwire hub.
 *
 * Credentials live in `~/.proofwire/credentials.json`, not in the project, so
 * a token cannot be committed by accident and one machine's credentials serve
 * every project on it.
 */

const CRED_DIR = path.join(os.homedir(), '.proofwire');
const CRED_FILE = path.join(CRED_DIR, 'credentials.json');

/** @returns {Record<string, { url: string, token: string, log?: string }>} */
export function loadRemotes() {
  if (!fs.existsSync(CRED_FILE)) return {};
  try {
    return JSON.parse(fs.readFileSync(CRED_FILE, 'utf8'));
  } catch {
    return {};
  }
}

/** @param {Record<string, object>} remotes */
function saveRemotes(remotes) {
  fs.mkdirSync(CRED_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(CRED_FILE, JSON.stringify(remotes, null, 2) + '\n', { mode: 0o600 });
}

/**
 * The remote a command should use: the one named, or the default.
 *
 * @param {any} args
 * @returns {{ name: string, url: string, token: string, log?: string }}
 */
export function resolveRemote(args) {
  const remotes = loadRemotes();
  const name = args.remote ?? 'default';
  const remote = remotes[name];
  if (!remote) {
    const known = Object.keys(remotes);
    throw new Error(
      known.length
        ? `no remote "${name}" (have: ${known.join(', ')})`
        : 'no hub configured — run `pw remote add --url <hub> --token <key>`',
    );
  }
  return { name, ...remote };
}

/** @param {any} args */
export async function cmdRemote(args) {
  const action = args._[1] ?? 'list';

  if (action === 'list') {
    const remotes = loadRemotes();
    const names = Object.keys(remotes);
    heading('Hubs');
    if (names.length === 0) {
      out('  ' + c.grey('none configured'));
      out('');
      info(`add one:  ${c.cyan('pw remote add --url https://hub.acme.com --token <key>')}`);
      out('');
      return 0;
    }
    table(
      ['name', 'url', 'log', 'token'],
      names.map((n) => [
        c.bold(n),
        remotes[n].url,
        remotes[n].log ?? c.grey('—'),
        // Enough to tell two keys apart, not enough to use one.
        c.grey(remotes[n].token.slice(0, 12) + '…'),
      ]),
    );
    out('');
    return 0;
  }

  if (action === 'add') {
    if (!args.url || !args.token) {
      bad('usage: pw remote add --url <hub url> --token <api key> [--name default] [--log <slug>]');
      return 2;
    }
    const name = args.name ?? 'default';

    // Prove the credential works before storing it, so a typo surfaces now
    // rather than as silent shipping failures during a live agent session.
    let who;
    try {
      const res = await fetch(String(args.url).replace(/\/+$/, '') + '/v1/me', {
        headers: { authorization: `Bearer ${args.token}` },
        signal: AbortSignal.timeout(15_000),
      });
      if (res.status === 401) {
        bad('the hub rejected that token');
        return 1;
      }
      if (!res.ok) {
        bad(`the hub returned HTTP ${res.status}`);
        return 1;
      }
      who = await res.json();
    } catch (err) {
      bad(`could not reach ${args.url}: ${err.message}`);
      return 1;
    }

    const remotes = loadRemotes();
    remotes[name] = { url: String(args.url).replace(/\/+$/, ''), token: String(args.token) };
    if (args.log) remotes[name].log = String(args.log);
    saveRemotes(remotes);

    heading(`Connected to ${who.org.name ?? who.org.id}`);
    kv([
      ['remote', name],
      ['url', remotes[name].url],
      ['identity', who.label],
      ['scopes', who.scopes.join(' ')],
      ['stored', CRED_FILE],
    ]);
    out('');
    if (!who.scopes.includes('receipts:write')) {
      warn('This key cannot push receipts. That is right for an auditor, wrong for an agent.');
      out('');
    }
    return 0;
  }

  if (action === 'remove') {
    const name = args._[2] ?? args.name ?? 'default';
    const remotes = loadRemotes();
    if (!remotes[name]) {
      bad(`no remote "${name}"`);
      return 1;
    }
    delete remotes[name];
    saveRemotes(remotes);
    ok(`removed remote "${name}"`);
    return 0;
  }

  bad('usage: pw remote <list|add|remove>');
  return 2;
}

/**
 * Ship everything the hub has not confirmed.
 *
 * @param {any} args
 */
export async function cmdPush(args) {
  const remote = resolveRemote(args);
  const dir = path.resolve(args.log ?? '.proofwire');
  const localLog = ProofLog.open(dir, { readOnly: true });
  const slug = args.name ?? remote.log ?? localLog.logId;

  const sink = new RemoteSink({
    url: remote.url,
    token: remote.token,
    log: slug,
    localLog,
    onLog: (level, msg) => {
      if (level === 'error') bad(msg);
      else if (level === 'warn') warn(msg);
      else info(msg);
    },
  });

  if (!(await sink.connect())) return 1;

  heading(`Pushing to ${remote.name}`);
  const sent = await sink.flush();
  const status = sink.status();

  kv([
    ['hub', status.url],
    ['log', slug],
    ['local', String(localLog.size)],
    ['sent', String(sent)],
    ['behind', status.behind === 0 ? c.green('0') : c.yellow(String(status.behind))],
  ]);
  out('');

  if (status.fatal) {
    bad(status.lastError ?? 'the hub refused these receipts');
    out('');
    return 1;
  }
  if (status.behind > 0) {
    warn(`${status.behind} receipt(s) still local. They are safe; retry when the hub is reachable.`);
    out('');
    return 1;
  }
  ok('the hub holds every local receipt');
  out('');
  return 0;
}

/**
 * Verify a hosted log — from the outside, the way an auditor would.
 *
 * @param {any} args
 */
export async function cmdRemoteVerify(args) {
  const remote = resolveRemote(args);
  const slug = args._[1] ?? args.name ?? remote.log;
  if (!slug) {
    bad('which log? `pw remote-verify <log>`');
    return 2;
  }

  const get = async (p) => {
    const res = await fetch(`${remote.url}${p}`, {
      headers: { authorization: `Bearer ${remote.token}` },
      signal: AbortSignal.timeout(60_000),
    });
    if (!res.ok) throw new Error(`GET ${p} → HTTP ${res.status}`);
    return res.json();
  };

  heading(`Verifying ${slug} on ${remote.url}`);

  const bundle = await get(`/v1/logs/${encodeURIComponent(slug)}/bundle`);
  const result = verifyBundle(bundle, { minWitnesses: Number(args.witnesses ?? 0) });

  kv([
    ['entries', String(bundle.entries.length)],
    ['root', bundle.root],
    ['checkpoints', String((bundle.checkpoints ?? []).length)],
    ['keys', Object.keys(bundle.keyring).join(', ')],
  ]);
  out('');

  if (!result.ok) {
    bad(`${result.issues.length} problem(s):`);
    for (const i of result.issues) out(`  ${c.red('✗')} ${i}`);
    out('');
    return 1;
  }

  ok('Verified independently of the hub: every receipt is signed and provably in the tree.');

  // A hub could still show two histories. Comparing against a local copy is
  // the cheapest way to catch that, and costs nothing when one exists.
  const dir = path.resolve(args.compare ?? '.proofwire');
  if (fs.existsSync(path.join(dir, 'config.json'))) {
    const localLog = ProofLog.open(dir, { readOnly: true });
    if (localLog.size === bundle.treeSize && localLog.root !== bundle.root) {
      out('');
      bad('The hub is showing a different history than your local log holds at the same size.');
      bad('This is what a split view looks like. Do not dismiss it.');
      out('');
      return 1;
    }
    if (localLog.size === bundle.treeSize) {
      ok('the hub root matches your local log exactly');
    } else {
      info(`local holds ${localLog.size}, hub holds ${bundle.treeSize}`);
    }
  }
  out('');
  return 0;
}

/**
 * Publish or fetch a policy.
 *
 * @param {any} args
 */
export async function cmdPolicy(args) {
  const action = args._[1] ?? 'list';
  const remote = resolveRemote(args);
  const headers = { authorization: `Bearer ${remote.token}`, 'content-type': 'application/json' };

  if (action === 'push') {
    const file = args._[2] ?? 'proofwire.policy.json';
    const slug = args.name ?? path.basename(file).replace(/\.policy\.json$|\.json$/, '');
    const text = fs.readFileSync(file, 'utf8');

    // Compile locally first: a policy rejected here never reaches the hub,
    // and the error arrives while the author is still looking at the file.
    let policy;
    try {
      policy = Policy.parse(text);
    } catch (err) {
      bad(`${file} will not load: ${err.message}`);
      return 1;
    }

    const res = await fetch(`${remote.url}/v1/policies/${encodeURIComponent(slug)}`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        policy: policy.doc,
        note: args.note ?? '',
        activate: args.draft !== true,
      }),
    });
    const body = await res.json();
    if (!res.ok) {
      bad(body.error?.message ?? `HTTP ${res.status}`);
      return 1;
    }

    heading(`Published ${slug} v${body.version}`);
    kv([
      ['hash', body.hash],
      ['rules', String(policy.rules.length)],
      ['budgets', String(policy.budgets.length)],
      ['state', body.active ? c.green('active') : c.grey('draft')],
    ]);
    out('');
    if (body.active) info('Agents pick this up the next time they start.');
    out('');
    return 0;
  }

  if (action === 'pull') {
    const slug = args._[2] ?? args.name;
    if (!slug) {
      bad('usage: pw policy pull <slug> [--out file]');
      return 2;
    }
    const active = await fetchPolicy({ url: remote.url, token: remote.token, slug });
    if (!active) {
      bad(`no active policy "${slug}" on ${remote.name}`);
      return 1;
    }
    const file = args.out ?? `${slug}.policy.json`;
    fs.writeFileSync(file, JSON.stringify(active.policy, null, 2) + '\n');
    ok(`wrote ${file} (v${active.version}, ${active.hash.slice(0, 12)}…)`);
    return 0;
  }

  if (action === 'list') {
    const res = await fetch(`${remote.url}/v1/policies`, { headers });
    const body = await res.json();
    if (!res.ok) {
      bad(body.error?.message ?? `HTTP ${res.status}`);
      return 1;
    }
    heading(`Policies on ${remote.name}`);
    if (body.policies.length === 0) {
      out('  ' + c.grey('none published'));
      out('');
      return 0;
    }
    table(
      ['policy', 'version', 'hash', 'state', 'published'],
      body.policies.map((p) => [
        p.slug,
        `v${p.version}`,
        c.grey(p.hash.slice(0, 12) + '…'),
        p.active ? c.green('active') : c.grey('superseded'),
        c.grey(p.created_at.slice(0, 10)),
      ]),
    );
    out('');
    return 0;
  }

  bad('usage: pw policy <list|push|pull>');
  return 2;
}

/**
 * Ask the hub's witness to counter-sign the latest checkpoint of a local log.
 *
 * @param {any} args
 */
export async function cmdCosign(args) {
  const remote = resolveRemote(args);
  const dir = path.resolve(args.log ?? '.proofwire');
  const localLog = ProofLog.open(dir);

  const cp = localLog.checkpoints().at(-1) ?? localLog.checkpoint();
  const headers = { authorization: `Bearer ${remote.token}`, 'content-type': 'application/json' };

  // The witness will demand proof that this root extends the last one it saw.
  const prior = localLog.checkpoints().filter((c2) => c2.body.size < cp.body.size).at(-1);
  const proof = prior
    ? localLog.tree.consistencyProof(prior.body.size, cp.body.size).map((b) => b.toString('hex'))
    : undefined;

  const res = await fetch(`${remote.url}/v1/witness/cosign`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ checkpoint: cp, consistencyProof: proof }),
  });
  const body = await res.json();

  if (!res.ok) {
    heading('Witness refused');
    bad(body.error?.message ?? `HTTP ${res.status}`);
    if (body.error?.code === 'split_view' || body.error?.code === 'not_an_extension') {
      out('');
      warn('A witness refusing on these grounds means the history it was shown does not');
      warn('match the history it saw before. Investigate before doing anything else.');
    }
    out('');
    return 1;
  }

  // Trust the witness's key *and* keep its signature. Without the second step
  // the signature exists only in this process's memory, and the bundle an
  // auditor is later handed would carry no witness attestation at all.
  localLog.trustKey(body.witness.kid, body.witness.publicKey);
  const updated = localLog.addSignature(cp.body.size, body.signature);
  const witnesses = updated.sigs.filter((s) => s.role === 'witness').length;

  heading('Checkpoint witnessed');
  kv([
    ['log', localLog.logId],
    ['size', String(cp.body.size)],
    ['root', cp.body.root],
    ['witness', body.witness.kid],
    ['signatures', `${witnesses} witness${witnesses === 1 ? '' : 'es'} on this root`],
  ]);
  out('');
  info('An auditor can now require this signature:');
  out(`  ${c.cyan('pw check evidence.json --witnesses 1')}`);
  out('');
  return 0;
}
