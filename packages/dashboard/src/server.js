import http from 'node:http';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ProofLog } from '@proof_wire/core';

/**
 * A local, read-only dashboard over a Proofwire log.
 *
 * Read-only and loopback-only, both deliberately. This process can see the
 * log directory, which on a live machine sits next to the signing key; binding
 * it to a public interface would turn a debugging convenience into the
 * shortest path to forging receipts. The log is opened read-only so the
 * dashboard cannot append even by accident.
 */

const PUBLIC = fileURLToPath(new URL('../public/', import.meta.url));

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
};

/**
 * The page's one inline script, allowed by hash rather than by
 * `'unsafe-inline'`: a string from the log that somehow became markup still
 * could not run, because its hash would not be on the list.
 */
function inlineScriptHashes() {
  const html = fs.readFileSync(path.join(PUBLIC, 'index.html'), 'utf8');
  return [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)].map(
    (m) => `'sha256-${createHash('sha256').update(m[1], 'utf8').digest('base64')}'`,
  );
}

const PAGE_CSP = [
  "default-src 'none'",
  `script-src ${inlineScriptHashes().join(' ')}`,
  "style-src 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

const COMMON_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
};

/**
 * @param {http.ServerResponse} res
 * @param {number} status
 * @param {unknown} body
 */
function json(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    ...COMMON_HEADERS,
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    // This page renders log contents, which are attacker-influenced strings.
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
  });
  res.end(text);
}

/**
 * The Host values this dashboard answers to.
 *
 * Binding to loopback keeps other machines out, but not other *websites*: a
 * page on evil.example can point its own DNS name at 127.0.0.1 (DNS
 * rebinding), and the browser will then let that page read this server's
 * responses as same-origin. The browser still sends `Host: evil.example`, so
 * refusing any Host that is not ours closes it.
 *
 * @param {string} host
 * @param {number} port
 */
export function allowedHosts(host, port) {
  const names = new Set(['127.0.0.1', 'localhost', '[::1]']);
  names.add(host.includes(':') && !host.startsWith('[') ? `[${host}]` : host);
  return new Set([...names].map((n) => `${n}:${port}`.toLowerCase()));
}

/**
 * Resolve a request path inside `root`, or null if it would land outside.
 *
 * The URL parser already collapses `..` before a path gets here, so this is
 * the second lock, not the first. It compares against `root` plus a
 * separator, so a sibling directory whose name merely starts the same way
 * (`public-old` next to `public`) does not count as inside.
 *
 * @param {string} root  Absolute directory.
 * @param {string} rel
 * @returns {string | null}
 */
export function insideRoot(root, rel) {
  const file = path.resolve(root, rel);
  return file.startsWith(root + path.sep) ? file : null;
}

/**
 * Summarise a receipt for the timeline — enough to scan, not the whole thing.
 *
 * @param {any} r
 */
function summarise(r) {
  return {
    seq: r.seq,
    ts: r.ts,
    phase: r.phase,
    ref: r.ref,
    target: r.action.target,
    kind: r.action.kind,
    metrics: r.action.metrics ?? {},
    outcome: r.decision.outcome,
    // Monitor mode: the call ran, but the policy would have stopped it.
    wouldBe: r.decision.wouldBe ?? null,
    reason: r.decision.reason,
    rules: r.decision.rules ?? [],
    approval: r.decision.approval ?? null,
    principal: r.actor.principal,
    agent: r.actor.agent,
    session: r.actor.session,
    status: r.result?.status ?? null,
    latencyMs: r.result?.latencyMs ?? null,
    redacted: r.action.params?.redacted ?? [],
  };
}

/**
 * @param {object} opts
 * @param {string} opts.dir
 * @param {number} [opts.port]
 * @param {string} [opts.host]
 * @returns {Promise<string>} The URL the dashboard is listening on.
 */
export function serve(opts) {
  const host = opts.host ?? '127.0.0.1';
  const server = createServer({ dir: opts.dir, host });
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(opts.port ?? 7788, host, () => {
      const addr = /** @type {import('node:net').AddressInfo} */ (server.address());
      resolve(`http://${host}:${addr.port}`);
    });
  });
}

/**
 * The dashboard's HTTP server, not yet listening. It learns its own port when
 * it starts listening, and answers only to Host values naming that port.
 *
 * @param {{ dir: string, host?: string }} opts
 * @returns {http.Server}
 */
export function createServer(opts) {
  const host = opts.host ?? '127.0.0.1';
  const root = path.resolve(PUBLIC);
  /** @type {Set<string>} */
  let hosts = new Set();

  const server = http.createServer((req, res) => {
    if (!hosts.has(String(req.headers.host ?? '').toLowerCase())) {
      return json(res, 403, { error: 'unexpected Host header' });
    }
    const url = new URL(req.url ?? '/', `http://${host}`);

    if (req.method !== 'GET') return json(res, 405, { error: 'read-only' });

    try {
      if (url.pathname === '/api/log') {
        // Reopened per request: the proxy is appending to this file while we
        // watch, and a cached handle would show a stale tree.
        const log = ProofLog.open(opts.dir, { readOnly: true });
        const audit = log.audit();
        return json(res, 200, {
          log: log.logId,
          created: log.config.created,
          size: log.size,
          root: log.root,
          head: log.head,
          keys: Object.keys(log.keyring),
          checkpoints: log.checkpoints().map((c) => ({
            size: c.body.size,
            root: c.body.root,
            ts: c.body.ts,
            witnesses: c.sigs.filter((s) => s.role === 'witness').length,
          })),
          audit: { ok: audit.ok, issues: audit.issues },
          entries: log.entries.map(summarise),
        });
      }

      const entryMatch = /^\/api\/entry\/(\d+)$/.exec(url.pathname);
      if (entryMatch) {
        const log = ProofLog.open(opts.dir, { readOnly: true });
        const seq = Number(entryMatch[1]);
        if (seq >= log.size) return json(res, 404, { error: 'no such entry' });
        return json(res, 200, {
          receipt: log.entries[seq],
          proof: log.proofFor(seq),
        });
      }

      // Static assets. Paths are resolved and then confirmed to be inside the
      // public directory, so `..` cannot walk out of it.
      const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
      const file = insideRoot(root, rel);
      if (!file) {
        return json(res, 403, { error: 'forbidden' });
      }
      if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
        return json(res, 404, { error: 'not found' });
      }
      const body = fs.readFileSync(file);
      res.writeHead(200, {
        ...COMMON_HEADERS,
        'content-type': TYPES[path.extname(file)] ?? 'application/octet-stream',
        'content-length': body.length,
        'content-security-policy': PAGE_CSP,
      });
      return res.end(body);
    } catch (err) {
      // The detail goes to the terminal that started the dashboard, not to
      // whatever made the request: error text can carry file paths.
      process.stderr.write(`proofwire dashboard: ${/** @type {Error} */ (err).stack}\n`);
      return json(res, 500, { error: 'internal error' });
    }
  });

  server.on('listening', () => {
    const addr = /** @type {import('node:net').AddressInfo} */ (server.address());
    hosts = allowedHosts(host, addr.port);
  });
  return server;
}
