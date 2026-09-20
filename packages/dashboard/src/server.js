import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ProofLog } from '@proofwire/core';

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
 * @param {http.ServerResponse} res
 * @param {number} status
 * @param {unknown} body
 */
function json(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    // This page renders log contents, which are attacker-influenced strings.
    'content-security-policy': "default-src 'none'",
    'x-content-type-options': 'nosniff',
  });
  res.end(text);
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

  const server = http.createServer((req, res) => {
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
      const file = path.resolve(PUBLIC, rel);
      if (!file.startsWith(path.resolve(PUBLIC))) {
        return json(res, 403, { error: 'forbidden' });
      }
      if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
        return json(res, 404, { error: 'not found' });
      }
      const body = fs.readFileSync(file);
      res.writeHead(200, {
        'content-type': TYPES[path.extname(file)] ?? 'application/octet-stream',
        'content-length': body.length,
        'x-content-type-options': 'nosniff',
      });
      return res.end(body);
    } catch (err) {
      return json(res, 500, { error: /** @type {Error} */ (err).message });
    }
  });

  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(opts.port ?? 7788, host, () => {
      const addr = /** @type {import('node:net').AddressInfo} */ (server.address());
      resolve(`http://${host}:${addr.port}`);
    });
  });
}
