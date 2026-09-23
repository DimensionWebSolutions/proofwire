import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { ProofLog } from '@proof_wire/core';
import { createServer, allowedHosts, insideRoot } from '../src/server.js';

/** Start a dashboard over a fresh log on a random loopback port. */
async function start(dir = ProofLogDir()) {
  const server = createServer({ dir });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = /** @type {import('node:net').AddressInfo} */ (server.address()).port;
  return { server, port, dir };
}

function ProofLogDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'proofwire-dash-'));
  ProofLog.create(dir);
  return dir;
}

/**
 * A raw request, so the Host header is exactly what the test says — as it is
 * when a rebinding page makes the browser send its own name.
 *
 * @param {number} port
 * @param {string} pathname
 * @param {string} host
 * @returns {Promise<{ status: number, headers: http.IncomingHttpHeaders, body: string }>}
 */
function get(port, pathname, host) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: pathname, headers: { host } }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('a request naming a foreign Host is refused, so DNS rebinding reads nothing', async () => {
  const { server, port } = await start();
  try {
    const evil = await get(port, '/api/log', `evil.example:${port}`);
    assert.equal(evil.status, 403);
    assert.doesNotMatch(evil.body, /lg_/, 'no log data in the refusal');

    // Right name, wrong port: a rebinding page on another port is still foreign.
    assert.equal((await get(port, '/api/log', `127.0.0.1:${port + 1}`)).status, 403);

    for (const name of ['127.0.0.1', 'localhost', 'LOCALHOST']) {
      const ok = await get(port, '/api/log', `${name}:${port}`);
      assert.equal(ok.status, 200, name);
      assert.match(JSON.parse(ok.body).log, /^lg_/);
    }
  } finally {
    server.close();
  }
});

test('the page is served under a CSP that allows its own script by hash and nothing inline besides', async () => {
  const { server, port } = await start();
  try {
    const page = await get(port, '/', `127.0.0.1:${port}`);
    assert.equal(page.status, 200);
    const csp = String(page.headers['content-security-policy']);
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.doesNotMatch(csp, /script-src[^;]*unsafe-inline/);
    assert.equal(page.headers['x-frame-options'], 'DENY');
    assert.equal(page.headers['referrer-policy'], 'no-referrer');

    // Every script on the page must be covered, or the dashboard renders blank.
    const scripts = [...page.body.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi)];
    assert.ok(scripts.length > 0);
    for (const [, code] of scripts) {
      const hash = createHash('sha256').update(code, 'utf8').digest('base64');
      assert.ok(csp.includes(`'sha256-${hash}'`), 'an inline script is missing from script-src');
    }
  } finally {
    server.close();
  }
});

test('paths cannot walk out of the public directory', async () => {
  const { server, port } = await start();
  try {
    for (const p of ['/../package.json', '/..%2fpackage.json', '/%2e%2e/package.json', '/..\package.json']) {
      const res = await get(port, p, `127.0.0.1:${port}`);
      assert.notEqual(res.status, 200, p);
      assert.doesNotMatch(res.body, /"name": "@proof_wire\/dashboard"/, p);
    }
  } finally {
    server.close();
  }
});

test('the path check keeps to the directory, not to directories that share its prefix', () => {
  const root = path.resolve(os.tmpdir(), 'public');
  assert.equal(insideRoot(root, 'index.html'), path.join(root, 'index.html'));
  assert.equal(insideRoot(root, '../package.json'), null);
  assert.equal(insideRoot(root, '../public-old/secret.txt'), null);
  assert.equal(insideRoot(root, ''), null, 'the directory itself is not a file to serve');
});

test('an internal error does not tell the caller where files live', async () => {
  const dir = ProofLogDir();
  const { server, port } = await start(dir);
  const write = process.stderr.write;
  process.stderr.write = () => true;
  try {
    fs.rmSync(dir, { recursive: true, force: true });
    const res = await get(port, '/api/log', `127.0.0.1:${port}`);
    assert.equal(res.status, 500);
    assert.deepEqual(JSON.parse(res.body), { error: 'internal error' });
  } finally {
    process.stderr.write = write;
    server.close();
  }
});

test('the allowed Host set names the port and brackets IPv6', () => {
  assert.deepEqual([...allowedHosts('127.0.0.1', 7788)].sort(), ['127.0.0.1:7788', '[::1]:7788', 'localhost:7788']);
  assert.ok(allowedHosts('::1', 9).has('[::1]:9'));
  assert.ok(allowedHosts('dash.internal', 80).has('dash.internal:80'));
});
