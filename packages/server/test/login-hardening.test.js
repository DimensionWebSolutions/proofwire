import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Hub } from '../src/app.js';
import { Auth } from '../src/auth.js';

/**
 * Sign-in hardening: an attacker should learn nothing about which accounts
 * exist, and should not get unlimited guesses at one account by spreading
 * them across many addresses.
 */

/** @type {Hub} */
let hub;
/** @type {string} */
let base;
let nextIp = 1;

const PASSWORD = 'the-real-password-123';

before(async () => {
  hub = new Hub({
    database: ':memory:',
    checkpointEvery: 0,
    // Behind a proxy, so each request can claim its own address: this is the
    // botnet case the per-address limiter cannot see.
    trustProxy: true,
    apiRate: { capacity: 100000, refillPerSec: 100000 },
    ingestRate: { capacity: 100000, refillPerSec: 100000 },
    authRate: { capacity: 100000, refillPerSec: 100000 },
  });
  const { url } = await hub.listen(0);
  base = url.replace('0.0.0.0', '127.0.0.1');
  const auth = new Auth(hub.store);
  for (const email of ['victim@acme.test', 'bystander@acme.test', 'timing@acme.test']) {
    auth.createUser({ email, password: PASSWORD });
  }
});

after(async () => {
  await hub.close();
});

/**
 * @param {string} email
 * @param {string} password
 */
async function login(email, password) {
  const res = await fetch(base + '/v1/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': `203.0.113.${nextIp++ % 250}` },
    body: JSON.stringify({ email, password }),
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, code: json?.error?.code, retryAfter: res.headers.get('retry-after') };
}

/** @param {() => Promise<unknown>} fn */
async function medianMs(fn, runs = 5) {
  const times = [];
  for (let i = 0; i < runs; i++) {
    const t = performance.now();
    await fn();
    times.push(performance.now() - t);
  }
  return times.sort((a, b) => a - b)[Math.floor(runs / 2)];
}

test('an unknown email costs the same scrypt as a wrong password, so timing does not reveal accounts', async () => {
  // Unknown addresses spread over many names, so the per-account limiter
  // never engages and both sides are measured doing the same work.
  let n = 0;
  const unknown = await medianMs(() => login(`nobody${n++}@acme.test`, 'wrong-password-000'));
  const known = await medianMs(() => login('timing@acme.test', 'wrong-password-000'));
  // Without the dummy hash, the unknown path is ~1ms against scrypt's tens of
  // milliseconds. The bound is loose on purpose: CI machines are noisy, and
  // the difference being closed is an order of magnitude.
  assert.ok(unknown > known * 0.4, `unknown ${unknown.toFixed(1)}ms vs known ${known.toFixed(1)}ms`);
});

test('failed sign-ins are counted per account, whatever address they come from', async () => {
  for (let i = 0; i < 10; i++) {
    const res = await login('victim@acme.test', `guess-${i}-wrong`);
    assert.equal(res.status, 401, `attempt ${i + 1}`);
  }

  // The eleventh, from yet another address, is refused before the password
  // is even checked, so the right one does not get in either.
  const blocked = await login('victim@acme.test', PASSWORD);
  assert.equal(blocked.status, 429);
  assert.equal(blocked.code, 'too_many_attempts');
  assert.ok(Number(blocked.retryAfter) > 0);

  // Someone else's account is unaffected.
  assert.equal((await login('bystander@acme.test', PASSWORD)).status, 200);
});

test('a non-existent account throttles exactly like a real one', async () => {
  for (let i = 0; i < 10; i++) await login('ghost@acme.test', `guess-${i}`);
  const res = await login('ghost@acme.test', 'anything');
  assert.equal(res.status, 429);
  assert.equal(res.code, 'too_many_attempts');
});

test('the account key ignores case and surrounding spaces', async () => {
  const auth = new Auth(hub.store);
  auth.createUser({ email: 'cased@acme.test', password: PASSWORD });
  for (let i = 0; i < 10; i++) await login(i % 2 ? 'CASED@acme.test' : ' cased@acme.test ', `guess-${i}`);
  assert.equal((await login('cased@acme.test', PASSWORD)).status, 429);
});

test('the console sign-in form is throttled by the same counter, and says so', async () => {
  const auth = new Auth(hub.store);
  auth.createUser({ email: 'console@acme.test', password: PASSWORD });
  const form = async (/** @type {string} */ password) =>
    fetch(base + '/login', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-forwarded-for': `198.51.100.${nextIp++ % 250}` },
      body: new URLSearchParams({ email: 'console@acme.test', password }),
      redirect: 'manual',
    });

  for (let i = 0; i < 10; i++) {
    assert.match((await form(`wrong-${i}`)).headers.get('location') ?? '', /\/login\?e=1$/);
  }
  const blocked = await form(PASSWORD);
  assert.match(blocked.headers.get('location') ?? '', /\/login\?e=2$/);
  assert.equal(blocked.headers.getSetCookie?.().length ?? 0, 0, 'no session for a throttled account');

  const page = await (await fetch(base + '/login?e=2')).text();
  assert.match(page, /Too many failed sign-ins/);
});

test('password-reset requests fall under the strict auth limiter', async () => {
  const strict = new Hub({
    database: ':memory:',
    checkpointEvery: 0,
    apiRate: { capacity: 100000, refillPerSec: 100000 },
    authRate: { capacity: 3, refillPerSec: 0.01 },
  });
  const { url } = await strict.listen(0);
  const at = url.replace('0.0.0.0', '127.0.0.1');
  try {
    /** @type {number[]} */
    const codes = [];
    for (let i = 0; i < 5; i++) {
      const res = await fetch(at + '/forgot', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ email: `someone${i}@acme.test` }),
        redirect: 'manual',
      });
      codes.push(res.status);
    }
    assert.deepEqual(codes.slice(0, 3), [303, 303, 303]);
    assert.ok(codes.slice(3).every((c) => c === 429), `got ${codes.join(',')}`);
  } finally {
    await strict.close();
  }
});
