import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCookies } from '../src/http.js';

test('a cookie named after an Object.prototype member is only a cookie', () => {
  const jar = parseCookies('__proto__=x; constructor=y; pw_session=abc');
  assert.equal(Object.getPrototypeOf(jar), null);
  assert.equal(jar.pw_session, 'abc');
  assert.equal(jar.__proto__, 'x');
  assert.equal(({}).polluted, undefined);
});

test('a malformed %-escape drops that cookie instead of failing the request', () => {
  assert.deepEqual({ ...parseCookies('bad=%E0%A4%A; pw_session=abc') }, { pw_session: 'abc' });
});
