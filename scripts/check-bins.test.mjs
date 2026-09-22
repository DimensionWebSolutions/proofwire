import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { binProblems } from './check-bins.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** A throwaway package whose one bin has exactly these bytes. */
function fixture(bytes, bin = { tool: 'bin.js' }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-bins-'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'fixture', bin }));
  if (bytes !== null) fs.writeFileSync(path.join(dir, 'bin.js'), bytes);
  return dir;
}

test('the packages about to be released have runnable executables', () => {
  // Checks the working copy, which is what npm packs. On a Windows checkout
  // this only passes because .gitattributes forces LF.
  const dirs = ['packages/core', 'packages/proxy', 'packages/dashboard', 'packages/server', 'packages/cli'];
  assert.deepEqual(binProblems(ROOT, dirs), []);
});

test('an LF #! line passes', () => {
  // Only line 1 matters; CRLF after it is harmless to the kernel.
  assert.deepEqual(binProblems(fixture('#!/usr/bin/env node\nconsole.log(1)\r\n'), ['.']), []);
});

test('a CRLF #! line is refused', () => {
  const [p] = binProblems(fixture('#!/usr/bin/env node\r\nconsole.log(1)\r\n'), ['.']);
  assert.match(p, /CRLF #! line/);
});

test('a byte-order mark before #! is refused', () => {
  const [p] = binProblems(fixture('﻿#!/usr/bin/env node\nconsole.log(1)\n'), ['.']);
  assert.match(p, /does not start with a #! line/);
});

test('a missing bin file is refused', () => {
  const [p] = binProblems(fixture(null), ['.']);
  assert.match(p, /does not exist/);
});

test('a string bin is checked like an object one', () => {
  const [p] = binProblems(fixture('#!/usr/bin/env node\r\n', 'bin.js'), ['.']);
  assert.match(p, /fixture: bin "fixture"/);
});
