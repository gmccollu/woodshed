import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPort, keepEdits, lanUrls, refusedWithoutPassword } from './uiaccess.ts';

test('lanUrls: https, the UI port, IPv6 in brackets', () => {
  assert.deepEqual(lanUrls(['10.1.0.50', 'fd00::50'], 8514), ['https://10.1.0.50:8514/', 'https://[fd00::50]:8514/']);
  assert.deepEqual(lanUrls([], 8514), []);
});

test('lanUrls: no URL for a port field that is not a port', () => {
  for (const p of [0, -1, 65536, 8514.5, NaN, null, undefined]) assert.deepEqual(lanUrls(['10.1.0.50'], p), [], String(p));
  assert.deepEqual(lanUrls(['10.1.0.50'], 65535), ['https://10.1.0.50:65535/']);
  assert.equal(isPort(8514), true);
  assert.equal(isPort('8514'), false);
});

test('refusedWithoutPassword: only turning on without a password is refused', () => {
  assert.equal(refusedWithoutPassword(false, false), true);
  assert.equal(refusedWithoutPassword(false, true), false, 'turning it off is always allowed');
  assert.equal(refusedWithoutPassword(true, false), false);
  assert.equal(refusedWithoutPassword(true, true), false);
});

test('keepEdits: unsaved edits survive a reload, except the named fields', () => {
  const base = { port: 8514, lan: false, local: false, hosts: ['a'] };
  const mine = { port: 8090, lan: false, local: false, hosts: ['a', 'b'] };
  const fresh = { port: 8514, lan: false, local: true, hosts: ['a'] };
  assert.deepEqual(keepEdits(base, mine, fresh, ['local']), { port: 8090, lan: false, local: true, hosts: ['a', 'b'] });
  // Nothing edited: the fresh settings as they are.
  assert.deepEqual(keepEdits(base, base, fresh), fresh);
  // A named field takes the fresh value even when the user changed it.
  assert.equal(keepEdits(base, { ...mine, local: true }, { ...fresh, local: false }, ['local']).local, false);
});
