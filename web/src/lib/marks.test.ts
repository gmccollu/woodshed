import { test } from 'node:test';
import assert from 'node:assert/strict';
import { marks } from './marks.ts';
import { num } from './format.ts';

test('a whole message has no marks', () => {
  assert.deepEqual(marks({}), []);
  assert.deepEqual(marks({ truncated: false, incomplete: false }), []);
});

test('an incomplete octet-counted frame says how much arrived', () => {
  const m = marks({ incomplete: true, frame_arrived: 9, frame_length: 50 });
  assert.equal(m.length, 1);
  assert.equal(m[0].label, 'incomplete: 9 of 50 bytes');
  assert.match(m[0].title, /said 50 bytes and 9 came/);
});

test('a line Woodshed cut has no lengths', () => {
  assert.deepEqual(marks({ incomplete: true }).map((m) => m.label), ['incomplete']);
});

test('both marks, truncated first as on the stored line', () => {
  const m = marks({ truncated: true, incomplete: true, frame_arrived: 70000, frame_length: 100000 });
  assert.deepEqual(m.map((x) => x.label), ['truncated', `incomplete: ${num(70000)} of ${num(100000)} bytes`]);
});
