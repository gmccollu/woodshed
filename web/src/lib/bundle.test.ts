// Unit tests for bundle.ts: `npm test`. Local times are New York's, set before any Date is made
// (node --test runs each file in its own process), so the midnight and DST cases are fixed.
process.env.TZ = 'America/New_York';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BUNDLE_KEYS,
  BUNDLE_PRESETS,
  bundleBody,
  bundleFromQuery,
  bundleTitle,
  bundleToQuery,
  bundleWindow,
  checkDevice,
  formatDuration,
  humanDuration,
  momentFromParts,
  momentParts,
  momentText,
  narrowTo,
  newBundle,
  parseDuration,
  pointTime,
  presetIndex,
  sideError,
  sidesText,
  typesText,
  uncheckDevice,
  type BundleWindow,
} from './bundle.ts';

const M = 60_000;
const H = 60 * M;
const D = 24 * H;
const win = (w: BundleWindow | string) => {
  assert.equal(typeof w, 'object', `expected a window, got ${String(w)}`);
  return w as BundleWindow;
};

test('durations: the API forms, forgiving input, and NaN for the rest', () => {
  assert.equal(parseDuration('15m'), 15 * M);
  assert.equal(parseDuration('1h30m'), 90 * M);
  assert.equal(parseDuration('0s'), 0);
  assert.equal(parseDuration('7d'), 7 * D);
  assert.equal(parseDuration('1500ms'), 1500);
  assert.equal(parseDuration(' 1 H 30 min '), 90 * M);
  assert.equal(parseDuration('2 hours'), 2 * H);
  assert.equal(parseDuration('3 days'), 3 * D);
  assert.equal(parseDuration('45 secs'), 45_000);
  assert.equal(parseDuration('45'), 45 * M, 'a bare number is minutes');
  assert.equal(parseDuration('1.5h'), 90 * M);
  for (const bad of ['', 'abc', '10x', 'h', '-5m', '1h 30', '5 weeks']) assert.ok(Number.isNaN(parseDuration(bad)), bad);
});

test('durations: canonical form and words', () => {
  assert.equal(formatDuration(30 * M), '30m');
  assert.equal(formatDuration(75 * M), '1h15m');
  assert.equal(formatDuration(7 * D), '7d');
  assert.equal(formatDuration(D + 2 * H), '1d2h');
  assert.equal(formatDuration(0), '0s');
  assert.equal(formatDuration(90_500), '1m30s500ms');
  assert.equal(humanDuration(75 * M), '1 h 15 min');
  assert.equal(humanDuration(45_000), '45 s');
  assert.equal(humanDuration(0), '0 s');
  for (const s of ['15m', '1h15m', '7d', '0s', '1d2h3m4s']) assert.equal(formatDuration(parseDuration(s)), s, s);
});

test('sides: 0s to 7d each', () => {
  assert.equal(sideError('Before', '7d'), '');
  assert.equal(sideError('Before', '0s'), '');
  assert.match(sideError('Before', '7d1s'), /at most 7 days/);
  assert.match(sideError('After', 'soon'), /^After: write a duration/);
});

test('window: [at − before, at + after), cut at now', () => {
  const now = Date.parse('2026-11-14T12:00:00Z');
  const w = win(bundleWindow('2026-11-14T09:42:00Z', '30m', '10m', now));
  assert.equal(w.from, '2026-11-14T09:12:00.000Z');
  assert.equal(w.to, '2026-11-14T09:52:00.000Z');
  assert.equal(w.cut, false);
  const c = win(bundleWindow('2026-11-14T11:55:00Z', '15m', '10m', now));
  assert.equal(c.to, '2026-11-14T12:00:00.000Z');
  assert.equal(c.cut, true);
  // at = now with something before: the window is everything before it.
  assert.equal(win(bundleWindow('2026-11-14T12:00:00Z', '1h', '15m', now)).to, '2026-11-14T12:00:00.000Z');
});

test('window: what the API refuses, said in words', () => {
  const now = Date.parse('2026-11-14T12:00:00Z');
  assert.match(bundleWindow('2026-11-14T12:00:01Z', '30m', '10m', now) as string, /future/);
  assert.match(bundleWindow('', '30m', '10m', now) as string, /Pick the moment/);
  assert.match(bundleWindow('2026-11-14T09:00:00Z', '0s', '0s', now) as string, /more than 0/);
  assert.match(bundleWindow('2026-11-14T09:00:00Z', '8d', '0s', now) as string, /^Before: at most 7 days/);
  assert.match(bundleWindow('2026-11-14T09:00:00Z', '1h', 'x', now) as string, /^After:/);
  assert.match(bundleWindow('2026-11-14T12:00:00Z', '0s', '10m', now) as string, /empty/);
});

test('moment: local and UTC fields, crossing midnight', () => {
  // 23:50 on the 13th in New York (EST, UTC−5) is 04:50 on the 14th in UTC.
  assert.equal(momentFromParts('2026-11-13', '23:50:00', false), '2026-11-14T04:50:00Z');
  assert.equal(momentFromParts('2026-11-13', '23:50', true), '2026-11-13T23:50:00Z');
  assert.deepEqual(momentParts('2026-11-14T04:50:00Z', false), { date: '2026-11-13', time: '23:50:00' });
  assert.deepEqual(momentParts('2026-11-14T04:50:00Z', true), { date: '2026-11-14', time: '04:50:00' });
  // A window around 00:10 local reaches back into the day before.
  const w = win(bundleWindow(momentFromParts('2026-11-14', '00:10:00', false), '30m', '10m', Date.parse('2026-11-15T00:00:00Z')));
  assert.deepEqual(momentParts(w.from, false), { date: '2026-11-13', time: '23:40:00' });
  assert.equal(momentFromParts('2026-11-14', 'noon', false), '');
  assert.equal(momentFromParts('', '10:00', false), '');
});

test('moment: DST changes keep the window exact', () => {
  // 2026-03-08 02:30 doesn't exist in New York (clocks go 02:00 → 03:00): it reads as 03:30 EDT.
  assert.equal(momentFromParts('2026-03-08', '02:30:00', false), '2026-03-08T07:30:00Z');
  // 2026-11-01 01:30 happens twice; the first one (EDT, UTC−4) is taken.
  assert.equal(momentFromParts('2026-11-01', '01:30:00', false), '2026-11-01T05:30:00Z');
  // 4 h before 02:00 EST on Nov 1 is 4 real hours: 23:00 EDT the day before, 3 h earlier on the wall clock.
  const at = momentFromParts('2026-11-01', '02:00:00', false);
  assert.equal(at, '2026-11-01T07:00:00Z');
  const w = win(bundleWindow(at, '4h', '1h', Date.parse('2026-11-02T00:00:00Z')));
  assert.equal(Date.parse(w.to) - Date.parse(w.from), 5 * H);
  assert.deepEqual(momentParts(w.from, false), { date: '2026-10-31', time: '23:00:00' });
  assert.deepEqual(momentParts(w.to, false), { date: '2026-11-01', time: '03:00:00' });
});

test('body: one device choice, canonical sides, types as given', () => {
  const f = { ...newBundle('2026-11-14T09:42:00.000Z'), before: '1 h 30 min', after: '0' };
  assert.deepEqual(bundleBody(f), { kind: 'bundle', at: '2026-11-14T09:42:00Z', before: '1h30m', after: '0s', active_devices: true, types: [] });
  assert.deepEqual(bundleBody({ ...f, scope: { mode: 'devices', group: '', devices: ['10.1.0.1'] }, types: ['trap'] }), {
    kind: 'bundle', at: '2026-11-14T09:42:00Z', before: '1h30m', after: '0s', devices: ['10.1.0.1'], types: ['trap'],
  });
  assert.equal(bundleBody({ ...f, scope: { mode: 'group', group: 'HQ', devices: [] } }).group, 'HQ');
  const ug = bundleBody({ ...f, scope: { mode: 'ungrouped', group: '', devices: [] } });
  assert.equal(ug.ungrouped, true);
  assert.equal('active_devices' in ug, false);
  // A received time keeps its milliseconds.
  assert.equal(bundleBody(newBundle('2026-11-14T09:42:13.482Z')).at, '2026-11-14T09:42:13.482Z');
});

test('presets: the SPEC four and the API default; anything else is custom', () => {
  assert.deepEqual(BUNDLE_PRESETS.map((p) => `${p.before}/${p.after}`), ['15m/5m', '30m/10m', '1h/15m', '4h/1h', '24h/1h']);
  assert.equal(presetIndex('30m', '10m'), 1);
  assert.equal(presetIndex('60m', '15 min'), 2, 'compared as durations');
  assert.equal(presetIndex('2h', '10m'), -1);
});

test('URL: round trip, and the keys the page reserves', () => {
  const cases = [
    newBundle('2026-11-14T09:42:00Z'),
    { ...newBundle('2026-11-14T09:42:00Z'), before: '4h', after: '1h', scope: { mode: 'devices' as const, group: '', devices: ['10.1.0.1', 'fd00:1::5'] }, types: ['syslog', 'trap'] },
    { ...newBundle('2026-11-14T09:42:00Z'), scope: { mode: 'group' as const, group: 'HQ', devices: [] } },
    { ...newBundle('2026-11-14T09:42:00Z'), scope: { mode: 'ungrouped' as const, group: '', devices: [] }, types: ['trap'] },
  ];
  for (const f of cases) {
    const q = new URLSearchParams();
    bundleToQuery(f, q);
    for (const k of q.keys()) assert.ok(BUNDLE_KEYS.includes(k), k);
    assert.deepEqual(bundleFromQuery(new URLSearchParams(q.toString())), f);
  }
  assert.equal(bundleFromQuery(new URLSearchParams('q=deny')), null);
  // Unchecking every device leaves an explicit empty list, not "every active device".
  const q = new URLSearchParams();
  bundleToQuery({ ...newBundle('2026-11-14T09:42:00Z'), scope: { mode: 'devices', group: '', devices: [] } }, q);
  assert.deepEqual(bundleFromQuery(q)?.scope, { mode: 'devices', group: '', devices: [] });
});

test('narrowing: a histogram range keeps the moment inside it', () => {
  assert.deepEqual(narrowTo('2026-11-14T09:42:00Z', '2026-11-14T09:30:00Z', '2026-11-14T09:50:00Z'), {
    at: '2026-11-14T09:42:00Z', before: '12m', after: '8m',
  });
  assert.deepEqual(narrowTo('2026-11-14T09:42:00Z', '2026-11-14T09:15:00Z', '2026-11-14T09:30:00Z'), {
    at: '2026-11-14T09:30:00Z', before: '15m', after: '0s',
  });
  assert.deepEqual(narrowTo('2026-11-14T09:42:00Z', '2026-11-14T09:45:00Z', '2026-11-14T09:52:00Z'), {
    at: '2026-11-14T09:45:00Z', before: '0s', after: '7m',
  });
});

test('a point on the histogram: rounded, and inside the range and the past', () => {
  const now = Date.parse('2026-11-14T12:00:00Z');
  // 60 one-minute buckets from 09:00; 42.5 % of the way is 09:25:30 → 09:25.
  assert.equal(pointTime('2026-11-14T09:00:00Z', 60, 60, 0.425, '2026-11-14T09:00:00Z', '2026-11-14T10:00:00Z', now), '2026-11-14T09:25:00Z');
  // 15 s buckets round to the second.
  assert.equal(pointTime('2026-11-14T09:00:00Z', 15, 40, 0.5, '2026-11-14T09:00:00Z', '2026-11-14T09:10:00Z', now), '2026-11-14T09:05:00Z');
  assert.equal(pointTime('2026-11-14T09:00:00Z', 15, 40, 0.5013, '2026-11-14T09:00:00Z', '2026-11-14T09:10:00Z', now), '2026-11-14T09:05:00Z');
  // The first bucket starts before the range: kept at the range's start.
  assert.equal(pointTime('2026-11-14T08:45:00Z', 900, 4, 0, '2026-11-14T08:50:00Z', '2026-11-14T09:50:00Z', now), '2026-11-14T08:50:00Z');
  // Never after now, nor at the range's (exclusive) end.
  assert.equal(pointTime('2026-11-14T11:00:00Z', 60, 60, 1, '2026-11-14T11:00:00Z', '2026-11-14T12:00:00Z', now), '2026-11-14T11:59:00Z');
  assert.equal(pointTime('2026-11-14T11:00:00Z', 60, 120, 1, '2026-11-14T11:00:00Z', '2026-11-14T13:00:00Z', Date.parse('2026-11-14T12:30:20Z')), '2026-11-14T12:30:00Z');
});

test('devices: unchecking turns "every active device" into the list of the rest', () => {
  const all = { mode: 'all' as const, group: '', devices: [] };
  const listed = ['10.1.0.1', '10.1.0.2', '10.1.0.10'];
  const s1 = uncheckDevice(all, listed, '10.1.0.2');
  assert.deepEqual(s1, { mode: 'devices', group: '', devices: ['10.1.0.1', '10.1.0.10'] });
  assert.deepEqual(uncheckDevice(s1, listed, '10.1.0.1').devices, ['10.1.0.10']);
  assert.deepEqual(checkDevice(s1, listed, '10.1.0.2').devices, ['10.1.0.1', '10.1.0.10', '10.1.0.2']);
  assert.deepEqual(checkDevice(s1, listed, '10.1.0.1').devices, ['10.1.0.1', '10.1.0.10']);
  // A group unchecked the same way.
  assert.deepEqual(uncheckDevice({ mode: 'group', group: 'HQ', devices: [] }, listed, '10.1.0.10').devices, ['10.1.0.1', '10.1.0.2']);
});

test('words: the export list title, sides and types', () => {
  const now = Date.parse('2026-11-14T12:00:00Z');
  assert.equal(bundleTitle('2026-11-14T09:42:00Z', '30m', '10m', true, now), 'Bundle around 09:42 UTC, 30 min before, 10 min after');
  assert.equal(bundleTitle('2026-11-13T09:42:13Z', '1h15m', '0s', true, now), 'Bundle around 11-13 09:42:13 UTC, 1 h 15 min before, nothing after');
  // Local time (New York): 04:50 UTC on the 14th is 23:50 on the 13th, so the date shows.
  assert.equal(momentText('2026-11-14T04:50:00Z', false, now), '11-13 23:50');
  assert.equal(sidesText('7d', '1h'), '7 d before, 1 h after');
  assert.equal(typesText([]), 'every type with data');
  assert.equal(typesText(['syslog']), 'syslog');
  assert.equal(typesText(['syslog', 'trap']), 'syslog and SNMP traps');
});
