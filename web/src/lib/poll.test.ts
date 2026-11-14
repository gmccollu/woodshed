// Unit tests for poll.ts: `npm test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  aligned,
  bps,
  bucketsOf,
  capMarkers,
  chartSet,
  delta,
  ifSeriesBatches,
  interfacesText,
  isIP,
  isOID,
  linePath,
  markerTitle,
  MAX_CHARTED,
  niceCeil,
  parseInterfaces,
  speed,
  stripsOf,
  sumAligned,
  targetErrors,
  toggleCharted,
  uptime,
  type PollMarker,
  type PollPoint,
  type PollSeries,
} from './poll.ts';

test('bps: SI units, a decimal below 100, a dash when not measured', () => {
  assert.equal(bps(812_345_678), '812 Mb/s');
  assert.equal(bps(1_234_000_000), '1.2 Gb/s');
  assert.equal(bps(640), '640 b/s');
  assert.equal(bps(95_123_456), '95.1 Mb/s');
  assert.equal(bps(0), '0 b/s');
  assert.equal(bps(null), '–');
  assert.equal(speed(1000), '1 Gb/s');
  assert.equal(speed(0), '–');
});

test('uptime: the two largest units', () => {
  assert.equal(uptime(12 * 86400 + 3 * 3600 + 59), '12 d 3 h');
  assert.equal(uptime(3 * 3600 + 5 * 60), '3 h 5 min');
  assert.equal(uptime(250), '4 min 10 s');
  assert.equal(uptime(120), '2 min');
  assert.equal(uptime(42), '42 s');
  assert.equal(uptime(null), '–');
  assert.equal(delta(12), '+12');
  assert.equal(delta(null), '–');
});

test('addresses and OIDs', () => {
  assert.ok(isIP('10.1.0.1'));
  assert.ok(isIP('fd00:1::5'));
  assert.ok(!isIP('edge-fw-01'));
  assert.ok(!isIP('10.1.0.256'));
  assert.ok(!isIP('10.01.0.1'));
  assert.ok(isOID('1.3.6.1.2.1.1.3.0'));
  assert.ok(isOID('.1.3.6.1.4.1.32473.1'));
  assert.ok(!isOID('sysUpTime.0'));
  assert.ok(!isOID('1'));
});

test('interfaces: all, or names and indexes', () => {
  assert.equal(parseInterfaces(''), 'all');
  assert.equal(parseInterfaces(' All '), 'all');
  assert.deepEqual(parseInterfaces('eth1, eth2,7\neth1'), ['eth1', 'eth2', 7]);
  assert.equal(interfacesText('all'), '');
  assert.equal(interfacesText(['eth1', 7]), 'eth1, 7');
});

test('targetErrors: the contract limits, a community on create, a v3 user', () => {
  assert.deepEqual(targetErrors({ address: '10.1.0.1', version: '2c', community: 'x' }), {});
  const e = targetErrors({ address: 'router', version: '2c', port: 0, interval_s: 10 });
  assert.ok(e.address && e.port && e.interval_s && e.community);
  // Editing a target with a stored community: leaving it out keeps it.
  assert.deepEqual(targetErrors({ address: '10.1.0.1', version: '2c' }, { creating: false, communitySet: true }), {});
  assert.ok(targetErrors({ address: '10.1.0.1', version: '2c', community: '' }, { creating: false, communitySet: true }).community);
  assert.ok(targetErrors({ address: '10.1.0.1', version: '3' }).v3_user);
  const c = targetErrors({
    address: '10.1.0.1',
    version: '3',
    v3_user: 'monitor',
    custom: [
      { oid: 'nope', kind: 'scalar', label: '', max_rows: 0 },
      { oid: '1.3.6.1.2.1.2.2.1.10', kind: 'walk', label: '', max_rows: 2000 },
    ],
  });
  assert.ok(c['custom[0].oid']);
  assert.ok(c['custom[1].max_rows']);
  assert.ok(!c['custom[1].oid']);
  const many = Array.from({ length: 33 }, () => ({ oid: '1.3.6.1.2.1.1.3.0', kind: 'scalar' as const, label: '', max_rows: 0 }));
  assert.ok(targetErrors({ address: '10.1.0.1', version: '2c', community: 'x', custom: many }).custom);
});

const pt = (start: string, avg: number | null, count = 1, max = avg): PollPoint => ({ start, avg, max, count });

test('aligned: gaps for count 0 and missing buckets; totals for deltas', () => {
  const start = Date.parse('2026-11-15T10:00:00Z');
  const pts = [pt('2026-11-15T10:00:00Z', 5, 2), pt('2026-11-15T10:01:00Z', 0, 0), pt('2026-11-15T10:03:00Z', 3)];
  assert.deepEqual(aligned(pts, start, 60_000, 4), [5, null, null, 3]);
  assert.deepEqual(aligned(pts, start, 60_000, 4, true), [10, null, null, 3]);
  assert.deepEqual(sumAligned([1, null, null], [2, 3, null]), [3, 3, null]);
});

test('bucketsOf: from the earliest point (a bucket edge before from) to to', () => {
  const b = bucketsOf('2026-11-15T10:00:30Z', '2026-11-15T10:05:00Z', 60, [[pt('2026-11-15T10:00:00Z', 1)]]);
  assert.equal(new Date(b.start).toISOString(), '2026-11-15T10:00:00.000Z');
  assert.equal(b.n, 5);
});

test('linePath: breaks at gaps, a lone point is a short stroke', () => {
  assert.equal(linePath([0, 10], 20, 10, 10), 'M5 10L15 0');
  const d = linePath([5, null, 5], 30, 10, 10);
  assert.equal((d.match(/M/g) ?? []).length, 2);
  assert.ok(d.includes('h'));
  assert.equal(linePath([null, null], 20, 10, 10), '');
  assert.equal(niceCeil(812), 1000);
  assert.equal(niceCeil(230), 250);
  assert.equal(niceCeil(0), 1);
});

test('chart set: the 4 busiest, picks added, at most 8', () => {
  const defaults = ['eth1', 'eth3', 'eth2', 'eth7'];
  assert.deepEqual(chartSet(defaults, [], []), defaults);
  assert.deepEqual(chartSet(defaults, ['eth9'], ['eth3']), ['eth1', 'eth2', 'eth7', 'eth9']);
  let cur = chartSet(defaults, [], []);
  let st = { picked: [] as string[], removed: [] as string[] };
  for (const n of ['a', 'b', 'c', 'd']) {
    const r = toggleCharted(cur, n, defaults, st.picked, st.removed);
    st = r;
    cur = chartSet(defaults, st.picked, st.removed);
  }
  assert.equal(cur.length, MAX_CHARTED);
  assert.equal(toggleCharted(cur, 'e', defaults, st.picked, st.removed).full, true);
  const off = toggleCharted(cur, 'eth1', defaults, st.picked, st.removed);
  assert.deepEqual(chartSet(defaults, off.picked, off.removed).includes('eth1'), false);
  assert.deepEqual(ifSeriesBatches(Array.from({ length: 8 }, (_, i) => `e${i}`)).map((b) => b.length), [16]);
  assert.deepEqual(ifSeriesBatches(Array.from({ length: 9 }, (_, i) => `e${i}`)).map((b) => b.length), [16, 2]);
});

test('markers: titles name the device and source; the cap keeps restarts', () => {
  const r: PollMarker = { time: '2026-11-15T10:04:00Z', kind: 'restart', reboot: '1', detail: 'sysUpTime and hrSystemUptime reset' };
  assert.equal(markerTitle(r, 'edge-fw-01'), 'edge-fw-01: rebooted (sysUpTime and hrSystemUptime reset)');
  assert.match(markerTitle({ ...r, reboot: '?' }), /may have rebooted/);
  assert.equal(markerTitle({ time: r.time, kind: 'oper', if: 'eth3', oper: 'down', detail: '' }), 'eth3 down');
  assert.equal(markerTitle({ time: r.time, kind: 'oper', detail: 'eth3 down' }, 'x'), 'x: eth3 down');
  const many: PollMarker[] = Array.from({ length: 50 }, (_, i) => ({ time: new Date(Date.parse(r.time) + i * 1000).toISOString(), kind: 'oper', detail: '' }));
  many.push({ ...r, time: '2026-11-15T11:00:00Z' });
  const c = capMarkers(many, 10);
  assert.equal(c.shown.length, 10);
  assert.equal(c.hidden, 41);
  assert.ok(c.shown.some((m) => m.kind === 'restart'));
});

test('stripsOf: traffic in and out share a strip', () => {
  const s = (key: string): PollSeries => ({ key, label: key, unit: key === 'cpu' ? '%' : 'bit/s', points: [] });
  const strips = stripsOf([s('in_bps'), s('out_bps'), s('cpu'), s('errors_d')]);
  assert.deepEqual(strips.map((x) => x.key), ['traffic', 'cpu', 'errors_d']);
  assert.equal(strips[0].series.length, 2);
  assert.deepEqual(stripsOf([s('in_bps'), s('out_bps')]).map((x) => x.label), ['Traffic in / out']);
});
