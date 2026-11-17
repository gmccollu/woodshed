import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  addFilters,
  amountText,
  byTypeText,
  dbytes,
  defaultMetric,
  detailRows,
  eventNote,
  filterErrors,
  FLOW_FILTERS,
  FLOW_PARAMS,
  flowBudgetBody,
  flowFormatsBody,
  flowFormErrors,
  flowListenerBody,
  flowReadme,
  flowSettingsForm,
  isAddrOrPrefix,
  isPortOrRange,
  isTooManyFlows,
  leaveFlowsOutByDefault,
  offsetText,
  progressText,
  rowFilters,
  ruleIeCandidate,
  ruleIeOk,
  samplingText,
  shareText,
  zeroOmittedText,
  short,
  TIME_BANNER_MIN,
  timeOffNow,
  timeOffWords,
  type FlowBundleSummary,
  type FlowExporter,
  type FlowFields,
} from './flows.ts';

test('addresses and prefixes, both families', () => {
  for (const ok of ['10.20.0.5', '10.20.0.0/16', '0.0.0.0/0', '2001:db8::/32', '2001:db8::5', '::1', 'fe80::1:2:3:4', '::ffff:192.0.2.1'])
    assert.ok(isAddrOrPrefix(ok), ok);
  for (const bad of ['10.20.0', '10.20.0.256', '10.0.0.0/33', '2001:db8::/129', 'host.example', '1::2::3', '10.0.0.0/8/9', ''])
    assert.ok(!isAddrOrPrefix(bad), bad);
});

test('ports and ranges', () => {
  for (const ok of ['0', '443', '65535', '8000-8100', '22-22']) assert.ok(isPortOrRange(ok), ok);
  for (const bad of ['65536', '8100-8000', 'http', '1-', '-1']) assert.ok(!isPortOrRange(bad), bad);
});

test('filter errors name the parameter and the value', () => {
  const e = filterErrors({ src: ['10.0.0.0/8', 'nope'], proto: ['tcp', '47'], exclude_dst_port: ['70000'], fw_event: ['denied'], tcp_flags: ['syn', 'xyz'] });
  assert.match(e.src, /"nope" isn't an address/);
  assert.equal(e.proto, undefined);
  assert.match(e.exclude_dst_port, /"70000" isn't a port/);
  assert.equal(e.fw_event, undefined);
  assert.match(e.tcp_flags, /"xyz"/);
  // Every include and exclude parameter, each once.
  assert.equal(new Set(FLOW_PARAMS).size, FLOW_PARAMS.length);
  assert.ok(FLOW_PARAMS.includes('exclude_rule_id') && FLOW_PARAMS.includes('ip_any') && !FLOW_PARAMS.includes('q'));
  assert.equal(FLOW_FILTERS.filter((f) => f.main).length, 5);
});

test('exported and scaled are both shown, never one silently for the other', () => {
  assert.equal(amountText('bytes', 312e6, 312e9, { sampling: 1000 }), '312 MB exported (≈ 312 GB at 1:1,000)');
  assert.equal(amountText('bytes', 312e6, 312e6), '312 MB');
  assert.equal(amountText('bytes', 312e6, null), '312 MB');
  assert.equal(amountText('bytes', 1.2e9, 4.8e9, { lowerBound: true }), '1.2 GB exported (≥ 4.8 GB scaled)');
  assert.equal(amountText('packets', 21_400_000, 2_100_000_000), '21.4 M exported (≈ 2.1 G scaled)');
  assert.equal(samplingText(1), 'unsampled');
  assert.equal(samplingText(0), 'sampling unknown');
  assert.equal(dbytes(999), '999 B');
  assert.equal(dbytes(1840), '1.8 kB');
  assert.equal(short(840), '840');
  assert.equal(short(1_204_332), '1.2 M');
  assert.equal(shareText(0.31), '31 %');
  assert.equal(shareText(0.042), '4.2 %');
  assert.equal(shareText(0.0004), '<0.1 %');
  // The README's rule too (internal/export TestFlowShareText).
  for (const [x, want] of [[0.0031, '0.3 %'], [0.04, '4 %'], [0.0999, '10 %'], [0.001, '0.1 %'], [0.0009, '<0.1 %'], [1, '100 %']] as const)
    assert.equal(shareText(x), want);
});

test('Top rows become filters; denied defaults to the flows metric', () => {
  assert.deepEqual(rowFilters('dst_port', 'tcp/443'), { proto: ['tcp'], dst_port: ['443'] });
  assert.deepEqual(rowFilters('conversation', '10.20.0.5 ↔ 198.51.100.7'), { src: ['10.20.0.5', '198.51.100.7'], dst: ['10.20.0.5', '198.51.100.7'] });
  assert.deepEqual(rowFilters('in_if', '3'), { in_if: ['3'] });
  assert.deepEqual(rowFilters('rule_id', 'acl-in 1042'), { rule_id: ['acl-in 1042'] });
  assert.deepEqual(addFilters({ proto: ['TCP'] }, { proto: ['tcp'], dst_port: ['443'] }), { proto: ['TCP'], dst_port: ['443'] });
  assert.equal(defaultMetric({ fw_event: ['denied'] }), 'flows');
  assert.equal(defaultMetric({ fw_event: ['denied', 'created'] }), 'bytes');
  assert.equal(defaultMetric({}), 'bytes');
});

test('progress text for partial flow answers', () => {
  const p = { blocks_done: 31, blocks_total: 50, records_done: 620, records_total: 1000, complete_from: '2026-11-16T09:30:00Z' };
  assert.equal(progressText(p, true), "Counted 62 % of the window's flow records, newest first");
  assert.equal(progressText(p, false), '');
  assert.equal(progressText({ ...p, records_done: 1000 }, true), "Counted 99 % of the window's flow records, newest first");
});

test('Leave flows out: over 4 h and above 1 GB', () => {
  const H = 3600_000;
  assert.ok(leaveFlowsOutByDefault(5 * H, 2e9));
  assert.ok(!leaveFlowsOutByDefault(4 * H, 2e9));
  assert.ok(!leaveFlowsOutByDefault(5 * H, 1e9));
  assert.ok(isTooManyFlows('Too many flow records for one zip (24,113,002 for 10.1.0.1); narrow the window or add a flow filter.'));
  assert.equal(flowFormatsBody(['csv', 'ipfix']), undefined);
  assert.equal(flowFormatsBody(['ipfix', 'csv']), undefined);
  assert.deepEqual(flowFormatsBody(['ipfix']), ['ipfix']);
  assert.equal(
    byTypeText({ syslog: { lines: 12_400, bytes: 1_700_000 }, flow: { records: 3_100_000, bytes: 52e6 }, trap: { lines: 0, bytes: 0 } }),
    '12,400 syslog lines (1.7 MB), 3.1 M flow records (52 MB)',
  );
});

test('the README Flows block matches SPEC §13.4', () => {
  const s: FlowBundleSummary = {
    records: 1_204_332,
    domains: 2,
    sampling: [{ domain: 1, sampling: 1000 }, { domain: 2, sampling: 1 }],
    bytes: 18.2e9,
    bytes_scaled: 1.9e12,
    packets: 21.4e6,
    packets_scaled: 2.1e9,
    top_talkers: [{ key: '10.20.0.5', share: 0.31 }, { key: '10.20.0.9', share: 0.12 }, { key: '192.0.2.44', share: 0.074 }],
    top_dst_ports: [{ key: 'tcp/443', share: 0.54 }, { key: 'udp/53', share: 0.09 }, { key: 'tcp/22', share: 0.04 }],
    top_conversations: [{ key: '10.20.0.5 ↔ 198.51.100.7', share: 0.22 }],
    fw_events: { created: 48_210, deleted: 47_902, denied: 3_114 },
    top_denied_sources: [{ key: '203.0.113.50', count: 1920 }, { key: '198.51.100.23', count: 411 }],
    top_denied_ports: [{ key: 'tcp/23', count: 1204 }, { key: 'tcp/445', count: 870 }],
    nat_connections: 41_377,
    top_post_nat_sources: [{ key: '192.0.2.10', share: 0.88 }],
    sequence_gaps: 3,
    lost_estimate: 90,
    no_template: 0,
    malformed: 0,
  };
  const want = [
    '    Flows        1,204,332 records from 2 observation domains; sampled 1 in 1,000 on domain 1, unsampled on domain 2',
    '                 bytes 18.2 GB exported (≈ 1.9 TB scaled), packets 21.4 M (≈ 2.1 G scaled)',
    '                 top talkers by bytes: 10.20.0.5 31 %, 10.20.0.9 12 %, 192.0.2.44 7.4 %',
    '                 top destination ports: tcp/443 54 %, udp/53 9 %, tcp/22 4 %',
    '                 top conversations: 10.20.0.5 ↔ 198.51.100.7 22 %',
    '                 firewall events: 48,210 created, 47,902 deleted, 3,114 denied',
    '                 top denied sources: 203.0.113.50 1,920, 198.51.100.23 411; top denied ports: tcp/23 1,204, tcp/445 870',
    '                 NAT: 41,377 translated connections; top post-NAT sources: 192.0.2.10 88 %',
    '                 sequence gaps 3 (≈ 90 records lost before Woodshed) in this window; waiting for a template 0; malformed 0',
  ].join('\n');
  assert.equal(flowReadme(s), want);
  // Keys with 0 bytes are left out and counted; a list of only those says "none"; small shares never read "0 %"
  // (the Go README's TestFlowReadmeZeroOmitted and TestFlowShareText).
  const z = flowReadme({ ...s, top_conversations: [{ key: '10.20.0.5 ↔ 198.51.100.7', share: 0.0031 }], top_dst_ports: [],
    zero_omitted: { top_talkers: 3, top_dst_ports: 2 } }).split('\n');
  assert.equal(z[2], '                 top talkers by bytes: 10.20.0.5 31 %, 10.20.0.9 12 %, 192.0.2.44 7.4 % (3 with 0 bytes not shown)');
  assert.equal(z[3], '                 top destination ports: none (2 with 0 bytes not shown)');
  assert.equal(z[4], '                 top conversations: 10.20.0.5 ↔ 198.51.100.7 0.3 %');
  assert.equal(zeroOmittedText(1234, 'bytes'), '1,234 with 0 bytes not shown');
  assert.equal(zeroOmittedText(2, 'flows'), '2 with 0 flow records not shown');
  assert.equal(zeroOmittedText(0, 'bytes'), '');
  // Sequence gaps (decision 82): the window's; by the hour past a day; not known, and only then the collector's 24 h.
  const last = (x: Partial<FlowBundleSummary>) => flowReadme({ ...s, ...x }).split('\n').slice(-2);
  assert.equal(last({ sequence_gaps: 0, lost_estimate: 0, sequence_gaps_24h: 849 })[1], '                 sequence gaps 0 in this window; waiting for a template 0; malformed 0');
  assert.equal(
    last({ sequence_gaps: 1234, lost_estimate: 5000, sequence_gaps_span: { from: '2026-11-15T14:00:00Z', to: '2026-11-15T16:00:00Z', by_hour: true } })[1],
    '                 sequence gaps 1,234 (≈ 5,000 records lost before Woodshed) in the whole hours 2026-11-15 14:00–16:00 UTC (counts older than a day are kept by the hour); waiting for a template 0; malformed 0',
  );
  assert.deepEqual(last({ sequence_gaps: null, lost_estimate: null, sequence_gaps_unknown: 'not_kept', sequence_gaps_24h: 849, lost_estimate_24h: 37_498 }), [
    '                 sequence gaps in this window not known (Woodshed keeps them 7 days, by datagram arrival); waiting for a template 0; malformed 0',
    '                 collector sequence gaps in the 24 h before this bundle was made (not limited to this window): 849 (≈ 37,498 records lost)',
  ]);
  assert.deepEqual(last({ sequence_gaps: null, lost_estimate: null, sequence_gaps_unknown: 'preview', sequence_gaps_24h: 3, lost_estimate_24h: null }), [
    '                 sequence gaps in this window are counted when the bundle is built; waiting for a template 0; malformed 0',
    '                 collector sequence gaps in the last 24 h (not limited to this window): 3',
  ]);
  // A plain-flow exporter: no event or NAT lines, no scaled values.
  const plain = flowReadme({ ...s, domains: 1, sampling: [{ domain: 0, sampling: 1 }], bytes_scaled: null, packets_scaled: null, fw_events: { created: 0, deleted: 0, denied: 0 },
    top_denied_sources: [], top_denied_ports: [], nat_connections: 0, top_post_nat_sources: [], sequence_gaps: 0 });
  assert.ok(!plain.includes('firewall events') && !plain.includes('NAT:') && !plain.includes('≈'));
  assert.ok(plain.includes('from 1 observation domain; unsampled on domain 0'));
});

test('Settings → Flows round trip and checks', () => {
  const f = flowSettingsForm(undefined, 0);
  assert.deepEqual(flowListenerBody(f), { enabled: false, addr: '0.0.0.0', flow_port: 2055, ipfix_port: 4739, template_timeout: '30m', rule_id_ies: [] });
  assert.equal(flowBudgetBody(f), 0);
  const g = { ...f, flowEnabled: true, flowTimeout: '90 min', flowRuleIes: '32473:7\n32473:7, 9:12001', flowBudgetGiB: 6 };
  assert.deepEqual(flowListenerBody(g).rule_id_ies, ['32473:7', '9:12001']);
  assert.equal(flowListenerBody(g).template_timeout, '1h30m');
  assert.equal(flowBudgetBody(g), 6 * 1024 ** 3);
  assert.deepEqual(flowFormErrors(g, 20 * 1024 ** 3), {});
  const bad = flowFormErrors({ ...g, flowPort: 0, flowIpfixPort: 0, flowTimeout: '10s', flowRuleIes: 'acl', flowBudgetGiB: 19 }, 20 * 1024 ** 3);
  assert.deepEqual(Object.keys(bad).sort(), ['listeners.flow.ipfix_port', 'listeners.flow.rule_id_ies', 'listeners.flow.template_timeout', 'storage.flow_budget_bytes']);
  assert.ok(ruleIeOk('32473:7') && !ruleIeOk('32473:40000') && !ruleIeOk('7'));
  // Flow v9 field types: enterprise number 0 takes a 16-bit ID (the vendor range 32768–65535).
  assert.ok(ruleIeOk('0:40003') && ruleIeOk('0:65535') && ruleIeOk('0:7') && !ruleIeOk('0:65536') && !ruleIeOk('1:32768') && !ruleIeOk('v9:40003'));
  assert.deepEqual(flowFormErrors({ ...g, flowRuleIes: '0:40003\n32473:3' }, 20 * 1024 ** 3), {});
  assert.ok(ruleIeCandidate({ pen: 0, id: 40003, name: '', length: 4 }) && ruleIeCandidate({ pen: 32473, id: 3, name: '', length: 4 }));
  assert.ok(!ruleIeCandidate({ pen: 0, id: 8, name: 'sourceIPv4Address', length: 4 }));
  assert.equal(flowSettingsForm({ ...flowListenerBody(g) }, 6 * 1024 ** 3).flowBudgetGiB, 6);
});

test('a record’s detail and its event note', () => {
  const f: FlowFields = {
    start: '2026-11-16T09:30:11.200Z', end: '2026-11-16T09:31:01.950Z', src: '10.20.0.5', src_port: 51544, dst: '198.51.100.7', dst_port: 443, proto: 6,
    proto_name: 'tcp', tcp_flags: 'SAPF', packets: 1840, bytes: 2_210_444, sampling: 1000, packets_scaled: 1_840_000, bytes_scaled: 2_210_444_000,
    in_if: 3, in_if_name: 'eth3', out_if: 1, out_if_name: 'eth1', domain: 1, fw_event: 'deleted', nat_event: 'nat44_session_delete', event_time: null,
    post_nat_src: '192.0.2.10', post_nat_src_port: 40112, post_nat_dst: '198.51.100.7', post_nat_dst_port: 443, initiator_bytes: null, responder_bytes: null,
    initiator_packets: null, responder_packets: null, rev_bytes: null, rev_packets: null, rule_id: '1042', time_source: 'exporter', status: 'ok',
    extras: [{ pen: 32473, id: 1, hex: '0a0b' }],
  };
  assert.equal(eventNote(f), 'deleted · NAT 192.0.2.10:40112 · rule 1042');
  const d = Object.fromEntries(detailRows(f));
  assert.equal(d.Bytes, '2.2 MB exported (≈ 2.2 GB at 1:1,000)');
  assert.equal(d['Input interface'], '3 (eth3)');
  assert.equal(d.Protocol, 'tcp (6)');
  assert.ok(!('Event time' in d) && !('Reverse bytes / packets' in d));
});

test('times off arrival: words, the banner count and the README line (SPEC §13.10 decision 70)', () => {
  // The same as the server's flow.OffsetText.
  for (const [ms, want] of [[3_600_001, '1.0 h'], [5_400_000, '1.5 h'], [30 * 3_600_000, '30 h'], [47 * 3_600_000 + 1, '47 h'], [48 * 3_600_000, '2.0 days'], [2 ** 32, '49.7 days']] as const)
    assert.equal(offsetText(ms), want);
  assert.equal(timeOffWords({ ahead: 3600, behind: 2, max_ahead_ms: 2 ** 32, max_behind_ms: 30 * 3_600_000 }), '3,600 ahead (up to 49.7 days), 2 behind (up to 30 h)');
  assert.equal(timeOffWords({ ahead: 0, behind: 0, max_ahead_ms: 0, max_behind_ms: 0 }), '');
  assert.equal(timeOffWords(null), '');
  const none = { ahead: 0, behind: 0, max_ahead_ms: 0, max_behind_ms: 0 };
  const exp = (ahead: number, behind: number) =>
    ({ device_id: '10.1.0.1', domains: [], records_per_sec: 1, pending_bytes: 0, clock_skew_ms: 0, time_source: 'exporter',
      counts_24h: { records: 1, late: 0, no_template: 0, malformed: 0, sequence_gaps: 0, duplicates: 0 }, time_offsets_24h: none,
      time_offsets_1h: { ...none, ahead, behind } }) as FlowExporter;
  assert.equal(TIME_BANNER_MIN, 10);
  assert.ok(!timeOffNow(exp(9, 9)));
  assert.ok(timeOffNow(exp(10, 0)) && timeOffNow(exp(0, 10)));
  const base: FlowBundleSummary = {
    records: 2, domains: 1, sampling: [{ domain: 1, sampling: 1 }], bytes: 200, bytes_scaled: null, packets: 2, packets_scaled: null,
    top_talkers: [], top_dst_ports: [], top_conversations: [], fw_events: { created: 0, deleted: 0, denied: 0 }, top_denied_sources: [],
    top_denied_ports: [], nat_connections: 0, top_post_nat_sources: [], sequence_gaps: 0, lost_estimate: 0, no_template: 0, malformed: 0,
  };
  assert.ok(!flowReadme(base).includes('times off arrival'));
  assert.ok(!flowReadme({ ...base, time_offsets: none, time_offsets_24h: none }).includes('times off arrival'));
  // The same line as the Go README (internal/export TestFlowBundleTimeOffsets).
  const lines = flowReadme({ ...base, time_offsets: { ...none, ahead: 1, max_ahead_ms: 70 * 60_000 }, time_offsets_24h: { ...none, ahead: 2, max_ahead_ms: 2 ** 32 } }).split('\n');
  assert.equal(
    lines[lines.length - 2],
    "                 times off arrival: 1 ahead (up to 1.2 h) in this window; 2 ahead (up to 49.7 days) in the last 24 h; kept at their own times, so a window around their arrival misses them (the exporter's clock or uptime is probably wrong)",
  );
});
