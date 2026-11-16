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
  progressText,
  rowFilters,
  ruleIeOk,
  samplingText,
  shareText,
  short,
  type FlowBundleSummary,
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
    top_talkers: [{ key: '10.20.0.5', share: 0.31 }, { key: '10.20.0.9', share: 0.12 }, { key: '192.0.2.44', share: 0.07 }],
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
    '                 top talkers by bytes: 10.20.0.5 31 %, 10.20.0.9 12 %, 192.0.2.44 7 %',
    '                 top destination ports: tcp/443 54 %, udp/53 9 %, tcp/22 4 %',
    '                 top conversations: 10.20.0.5 ↔ 198.51.100.7 22 %',
    '                 firewall events: 48,210 created, 47,902 deleted, 3,114 denied',
    '                 top denied sources: 203.0.113.50 1,920, 198.51.100.23 411; top denied ports: tcp/23 1,204, tcp/445 870',
    '                 NAT: 41,377 translated connections; top post-NAT sources: 192.0.2.10 88 %',
    '                 sequence gaps 3 (≈ 90 records lost before Woodshed); waiting for a template 0; malformed 0',
  ].join('\n');
  assert.equal(flowReadme(s), want);
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
