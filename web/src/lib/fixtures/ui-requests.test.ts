// The shared request fixture (ui-requests.json) is exactly what the forms' body builders send.
// The Go side replays it against a real server; screenshots.mjs ("ui-requests-mock") replays it
// against the mock. To regenerate after a deliberate form change: UPDATE_FIXTURES=1 npm test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { buildSteps, NOTES } from './ui-requests.ts';

const file = new URL('./ui-requests.json', import.meta.url);
const built = { notes: NOTES, steps: buildSteps() };
if (process.env.UPDATE_FIXTURES) writeFileSync(file, `${JSON.stringify(built, null, 2)}\n`);
const fixture = JSON.parse(readFileSync(file, 'utf8'));

test('ui-requests.json is what the forms build', () => {
  assert.deepEqual(fixture, built);
});

test('the fixture covers the poller and the user form as the contract expects', () => {
  const by = Object.fromEntries(built.steps.map((s) => [s.name, s]));
  const user = by.snmp_user_add.body as Record<string, unknown>;
  assert.equal(user.key_ext, 'draft');
  assert.ok(user.auth_pass && user.priv_pass);
  assert.ok(!('auth_pass' in (by.snmp_user_edit_keep_passphrases.body as object)));
  const v2 = by.poll_add_v2c.body as Record<string, unknown>;
  assert.equal(v2.community, 'fixture-community');
  assert.equal(v2.port, '{agent_port}');
  assert.equal(v2.interval_s, 30); // the Settings defaults saved just before
  assert.deepEqual(v2.presets, ['system', 'system-info', 'interfaces']);
  const v3 = by.poll_add_v3.body as Record<string, unknown>;
  assert.equal(v3.v3_user, 'monitor');
  assert.ok(!('community' in v3));
  const ed = by.poll_edit.body as Record<string, unknown>;
  assert.ok(!('community' in ed), 'an edit that leaves the community empty keeps it');
  assert.equal((ed.custom as unknown[]).length, 2);
  assert.deepEqual((by.poll_pin.body as Record<string, unknown>).pinned, ['eth1', 2]);
  assert.ok(!('community' in (by.poll_pin.body as object)), 'pinning keeps the stored community');
  assert.deepEqual(by.poll_test_id.body, { id: '{poll_id}' });
  for (const s of built.steps) if (s.if_match) assert.ok(s.etag_get, `${s.name}: if_match needs etag_get`);
});

test('the fixture covers the 2.0 flow forms as the contract expects', () => {
  const by = Object.fromEntries(built.steps.map((s) => [s.name, s]));
  const fs = by.settings_flow_save.body as { listeners: { flow: Record<string, unknown> }; storage: { flow_budget_bytes: number } };
  assert.deepEqual(fs.listeners.flow, {
    enabled: true, addr: '0.0.0.0', flow_port: '{flow_port}', ipfix_port: '{flow_ipfix_port}', template_timeout: '45m', rule_id_ies: ['32473:7', '32473:9'],
  });
  assert.equal(fs.storage.flow_budget_bytes, 2 * 1024 ** 3);
  const all = by.export_every_type.body as Record<string, unknown>;
  assert.deepEqual(all.types, ['syslog', 'trap', 'poll', 'flow']);
  assert.ok(!('flow_formats' in all), 'both formats is the default and is left out');
  assert.deepEqual((by.export_estimate_leave_flows_out.body as Record<string, unknown>).types, ['syslog', 'trap', 'poll']);
  const fo = by.export_flows_filtered_csv.body as Record<string, unknown>;
  assert.deepEqual(fo.types, ['flow']);
  assert.deepEqual(fo.flow_formats, ['csv']);
  assert.deepEqual([fo.proto, fo.dst_port, fo.fw_event], [['tcp'], ['443'], ['denied']]);
  assert.ok(!('q' in fo) && !('flow' in fo), 'flow filters are top-level lists, and flows have no q');
  const bi = by.bundle_estimate_flows_ipfix.body as Record<string, unknown>;
  assert.equal(bi.kind, 'bundle');
  assert.equal(bi.at, '{at}');
  assert.deepEqual(bi.types, []);
  assert.deepEqual(bi.flow_formats, ['ipfix']);
  assert.deepEqual((by.bundle_leave_flows_out.body as Record<string, unknown>).types, ['syslog', 'trap', 'poll']);
  assert.ok(!('flow_formats' in (by.bundle_leave_flows_out.body as object)));
});
