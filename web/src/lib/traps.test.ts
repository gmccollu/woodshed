// Unit tests for traps.ts: `npm test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  cleanFilters,
  excludeValue,
  filterParams,
  filtersFromQuery,
  filtersOfSaved,
  filtersToQuery,
  includeValue,
  isCommunityHash,
  levelOf,
  needsKeyExt,
  parseEngineIds,
  pduLabel,
  removeValue,
  statusLabel,
  ticks,
  trapTitle,
  typeFromQuery,
  typeToQuery,
  userErrors,
  varbindLine,
  typeFiltersFromQuery,
  savedTypeFilters,
} from './traps.ts';
import type { FieldDescriptor, TrapFields } from './api';

test('type in the URL: absent or unknown is syslog, trap round-trips', () => {
  assert.equal(typeFromQuery(new URLSearchParams('')), 'syslog');
  assert.equal(typeFromQuery(new URLSearchParams('type=trap')), 'trap');
  assert.equal(typeFromQuery(new URLSearchParams('type=flow')), 'syslog');
  const q = new URLSearchParams();
  typeToQuery('syslog', q);
  assert.equal(q.toString(), '');
  typeToQuery('trap', q);
  assert.equal(q.toString(), 'type=trap');
});

const FIELDS: FieldDescriptor[] = [
  { key: 'device', label: 'Device', param: 'devices', exclude_param: 'exclude_devices', domain: null },
  { key: 'trap_oid', label: 'Trap', param: 'trap_oid', exclude_param: 'exclude_trap_oid', domain: null },
  { key: 'status', label: 'Status', param: 'status', exclude_param: '', domain: [{ value: 'ok', label: 'ok' }] },
];

test('filter parameters come from the schema, without the device ones', () => {
  assert.deepEqual(filterParams(FIELDS), ['trap_oid', 'exclude_trap_oid', 'status']);
});

test('trap filters round-trip through the page URL by their API names', () => {
  const q = new URLSearchParams();
  filtersToQuery({ trap_oid: ['linkDown', '1.3.6.1.4.1.32473.*'], status: ['ok'], exclude_trap_oid: [] }, q);
  assert.equal(q.toString(), 'status=ok&trap_oid=linkDown%2C1.3.6.1.4.1.32473.*');
  assert.deepEqual(filtersFromQuery(q, filterParams(FIELDS)), { trap_oid: ['linkDown', '1.3.6.1.4.1.32473.*'], status: ['ok'] });
});

test('include and exclude move a value between a parameter and its exclude form', () => {
  let f = includeValue({}, 'trap_oid', 'exclude_trap_oid', 'linkDown');
  assert.deepEqual(f, { trap_oid: ['linkDown'] });
  assert.deepEqual(includeValue(f, 'trap_oid', 'exclude_trap_oid', 'LINKDOWN'), f, 'ignoring case, no duplicate');
  f = excludeValue(f, 'trap_oid', 'exclude_trap_oid', 'linkDown');
  assert.deepEqual(f, { exclude_trap_oid: ['linkDown'] });
  assert.deepEqual(removeValue(f, 'exclude_trap_oid', 'linkdown'), {});
  assert.deepEqual(cleanFilters({ b: ['1'], a: [] }), { b: ['1'] });
});

test('a saved trap query gives back its filters', () => {
  assert.deepEqual(filtersOfSaved({ q: 'x', trap_oid: ['linkDown'], status: [] }, filterParams(FIELDS)), { trap_oid: ['linkDown'] });
});

const base: TrapFields = {
  version: '2c', pdu: 'trap', trap_oid: '1.3.6.1.6.3.1.1.5.3', trap_name: 'linkDown', enterprise: '', generic: null, specific: null,
  cred: '#3f9a1c07', status: 'ok', error: '', uptime: 8641234, dup: false,
  varbinds: [
    { oid: '1.3.6.1.2.1.2.2.1.1.3', name: 'ifIndex.3', type: 'int', value: '3' },
    { oid: '1.3.6.1.2.1.2.2.1.8.3', name: 'ifOperStatus.3', type: 'int', value: '2', value_name: 'down' },
    { oid: '1.3.6.1.4.1.32473.1.1.9.0', name: '', type: 'str', value: 'port "3"' },
    { oid: '1.3.6.1.4.1.32473.1.1.8.0', name: '', type: 'hex', value: '00ff' },
    { oid: '1.3.6.1.4.1.32473.1.1.7.0', name: '', type: 'null', value: '' },
  ],
};

test('varbinds on one line: names (or OIDs), named values, quoted strings', () => {
  assert.equal(
    varbindLine(base.varbinds),
    'ifIndex.3=3 ifOperStatus.3=down 1.3.6.1.4.1.32473.1.1.9.0="port \\"3\\"" 1.3.6.1.4.1.32473.1.1.8.0=0x00ff 1.3.6.1.4.1.32473.1.1.7.0=null',
  );
});

test('a trap is called by its name, else its OID, else its status', () => {
  assert.equal(trapTitle(base), 'linkDown');
  assert.equal(trapTitle({ ...base, trap_name: '' }), '1.3.6.1.6.3.1.1.5.3');
  assert.equal(trapTitle({ ...base, trap_name: '', trap_oid: '', status: 'auth_failed' }), statusLabel('auth_failed'));
  assert.equal(pduLabel({ ...base, version: '1', pdu: 'v1trap' }), 'v1 trap');
  assert.equal(pduLabel({ ...base, pdu: 'inform', dup: true }), 'v2c inform (retransmitted)');
  assert.equal(statusLabel('new_status'), 'new_status');
});

test('TimeTicks as a duration', () => {
  assert.equal(ticks(8641234), '1d 0h 00m 12s');
  assert.equal(ticks(360000), '1h 00m 00s');
  assert.equal(ticks(100 * 86400 * 3 + 6100), '3d 0h 01m 01s');
  assert.equal(ticks(null), '');
});

test('v3 user form checks', () => {
  const ok = { name: 'monitor', auth: 'sha-256', priv: 'aes-128', auth_pass: '0123456789', priv_pass: 'abcdefghij', engine_ids: [], keepAuth: false, keepPriv: false };
  assert.deepEqual(userErrors(ok), {});
  assert.ok(userErrors({ ...ok, name: '' }).name);
  assert.ok(userErrors({ ...ok, name: 'x'.repeat(33) }).name);
  assert.ok(userErrors({ ...ok, auth_pass: 'short' }).auth_pass);
  assert.ok(userErrors({ ...ok, auth_pass: '' }).auth_pass, 'required for a new user');
  assert.deepEqual(userErrors({ ...ok, auth_pass: '', priv_pass: '', keepAuth: true, keepPriv: true }), {}, 'editing keeps the stored ones');
  assert.ok(userErrors({ ...ok, auth: 'none' }).priv, 'privacy needs auth');
  assert.ok(userErrors({ ...ok, engine_ids: ['zz'] })['engine_ids[0]']);
  assert.deepEqual(userErrors({ ...ok, engine_ids: ['8000000005a1b2c3d4e5f60718'] }), {});
  assert.equal(levelOf('none', 'none'), 'noAuthNoPriv');
  assert.equal(levelOf('sha', 'none'), 'authNoPriv');
  assert.equal(levelOf('sha', 'des'), 'authPriv');
  assert.ok(needsKeyExt('aes-256') && !needsKeyExt('aes-128'));
  assert.deepEqual(parseEngineIds('80000000050102030405, 0x8000000005aa\n'), ['80000000050102030405', '0x8000000005aa']);
  assert.ok(isCommunityHash('#3f9a1c07') && !isCommunityHash('public'));
});

test('a trap link: every key the page does not own is a trap filter', () => {
  const q = new URLSearchParams('type=trap&q=x&dev=10.1.0.1&r=24h&trap_oid=linkDown,linkUp&status=auth_failed&exclude_cred=');
  assert.deepEqual(typeFiltersFromQuery(q), { status: ['auth_failed'], trap_oid: ['linkDown', 'linkUp'] });
  // The bundle preview's keys are the page's own too.
  const b = new URLSearchParams('type=trap&bundle=2026-11-14T09:42:00Z&bb=30m&ba=10m&bdev=10.1.0.1&btypes=trap&trap_oid=linkDown');
  assert.deepEqual(typeFiltersFromQuery(b), { trap_oid: ['linkDown'] });
  assert.deepEqual(savedTypeFilters({ q: 'x', severities: [], devices: ['a'], trap_oid: ['linkDown'], status: [] }), { trap_oid: ['linkDown'] });
});
