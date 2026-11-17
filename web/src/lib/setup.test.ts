import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formErrors, newSetupForm, snippetBody, type SetupFamily } from './setup.ts';

const netsnmp: SetupFamily = {
  id: 'net-snmp', label: 'Linux: net-snmp', what: ['trap', 'poll'], verification: 'tested', reference: '', notes: [],
  transports: { trap: ['v2c', 'v3'], poll: ['v2c', 'v3'] }, choices: { trap: ['v3_user', 'auth', 'priv'], poll: ['agent_port', 'v3_user', 'auth', 'priv'] },
};

test('a typo in the agent port is an error, never the default 161', () => {
  const f = newSetupForm(netsnmp, 'poll');
  for (const typo of ['16x1', '0', '70000', '-1', '1.5', ' 1 61']) {
    f.agentPort = typo;
    assert.ok(formErrors(netsnmp, f).agent_port, `${typo} should be refused`);
    assert.ok(!('agent_port' in snippetBody(netsnmp, f)), `${typo} isn't sent`);
  }
  f.agentPort = ' 1161 ';
  assert.deepEqual(formErrors(netsnmp, f), {});
  assert.equal(snippetBody(netsnmp, f).agent_port, 1161);
  f.agentPort = '';
  assert.deepEqual(formErrors(netsnmp, f), {});
  assert.ok(!('agent_port' in snippetBody(netsnmp, f)));
});

test('the agent port is checked only where it applies', () => {
  const f = newSetupForm(netsnmp, 'trap');
  f.agentPort = 'oops';
  assert.deepEqual(formErrors(netsnmp, f), {});
});
