import { test } from 'node:test';
import assert from 'node:assert/strict';
import { countsText, FILTER_LEVELS, filterChoice, filterPhrase, leftOut, severityPatch, syslogSettingsBody } from './severity.ts';

test('the severity filter wording matches the server', () => {
  assert.equal(filterPhrase('debug'), 'everything');
  assert.equal(filterPhrase(undefined), 'everything');
  assert.equal(filterPhrase('info'), 'info and above');
  assert.equal(filterPhrase('emerg'), 'emerg only');
  assert.deepEqual(FILTER_LEVELS, ['debug', 'info', 'notice', 'warning', 'err', 'crit', 'alert', 'emerg']);
  assert.deepEqual(leftOut('notice'), ['info', 'debug']);
  assert.deepEqual(leftOut('debug'), []);
  assert.equal(filterChoice('debug'), 'Everything (debug and above)');
  assert.equal(filterChoice('info'), 'Info and above (leaves out debug)');
  assert.equal(filterChoice('warning'), 'Warning and above (leaves out notice, info and debug)');
  assert.equal(filterChoice('emerg'), 'Emerg only (leaves out alert to debug)');
  assert.equal(countsText({ info: 2, debug: 12345 }, (n) => n.toLocaleString('en-US')), '12,345 debug, 2 info');
  assert.equal(countsText({}, String), '');
  assert.deepEqual(severityPatch('default'), { min_severity: 'default' });
  assert.deepEqual(syslogSettingsBody('info'), { min_severity: 'info' });
});
