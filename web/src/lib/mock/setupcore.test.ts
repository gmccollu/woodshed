// The mock answers setup requests as the server does: setup-fixture.json holds requests with the
// server's own verdicts (internal/setuphelper's TestMockFixture runs them through Generate), and
// the mock must give the same field error, or the same address, for each.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { snippetReply, type SetupFixture } from './setupcore.ts';

const FX = JSON.parse(readFileSync(new URL('./setup-fixture.json', import.meta.url), 'utf8')) as SetupFixture;

test('the mock refuses and accepts what the server does', () => {
  assert.ok((FX.parity ?? []).length >= 20, 'the fixture has its parity cases');
  for (const c of FX.parity ?? []) {
    const r = snippetReply(FX, c.body);
    const body = r.body as { errors?: Record<string, string>; address?: string };
    if (c.field) {
      assert.equal(r.status, 400, `${JSON.stringify(c.body)} should be refused on ${c.field}`);
      assert.deepEqual(Object.keys(body.errors ?? {}), [c.field], JSON.stringify(c.body));
    } else {
      assert.equal(r.status, 200, `${JSON.stringify(c.body)}: ${JSON.stringify(body)}`);
      assert.equal(body.address, c.address, JSON.stringify(c.body));
    }
  }
});

test('an IPv6 address gets brackets and rocommunity6, as from the server', () => {
  const v6 = snippetReply(FX, { family: 'net-snmp', what: 'poll', transport: 'v2c', address: '2001:DB8::7' }).body as { text: string };
  assert.match(v6.text, /rocommunity6 <COMMUNITY> 2001:db8::7/);
  const sf = snippetReply(FX, { family: 'softflowd', what: 'flow', address: '2001:db8::7' }).body as { text: string };
  assert.match(sf.text, /-n \[2001:db8::7\]:2055/);
});
