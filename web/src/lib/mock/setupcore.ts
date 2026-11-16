// The setup helper's routes in mock mode (the pure part, so node tests run it), from
// setup-fixture.json, which internal/setuphelper's TestMockFixture generates from the real templates and the server's own patterns and choice
// lists. A request is checked as setuphelper.Generate checks it, in the same order and with the
// same patterns, so the mock refuses exactly what the server refuses. The snippet is the one
// rendered for the same kind of address (IPv4, IPv6 or a host name, so brackets, rocommunity6 and
// the name placeholders come out as from the server), with the sample address swapped for the
// requested one. Other choices (severity, interface…) aren't re-rendered into the text.
import type { SetupFamily, Snippet, SnippetBody } from '../setup.ts';

export type Kind = 'ipv4' | 'ipv6' | 'name';
/** setup-fixture.json's shape. */
export interface SetupFixture {
  families: SetupFamily[];
  patterns: { hostname: string; interface: string; user: string };
  choices: { severities: string[]; facilities: string[]; auths: string[]; privs: string[] };
  samples: Record<Kind, string>;
  snippets: Record<string, Record<Kind, Snippet>>;
  parity?: { body: SnippetBody; field: string; address: string }[];
}
const V3 = ['v3_user', 'auth', 'priv'];
const ORDER = ['source_interface', 'interface', 'severity', 'facility', 'v3_user', 'auth', 'priv', 'agent_port'] as const;

export type Reply = { status: number; body: unknown };
const bad = (field: string, msg: string): Reply => ({ status: 400, body: { error: `${field}: ${msg}`, errors: { [field]: msg } } });
const quote = (s: string) => (s === '' ? 'an empty value' : JSON.stringify(s));

/** An IPv4 address as Go's netip parses it: four decimal octets, no leading zeros. */
function ipv4(s: string): string | null {
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m || m.slice(1).some((o) => Number(o) > 255 || (o.length > 1 && o.startsWith('0')))) return null;
  return s;
}
/** An IPv6 address in its canonical form (lower case, compressed), unmapped when it holds an IPv4 one; null if it isn't one. */
function ipv6(s: string): string | null {
  if (!s.includes(':') || s.includes('%') || /[^0-9a-fA-F:.]/.test(s)) return null;
  try {
    const h = new URL(`http://[${s}]/`).hostname.slice(1, -1);
    const mapped = h.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (mapped) {
      const [a, b] = [parseInt(mapped[1], 16), parseInt(mapped[2], 16)];
      return `${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`;
    }
    return h;
  } catch {
    return null;
  }
}

/** POST /api/setup/snippet against the fixture, checked as setuphelper.Generate checks it. */
export function snippetReply(FX: SetupFixture, b: SnippetBody): Reply {
  const HOSTNAME = new RegExp(FX.patterns.hostname, 'i');
  const IFACE = new RegExp(FX.patterns.interface);
  const USER = new RegExp(FX.patterns.user);
  const f = FX.families.find((x) => x.id === b.family);
  if (!f) return bad('family', `${JSON.stringify(b.family)} isn't a setup family (${FX.families.map((x) => x.id).join(', ')})`);
  if (!['syslog', 'trap', 'poll', 'flow'].includes(b.what)) return bad('what', `${JSON.stringify(b.what)} isn't syslog, trap, poll or flow`);
  if (!f.what.includes(b.what)) return bad('what', `the ${f.label} family has no ${b.what} snippet (it has ${f.what.join(', ')})`);
  const ts = f.transports[b.what] ?? [];
  const transport = b.transport || ts[0];
  if (!ts.includes(transport)) return bad('transport', `${JSON.stringify(transport)} isn't one of ${ts.join(', ')} for ${b.what}`);
  const allowed = (f.choices[b.what] ?? []).filter((c) => transport === 'v3' || !V3.includes(c));
  for (const c of ORDER) {
    const v = b[c];
    const given = c === 'agent_port' ? v !== undefined : !!v;
    if (given && !(allowed as string[]).includes(c)) return bad(c, `doesn't apply to ${b.family} ${b.what} (${transport})`);
  }

  // The address, as Generate parses it.
  let kind: Kind = 'ipv4';
  let addr = '';
  if (b.address !== undefined && b.address !== '') {
    const a = b.address;
    if (a.includes(':') && a.includes('%')) return bad('address', "an address with a zone (%) can't go in a device's configuration");
    const v4 = ipv4(a);
    const v6 = v4 ? null : ipv6(a);
    if (v4) addr = v4;
    else if (v6) [kind, addr] = [ipv4(v6) ? 'ipv4' : 'ipv6', v6];
    else if (a.length <= 253 && HOSTNAME.test(a) && /[a-zA-Z-]/.test(a)) [kind, addr] = ['name', a.toLowerCase().replace(/\.$/, '')];
    else return bad('address', `${quote(a)} isn't an IP address or a host name`);
  }
  if (b.what === 'syslog') {
    if (b.severity && !FX.choices.severities.includes(b.severity)) return bad('severity', `${JSON.stringify(b.severity)} isn't one of ${FX.choices.severities.join(', ')}`);
    if (b.facility && !FX.choices.facilities.includes(b.facility)) return bad('facility', `${JSON.stringify(b.facility)} isn't local0 to local7`);
  }
  for (const k of ['source_interface', 'interface'] as const) {
    const v = b[k];
    if (v && !IFACE.test(v)) return bad(k, `${JSON.stringify(v)} isn't an interface name (letters, digits and / . _ : @ -, at most 64)`);
  }
  if (transport === 'v3') {
    if (b.v3_user && !USER.test(b.v3_user)) return bad('v3_user', `${JSON.stringify(b.v3_user)} isn't a user name (letters, digits and . _ -, at most 32)`);
    if (b.auth && !FX.choices.auths.includes(b.auth)) return bad('auth', `${JSON.stringify(b.auth)} isn't one of ${FX.choices.auths.join(', ')}`);
    if (b.priv && !FX.choices.privs.includes(b.priv)) return bad('priv', `${JSON.stringify(b.priv)} isn't one of ${FX.choices.privs.join(', ')}`);
  }
  if (b.agent_port !== undefined && !(Number.isInteger(b.agent_port) && b.agent_port >= 1 && b.agent_port <= 65535)) return bad('agent_port', 'must be 1 to 65535');

  const s: Snippet = structuredClone(FX.snippets[`${b.family}/${b.what}/${transport}`][kind]);
  if (addr && addr !== FX.samples[kind]) {
    const swap = (t: string) => t.replaceAll(FX.samples[kind], addr);
    s.text = swap(s.text);
    s.does = swap(s.does);
    s.check = swap(s.check);
    s.parts = s.parts.map((p) => ({ ...p, text: swap(p.text) }));
    s.notes = s.notes.map(swap);
    s.address = addr;
  }
  return { status: 200, body: s };
}
