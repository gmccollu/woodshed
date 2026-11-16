// The setup helper's routes in mock mode, from setup-fixture.json, which internal/setuphelper's
// TestMockFixture generates from the real templates (so the mock never drifts from them). The
// fixture holds each family, data type and transport with the default choices; the mock applies
// the address the form picks and validates the choices as the server does, but doesn't re-render
// the other choices (severity, interface…) into the text.
import fixture from './setup-fixture.json';
import type { SetupFamily, Snippet, SnippetBody } from '../setup';

const FX = fixture as unknown as { families: SetupFamily[]; snippets: Record<string, Snippet> };

type Reply = { status: number; body: unknown };
const bad = (field: string, msg: string): Reply => ({ status: 400, body: { error: `${field}: ${msg}`, errors: { [field]: msg } } });

export function setupFamilies(): SetupFamily[] {
  return FX.families;
}

export function setupSnippet(b: SnippetBody): Reply {
  const f = FX.families.find((x) => x.id === b.family);
  if (!f) return bad('family', `"${b.family}" isn't a setup family`);
  if (!f.what.includes(b.what)) return bad('what', `the ${f.label} family has no ${b.what} snippet`);
  const transport = b.transport || f.transports[b.what]![0];
  if (!f.transports[b.what]!.includes(transport)) return bad('transport', `"${transport}" isn't one of ${f.transports[b.what]!.join(', ')}`);
  const s: Snippet = structuredClone(FX.snippets[`${b.family}/${b.what}/${transport}`]);
  const addr = b.address?.trim();
  if (addr) {
    if (!/^[A-Za-z0-9.:-]+$/.test(addr)) return bad('address', `"${addr}" isn't an IP address or a host name`);
    const swap = (t: string) => t.replaceAll(s.address, addr);
    s.text = swap(s.text);
    s.parts = s.parts.map((p) => ({ ...p, text: swap(p.text) }));
    s.notes = s.notes.map(swap);
    s.address = addr;
  }
  for (const [k, v] of Object.entries(b)) {
    if (['family', 'what', 'transport', 'address'].includes(k) || v === undefined) continue;
    const ok = (f.choices[b.what] ?? []).includes(k as never) && (transport === 'v3' || !['v3_user', 'auth', 'priv'].includes(k));
    if (!ok) return bad(k, `doesn't apply to ${b.family} ${b.what} (${transport})`);
  }
  return { status: 200, body: s };
}
