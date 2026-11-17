// Stored history for mock search, context and exports. Line i was received at
// i × STEP ms (epoch) and is generated from a seed of i, so any page, cursor or
// context window gives the same lines every time without keeping them in memory.

import { FLEET, line, type GenLine, type MockDeviceDef } from './gen';

/** One stored line every 1.5 s across the fleet: 57,600 a day. */
export const STEP = 1500;

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Devices that have history: every fleet device (silent ones too, they sent before going quiet). */
const SENDERS: MockDeviceDef[] = FLEET.map((d) => ({ ...d, weight: d.weight || 1 }));
const TOTAL = SENDERS.reduce((s, d) => s + d.weight, 0);

/** The device for line i, cheaply, without generating the text. */
export function deviceAt(i: number): MockDeviceDef {
  let r = mulberry32(i * 2654435761)() * TOTAL;
  for (const d of SENDERS) {
    r -= d.weight;
    if (r <= 0) return d;
  }
  return SENDERS[SENDERS.length - 1];
}

/** The full line i. gen.line draws from Math.random, so swap in a seeded one while it runs. */
export function lineAt(i: number): GenLine {
  const rnd = Math.random;
  Math.random = mulberry32(i ^ 0x5bd1e995);
  try {
    const l = line(deviceAt(i), new Date(i * STEP));
    // About one in a thousand: an octet-counted frame its sender cut short (2.0 marks).
    if (i % 997 === 0 && l.raw.length > 40) {
      return { ...l, raw: l.raw.slice(0, 40), incomplete: true, frame_arrived: 40, frame_length: l.raw.length };
    }
    return l;
  } finally {
    Math.random = rnd;
  }
}

/** Share of all lines that come from these devices (for estimates). */
export function shareOf(ips: string[]): number {
  return SENDERS.filter((d) => ips.includes(d.ip)).reduce((s, d) => s + d.weight, 0) / TOTAL;
}
