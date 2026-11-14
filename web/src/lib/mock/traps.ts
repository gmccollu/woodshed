// Stored SNMP traps for mock mode (SPEC §11.2.4, docs/api.md → Data types: type=trap). Trap i
// was received at i × TRAP_STEP ms and is generated from a seed of i, like the syslog history,
// so search, the summary and context give the same records every time. Generic examples
// only: documentation addresses and enterprise 32473 (RFC 5612).

import type { FieldDescriptor, TrapFields, TrapResult, TrapVarbind } from '../api';
import { matchTerms, parseTerms, TERMS_AND_REGEX } from '../terms';

/** One trap every 150 s across the trap senders: 576 a day. */
export const TRAP_STEP = 150_000;
/** Trap history goes back this far. */
export const TRAP_DAYS = 14;

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

// ----- the mock MIB set: the built-in names plus an example module from the MIB folder -----

interface MibName {
  name: string;
  module: string;
  kind: 'notification' | 'object';
  enums?: Record<number, string>;
}

const UPDOWN = { 1: 'up', 2: 'down', 3: 'testing' };
export const MIB: Record<string, MibName> = {
  '1.3.6.1.6.3.1.1.5.1': { name: 'coldStart', module: 'SNMPv2-MIB', kind: 'notification' },
  '1.3.6.1.6.3.1.1.5.2': { name: 'warmStart', module: 'SNMPv2-MIB', kind: 'notification' },
  '1.3.6.1.6.3.1.1.5.3': { name: 'linkDown', module: 'IF-MIB', kind: 'notification' },
  '1.3.6.1.6.3.1.1.5.4': { name: 'linkUp', module: 'IF-MIB', kind: 'notification' },
  '1.3.6.1.6.3.1.1.5.5': { name: 'authenticationFailure', module: 'SNMPv2-MIB', kind: 'notification' },
  '1.3.6.1.2.1.1.3': { name: 'sysUpTime', module: 'SNMPv2-MIB', kind: 'object' },
  '1.3.6.1.2.1.1.5': { name: 'sysName', module: 'SNMPv2-MIB', kind: 'object' },
  '1.3.6.1.2.1.2.2.1.1': { name: 'ifIndex', module: 'IF-MIB', kind: 'object' },
  '1.3.6.1.2.1.2.2.1.2': { name: 'ifDescr', module: 'IF-MIB', kind: 'object' },
  '1.3.6.1.2.1.2.2.1.7': { name: 'ifAdminStatus', module: 'IF-MIB', kind: 'object', enums: UPDOWN },
  '1.3.6.1.2.1.2.2.1.8': { name: 'ifOperStatus', module: 'IF-MIB', kind: 'object', enums: UPDOWN },
  '1.3.6.1.4.1.32473.1.0.1': { name: 'exampleBatteryLow', module: 'EXAMPLE-POWER-MIB', kind: 'notification' },
  '1.3.6.1.4.1.32473.1.0.2': { name: 'exampleFanFailure', module: 'EXAMPLE-POWER-MIB', kind: 'notification' },
  '1.3.6.1.4.1.32473.1.1.1': { name: 'exampleBatteryCharge', module: 'EXAMPLE-POWER-MIB', kind: 'object' },
  '1.3.6.1.4.1.32473.1.1.2': { name: 'exampleBatteryStatus', module: 'EXAMPLE-POWER-MIB', kind: 'object', enums: { 1: 'normal', 2: 'low', 3: 'depleted' } },
  '1.3.6.1.4.1.32473.1.1.3': { name: 'exampleFanIndex', module: 'EXAMPLE-POWER-MIB', kind: 'object' },
};
const BY_NAME = new Map(Object.entries(MIB).map(([oid, m]) => [m.name.toLowerCase(), oid]));

/** An OID's name: its own, or the object it's an instance of plus the index ("ifOperStatus.3"). */
export function oidName(oid: string): string {
  const own = MIB[oid];
  if (own) return own.name;
  const parts = oid.split('.');
  for (let k = parts.length - 1; k > 0; k--) {
    const m = MIB[parts.slice(0, k).join('.')];
    if (m) return m.kind === 'object' ? `${m.name}.${parts.slice(k).join('.')}` : '';
  }
  return '';
}

function objectOf(oid: string): MibName | undefined {
  const parts = oid.split('.');
  for (let k = parts.length; k > 0; k--) {
    const m = MIB[parts.slice(0, k).join('.')];
    if (m) return m;
  }
  return undefined;
}

/** A MIB name ("linkDown", "IF-MIB::linkDown") as its OID, or null. */
export function lookupName(name: string): string | null {
  const bare = name.includes('::') ? name.split('::')[1] : name;
  return BY_NAME.get(bare.toLowerCase()) ?? null;
}

export const MIB_FILES = 3;
export const MIB_NAMES = 18_234;

// ----- senders and the trap each one sends -----

type Kind = 'link' | 'inform' | 'cold' | 'v1spec' | 'battery' | 'authfail' | 'malformed' | 'fan';

interface TrapSender {
  ip: string;
  weight: number;
  kinds: [Kind, number][];
}

export const TRAP_SENDERS: TrapSender[] = [
  { ip: '10.1.0.1', weight: 6, kinds: [['link', 8], ['fan', 1]] }, // v3 authPriv, user monitor
  { ip: '10.1.0.10', weight: 10, kinds: [['link', 10]] }, // v2c
  { ip: '10.1.0.11', weight: 6, kinds: [['inform', 6], ['link', 3]] }, // v2c informs
  { ip: '10.8.0.5', weight: 4, kinds: [['cold', 1], ['v1spec', 3], ['malformed', 1]] }, // v1
  { ip: '10.1.0.40', weight: 5, kinds: [['battery', 5], ['v1spec', 1]] }, // trap-only: a UPS
  { ip: '198.51.100.7', weight: 2, kinds: [['authfail', 1]] }, // trap-only: wrong v3 passphrase
];
const TOTAL = TRAP_SENDERS.reduce((s, d) => s + d.weight, 0);

/** The trap-only senders, for the mock fleet (they have no syslog). */
export const TRAP_ONLY = [
  { ip: '10.1.0.40', name: 'ups-01', group: 'HQ' },
  { ip: '198.51.100.7', name: '', group: '' },
];

export const COMMUNITY_HASH = '#3f9a1c07';
const ENGINE_FW = '80007e5e03021a2b3c4d5e';

const pickW = <T>(r: () => number, list: [T, number][]): T => {
  let x = r() * list.reduce((s, [, w]) => s + w, 0);
  for (const [v, w] of list) {
    x -= w;
    if (x <= 0) return v;
  }
  return list[list.length - 1][0];
};

export function senderAt(i: number): TrapSender {
  let r = mulberry32(i * 2246822519)() * TOTAL;
  for (const d of TRAP_SENDERS) {
    r -= d.weight;
    if (r <= 0) return d;
  }
  return TRAP_SENDERS[TRAP_SENDERS.length - 1];
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function fakeRaw(r: () => number, n: number): string {
  let s = 'MI';
  for (let k = 0; k < n; k++) s += B64[Math.floor(r() * 64)];
  return s.slice(0, Math.floor(s.length / 4) * 4);
}

const vb = (oid: string, type: string, value: string): TrapVarbind => {
  const name = oidName(oid);
  const en = type === 'int' ? objectOf(oid)?.enums?.[Number(value)] : undefined;
  return { oid, name, type, value, ...(en ? { value_name: en } : {}) };
};

export interface StoredTrap {
  i: number;
  ms: number;
  ip: string;
  fields: TrapFields;
  /** The stored record line (SPEC §11.2.4), as /api/search returns it in raw. */
  raw: string;
}

const UPTIME_BASE = 8_641_234;

/** Trap i, as stored. */
export function trapAt(i: number): StoredTrap {
  const d = senderAt(i);
  const r = mulberry32(i ^ 0x2f6b9a13);
  const kind = pickW(r, d.kinds);
  const ms = i * TRAP_STEP + Math.floor(r() * 1000);
  const uptime = UPTIME_BASE + (i % 100_000) * 1500;
  const base: TrapFields = {
    version: '2c', pdu: 'trap', trap_oid: '', trap_name: '', enterprise: '', generic: null, specific: null,
    cred: COMMUNITY_HASH, status: 'ok', error: '', uptime, dup: false, varbinds: [],
  };
  let f: TrapFields;
  let id = String(1000 + (i % 90_000));
  const v3 = d.ip === '10.1.0.1';
  switch (kind) {
    case 'link': {
      const port = 1 + Math.floor(r() * 24);
      const down = r() < 0.55;
      const oid = down ? '1.3.6.1.6.3.1.1.5.3' : '1.3.6.1.6.3.1.1.5.4';
      f = {
        ...base, ...(v3 ? { version: '3', cred: 'monitor' } : {}), trap_oid: oid,
        varbinds: [
          vb(`1.3.6.1.2.1.2.2.1.1.${port}`, 'int', String(port)),
          vb(`1.3.6.1.2.1.2.2.1.7.${port}`, 'int', '1'),
          vb(`1.3.6.1.2.1.2.2.1.8.${port}`, 'int', down ? '2' : '1'),
          vb(`1.3.6.1.2.1.2.2.1.2.${port}`, 'str', `port ${port}`),
        ],
      };
      break;
    }
    case 'inform': {
      const port = 1 + Math.floor(r() * 48);
      const down = r() < 0.5;
      f = {
        ...base, pdu: 'inform', trap_oid: down ? '1.3.6.1.6.3.1.1.5.3' : '1.3.6.1.6.3.1.1.5.4', dup: r() < 0.08,
        varbinds: [vb(`1.3.6.1.2.1.2.2.1.1.${port}`, 'int', String(port)), vb(`1.3.6.1.2.1.2.2.1.8.${port}`, 'int', down ? '2' : '1')],
      };
      break;
    }
    case 'cold':
      id = '';
      f = { ...base, version: '1', pdu: 'v1trap', enterprise: '1.3.6.1.4.1.32473.1', generic: 0, specific: 0, trap_oid: '1.3.6.1.6.3.1.1.5.1', uptime: 312 + Math.floor(r() * 400) };
      break;
    case 'v1spec':
      id = '';
      f = {
        ...base, version: '1', pdu: 'v1trap', enterprise: '1.3.6.1.4.1.32473.1', generic: 6, specific: 1, trap_oid: '1.3.6.1.4.1.32473.1.0.1',
        varbinds: [vb('1.3.6.1.4.1.32473.1.1.1.0', 'g32', String(5 + Math.floor(r() * 20)))],
      };
      break;
    case 'battery': {
      const charge = 3 + Math.floor(r() * 30);
      f = {
        ...base, trap_oid: '1.3.6.1.4.1.32473.1.0.1',
        varbinds: [vb('1.3.6.1.4.1.32473.1.1.1.0', 'g32', String(charge)), vb('1.3.6.1.4.1.32473.1.1.2.0', 'int', charge < 10 ? '3' : '2')],
      };
      break;
    }
    case 'fan':
      f = {
        ...base, version: '3', cred: 'monitor', trap_oid: '1.3.6.1.4.1.32473.1.0.2',
        varbinds: [vb('1.3.6.1.4.1.32473.1.1.3.0', 'int', String(1 + Math.floor(r() * 4))), vb('1.3.6.1.2.1.1.5.0', 'str', 'edge-fw-01')],
      };
      break;
    case 'authfail':
      f = { ...base, version: '3', cred: 'monitor', status: 'auth_failed', error: 'wrong digest (sha-256)', uptime: null };
      break;
    default:
      f = { ...base, status: 'malformed', error: 'BER: length 812 runs past the end of the datagram (at byte 41)', uptime: null };
  }
  if (f.version === '1') id = '';
  return { i, ms, ip: d.ip, fields: f, raw: recordLine(f, id, fakeRaw(r, 80 + Math.floor(r() * 120))) };
}

const named = (oid: string) => {
  const n = oidName(oid);
  return n ? `${oid}(${n})` : oid;
};
const vbText = (v: TrapVarbind) => {
  const val = v.type === 'str' ? JSON.stringify(v.value) : v.value;
  return `vb=${named(v.oid)}:${v.type}:${val}${v.value_name ? `(${v.value_name})` : ''}`;
};

/** The record line, in the keys' order (SPEC §11.2.4). */
export function recordLine(f: TrapFields, id: string, raw: string): string {
  const k: string[] = [`v=${f.version}`, `pdu=${f.pdu}`];
  if (id) k.push(`id=${id}`);
  if (f.dup) k.push('dup=1');
  k.push(`cred=${f.cred}`);
  if (f.version === '3') k.push('level=authPriv', `engine=${ENGINE_FW}`);
  k.push(`status=${f.status}`);
  if (f.error) k.push(`error=${JSON.stringify(f.error)}`);
  if (f.version === '1') k.push(`enterprise=${f.enterprise}`, 'agent=10.8.0.5', `generic=${f.generic}`, `specific=${f.specific}`);
  if (f.uptime !== null && f.status === 'ok') k.push(`uptime=${f.uptime}`);
  if (f.trap_oid) k.push(`trap=${named(f.trap_oid)}`);
  for (const v of f.varbinds) k.push(vbText(v));
  k.push(`raw=${raw}`);
  return k.join(' ');
}

/** The record without its raw= (what q and the field values read, SPEC §11.2.4). */
export const recordText = (rec: string) => {
  const i = rec.lastIndexOf(' raw=');
  return i < 0 ? rec : rec.slice(0, i);
};

// ----- the schema (docs/api.md → Data types) -----

const GENERIC = ['coldStart', 'warmStart', 'linkDown', 'linkUp', 'authenticationFailure', 'egpNeighborLoss', 'enterpriseSpecific'];
export const STATUSES = ['ok', 'malformed', 'unexpected_pdu', 'unknown_user', 'unknown_engine', 'not_in_time', 'auth_failed', 'decrypt_failed', 'level'];
const STATUS_LABEL: Record<string, string> = { auth_failed: 'wrong auth', unexpected_pdu: 'unexpected PDU', not_in_time: 'not in time', decrypt_failed: "couldn't decrypt", level: 'below level', unknown_user: 'unknown user', unknown_engine: 'unknown engine' };

export const TRAP_SCHEMA: { type: string; label: string; default: boolean; fields: FieldDescriptor[] } = {
  type: 'trap',
  label: 'SNMP traps',
  default: false,
  fields: [
    { key: 'device', label: 'Device', param: 'devices', exclude_param: 'exclude_devices', domain: null },
    { key: 'version', label: 'Version', param: 'snmp_versions', exclude_param: '', domain: [{ value: '1', label: 'v1' }, { value: '2c', label: 'v2c' }, { value: '3', label: 'v3' }] },
    {
      key: 'pdu', label: 'PDU', param: 'pdus', exclude_param: '',
      domain: [{ value: 'v1trap', label: 'v1 trap' }, { value: 'trap', label: 'trap' }, { value: 'inform', label: 'inform' }, { value: 'unexpected', label: 'other PDU' }],
    },
    { key: 'trap_oid', label: 'Trap', param: 'trap_oid', exclude_param: 'exclude_trap_oid', domain: null },
    { key: 'enterprise', label: 'Enterprise (v1)', param: 'enterprise', exclude_param: 'exclude_enterprise', domain: null },
    { key: 'generic', label: 'Generic trap (v1)', param: 'generic', exclude_param: '', domain: GENERIC.map((label, v) => ({ value: String(v), label })) },
    { key: 'specific', label: 'Specific trap (v1)', param: 'specific', exclude_param: 'exclude_specific', domain: null },
    { key: 'cred', label: 'Community or user', param: 'cred', exclude_param: 'exclude_cred', domain: null },
    { key: 'status', label: 'Status', param: 'status', exclude_param: '', domain: STATUSES.map((value) => ({ value, label: STATUS_LABEL[value] ?? value })) },
  ],
};
export const TRAP_FIELD_KEYS = TRAP_SCHEMA.fields.map((f) => f.key);

// ----- filters -----

const SYSLOG_ONLY = ['severities', 'min_severity', 'facilities', 'app', 'host', 'exclude_app', 'exclude_host'];
/** The trap filters, refused with type=syslog (docs/api.md). */
export const TRAP_ONLY_PARAMS = ['snmp_versions', 'pdus', 'trap_oid', 'exclude_trap_oid', 'enterprise', 'exclude_enterprise', 'generic', 'specific', 'exclude_specific', 'cred', 'exclude_cred', 'status'];

const list = (u: URLSearchParams, k: string) => (u.get(k) ?? '').split(',').map((x) => x.trim()).filter(Boolean);

/** A trap filter over stored traps; a string is the 400's message. */
export interface TrapFilter {
  from: number;
  to: number;
  pass: (t: StoredTrap) => boolean;
  unfiltered: boolean;
}

type OidPat = { oid: string; prefix: boolean };

function oidPatterns(u: URLSearchParams, k: string): OidPat[] | string {
  const out: OidPat[] = [];
  for (const v of list(u, k)) {
    let s = v;
    let prefix = false;
    if (s.endsWith('.*')) {
      prefix = true;
      s = s.slice(0, -2);
    }
    if (/^\.?\d+(\.\d+)*$/.test(s)) out.push({ oid: s.replace(/^\./, ''), prefix });
    else {
      const o = lookupName(s);
      if (!o) return `${k}: unknown MIB name "${s}".`;
      out.push({ oid: o, prefix });
    }
  }
  return out;
}

const oidHit = (oid: string, ps: OidPat[]) => !!oid && ps.some((p) => oid === p.oid || (p.prefix && oid.startsWith(`${p.oid}.`)));

function setOf(u: URLSearchParams, k: string, domain: string[]): Set<string> | null | string {
  const v = list(u, k);
  if (!v.length) return null;
  if (v.includes('none')) return v.length > 1 ? `${k}: none can't be combined with other values` : new Set();
  for (const x of v) if (!domain.includes(x)) return `${k}: "${x}" isn't one of ${domain.join(', ')}.`;
  return new Set(v);
}

/** A matcher for q or exclude over the record text, as the syslog one (text, terms or regex). */
function textMatcher(v: string, syntax: string, isRe: boolean, cs: boolean): ((s: string) => boolean) | null {
  if (!v) return null;
  if (isRe) {
    let re: RegExp;
    try {
      re = new RegExp(v, cs ? '' : 'i');
    } catch (e) {
      throw new Error(`error parsing regexp: ${(e as Error).message.replace(/^Invalid regular expression: /, '')}`);
    }
    return (s) => re.test(s);
  }
  if (syntax === 'terms') {
    const n = parseTerms(v);
    return n ? (s) => matchTerms(n, s, cs) : null;
  }
  const lv = v.toLowerCase();
  return cs ? (s) => s.includes(v) : (s) => s.toLowerCase().includes(lv);
}

/**
 * Reads type=trap's parameters. devicePasses applies the device selection (the caller's: it
 * knows groups and hidden devices).
 */
export function trapFilter(u: URLSearchParams, now: number, devicePasses: (ip: string) => boolean): TrapFilter | string {
  for (const k of SYSLOG_ONLY) if (u.has(k)) return `${k}: not a filter for SNMP traps.`;
  const syntax = u.get('syntax') ?? 'text';
  if (syntax !== 'text' && syntax !== 'terms') return `syntax must be text or terms, not "${syntax}"`;
  const isRe = u.get('regex') === 'true';
  const cs = u.get('case') === 'true';
  if (isRe && syntax === 'terms') return TERMS_AND_REGEX;
  let qm: ((s: string) => boolean) | null;
  let exm: ((s: string) => boolean) | null;
  try {
    qm = textMatcher(u.get('q') ?? '', syntax, isRe, cs);
  } catch (e) {
    return (e as Error).message;
  }
  try {
    exm = textMatcher(u.get('exclude') ?? '', syntax, isRe, cs);
  } catch (e) {
    return `exclude: ${(e as Error).message}`;
  }
  const vers = setOf(u, 'snmp_versions', ['1', '2c', '3']);
  const pdus = setOf(u, 'pdus', ['v1trap', 'trap', 'inform', 'unexpected']);
  const gens = setOf(u, 'generic', ['0', '1', '2', '3', '4', '5', '6']);
  const stats = setOf(u, 'status', STATUSES);
  for (const x of [vers, pdus, gens, stats]) if (typeof x === 'string') return x;
  const oids: Record<string, OidPat[]> = {};
  for (const k of ['trap_oid', 'exclude_trap_oid', 'enterprise', 'exclude_enterprise']) {
    const p = oidPatterns(u, k);
    if (typeof p === 'string') return p;
    oids[k] = p;
  }
  const ints: Record<string, number[]> = {};
  for (const k of ['specific', 'exclude_specific']) {
    const v = list(u, k);
    for (const x of v) if (!/^-?\d+$/.test(x)) return `${k}: "${x}" is not an integer.`;
    ints[k] = v.map(Number);
  }
  const creds = list(u, 'cred').map((x) => x.toLowerCase());
  const xcreds = list(u, 'exclude_cred').map((x) => x.toLowerCase());
  const to = u.has('to') ? Date.parse(u.get('to')!) : now;
  const from = u.has('from') ? Date.parse(u.get('from')!) : to - 24 * 3600_000;
  if (Number.isNaN(from) || Number.isNaN(to)) return '"from" and "to" must be RFC 3339 times.';
  if (!(from < to)) return '"from" must be before "to".';
  const pduKey = (p: string) => (['v1trap', 'trap', 'inform'].includes(p) ? p : 'unexpected');
  const pass = (t: StoredTrap) => {
    const f = t.fields;
    if (t.ms < from || t.ms >= to || !devicePasses(t.ip)) return false;
    if (vers && !(vers as Set<string>).has(f.version)) return false;
    if (pdus && !(pdus as Set<string>).has(pduKey(f.pdu))) return false;
    if (gens && (f.generic === null || !(gens as Set<string>).has(String(f.generic)))) return false;
    if (stats && !(stats as Set<string>).has(f.status)) return false;
    if (oids.trap_oid.length && !oidHit(f.trap_oid, oids.trap_oid)) return false;
    if (oids.exclude_trap_oid.length && oidHit(f.trap_oid, oids.exclude_trap_oid)) return false;
    if (oids.enterprise.length && !oidHit(f.enterprise, oids.enterprise)) return false;
    if (oids.exclude_enterprise.length && oidHit(f.enterprise, oids.exclude_enterprise)) return false;
    if (ints.specific.length && (f.specific === null || !ints.specific.includes(f.specific))) return false;
    if (ints.exclude_specific.length && f.specific !== null && ints.exclude_specific.includes(f.specific)) return false;
    if (creds.length && !creds.includes(f.cred.toLowerCase())) return false;
    if (xcreds.length && xcreds.includes(f.cred.toLowerCase())) return false;
    const text = recordText(t.raw);
    if (qm && !qm(text)) return false;
    if (exm && exm(text)) return false;
    return true;
  };
  const unfiltered = !qm && !exm && !vers && !pdus && !gens && !stats && !Object.values(oids).some((x) => x.length) &&
    !ints.specific.length && !ints.exclude_specific.length && !creds.length && !xcreds.length;
  return { from, to, pass, unfiltered };
}

/** The result object of a stored trap. */
export const trapResult = (t: StoredTrap): TrapResult => ({
  received: new Date(t.ms).toISOString(),
  device_id: t.ip,
  type: 'trap',
  ref: `t${t.i}`,
  raw: t.raw,
  fields: t.fields,
});

/** Index range of the stored traps that can fall in [from, to). */
export function trapRange(from: number, to: number, now: number): { lo: number; hi: number } {
  const first = Math.ceil((now - TRAP_DAYS * 86_400_000) / TRAP_STEP);
  return { lo: Math.max(first, Math.floor(from / TRAP_STEP)), hi: Math.min(Math.floor(now / TRAP_STEP) - 1, Math.ceil(to / TRAP_STEP)) };
}

/** Per sender: stored traps, the first and the latest (for the device list). Cached per minute. */
let statsCache: { at: number; m: Map<string, { n: number; first: number; last: number }> } | null = null;
export function trapStats(now: number): Map<string, { n: number; first: number; last: number }> {
  if (statsCache && now - statsCache.at < 60_000) return statsCache.m;
  const { lo, hi } = trapRange(0, now, now);
  const m = new Map<string, { n: number; first: number; last: number }>();
  for (let i = lo; i <= hi; i++) {
    const ip = senderAt(i).ip;
    const ms = i * TRAP_STEP;
    const s = m.get(ip);
    if (s) {
      s.n++;
      s.last = ms;
    } else m.set(ip, { n: 1, first: ms, last: ms });
  }
  statsCache = { at: now, m };
  return m;
}

/** The field value(s) of a trap the summary counts, by field key ("" counts as none). */
export function trapFieldValue(t: StoredTrap, key: string): string {
  const f = t.fields;
  switch (key) {
    case 'device':
      return t.ip;
    case 'version':
      return f.version;
    case 'pdu':
      return ['v1trap', 'trap', 'inform'].includes(f.pdu) ? f.pdu : 'unexpected';
    case 'trap_oid':
      return f.trap_oid;
    case 'enterprise':
      return f.enterprise;
    case 'generic':
      return f.generic === null ? '' : String(f.generic);
    case 'specific':
      return f.specific === null ? '' : String(f.specific);
    case 'cred':
      return f.cred;
    case 'status':
      return f.status;
  }
  return '';
}
