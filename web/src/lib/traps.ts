// SNMP traps in the UI (SPEC §11.2.5, docs/api.md → Data types: type=trap): the Events type
// switch and the trap filters in the page URL, the one-line varbind summary of a result, and
// the plain words for statuses and v3 protocols. No Svelte state and no imports with side
// effects, so `npm test` can run it under Node.

import type { FieldDescriptor, SavedQuery, TrapFields, TrapVarbind } from './api';

export const SYSLOG = 'syslog';
export const TRAP = 'trap';

/** The page URL's type= (absent: syslog, as every 1.1 link). Unknown values open syslog. */
export function typeFromQuery(q: URLSearchParams, known: string[] = [SYSLOG, TRAP]): string {
  const t = q.get('type') ?? '';
  return t && known.includes(t) ? t : SYSLOG;
}

export function typeToQuery(t: string, q: URLSearchParams): void {
  if (t && t !== SYSLOG) q.set('type', t);
}

/**
 * A non-syslog type's own filters, by parameter name ({trap_oid: ["linkDown"], status: ["ok"]}).
 * Empty lists are left out, so two equal filter sets compare equal.
 */
export type TypeFilters = Record<string, string[]>;

/** The parameter names a type's fields filter with (include and exclude), less the device ones the page handles itself. */
export function filterParams(fields: FieldDescriptor[]): string[] {
  const out: string[] = [];
  for (const f of fields) {
    for (const p of [f.param, f.exclude_param]) if (p && p !== 'devices' && p !== 'exclude_devices' && !out.includes(p)) out.push(p);
  }
  return out;
}

const split = (s: string) =>
  s
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);

/** In the page URL each filter is its API parameter: #/events?type=trap&trap_oid=linkDown,linkUp&status=ok. */
export function filtersToQuery(f: TypeFilters, q: URLSearchParams): void {
  for (const k of Object.keys(f).sort()) if (f[k]?.length) q.set(k, f[k].join(','));
}

export function filtersFromQuery(q: URLSearchParams, params: string[]): TypeFilters {
  const out: TypeFilters = {};
  for (const p of params) {
    const v = split(q.get(p) ?? '');
    if (v.length) out[p] = v;
  }
  return out;
}

/** f without empty lists, with keys sorted (for comparing and saving). */
export function cleanFilters(f: TypeFilters): TypeFilters {
  const out: TypeFilters = {};
  for (const k of Object.keys(f).sort()) if (f[k]?.length) out[k] = [...f[k]];
  return out;
}

/** The trap filters a saved query holds: every list-valued key that's one of the type's parameters. */
export function filtersOfSaved(q: SavedQuery, params: string[]): TypeFilters {
  const out: TypeFilters = {};
  for (const p of params) {
    const v = q[p];
    if (Array.isArray(v) && v.length) out[p] = v.map(String);
  }
  return out;
}

/** An OID or name ignoring case, for comparing an open field's values ("linkDown" and "linkdown" are one). */
const key = (x: string) => x.toLowerCase();

/** Includes v for an open field: added to `param`, taken out of `exclude_param`. */
export function includeValue(f: TypeFilters, param: string, exParam: string, v: string): TypeFilters {
  const out = { ...f };
  const cur = out[param] ?? [];
  if (!cur.some((x) => key(x) === key(v))) out[param] = [...cur, v];
  if (exParam && out[exParam]) out[exParam] = out[exParam].filter((x) => key(x) !== key(v));
  return cleanFilters(out);
}

/** Leaves v out for an open field: added to `exclude_param`, taken out of `param`. */
export function excludeValue(f: TypeFilters, param: string, exParam: string, v: string): TypeFilters {
  const out = { ...f };
  const cur = out[exParam] ?? [];
  if (!cur.some((x) => key(x) === key(v))) out[exParam] = [...cur, v];
  if (out[param]) out[param] = out[param].filter((x) => key(x) !== key(v));
  return cleanFilters(out);
}

/** Removes one value from one parameter. */
export function removeValue(f: TypeFilters, param: string, v: string): TypeFilters {
  return cleanFilters({ ...f, [param]: (f[param] ?? []).filter((x) => key(x) !== key(v)) });
}

// ----- results -----

/** A varbind's value as the one-line summary shows it: the MIB's named value if any, strings quoted. */
export function varbindValue(vb: TrapVarbind): string {
  if (vb.value_name) return vb.value_name;
  switch (vb.type) {
    case 'str':
      return JSON.stringify(vb.value);
    case 'null':
    case 'nosuchobject':
    case 'nosuchinstance':
    case 'endofmibview':
      return vb.type;
    case 'hex':
    case 'opaque':
      return `0x${vb.value}`;
  }
  return vb.value;
}

/** "ifIndex.3=3 ifAdminStatus.3=up ifOperStatus.3=down": every varbind, by name (or OID), on one line. */
export function varbindLine(vbs: TrapVarbind[]): string {
  return vbs.map((vb) => `${vb.name || vb.oid}=${varbindValue(vb)}`).join(' ');
}

/** What a trap result is called: its trap name, else the trap OID, else (no notification) the PDU or status. */
export function trapTitle(f: TrapFields): string {
  if (f.trap_name) return f.trap_name;
  if (f.trap_oid) return f.trap_oid;
  if (f.status && f.status !== 'ok') return STATUS_LABELS[f.status] ?? f.status;
  return f.pdu || '(no trap OID)';
}

/** "v2c trap", "v1 trap", "v3 inform", "v2c inform (retransmitted)". */
export function pduLabel(f: TrapFields): string {
  const v = f.version ? `v${f.version}` : '';
  const pdu = f.pdu === 'v1trap' ? 'trap' : f.pdu || '';
  return [v, pdu].filter(Boolean).join(' ') + (f.dup ? ' (retransmitted)' : '');
}

/** The status values in plain words (SPEC §11.2.2). */
export const STATUS_LABELS: Record<string, string> = {
  ok: 'ok',
  malformed: 'malformed packet',
  unexpected_pdu: 'unexpected PDU',
  unknown_user: 'unknown v3 user',
  unknown_engine: 'unknown engine ID',
  not_in_time: 'outside the time window',
  auth_failed: 'wrong auth (digest)',
  decrypt_failed: "couldn't decrypt",
  level: 'below the user’s security level',
};
export const statusLabel = (s: string): string => STATUS_LABELS[s] ?? s;

/** A status that means the trap's content couldn't be read or trusted. */
export const isFailure = (s: string): boolean => !!s && s !== 'ok';

/** SNMP TimeTicks (hundredths of a second) as "12d 3h 04m 05s". */
export function ticks(t: number | null): string {
  if (t === null || !Number.isFinite(t)) return '';
  let s = Math.floor(t / 100);
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  const p = (n: number) => String(n).padStart(2, '0');
  return d ? `${d}d ${h}h ${p(m)}m ${p(s)}s` : h ? `${h}h ${p(m)}m ${p(s)}s` : `${m}m ${p(s)}s`;
}

// ----- v3 users (Settings) -----

export const AUTHS = ['none', 'md5', 'sha', 'sha-224', 'sha-256', 'sha-384', 'sha-512'] as const;
export const PRIVS = ['none', 'des', 'aes-128', 'aes-192', 'aes-256'] as const;

const AUTH_LABEL: Record<string, string> = {
  none: 'None',
  md5: 'MD5',
  sha: 'SHA-1',
  'sha-224': 'SHA-224',
  'sha-256': 'SHA-256',
  'sha-384': 'SHA-384',
  'sha-512': 'SHA-512',
};
const PRIV_LABEL: Record<string, string> = { none: 'None', des: 'DES', 'aes-128': 'AES-128', 'aes-192': 'AES-192', 'aes-256': 'AES-256' };
export const authLabel = (a: string) => AUTH_LABEL[a] ?? a;
export const privLabel = (p: string) => PRIV_LABEL[p] ?? p;

/** MD5, SHA-1 and DES: allowed (older gear uses them) and labelled weak (SPEC §11.2.2). */
export const isWeak = (proto: string) => proto === 'md5' || proto === 'sha' || proto === 'des';

/** AES-192 and AES-256 come in two key-extension methods; each user picks one. */
export const needsKeyExt = (priv: string) => priv === 'aes-192' || priv === 'aes-256';

/** The security level a user's protocols give. */
export function levelOf(auth: string, priv: string): 'noAuthNoPriv' | 'authNoPriv' | 'authPriv' {
  if (auth === 'none') return 'noAuthNoPriv';
  return priv === 'none' ? 'authNoPriv' : 'authPriv';
}

/** Client-side checks of a user form, with the server's limits (docs/api.md → SNMP v3 users). Keys as the server's errors. */
export function userErrors(u: {
  name: string;
  auth: string;
  priv: string;
  auth_pass: string;
  priv_pass: string;
  engine_ids: string[];
  /** Editing: an empty passphrase keeps the stored one unless the protocol changed. */
  keepAuth: boolean;
  keepPriv: boolean;
}): Record<string, string> {
  const e: Record<string, string> = {};
  const nb = new TextEncoder().encode(u.name).length;
  if (!nb) e.name = 'Give the user a name.';
  else if (nb > 32) e.name = 'At most 32 bytes.';
  if (u.priv !== 'none' && u.auth === 'none') e.priv = 'Privacy needs authentication too: pick an auth protocol.';
  const pass = (k: 'auth_pass' | 'priv_pass', v: string, need: boolean, keep: boolean) => {
    const n = new TextEncoder().encode(v).length;
    if (!need) return;
    if (!n && !keep) e[k] = 'Required (8 to 256 bytes).';
    else if (n && (n < 8 || n > 256)) e[k] = '8 to 256 bytes.';
  };
  pass('auth_pass', u.auth_pass, u.auth !== 'none', u.keepAuth);
  pass('priv_pass', u.priv_pass, u.priv !== 'none', u.keepPriv);
  if (u.engine_ids.length > 32) e.engine_ids = 'At most 32 engine IDs.';
  u.engine_ids.forEach((id, i) => {
    const h = id.replace(/^0x/i, '').replace(/:/g, '');
    if (!/^[0-9a-f]*$/i.test(h) || h.length % 2 || h.length < 10 || h.length > 64) e[`engine_ids[${i}]`] = 'Hex, 5 to 32 bytes (10 to 64 hex digits).';
  });
  return e;
}

/** Engine IDs as typed (commas, spaces or new lines between them). */
export function parseEngineIds(s: string): string[] {
  return s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

/** A community as /api/settings shows it: "#" and 8 hex digits of its SHA-256 (the community itself is never shown). */
export const isCommunityHash = (c: string) => /^#[0-9a-f]{8}$/i.test(c);

/** The Events page's own URL keys (text, mode, devices, range, syslog filters, order, saved search, type). */
const PAGE_KEYS = new Set(['q', 're', 'syn', 'cs', 'dev', 'group', 'ug', 'r', 'from', 'to', 'sev', 'app', 'host', 'ex', 'fac', 'xdev', 'xapp', 'xhost', 'order', 'saved', 'type']);

/**
 * A non-syslog type's filters from the page URL: every key the page doesn't use itself is one
 * of the type's parameters (so the page needs no list of them, and a link works before the
 * schema has loaded).
 */
export function typeFiltersFromQuery(q: URLSearchParams): TypeFilters {
  const out: TypeFilters = {};
  for (const [k, v] of q) if (!PAGE_KEYS.has(k)) out[k] = split(v);
  return cleanFilters(out);
}

/** A saved query's keys that every type shares or syslog owns (docs/api.md → Saved searches). */
const SAVED_KEYS = new Set(['q', 'syntax', 'regex', 'case', 'exclude', 'devices', 'group', 'ungrouped', 'exclude_devices', 'severities', 'facilities',
  'app', 'exclude_app', 'host', 'exclude_host', 'order', 'range']);

/** A non-syslog saved query's own filters: its list-valued keys that aren't shared or syslog's. */
export function savedTypeFilters(q: SavedQuery): TypeFilters {
  const out: TypeFilters = {};
  for (const [k, v] of Object.entries(q)) if (!SAVED_KEYS.has(k) && Array.isArray(v)) out[k] = v.map(String);
  return cleanFilters(out);
}

/** The syslog-only keys of a saved query, which a trap search must not send (the server refuses them). */
export const SYSLOG_SAVED_KEYS = ['severities', 'facilities', 'app', 'exclude_app', 'host', 'exclude_host'] as const;
