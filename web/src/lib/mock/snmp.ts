// The SNMP trap receiver's state for mock mode (docs/api.md → SNMP state, SNMP v3 users):
// the engine, the counts, the MIB folder, the failing senders and the v3 users. Secrets
// sent to the user routes are only checked, never kept or returned, as on the server.

import type { SnmpFailure, SnmpMibs, SnmpState, SnmpUser, SnmpUserInput } from '../api';
import { MIB_FILES, MIB_NAMES } from './traps';

const P = new URLSearchParams(location.search);

export const snmpMock = {
  /** mock_snmp_creds=1: one user's credentials can't be decrypted here (snmp_credentials banner). */
  credsBroken: P.get('mock_snmp_creds') === '1',
  /** mock_snmp_mibs=1: a file in the MIB folder failed to load (snmp_mibs banner). */
  mibErrors: P.get('mock_snmp_mibs') === '1',
  /** Windows: the SNMP firewall rule's state (mock_snmp_firewall, default disabled, as after install). */
  firewall: P.get('mock_snmp_firewall') ?? 'disabled',
  reloads: 0,
  loadedAt: Date.now() - 3 * 3600_000,
};

const WEAK = (u: { auth: string; priv: string }) => [u.auth, u.priv].filter((p) => p === 'md5' || p === 'sha' || p === 'des');
const level = (auth: string, priv: string) => (auth === 'none' ? 'noAuthNoPriv' : priv === 'none' ? 'authNoPriv' : 'authPriv');

interface StoredUser extends SnmpUser {
  /** The mock keeps only whether a passphrase is set, never the text. */
  _authSet: boolean;
  _privSet: boolean;
}

const users = new Map<string, StoredUser>();
function addUser(u: Omit<SnmpUser, 'level' | 'weak' | 'auth_set' | 'priv_set'> & { auth_set?: boolean; priv_set?: boolean }) {
  const authSet = u.auth_set ?? u.auth !== 'none';
  const privSet = u.priv_set ?? u.priv !== 'none';
  users.set(u.name, {
    ...u,
    level: level(u.auth, u.priv),
    weak: WEAK(u),
    auth_set: authSet,
    priv_set: privSet,
    _authSet: authSet,
    _privSet: privSet,
  });
}
addUser({ name: 'monitor', auth: 'sha-256', priv: 'aes-128', key_ext: 'draft', engine_ids: [], stored: 'passphrase', readable: true });
addUser({ name: 'legacy-gear', auth: 'md5', priv: 'des', key_ext: 'draft', engine_ids: [], stored: 'passphrase', readable: true });
addUser({
  name: 'branch-ups', auth: 'sha-512', priv: 'aes-256', key_ext: 'alt', engine_ids: ['80007e5e030a01002801', '80007e5e030a01002802'],
  stored: 'localized', readable: !snmpMock.credsBroken,
});

const AUTHS = ['none', 'md5', 'sha', 'sha-224', 'sha-256', 'sha-384', 'sha-512'];
const PRIVS = ['none', 'des', 'aes-128', 'aes-192', 'aes-256'];

export const listUsers = (): SnmpUser[] =>
  [...users.values()].sort((a, b) => (a.name < b.name ? -1 : 1)).map(({ _authSet: _a, _privSet: _p, ...u }) => u);

export const unreadableUsers = () => [...users.values()].filter((u) => !u.readable).length;

/** Checks a user body; returns the server's field errors ({} when valid). */
function checkUser(b: Partial<SnmpUserInput>, prev: StoredUser | null): Record<string, string> {
  const e: Record<string, string> = {};
  const name = typeof b.name === 'string' ? b.name : '';
  const nb = new TextEncoder().encode(name).length;
  if (!nb) e.name = 'is required';
  else if (nb > 32) e.name = 'must be 1 to 32 bytes';
  if (!AUTHS.includes(b.auth ?? '')) e.auth = `must be one of ${AUTHS.join(', ')}`;
  if (!PRIVS.includes(b.priv ?? '')) e.priv = `must be one of ${PRIVS.join(', ')}`;
  else if (b.priv !== 'none' && b.auth === 'none') e.priv = 'needs an auth protocol (authPriv)';
  if (!['draft', 'alt', '', undefined].includes(b.key_ext)) e.key_ext = 'must be draft or alt';
  const pass = (k: 'auth_pass' | 'priv_pass', proto: string | undefined, prevProto: string | undefined, prevSet: boolean) => {
    if (!proto || proto === 'none') return;
    const v = b[k] ?? '';
    const n = new TextEncoder().encode(v).length;
    const keep = !!prev && prevProto === proto && prevSet && prev.readable;
    if (!n && !keep) e[k] = prev && prevProto !== proto ? 'is required when the protocol changes' : 'is required (8 to 256 bytes)';
    else if (n && (n < 8 || n > 256)) e[k] = 'must be 8 to 256 bytes (RFC 3414 §11.2)';
  };
  pass('auth_pass', b.auth, prev?.auth, !!prev?._authSet);
  pass('priv_pass', b.priv, prev?.priv, !!prev?._privSet);
  const ids = b.engine_ids ?? [];
  if (!Array.isArray(ids) || ids.length > 32) e.engine_ids = 'at most 32 engine IDs';
  else
    ids.forEach((id, i) => {
      const h = String(id).replace(/^0x/i, '').replace(/:/g, '');
      if (!/^[0-9a-f]*$/i.test(h) || h.length % 2 || h.length < 10 || h.length > 64) e[`engine_ids[${i}]`] = 'must be 5 to 32 bytes of hex';
    });
  return e;
}

export type UserResult = { status: number; body: unknown };

export function createUser(b: Partial<SnmpUserInput>): UserResult {
  const e = checkUser(b, null);
  if (Object.keys(e).length) return { status: 400, body: { error: 'Some fields need fixing.', errors: e } };
  if (users.has(b.name!)) return { status: 409, body: { error: 'A v3 user with that name already exists.' } };
  if (users.size >= 100) return { status: 400, body: { error: 'Some fields need fixing.', errors: { name: 'at most 100 users' } } };
  const ids = (b.engine_ids ?? []).map((x) => x.toLowerCase());
  addUser({ name: b.name!, auth: b.auth!, priv: b.priv!, key_ext: b.key_ext || 'draft', engine_ids: ids, stored: ids.length ? 'localized' : 'passphrase', readable: true });
  return { status: 201, body: listUsers().find((u) => u.name === b.name) };
}

export function updateUser(name: string, b: Partial<SnmpUserInput>): UserResult {
  const prev = users.get(name);
  if (!prev) return { status: 404, body: { error: 'No v3 user with that name.' } };
  const e = checkUser(b, prev);
  if (Object.keys(e).length) return { status: 400, body: { error: 'Some fields need fixing.', errors: e } };
  if (b.name !== name && users.has(b.name!)) return { status: 409, body: { error: 'A v3 user with that name already exists.' } };
  users.delete(name);
  const ids = (b.engine_ids ?? []).map((x) => x.toLowerCase());
  addUser({ name: b.name!, auth: b.auth!, priv: b.priv!, key_ext: b.key_ext || 'draft', engine_ids: ids, stored: ids.length ? 'localized' : 'passphrase', readable: true });
  return { status: 200, body: listUsers().find((u) => u.name === b.name) };
}

export function deleteUser(name: string): UserResult {
  if (!users.delete(name)) return { status: 404, body: { error: 'No v3 user with that name.' } };
  return { status: 204, body: null };
}

export function mibsJSON(dir: string): SnmpMibs {
  return {
    dir,
    files: MIB_FILES + (snmpMock.mibErrors ? 1 : 0),
    names: MIB_NAMES,
    loaded_at: new Date(snmpMock.loadedAt).toISOString(),
    errors: snmpMock.mibErrors ? [{ file: 'EXAMPLE-SENSOR-MIB.my', line: 212, message: 'unexpected token "SEQUENCE"' }] : [],
    warnings: [{ file: 'EXAMPLE-POWER-MIB.my', line: 14, message: 'import EXAMPLE-SMI not found; its names are left out' }],
  };
}

export function failures(now: number): SnmpFailure[] {
  return [
    { ip: '198.51.100.7', count_24h: 25 + Math.floor((now / 60_000) % 7), last_seen: new Date(now - 4 * 60_000).toISOString(), status: 'auth_failed',
      detail: 'user monitor: wrong digest (sha-256)', device_id: '198.51.100.7', time_resyncs_24h: 0 },
    { ip: '10.8.0.5', count_24h: 4, last_seen: new Date(now - 47 * 60_000).toISOString(), status: 'malformed',
      detail: 'BER: length 812 runs past the end of the datagram (at byte 41)', device_id: '10.8.0.5', time_resyncs_24h: 0 },
    { ip: '10.1.0.1', count_24h: 2, last_seen: new Date(now - 5 * 3600_000).toISOString(), status: 'not_in_time',
      detail: 'engine 80007e5e03021a2b3c4d5e: boots 3 time 41 outside the window; clock relearned', device_id: '10.1.0.1', time_resyncs_24h: 2 },
  ];
}

export function snmpState(o: { enabled: boolean; port: number; mibDir: string; windows: boolean; started: number; now: number }): SnmpState {
  const fw = !o.windows ? 'unknown' : snmpMock.firewall;
  return {
    enabled: o.enabled,
    port: o.port,
    engine: { id: '8000000005a1b2c3d4e5f60718', boots: 12, time: Math.floor((o.now - o.started) / 1000) },
    counts_24h: {
      received: 15_230,
      informs_answered: 2_112,
      replies_rate_limited: 0,
      discovery_reports: 3,
      time_resyncs: 2,
      by_status: { ok: 15_199, malformed: 4, auth_failed: 25, not_in_time: 2 },
    },
    mibs: mibsJSON(o.mibDir),
    firewall: { state: fw, command: o.windows && fw !== 'ok' ? 'woodshed snmp on' : '' },
  };
}
