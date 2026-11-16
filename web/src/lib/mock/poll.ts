// The SNMP poller for mock mode (docs/api.md → 1.3): poll targets with ETags, the test poll,
// /api/poll, and deterministic series for the device page and the Events timeline strips.
// Every value is a function of the device, the series and the time, so a bucket reads the same
// on every request. Communities sent to the routes are only checked, never kept or returned.
//
// The polled devices:
//   edge-fw-01 (10.1.0.1)   v3, 64-bit counters, CPU and memory; rebooted 2 h 7 min before the mock
//                           started (reboot=1), and its eth3 went down for 42 s 50 min before
//   core-sw-01 (10.1.0.10)  v2c, 72 interfaces with the cap at 64: 8 are left out
//   branch-fw-08 (10.8.0.1) v1: 32-bit counters, no HOST-RESOURCES; an agent restart 26 h before (reboot=?)
//   branch-fw-07 (10.7.0.1) v2c, not answering for 2.5 min (failing); mock_poll_down=1: for 2 h (backing off,
//                           the poll_unreachable banner)
//   10.9.0.1                added by address, never answered (pending; not a device yet)
// URL parameters: mock_poll_down=1 (above), mock_poll_overrun=1 (cycles skipped: the poll_overrun banner).

import type {
  PollCustom,
  PollDevicePanel,
  PollInterfaceRow,
  PollMarker,
  PollPoint,
  PollSeries,
  PollSettings,
  PollState,
  PollTarget,
  PollTargetInput,
  PollTestResult,
  PollTestStep,
  PollTimeline,
} from '../poll';
import { MAX_SERIES, targetErrors } from '../poll';

const P = new URLSearchParams(location.search);
const MIN = 60_000;
const H = 60 * MIN;
const DAY = 24 * H;
const T0 = Date.now();

export const pollMock = {
  down: P.get('mock_poll_down') === '1',
  overrun: P.get('mock_poll_overrun') === '1',
  /** Test polls in the last minute (10 a minute in all). */
  tests: [] as number[],
};

export const pollDefaults = (): PollSettings => ({
  interval_s: 60,
  timeout_ms: 2000,
  retries: 1,
  concurrency: 32,
  max_interfaces: 64,
  max_targets: 500,
  presets: ['system', 'system-info', 'interfaces'],
});

// ---------- deterministic noise ----------

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return ((h >>> 0) % 100_000) / 100_000;
}

// ---------- the polled devices ----------

interface MockIf {
  index: number;
  name: string;
  alias: string;
  speed: number; // Mb/s
  /** Share of the speed at the daily peak (0: idle). */
  load: number;
  down: boolean;
}
interface MockPolled {
  device: string;
  sysName: string;
  sysDescr: string;
  ifs: MockIf[];
  hc: boolean;
  hr: boolean;
  restart?: { at: number; reboot: '1' | '0' | '?'; detail: string };
  /** An interface down for a while: [from, to). */
  flap?: { if: string; from: number; to: number };
  /** Answering until this moment (failing since then). */
  silentFrom?: number;
  engine: string;
}

function ifs(n: number, name: (i: number) => string, speed: (i: number) => number, alias: (i: number) => string = () => ''): MockIf[] {
  return Array.from({ length: n }, (_, k) => {
    const i = k + 1;
    const idle = i % 7 === 6;
    return { index: i, name: name(i), alias: alias(i), speed: speed(i), load: idle ? 0 : 0.04 + hash(`${name(i)}load`) * 0.5, down: idle };
  });
}

const EDGE_ALIASES = ['outside', 'inside', 'dmz', 'uplink', 'guest', 'voice', 'mgmt', 'backup'];
const POLLED: Record<string, MockPolled> = {
  '10.1.0.1': {
    device: '10.1.0.1',
    sysName: 'edge-fw-01',
    sysDescr: 'Example Networks EX-2100 firewall, software 7.4.2 (build 118)',
    ifs: ifs(8, (i) => `eth${i - 1}`, (i) => (i <= 2 ? 10_000 : 1000), (i) => EDGE_ALIASES[i - 1]).map((x) => (x.name === 'eth3' ? { ...x, load: 0.35, down: false } : x)),
    hc: true,
    hr: true,
    restart: { at: T0 - 2 * H - 7 * MIN, reboot: '1', detail: 'sysUpTime and hrSystemUptime reset' },
    flap: { if: 'eth3', from: T0 - 50 * MIN, to: T0 - 50 * MIN + 42_000 },
    engine: '80001f8880a1b2c3d4',
  },
  '10.1.0.10': {
    device: '10.1.0.10',
    sysName: 'core-sw-01',
    sysDescr: 'Example Networks SW-48X switch, 72 ports, firmware 3.2.1',
    ifs: ifs(72, (i) => `gi1/0/${i}`, (i) => (i > 68 ? 40_000 : 1000), (i) => (i > 68 ? `uplink-${i - 68}` : '')),
    hc: true,
    hr: true,
    engine: '',
  },
  '10.8.0.1': {
    device: '10.8.0.1',
    sysName: 'branch-fw-08',
    sysDescr: 'Example Networks EX-200 firewall, software 6.1.9',
    ifs: ifs(4, (i) => `port${i}`, () => 100, (i) => ['wan', 'lan', 'wifi', 'spare'][i - 1]),
    hc: false,
    hr: false,
    restart: { at: T0 - 26 * H, reboot: '?', detail: 'sysUpTime reset; the device has no HOST-RESOURCES, so it may have rebooted' },
    engine: '',
  },
  '10.7.0.1': {
    device: '10.7.0.1',
    sysName: 'branch-fw-07',
    sysDescr: 'Example Networks EX-200 firewall, software 6.1.9',
    ifs: ifs(4, (i) => `port${i}`, () => 100, (i) => ['wan', 'lan', 'wifi', 'spare'][i - 1]),
    hc: true,
    hr: true,
    silentFrom: T0 - (pollMock.down ? 2 * H : 150_000),
    engine: '',
  },
};

// ---------- targets ----------

interface StoredTarget extends PollTarget {
  version_n: number;
}
const targets = new Map<string, StoredTarget>();
let nextId = 0x5c1e9a2b;

const iso = (t: number) => new Date(t).toISOString().replace(/\.\d{3}Z$/, 'Z');

function stateFor(t: PollTarget, now: number): PollTarget['state'] {
  const d = POLLED[t.device_id];
  if (!t.enabled)
    return { ...emptyState(), status: 'disabled', sys_name: d?.sysName ?? '', sys_descr: d?.sysDescr ?? '' };
  if (!d) {
    const created = Date.parse(t.state?.last_attempt ?? '') || now;
    return { ...emptyState(), status: 'pending', last_attempt: iso(Math.max(created, now - 30_000)) };
  }
  const cycle = Math.floor(now / (t.interval_s * 1000)) * t.interval_s * 1000;
  const polled = Math.min(d.ifs.length, t.interfaces === 'all' ? t.max_interfaces : t.interfaces.length);
  const base = {
    ...emptyState(),
    engine_id: t.version === '3' ? d.engine : '',
    sys_name: d.sysName,
    sys_descr: d.sysDescr,
    hc_counters: d.hc && t.version !== '1',
    host_resources: d.hr,
    interfaces_polled: polled,
    interfaces_total: d.ifs.length,
  };
  if (d.silentFrom !== undefined && now >= d.silentFrom) {
    const long = now - d.silentFrom >= 3 * t.interval_s * 1000;
    return {
      ...base,
      status: long ? 'backing_off' : 'failing',
      last_attempt: iso(cycle),
      last_ok: iso(d.silentFrom - 1000),
      failing_since: iso(d.silentFrom),
      backoff_s: long ? 600 : 0,
      error: `no answer after ${t.retries} ${t.retries === 1 ? 'retry' : 'retries'}`,
    };
  }
  return { ...base, status: 'ok', last_attempt: iso(cycle), last_ok: iso(cycle), rtt_ms: 2 + Math.round(hash(`${t.id}${cycle}`) * 9) };
}

function emptyState(): PollTarget['state'] {
  return {
    status: 'pending',
    last_attempt: null,
    last_ok: null,
    failing_since: null,
    backoff_s: 0,
    error: '',
    rtt_ms: null,
    engine_id: '',
    sys_name: '',
    sys_descr: '',
    hc_counters: false,
    host_resources: false,
    interfaces_polled: 0,
    interfaces_total: 0,
  };
}

function seed() {
  const d = pollDefaults();
  const add = (t: Partial<PollTarget> & Pick<PollTarget, 'address' | 'version'>) => {
    const id = `pt_${(nextId++).toString(16)}`;
    const full: StoredTarget = {
      id,
      port: 161,
      device_id: t.address,
      enabled: true,
      community_set: t.version !== '3',
      v3_user: '',
      interval_s: d.interval_s,
      timeout_ms: d.timeout_ms,
      retries: d.retries,
      presets: [...d.presets],
      interfaces: 'all',
      max_interfaces: d.max_interfaces,
      pinned: [],
      custom: [],
      ...t,
      state: emptyState(),
      version_n: 1,
    };
    targets.set(id, full);
  };
  add({
    address: '10.1.0.1',
    version: '3',
    v3_user: 'monitor',
    custom: [{ oid: '1.3.6.1.4.1.32473.1.2.0', kind: 'scalar', label: 'queue depth', max_rows: 0 }],
  });
  add({ address: '10.1.0.10', version: '2c', pinned: ['gi1/0/69', 'gi1/0/70'] });
  add({ address: '10.8.0.1', version: '1', interval_s: 300 });
  add({ address: '10.7.0.1', version: '2c' });
  add({ address: '10.9.0.1', version: '2c', state: { ...emptyState(), last_attempt: iso(T0 - 20_000) } });
}
seed();

const etagOf = (t: StoredTarget) => `"${t.id}-${t.version_n}"`;
function targetJSON(t: StoredTarget, now: number): PollTarget {
  const { version_n: _v, ...rest } = t;
  return { ...structuredClone(rest), state: stateFor(t, now) };
}

/** The target polling a device, if any. */
export const targetOf = (device: string) => [...targets.values()].find((t) => t.device_id === device);
/** /api/devices' polled and poll_status (docs/api.md → 1.3). */
export function devicePoll(device: string, now: number): { polled: boolean; poll_status?: string } {
  const t = targetOf(device);
  return t ? { polled: true, poll_status: stateFor(t, now).status } : { polled: false };
}
/** Devices that answer polls but have never sent anything: none in the mock (10.9.0.1 never answers). */

type Reply = { status: number; body?: unknown; headers?: Record<string, string> };
const bad = (status: number, error: string): Reply => ({ status, body: { error } });

function clean(b: PollTargetInput, prev: StoredTarget | null, d: PollSettings, forTest = false): { t?: Omit<StoredTarget, 'id' | 'state' | 'version_n'>; errors?: Record<string, string> } {
  const version = b.version ?? prev?.version;
  const input: PollTargetInput = { ...b, version: version as PollTargetInput['version'] };
  const errors = targetErrors(
    {
      ...input,
      address: input.address ?? '',
      community: version !== '3' && !prev?.community_set && input.community === undefined ? '' : input.community,
    },
    { creating: !prev, communitySet: prev?.community_set && prev.version !== '3' },
  );
  if (!['1', '2c', '3'].includes(String(version))) errors.version = 'Use "1", "2c" or "3".';
  if (version === '3' && b.v3_user && !users().includes(b.v3_user)) errors.v3_user = `No v3 user "${b.v3_user}"; add it in Settings → SNMP traps.`;
  if (b.timeout_ms !== undefined && !(b.timeout_ms >= 200 && b.timeout_ms <= 10_000)) errors.timeout_ms = 'Use 200 ms to 10 s.';
  if (b.retries !== undefined && !(Number.isInteger(b.retries) && b.retries >= 0 && b.retries <= 5)) errors.retries = 'Use 0 to 5.';
  const port = b.port ?? 161;
  const address = (b.address ?? '').trim();
  const clash = [...targets.values()].find((x) => x.address === address && x.port === port && x.id !== prev?.id);
  if (clash && !forTest && !errors.address) errors.address = `${address}:${port} is already polled.`;
  if (Object.keys(errors).length) return { errors };
  const custom: PollCustom[] = (b.custom ?? prev?.custom ?? []).map((c) => ({
    oid: c.oid.trim().replace(/^\./, ''),
    kind: c.kind === 'walk' ? 'walk' : 'scalar',
    label: c.label ?? '',
    max_rows: c.kind === 'walk' ? c.max_rows || 128 : 0,
  }));
  return {
    t: {
      address,
      port,
      device_id: (b.device_id ?? '').trim() || address,
      enabled: b.enabled ?? prev?.enabled ?? true,
      version: version as PollTarget['version'],
      community_set: version === '3' ? false : b.community !== undefined ? b.community !== '' : !!prev?.community_set,
      v3_user: version === '3' ? (b.v3_user ?? '') : '',
      interval_s: b.interval_s ?? d.interval_s,
      timeout_ms: b.timeout_ms ?? d.timeout_ms,
      retries: b.retries ?? d.retries,
      presets: b.presets ?? [...d.presets],
      interfaces: b.interfaces ?? 'all',
      max_interfaces: b.max_interfaces ?? d.max_interfaces,
      pinned: b.pinned ?? [],
      custom,
    },
  };
}

let users: () => string[] = () => [];
/** The v3 user names the targets may name (the mock's /api/snmp/users). */
export function setPollUsers(f: () => string[]) {
  users = f;
}

export function pollRoute(method: string, p: string, body: unknown, ifMatch: string | null, settings: PollSettings, now: number): Reply | null {
  if (p === '/api/poll' && method === 'GET') return { status: 200, body: pollState(now) };
  if (p === '/api/poll/targets') {
    if (method === 'GET')
      return {
        status: 200,
        body: [...targets.values()]
          .sort((a, b) => a.device_id.localeCompare(b.device_id, undefined, { numeric: true }) || a.address.localeCompare(b.address))
          .map((t) => targetJSON(t, now)),
      };
    if (method === 'POST') {
      if (targets.size >= settings.max_targets) return bad(409, `There are already ${settings.max_targets} poll targets (poll.max_targets).`);
      const c = clean((body ?? {}) as PollTargetInput, null, settings);
      if (c.errors) return { status: 400, body: { error: 'Some fields need fixing.', errors: c.errors } };
      const id = `pt_${(nextId++).toString(16)}`;
      const t: StoredTarget = { id, ...c.t!, state: { ...emptyState(), last_attempt: iso(now) }, version_n: 1 };
      targets.set(id, t);
      return { status: 201, body: targetJSON(t, now), headers: { ETag: etagOf(t) } };
    }
    return null;
  }
  const m = /^\/api\/poll\/targets\/([^/]+)$/.exec(p);
  if (m) {
    const t = targets.get(decodeURIComponent(m[1]));
    if (!t) return bad(404, 'No such poll target.');
    if (method === 'GET') return { status: 200, body: targetJSON(t, now), headers: { ETag: etagOf(t) } };
    if (method === 'DELETE') {
      targets.delete(t.id);
      return { status: 204 };
    }
    if (method === 'PUT') {
      if (ifMatch && ifMatch !== '*' && ifMatch !== etagOf(t)) return bad(409, 'This poll target changed since you loaded it.');
      const b = (body ?? {}) as PollTargetInput;
      if (b.community === '' && (b.version ?? t.version) !== '3') return { status: 400, body: { error: 'Some fields need fixing.', errors: { community: 'Enter the community, or leave it out to keep the stored one.' } } };
      const c = clean(b, t, settings);
      if (c.errors) return { status: 400, body: { error: 'Some fields need fixing.', errors: c.errors } };
      Object.assign(t, c.t);
      t.version_n++;
      return { status: 200, body: targetJSON(t, now), headers: { ETag: etagOf(t) } };
    }
    return null;
  }
  if (p === '/api/poll/test' && method === 'POST') return testRoute((body ?? {}) as PollTargetInput & { id?: string }, settings, now);
  if (p.startsWith('/api/poll/device/') && method === 'GET') return null; // handled with query params (deviceRoute)
  return null;
}

function testRoute(b: PollTargetInput & { id?: string }, settings: PollSettings, now: number): Reply {
  pollMock.tests = pollMock.tests.filter((t) => now - t < MIN);
  if (pollMock.tests.length >= 10) return { status: 429, body: { error: 'At most 10 test polls a minute; try again shortly.' }, headers: { 'Retry-After': '20' } };
  let t: PollTargetInput & { community_set?: boolean };
  if (b.id) {
    const s = targets.get(b.id);
    if (!s) return bad(404, 'No such poll target.');
    t = s;
  } else {
    const c = clean(b, null, settings, true); // a test poll isn't saved, so another target at the address is fine
    if (c.errors) return { status: 400, body: { error: 'Some fields need fixing.', errors: c.errors } };
    t = { ...c.t!, community: b.community };
  }
  pollMock.tests.push(now);
  const d = POLLED[(t.device_id || t.address) as string] ?? POLLED[t.address];
  const steps: PollTestStep[] = [];
  const rtt = (k: string) => 2 + Math.round(hash(`${t.address}${k}`) * 8);
  const timeout = `no answer after ${t.retries ?? 1} ${(t.retries ?? 1) === 1 ? 'retry' : 'retries'} (${(t.timeout_ms ?? 2000) / 1000} s timeout)`;
  const result = (exit: PollTestResult['exit']): Reply => ({ status: 200, body: { ok: exit === 'ok', exit, steps } satisfies PollTestResult });
  const silent = !d || (d.silentFrom !== undefined && now >= d.silentFrom) || b.community === 'wrong';
  if (t.version === '3') {
    if (silent) {
      steps.push({ step: 'discovery', ok: false, detail: timeout, rtt_ms: null });
      return result('no_answer');
    }
    steps.push({ step: 'discovery', ok: true, detail: `engine ${d.engine || '80001f88807e5e0a01'}, boots 7, time 7,622`, rtt_ms: rtt('disc') });
    if (t.v3_user === 'legacy-gear') {
      steps.push({ step: 'system', ok: false, detail: 'wrong digest (md5): a wrong authentication passphrase or protocol', rtt_ms: rtt('sys') });
      return result('auth');
    }
    if (t.v3_user === 'branch-ups') {
      steps.push({
        step: 'system',
        ok: false,
        detail: `user branch-ups has keys only for its listed engine IDs; add ${d.engine || '80001f88807e5e0a01'} to the user in Settings → SNMP traps`,
        rtt_ms: rtt('sys'),
      });
      return result('auth');
    }
  } else if (silent) {
    steps.push({
      step: 'system',
      ok: false,
      detail: `${timeout}. A wrong community gets no answer at all in v1 and v2c, so check it too.`,
      rtt_ms: null,
    });
    return result('no_answer');
  }
  const presets = t.presets ?? settings.presets;
  const up = d.restart ? (now - d.restart.at) / 1000 : 12 * 86400 + 3 * 3600;
  const fmtUp = up > 86400 ? `${Math.floor(up / 86400)} d ${Math.floor((up % 86400) / 3600)} h` : `${Math.floor(up / 3600)} h ${Math.floor((up % 3600) / 60)} min`;
  steps.push({ step: 'system', ok: true, detail: `${d.sysName}, up ${fmtUp}`, rtt_ms: rtt('sys') });
  if (presets.includes('system-info')) steps.push({ step: 'system_info', ok: true, detail: d.sysDescr, rtt_ms: rtt('info') });
  let partial = false;
  if (presets.includes('system')) {
    if (d.hr) steps.push({ step: 'host_resources', ok: true, detail: `CPU ${Math.round(cpuAt(d, now))} % (2 processors), memory ${Math.round(memAt(d, now))} % used`, rtt_ms: rtt('hr') });
    else {
      partial = true;
      steps.push({ step: 'host_resources', ok: false, detail: `not available on this device (${t.version === '1' ? 'noSuchName' : 'noSuchObject'})`, rtt_ms: rtt('hr') });
    }
  }
  if (presets.includes('interfaces')) {
    const max = t.interfaces === 'all' || t.interfaces === undefined ? (t.max_interfaces ?? settings.max_interfaces) : t.interfaces.length;
    const n = Math.min(d.ifs.length, max);
    const hc = d.hc && t.version !== '1';
    if (!hc) partial = true;
    steps.push({
      step: 'interfaces',
      ok: hc,
      detail: `${d.ifs.length} interfaces, ${hc ? '64-bit counters' : '32-bit counters only (rates above about 115 Mb/s at a 5-minute interval can be wrong)'}; ${n} would be polled${d.ifs.length > n ? `, ${d.ifs.length - n} left out (the cap is ${max})` : ''}`,
      rtt_ms: rtt('if'),
    });
  }
  for (const c of t.custom ?? []) {
    const known = c.oid.startsWith('1.3.6.1.4.1.32473') || c.oid.startsWith('1.3.6.1.2.1');
    if (!known) partial = true;
    steps.push({
      step: `oid ${c.oid}`,
      ok: known,
      detail: known
        ? c.kind === 'walk'
          ? `${Math.min(c.max_rows || 128, 12)} rows${c.label ? ` (${c.label})` : ''}`
          : `${c.label ? `${c.label}: ` : ''}gauge32 17`
        : 'noSuchObject: the agent has no such OID',
      rtt_ms: rtt(c.oid),
    });
  }
  return result(partial ? 'partial' : 'ok');
}

function pollState(now: number): PollState {
  const st = [...targets.values()].map((t) => stateFor(t, now));
  const failing = st.filter((s) => s.status === 'failing').length;
  const backing = st.filter((s) => s.status === 'backing_off').length;
  const answering = st.filter((s) => s.status === 'ok').length;
  const cycles = [...targets.values()].filter((t) => t.enabled).reduce((n, t) => n + Math.round(3600 / t.interval_s), 0);
  // branch-fw-07's failed cycles (one per attempt while backing off) and 10.9.0.1's, one a minute.
  const failed = (pollMock.down ? 9 : 3) + 60;
  return {
    targets: targets.size,
    answering,
    failing,
    backing_off: backing,
    last_cycle: iso(Math.floor(now / 15_000) * 15_000 + 4000 > now ? Math.floor(now / 15_000) * 15_000 - 11_000 : Math.floor(now / 15_000) * 15_000 + 4000),
    hour: {
      cycles,
      failures: { timeout: failed, ...(pollMock.overrun ? { overrun: 42 } : {}) },
      overruns: pollMock.overrun ? 42 : 0,
      unmatched: 0,
    },
  };
}

/** The poll_unreachable and poll_overrun banners (docs/api.md → 1.3). */
export function pollBanners(now: number): { kind: string; level: 'warn'; action: ''; text: string }[] {
  const out: { kind: string; level: 'warn'; action: ''; text: string }[] = [];
  const down = [...targets.values()].filter((t) => {
    const s = stateFor(t, now);
    return (s.status === 'failing' || s.status === 'backing_off') && s.failing_since && now - Date.parse(s.failing_since) >= 10 * MIN;
  });
  if (down.length) {
    const names = down.map((t) => POLLED[t.device_id]?.sysName ? `${POLLED[t.device_id].sysName} (${t.address})` : t.address);
    out.push({
      kind: 'poll_unreachable',
      level: 'warn',
      action: '',
      text: `${down.length === 1 ? '1 polled device isn’t' : `${down.length} polled devices aren’t`} answering: ${names.join(', ')}. ${down.length === 1 ? 'It hasn’t' : 'They haven’t'} answered SNMP polls for over 10 minutes.`,
    });
  }
  if (pollMock.overrun)
    out.push({
      kind: 'poll_overrun',
      level: 'warn',
      action: '',
      text: '42 poll cycles were skipped in the last hour because polling couldn’t keep up. Use a longer interval for some devices, or raise poll.concurrency in Settings → Polling.',
    });
  return out;
}

// ---------- values ----------

const day = (t: number, phase: number) => 0.55 + 0.4 * Math.sin((2 * Math.PI * (t - 9 * H)) / DAY + phase);

function answered(d: MockPolled, t: number): boolean {
  if (d.silentFrom !== undefined && t >= d.silentFrom) return false;
  if (d.restart && t >= d.restart.at - 2 * MIN && t < d.restart.at) return false; // down while it rebooted
  return true;
}

function ifBps(d: MockPolled, f: MockIf, dir: 'in' | 'out', t: number): number {
  if (f.down) return 0;
  if (d.flap && d.flap.if === f.name && t >= d.flap.from && t < d.flap.to) return 0;
  const slot = Math.floor(t / MIN);
  const base = f.speed * 1e6 * f.load * (dir === 'in' ? 1 : 0.18 + hash(`${f.name}r`) * 0.3);
  const burst = hash(`${d.device}${f.name}${dir}b${Math.floor(t / (20 * MIN))}`) > 0.93 ? 1.6 : 1;
  return Math.max(0, base * day(t, f.index) * burst * (0.85 + 0.3 * hash(`${d.device}${f.name}${dir}${slot}`)));
}
const ifErr = (d: MockPolled, f: MockIf, dir: 'in' | 'out', kind: 'err' | 'disc', t: number) => {
  if (f.down) return 0;
  const slot = Math.floor(t / MIN);
  const flapping = d.flap && d.flap.if === f.name && Math.abs(t - d.flap.from) < 3 * MIN;
  const p = hash(`${d.device}${f.name}${dir}${kind}${slot}`);
  if (flapping) return kind === 'err' ? 4 : 110;
  if (kind === 'disc' && dir === 'in' && f.index === 4) return p > 0.6 ? Math.round(p * 6) : 0;
  return p > 0.985 ? 1 + Math.round(p * 3) : 0;
};
function cpuAt(d: MockPolled, t: number): number {
  const slot = Math.floor(t / MIN);
  const afterBoot = d.restart && t >= d.restart.at && t < d.restart.at + 6 * MIN ? 45 : 0;
  const spike = hash(`${d.device}cpu${Math.floor(t / (30 * MIN))}`) > 0.9 ? 30 : 0;
  return Math.min(100, 8 + 22 * day(t, 0.3) + 6 * hash(`${d.device}cpu${slot}`) + afterBoot + spike);
}
function memAt(d: MockPolled, t: number): number {
  const since = d.restart && t >= d.restart.at ? Math.min(1, (t - d.restart.at) / (90 * MIN)) : 1;
  return 22 + 18 * since + 4 * day(t, 1.1) + 2 * hash(`${d.device}mem${Math.floor(t / MIN)}`);
}

/** The interfaces the target polls: pinned first, then up by speed, then by index (SPEC §12.11 #3). */
function polledIfs(d: MockPolled, t: PollTarget): MockIf[] {
  if (t.interfaces !== 'all') {
    const want = t.interfaces;
    return d.ifs.filter((f) => want.includes(f.name) || want.includes(f.index));
  }
  const pin = t.pinned ?? [];
  const pinned = d.ifs.filter((f) => pin.includes(f.name) || pin.includes(f.index));
  const rest = d.ifs
    .filter((f) => !pinned.includes(f))
    .sort((a, b) => Number(a.down) - Number(b.down) || b.speed - a.speed || a.index - b.index);
  return [...pinned, ...rest].slice(0, t.max_interfaces).sort((a, b) => a.index - b.index);
}

// ---------- series ----------

const HEADLINE: Record<string, { label: string; unit: string }> = {
  in_bps: { label: 'In (all interfaces)', unit: 'bit/s' },
  out_bps: { label: 'Out (all interfaces)', unit: 'bit/s' },
  max_if_in_bps: { label: 'Busiest interface in', unit: 'bit/s' },
  max_if_out_bps: { label: 'Busiest interface out', unit: 'bit/s' },
  errors_d: { label: 'Errors (all interfaces)', unit: 'count' },
  discards_d: { label: 'Discards (all interfaces)', unit: 'count' },
  cpu: { label: 'CPU', unit: '%' },
  mem_used_pct: { label: 'Memory used', unit: '%' },
  uptime_s: { label: 'Uptime', unit: 's' },
};
const IF_PARTS: Record<string, { label: string; unit: string }> = {
  in_bps: { label: 'in', unit: 'bit/s' },
  out_bps: { label: 'out', unit: 'bit/s' },
  in_err_d: { label: 'errors in', unit: 'count' },
  out_err_d: { label: 'errors out', unit: 'count' },
  in_disc_d: { label: 'discards in', unit: 'count' },
  out_disc_d: { label: 'discards out', unit: 'count' },
  oper: { label: 'oper status (1 up)', unit: 'status' },
};

type Sampler = (t: number) => number | null;

function sampler(d: MockPolled, tgt: PollTarget, key: string): Sampler | string {
  const pif = polledIfs(d, tgt);
  if (key in HEADLINE) {
    switch (key) {
      case 'in_bps':
      case 'out_bps': {
        const dir = key === 'in_bps' ? 'in' : 'out';
        return (t) => pif.reduce((s, f) => s + ifBps(d, f, dir, t), 0);
      }
      case 'max_if_in_bps':
      case 'max_if_out_bps': {
        const dir = key === 'max_if_in_bps' ? 'in' : 'out';
        return (t) => Math.max(0, ...pif.map((f) => ifBps(d, f, dir, t)));
      }
      case 'errors_d':
        return (t) => pif.reduce((s, f) => s + ifErr(d, f, 'in', 'err', t) + ifErr(d, f, 'out', 'err', t), 0);
      case 'discards_d':
        return (t) => pif.reduce((s, f) => s + ifErr(d, f, 'in', 'disc', t) + ifErr(d, f, 'out', 'disc', t), 0);
      case 'cpu':
        return d.hr ? (t) => cpuAt(d, t) : () => null;
      case 'mem_used_pct':
        return d.hr ? (t) => memAt(d, t) : () => null;
      case 'uptime_s':
        return (t) => (d.restart && t >= d.restart.at ? (t - d.restart.at) / 1000 : (t - T0) / 1000 + 12 * 86400);
    }
  }
  const m = /^if\.(.+)\.(in_bps|out_bps|in_err_d|out_err_d|in_disc_d|out_disc_d|oper)$/.exec(key);
  if (m) {
    const f = pif.find((x) => x.name === m[1] || String(x.index) === m[1]);
    if (!f) return `series: ${key}: no polled interface "${m[1]}" on this device.`;
    switch (m[2]) {
      case 'in_bps':
        return (t) => ifBps(d, f, 'in', t);
      case 'out_bps':
        return (t) => ifBps(d, f, 'out', t);
      case 'in_err_d':
        return (t) => ifErr(d, f, 'in', 'err', t);
      case 'out_err_d':
        return (t) => ifErr(d, f, 'out', 'err', t);
      case 'in_disc_d':
        return (t) => ifErr(d, f, 'in', 'disc', t);
      case 'out_disc_d':
        return (t) => ifErr(d, f, 'out', 'disc', t);
      case 'oper':
        return (t) => (f.down || (d.flap?.if === f.name && t >= d.flap.from && t < d.flap.to) ? 2 : 1);
    }
  }
  if (/^oid\.[\d.]+$/.test(key)) {
    if (!tgt.custom.some((c) => key.slice(4).startsWith(c.oid))) return `series: ${key}: not a custom OID of this device.`;
    return (t) => 12 + Math.round(10 * day(t, 2) + 6 * hash(`${key}${Math.floor(t / MIN)}`));
  }
  return `series: unknown series "${key}".`;
}

function labelOf(key: string): { label: string; unit: string } {
  if (HEADLINE[key]) return HEADLINE[key];
  const m = /^if\.(.+)\.([a-z_]+)$/.exec(key);
  if (m) return { label: `${m[1]} ${IF_PARTS[m[2]]?.label ?? m[2]}`, unit: IF_PARTS[m[2]]?.unit ?? '' };
  return { label: key, unit: 'value' };
}

/** SPEC §10.1.2: the bucket for a range, at most 120 buckets (the summary's). */
export function defaultBucket(rangeMs: number): number {
  const S = 1000, M = 60 * S, HR = 60 * M, D = 24 * HR;
  const table: [number, number][] = [[2 * M, 1], [10 * M, 5], [30 * M, 15], [2 * HR, 60], [10 * HR, 300], [30 * HR, 900], [5 * D, 3600],
    [10 * D, 7200], [30 * D, 21600], [120 * D, 86400]];
  for (const [upTo, b] of table) if (rangeMs <= upTo) return b;
  return 604800;
}
const bucketStart = (t: number, sizeMs: number) => {
  const off = sizeMs === 604_800_000 ? 4 * 86_400_000 : 0;
  return Math.floor((t - off) / sizeMs) * sizeMs + off;
};

/**
 * The points of one series: a bucket's samples are the poll cycles in it (one per interval, the
 * cycle's offset from the device's hash); avg and max over them, count 0 where none answered. Long
 * buckets read a few cycles, not every one, so a 30-day range stays fast.
 */
function points(d: MockPolled, tgt: PollTarget, f: Sampler, from: number, to: number, sizeMs: number, now: number): PollPoint[] {
  const iv = tgt.interval_s * 1000;
  const off = Math.floor(hash(tgt.id) * iv);
  const out: PollPoint[] = [];
  const end = Math.min(to, now);
  for (let b = bucketStart(from, sizeMs); b < to; b += sizeMs) {
    const lo = Math.max(b, from);
    const hi = Math.min(b + sizeMs, end);
    const first = Math.ceil((lo - off) / iv) * iv + off;
    const cycles = hi > first ? Math.ceil((hi - first) / iv) : 0;
    const stride = Math.max(1, Math.floor(cycles / 24));
    let n = 0, sum = 0, max = -Infinity;
    for (let t = first; t < hi; t += iv * stride) {
      if (!answered(d, t)) continue;
      const v = f(t);
      if (v === null) continue;
      n++;
      sum += v;
      max = Math.max(max, v);
    }
    const start = new Date(b).toISOString();
    out.push(n ? { start, avg: sum / n, max, count: Math.min(cycles, n * stride) } : { start, avg: null, max: null, count: 0 });
  }
  return out;
}

function markersFor(d: MockPolled, from: number, to: number, withOper: boolean | string[]): PollMarker[] {
  const out: PollMarker[] = [];
  if (d.restart && d.restart.at >= from && d.restart.at < to)
    out.push({ device_id: d.device, time: new Date(d.restart.at + 410).toISOString(), kind: 'restart', reboot: d.restart.reboot, detail: d.restart.detail });
  const operOK = withOper === true || (Array.isArray(withOper) && d.flap && withOper.includes(d.flap.if));
  if (d.flap && operOK) {
    for (const [t, oper] of [[d.flap.from, 'down'], [d.flap.to, 'up']] as const)
      if (t >= from && t < to) out.push({ device_id: d.device, time: new Date(t).toISOString(), kind: 'oper', if: d.flap.if, oper, detail: `${d.flap.if} ${oper}` });
  }
  return out;
}

const parseRange = (u: URLSearchParams, now: number): { from: number; to: number } | string => {
  const to = u.get('to') ? Date.parse(u.get('to')!) : now;
  const from = u.get('from') ? Date.parse(u.get('from')!) : to - DAY;
  if (Number.isNaN(from) || Number.isNaN(to)) return 'from and to must be RFC 3339 times.';
  if (!(from < to)) return 'from must be before to.';
  return { from, to };
};
const bucketOf = (u: URLSearchParams, from: number, to: number): number | string => {
  if (!u.get('bucket')) return defaultBucket(to - from);
  const b = Number(u.get('bucket'));
  if (![1, 5, 15, 60, 300, 900, 3600, 7200, 21600, 86400, 604800].includes(b)) return `bucket: ${u.get('bucket')} is not a bucket size.`;
  if ((to - from) / (b * 1000) > 1000) return 'bucket: too small for the range (at most 1,000 buckets).';
  return b;
};

export function seriesRoute(u: URLSearchParams, now: number): Reply {
  const dev = u.get('device') ?? '';
  const tgt = targetOf(dev);
  const d = POLLED[dev];
  if (!tgt) return bad(404, `${dev} isn't polled.`);
  const r = parseRange(u, now);
  if (typeof r === 'string') return bad(400, r);
  const bucket = bucketOf(u, r.from, r.to);
  if (typeof bucket === 'string') return bad(400, bucket);
  const keys = (u.get('series') ?? 'in_bps,out_bps').split(',').map((s) => s.trim()).filter(Boolean);
  if (keys.length > MAX_SERIES) return bad(400, `series: at most ${MAX_SERIES} series per request.`);
  const series: PollSeries[] = [];
  for (const k of keys) {
    if (!d) {
      if (!(k in HEADLINE) && !k.startsWith('if.') && !k.startsWith('oid.')) return bad(400, `series: unknown series "${k}".`);
      series.push({ key: k, ...labelOf(k), points: [] });
      continue;
    }
    const f = sampler(d, tgt, k);
    if (typeof f === 'string') return bad(400, f);
    series.push({ key: k, ...labelOf(k), points: points(d, tgt, f, r.from, r.to, bucket * 1000, now) });
  }
  const ifNames = keys.filter((k) => k.startsWith('if.')).map((k) => k.split('.').slice(1, -1).join('.'));
  const rollup = bucket >= 3600 && keys.every((k) => k in HEADLINE && k !== 'uptime_s');
  return {
    status: 200,
    body: {
      device_id: dev,
      bucket_seconds: bucket,
      source: rollup ? 'rollup' : 'files',
      series,
      markers: d ? markersFor(d, r.from, r.to, ifNames).map(({ device_id: _d, ...m }) => m) : [],
      partial: false,
      next_cursor: '',
    },
  };
}

/** /api/poll/timeline: the selected devices that are polled, busiest 4, and every selected device's markers. */
export function timelineRoute(u: URLSearchParams, now: number, selected: (device: string) => boolean): Reply {
  const r = parseRange(u, now);
  if (typeof r === 'string') return bad(400, r);
  const bucket = bucketOf(u, r.from, r.to);
  if (typeof bucket === 'string') return bad(400, bucket);
  const sel = [...targets.values()].filter((t) => t.enabled && POLLED[t.device_id] && selected(t.device_id));
  const peak = new Map<string, number>();
  for (const t of sel) {
    const d = POLLED[t.device_id];
    const f = sampler(d, t, 'in_bps') as Sampler;
    const g = sampler(d, t, 'out_bps') as Sampler;
    const mid = Math.min(r.to, now) - 60_000;
    peak.set(t.id, (f(mid) ?? 0) + (g(mid) ?? 0));
  }
  sel.sort((a, b) => (peak.get(b.id) ?? 0) - (peak.get(a.id) ?? 0));
  const one = sel.length === 1;
  const keys = one ? ['in_bps', 'out_bps', 'cpu', 'errors_d'] : ['in_bps', 'out_bps'];
  const devices = sel.slice(0, 4).map((t) => {
    const d = POLLED[t.device_id];
    return {
      device_id: t.device_id,
      series: keys
        .filter((k) => !(k === 'cpu' && !d.hr))
        .map((k) => ({ key: k, ...labelOf(k), points: points(d, t, sampler(d, t, k) as Sampler, r.from, r.to, bucket * 1000, now) })),
    };
  });
  const markers = sel.flatMap((t) => markersFor(POLLED[t.device_id], r.from, r.to, true)).sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
  const body: PollTimeline = { devices, markers, more: Math.max(0, sel.length - 4), bucket_seconds: bucket };
  return { status: 200, body };
}

/** /api/poll/device/{id}: the system box, the interface table (busiest first) and the default chart set. */
export function deviceRoute(id: string, u: URLSearchParams, now: number): Reply {
  const tgt = targetOf(id);
  if (!tgt) return bad(404, `${id} isn't polled.`);
  const r = parseRange(u, now);
  if (typeof r === 'string') return bad(400, r);
  const d = POLLED[id];
  if (!d) {
    const empty: PollDevicePanel = {
      device_id: id,
      target_id: tgt.id,
      address: tgt.address,
      system: { sys_name: '', sys_descr: '', uptime_s: null, last_restart: null, cpu: null, mem_used_pct: null },
      interfaces: [],
      charted: [],
      interfaces_left_out: 0,
    };
    return { status: 200, body: empty };
  }
  const end = Math.min(r.to, now, d.silentFrom ?? Infinity);
  const step = Math.max(tgt.interval_s * 1000, Math.ceil((end - r.from) / 400 / MIN) * MIN);
  const times: number[] = [];
  for (let t = end; t >= r.from && times.length < 500; t -= step) if (answered(d, t)) times.push(t);
  const peakOf = (f: (t: number) => number) => {
    let best = -Infinity, at = 0;
    for (const t of times) {
      const v = f(t);
      if (v > best) (best = v), (at = t);
    }
    return times.length ? { peak: best, at } : { peak: null, at: 0 };
  };
  const pif = polledIfs(d, tgt);
  const rows: PollInterfaceRow[] = pif.map((f) => {
    const pin = peakOf((t) => ifBps(d, f, 'in', t));
    const pout = peakOf((t) => ifBps(d, f, 'out', t));
    const sum = (dir: 'in' | 'out', k: 'err' | 'disc') => (times.length ? times.reduce((s, t) => s + ifErr(d, f, dir, k, t), 0) * Math.max(1, step / (tgt.interval_s * 1000)) : null);
    const flaps = d.flap && d.flap.if === f.name ? [d.flap.from, d.flap.to].filter((t) => t >= r.from && t < r.to).length : 0;
    const operNow = f.down ? 'down' : 'up';
    return {
      index: f.index,
      name: f.name,
      alias: f.alias,
      oper: d.silentFrom !== undefined && now >= d.silentFrom ? 'unknown' : operNow,
      speed_mbps: f.speed,
      in_bps: times.length ? ifBps(d, f, 'in', times[0]) : null,
      out_bps: times.length ? ifBps(d, f, 'out', times[0]) : null,
      peak_in_bps: pin.peak,
      peak_out_bps: pout.peak,
      in_err_d: sum('in', 'err'),
      out_err_d: sum('out', 'err'),
      in_disc_d: sum('in', 'disc'),
      out_disc_d: sum('out', 'disc'),
      oper_changes: flaps,
    };
  });
  rows.sort((a, b) => (b.peak_in_bps ?? 0) + (b.peak_out_bps ?? 0) - ((a.peak_in_bps ?? 0) + (a.peak_out_bps ?? 0)) || a.index - b.index);
  const cpu = d.hr ? peakOf((t) => cpuAt(d, t)) : null;
  const mem = d.hr ? peakOf((t) => memAt(d, t)) : null;
  const restartAt = d.restart && d.restart.at < now ? d.restart.at + 410 : null;
  const body: PollDevicePanel = {
    device_id: id,
    target_id: tgt.id,
    address: tgt.address,
    system: {
      sys_name: d.sysName,
      sys_descr: d.sysDescr,
      uptime_s: times.length ? Math.round(((d.restart && times[0] >= d.restart.at ? times[0] - d.restart.at : times[0] - T0 + 12 * 86400_000 + 3 * H)) / 1000) : null,
      last_restart: restartAt ? new Date(restartAt).toISOString() : null,
      cpu: cpu && cpu.peak !== null ? { now: Math.round(cpuAt(d, times[0])), peak: Math.round(cpu.peak), peak_at: new Date(cpu.at).toISOString() } : null,
      mem_used_pct: mem && mem.peak !== null ? { now: Math.round(memAt(d, times[0])), peak: Math.round(mem.peak), peak_at: new Date(mem.at).toISOString() } : null,
    },
    interfaces: rows,
    charted: rows.filter((x) => (x.peak_in_bps ?? 0) > 0).slice(0, 4).map((x) => x.name),
    interfaces_left_out: tgt.interfaces === 'all' ? Math.max(0, d.ifs.length - tgt.max_interfaces) : 0,
  };
  return { status: 200, body };
}

// ---------- search (docs/api.md → Poll lines in search) ----------

const d = (key: string, label: string, param: string, exclude_param = '', domain: { value: string; label: string }[] | null = null) => ({ key, label, param, exclude_param, domain });
const dom = (vs: string[]) => vs.map((value) => ({ value, label: value }));
/** The poll type in /api/search/schema: searchable through the API and the CLI; Events doesn't offer it as a tab. */
export const POLL_SCHEMA = {
  type: 'poll',
  label: 'SNMP polls',
  default: false,
  fields: [
    d('device', 'Device', 'devices', 'exclude_devices'),
    d('kind', 'Kind', 'kinds', '', dom(['sys', 'if', 'oid', 'status', 'restart', 'info'])),
    d('if', 'Interface', 'ifs', 'exclude_ifs'),
    d('oper', 'Oper status', 'oper', '', dom(['up', 'down', 'testing', 'unknown', 'dormant', 'notPresent', 'lowerLayerDown'])),
    d('status', 'Status', 'poll_status', '', dom(['ok', 'timeout', 'unreachable', 'auth_failed', 'unknown_user', 'unknown_engine', 'not_in_time', 'decrypt_failed', 'error', 'overrun'])),
    d('reboot', 'Reboot', 'reboot', '', dom(['1', '0', '?'])),
  ],
};
