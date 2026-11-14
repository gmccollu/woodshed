// In-browser fake of the Woodshed server for `npm run dev:mock`. It answers every
// route in docs/api.md with realistic data and simulates the live tail over a
// fake EventSource. Only main.ts imports it, and only when VITE_MOCK is set, so
// it isn't in the production bundle.
//
// URL parameters (before the #), e.g. http://127.0.0.1:5173/?mock_rate=1284#/dashboard
//   mock_rate=N       simulated msgs/s across all devices (default 40; above 50 the live tail is sampled)
//   mock_clash=1      TCP 514 is held by another process (red banner, Retry clears it)
//   mock_paused=1     writes paused by the low-disk guard (red banner)
//   mock_uptime_hours=N how long ago the server started (default 3 h 17 min)
//   mock_queue_full=1 the UDP receive queue overflows (writing to disk fell behind): udp_queue_full banner,
//                     queue_full drops, and capacity reached at the top of some hours on the About page
//   mock_firstrun=1   no messages yet: opens on the welcome page; the test message arrives after mock_firstmsg s
//   mock_firstmsg=N   seconds until the first message in first-run mode (default 12; 0 = only via the panel)
//   mock_os=linux     server OS (darwin, linux, windows); changes kernel-drop visibility and the buffer size
//   mock_cycle=0      stop branch-ap-08 cycling online -> quiet -> offline -> online every 30 s
//   mock_latency=N    simulated response time in ms (default 120)
//   mock_releases=URL releases_url in /api/status (default empty: no public releases page yet)
//   mock_panel=0      hide the mock control panel (for screenshots)
//   mock_auth=1       LAN mode with auth: the password is "woodshed-demo" and the session starts logged out
//   mock_loggedin=1   with mock_auth: start logged in
//   mock_locked=1     with mock_auth: logins from "this address" are locked out for 15 minutes
//   mock_password=1   localhost mode, but a password is already set (so LAN mode can be turned on)
//   mock_slow_scan=1  search pages come back partial (budget used up) so the UI keeps fetching
//   mock_slow_summary=1 summaries count 1,200 lines a request and report 2 s each, so the field panel fills in
//                     slowly and stops after 60 s of scanning ("Count the rest")
//   mock_export_fail=1 exports fail at 40 %
//   mock_export_secs=N seconds an export takes to build (default 8)
//   mock_devices=N    add N generated devices (up to 10,000) to the fleet
//   mock_device_limit=1 new senders are being refused (device_limit banner)
//   mock_service_514=1 the installed Woodshed service holds UDP and TCP 514; this copy starts on 15514
//   mock_listen_514=1  with mock_service_514: start on 514 (so the clash shows straight away)
//   mock_ui_port_busy=1 the installed service can't open its UI because this copy holds the UI port
//   mock_blocked=LIST  start with this blocklist (comma-separated IPs or CIDRs)
//   mock_young=1       less than an hour of data: no retention estimate yet
//   mock_tls=MODE      TLS syslog listener: on (default; Woodshed's own CA), off (turned off, certificate kept),
//                      never (never turned on: no certificate yet) or file (your own certificate)
//   mock_tls_legacy=1  allow_legacy_tls on (tls_legacy banner)
//   mock_tls_expiring=1 the TLS certificate expires within 60 days (tls_cert_expiring banner)
//   mock_tls_names=1   the host has a DNS name the certificate doesn't cover (tls_cert_names banner)
//   mock_tls_firewall=STATE with mock_os=windows: the firewall rule's state (ok, missing, disabled, wrong_port,
//                      unknown; default ok). Anything but ok shows the tls_firewall banner
//   mock_updates=ask|on|off  a release build (1.1.0) with the update check in that state (default: a
//                      development build, which has no update check). releases_url defaults to the
//                      project's releases page then
//   mock_update_result=newer|latest|error  what checks find (default newer: 1.2.0 is out)
//   (at mock_rate=1284 the 20 GiB cap lasts about 13 days, so the size cap limits retention)

import type {
  Device,
  DeviceTls,
  ExportInfo,
  UpdateCheck,
  UpdateInfo,
  RejectedSender,
  SavedQuery,
  Settings,
  Stats,
  Status,
  StorageHistoryEntry,
  TlsCa,
  TlsCert,
  TlsFailure,
  TlsState,
  Transport,
} from '../api';
import { isKnown } from '../severity';
import { setSessionSecret } from '../api';
import { matchTerms, parseTerms, TERMS_AND_REGEX } from '../terms';
import { FLEET, fieldsOf, line, SPECIAL, specialLine, testLine, weighted, type GenLine, type MockDeviceDef, type Special } from './gen';
import { STEP, deviceAt, lineAt, shareOf } from './history';

const P = new URLSearchParams(location.search);
const n = (k: string, d: number) => {
  const v = Number(P.get(k));
  return P.has(k) && Number.isFinite(v) ? v : d;
};
const osParam = P.get('mock_os') ?? 'darwin';
const OS = osParam.includes('/') ? osParam : `${osParam}/${osParam === 'windows' ? 'amd64' : 'arm64'}`;

export const mock = $state({
  rate: n('mock_rate', 40),
  clash: P.get('mock_clash') === '1',
  paused: P.get('mock_paused') === '1',
  /** The UDP queue is overflowing (the udp_queue_full banner). */
  queueFull: P.get('mock_queue_full') === '1',
  firstRun: P.get('mock_firstrun') === '1',
  cycle: P.get('mock_cycle') !== '0',
  latency: n('mock_latency', 120),
  panel: P.get('mock_panel') !== '0',
  /** LAN mode with auth (mirrors settings.ui.lan_mode). */
  lan: P.get('mock_auth') === '1',
  loggedIn: P.get('mock_loggedin') === '1',
  /** Search scans run out of budget quickly, so results arrive as partial pages. */
  slowScan: P.get('mock_slow_scan') === '1',
  /** Each summary request counts only a little, so the field panel and histogram fill in over many requests. */
  slowSummary: P.get('mock_slow_summary') === '1',
  /** The next export fails part-way. */
  exportFail: P.get('mock_export_fail') === '1',
  /** Seconds an export takes to build. */
  exportSecs: n('mock_export_secs', 8),
  /** New senders are being refused (the device_limit banner). Also on when the fleet is at max_devices. */
  deviceLimit: P.get('mock_device_limit') === '1',
  /** Generated devices added to the fleet. */
  fleetExtra: 0,
  /** Another Woodshed (the installed service) holds port 514 on UDP and TCP. */
  service514: P.get('mock_service_514') === '1',
  /** The TLS certificate expires within 60 days (until it's renewed). */
  tlsExpiring: P.get('mock_tls_expiring') === '1',
  /** The host has a DNS name the TLS certificate doesn't cover. */
  tlsNames: P.get('mock_tls_names') === '1',
  /** Windows: the TLS firewall rule's state. */
  tlsFirewall: P.get('mock_tls_firewall') ?? 'ok',
});

export const MOCK_PASSWORD = 'woodshed-demo';

const authState = {
  password: P.get('mock_auth') === '1' || P.get('mock_password') === '1' ? MOCK_PASSWORD : '',
  /** The current session's secret; issued only by login. '' when there's no session. */
  secret: '',
  failures: [] as number[],
  lastAttempt: 0,
  lockedUntil: P.get('mock_locked') === '1' ? Date.now() + 15 * 60_000 : 0,
};

function newToken(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** For the smoke checks: what the mock saw (header values and /api/session bodies). */
const probe = {
  livePaths: [] as string[],
  /** X-Woodshed-Session on the last request of each kind. */
  lastGetHeader: '' as string | null,
  lastWriteHeader: '' as string | null,
  lastLiveHeader: '' as string | null,
  sessionBodies: [] as string[],
  /** The body of the last POST /api/exports(/estimate). */
  lastExportBody: '',
  /** Downloads served, and the status of the last download attempt. */
  downloads: [] as { id: string; ticket: boolean; status: number }[],
  lastDownloadStatus: 0,
  lastTicketUrl: '',
  /** Appended to the device_limit banner text, so a smoke check can change a banner's content. */
  bannerNote: '',
  /** Fetches a URL like a browser navigation would (no session header); returns the status. */
  async navigateStatus(path: string): Promise<number> {
    return (await mockTransport.fetch(path, { headers: {} })).status;
  },
  get secret() {
    return authState.secret;
  },
  /** Simulates a request that has the cookie but not the header (e.g. another app on this host). */
  cookieOnly: false,
  /** Drops every summary's running counts, so the next cursor gets "This summary expired". */
  expireSummaries(): void {
    expireSummaries();
  },
  /** Summary requests answered "expired", for the restart check. */
  expiredSummaries: 0,
  /**
   * Sends `n` of a named message (gen.ts SPECIAL) now, from the first sending device of its
   * kind, so a check needn't wait for a rare message by chance. Returns how many were sent.
   */
  emit(name: Special, n = 1): number {
    const d = [...devs.values()].find((x) => x.sending && x.def.kind === SPECIAL[name].kind && !blockedBy(x.def.ip));
    if (!d) return 0;
    const now = Date.now();
    for (let i = 0; i < n; i++) {
      d.lastHeard = now;
      d.total++;
      emit(specialLine(name, d.def, new Date(now - n + i)));
    }
    return n;
  },
  /** A request from elsewhere (another tab, a script): returns the status. */
  async request(method: string, path: string, body?: unknown): Promise<number> {
    return (await mockTransport.fetch(path, { method, headers: {}, body: body === undefined ? undefined : JSON.stringify(body) })).status;
  },
  /** If-Match on the last PUT /api/settings (null: none sent). */
  lastIfMatch: '' as string | null,
  /** Another tab or a script saves settings: the page's ETag goes stale (409 on its next save). */
  changeSettingsElsewhere() {
    settings.storage.retention_days = 45;
    settingsRev++;
  },
};
(window as unknown as { __woodshedMock: typeof probe }).__woodshedMock = probe;

// mock_loggedin=1 starts with a session, as if this browser had logged in earlier: the mock
// issues a secret and puts it where the UI keeps one.
if (P.get('mock_require_local') === '1') {
  // Localhost with require_login_local on (and so a password).
  if (!authState.password) authState.password = MOCK_PASSWORD;
}
if (mock.loggedIn && (mock.lan || P.get('mock_require_local') === '1')) {
  authState.secret = newToken();
  setSessionSecret(authState.secret);
}

/** Mock panel: switch LAN mode with auth on (logged out) or off. */
export function setLanAuth(on: boolean) {
  mock.lan = on;
  settings.ui.lan_mode = on;
  settingsRev++;
  if (on && !authState.password) authState.password = MOCK_PASSWORD;
  mock.loggedIn = false;
  authState.secret = '';
}

/** Mock panel: end the session as if it expired; the next API call gets a 401. */
export function expireSession() {
  mock.loggedIn = false;
  authState.secret = '';
}

/** Login is required in LAN mode, and on localhost too when require_login_local is on. */
const authOn = () => mock.lan || (!!settings.ui.require_login_local && !!authState.password);

/** The mock's stand-in for "cookie and matching X-Woodshed-Session header". */
const hasSession = (header: string | null) => mock.loggedIn && !!authState.secret && header === authState.secret;

function sessionJSON(header: string | null = null) {
  const on = authOn();
  return {
    mode: mock.lan ? 'lan' : 'localhost',
    auth_required: on,
    authenticated: !on || hasSession(header),
    password_set: !!authState.password,
  };
}

const PUBLIC = ['/api/session', '/api/login', '/api/logout', '/healthz'];

function lockout(now: number): Response | null {
  if (authState.lockedUntil > now)
    return retryLater(Math.ceil((authState.lockedUntil - now) / 1000), 'Too many failed logins from this address.');
  return null;
}

function retryLater(secs: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status: 429,
    headers: { 'Content-Type': 'application/json', 'Retry-After': String(secs) },
  });
}

/** 10 failures in 15 min lock the address out for 15 min; after 5, one attempt a second. */
function recordFailure(now: number) {
  authState.failures = authState.failures.filter((t) => now - t < 15 * 60_000);
  authState.failures.push(now);
  if (authState.failures.length >= 10) authState.lockedUntil = now + 15 * 60_000;
}

const GiB = 1024 ** 3;
const MiB = 1024 ** 2;
const START = Date.now();
/** When the mock server "started" (started_at; the UDP queue's hourly history begins there). */
const STARTED = START - (P.has('mock_uptime_hours') ? n('mock_uptime_hours', 0) * 3600_000 : (3 * 60 + 17) * 60_000);
const MIN = 60_000;

// ---------- Fleet state ----------

interface Dev {
  def: MockDeviceDef;
  name: string;
  group: string;
  hidden: boolean;
  firstSeen: number;
  lastHeard: number;
  total: number;
  bytes: number;
  sending: boolean;
}

const devs = new Map<string, Dev>();

/** joinedNow: the fleet starts sending now (after a first-run test message), so first_seen is now. */
function addFleet(now: number, joinedNow = false) {
  for (const def of FLEET) {
    if (devs.has(def.ip)) continue;
    const silentFor = def.name === 'branch-fw-07' ? 6 * MIN + 12_000 : def.name === 'dmz-fw-01' ? 2 * 60 * MIN : 0;
    devs.set(def.ip, {
      def,
      name: def.name,
      group: def.group,
      hidden: !!def.hidden,
      firstSeen: joinedNow ? now + Math.random() * 1000 : now - (30 + Math.random() * 10) * 24 * 60 * MIN,
      lastHeard: now - silentFor,
      total: Math.round(def.weight * 3e5 + Math.random() * 5e4),
      bytes: Math.round(def.weight * 4.2e7 + Math.random() * 1e6),
      sending: def.weight > 0,
    });
  }
}

const thisHost: MockDeviceDef = { ip: '127.0.0.1', name: '', group: '', kind: 'srv', weight: 0.3 };

if (!mock.firstRun) addFleet(Date.now());

const CERT_FP = 'SHA256:3F:9A:1C:77:0B:E4:52:D8:6A:91:C3:0E:F2:48:BB:17:65:2D:A0:C9:8E:11:7F:44:D6:5B:02:E9:A3:C8:70:1D';

// Generated devices for scale testing (mock_devices=N or the panel). Vendor-neutral names,
// private 10.100+ addresses, a few groups, a mix of busy, quiet and offline.
const BIG_GROUPS = ['Stores', 'Warehouses', 'Lab', ''];
const KINDS = ['sw', 'ap', 'srv', 'fw'] as const;
export function setFleetSize(extra: number) {
  extra = Math.max(0, Math.min(10_000, Math.round(extra)));
  for (const ip of [...devs.keys()]) if (ip.startsWith('10.1') && /^10\.1\d\d\./.test(ip) && Number(ip.split('.')[1]) >= 100) devs.delete(ip);
  const now = Date.now();
  for (let i = 0; i < extra; i++) {
    const ip = `10.${100 + Math.floor(i / 62500)}.${Math.floor(i / 250) % 250}.${(i % 250) + 1}`;
    const kind = KINDS[i % KINDS.length];
    const r = (Math.imul(i + 1, 2654435761) >>> 0) / 4294967296;
    const quietFor = r < 0.06 ? 20 * MIN : r < 0.1 ? 5 * 60 * MIN : 0;
    devs.set(ip, {
      def: { ip, name: i % 9 === 4 ? '' : `${kind === 'ap' ? 'ap' : kind === 'sw' ? 'sw' : kind === 'fw' ? 'fw' : 'srv'}-${String(i + 1).padStart(5, '0')}`, group: BIG_GROUPS[i % 4], kind, weight: quietFor ? 0 : 0.02 + r * 0.2 },
      name: i % 9 === 4 ? '' : `${kind}-${String(i + 1).padStart(5, '0')}`,
      group: BIG_GROUPS[i % 4],
      hidden: i % 97 === 0,
      firstSeen: now - (1 + r * 30) * 24 * 60 * MIN,
      lastHeard: now - quietFor,
      total: Math.round(r * 2e5),
      bytes: Math.round(r * 1.5e6),
      sending: !quietFor,
    });
  }
  pickerAt = 0;
  mock.fleetExtra = extra;
}

// Weighted random sender with a cumulative table and binary search (rebuilt each second).
let pickerAt = 0;
let pickTable: { cum: number[]; list: Dev[] } = { cum: [], list: [] };
function senderPicker(): (() => Dev) | null {
  const now = Date.now();
  if (now - pickerAt > 1000) {
    const list = [...devs.values()].filter((d) => d.sending);
    const cum: number[] = [];
    let t = 0;
    for (const d of list) cum.push((t += d.def.weight));
    pickTable = { cum, list };
    pickerAt = now;
  }
  const { cum, list } = pickTable;
  if (!list.length) return null;
  const total = cum[cum.length - 1];
  return () => {
    const x = Math.random() * total;
    let lo = 0;
    let hi = cum.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (cum[mid] < x) lo = mid + 1;
      else hi = mid;
    }
    return list[lo];
  };
}

/** Devices that sent in the last 10 minutes (what max_devices counts). */
function activeDevices(now: number): number {
  let n = 0;
  for (const d of devs.values()) if (now - d.lastHeard < 10 * MIN) n++;
  return n;
}

/** docs/api.md: limit/offset/sort/q/group/ungrouped/hidden → {devices, total}. */
function devicesRoute(u: URLSearchParams, now: number): Response {
  const limit = Math.min(1000, Math.max(1, Number(u.get('limit') || 200)));
  const offset = Math.max(0, Number(u.get('offset') || 0));
  const sort = u.get('sort') || 'rate';
  if (!['rate', 'name', 'last_heard', 'first_seen'].includes(sort)) return err(400, `invalid sort "${sort}"`);
  const hidden = u.get('hidden') || 'include';
  const blocked = u.get('blocked') || 'include';
  if (!['include', 'only', 'exclude'].includes(blocked)) return err(400, `blocked must be include, only or exclude, not "${blocked}"`);
  const q = (u.get('q') ?? '').toLowerCase();
  const group = u.get('group');
  const ungrouped = u.get('ungrouped') === 'true';
  let list = [...devs.values()].filter((d) => {
    if (hidden === 'exclude' && d.hidden) return false;
    if (hidden === 'only' && !d.hidden) return false;
    if (blocked === 'exclude' && blockedBy(d.def.ip)) return false;
    if (blocked === 'only' && !blockedBy(d.def.ip)) return false;
    if (group && d.group !== group) return false;
    if (ungrouped && d.group) return false;
    if (q && !d.def.ip.toLowerCase().includes(q) && !d.name.toLowerCase().includes(q)) return false;
    return true;
  });
  const rateOf = (d: Dev) => (d.sending && !mock.firstRun ? d.def.weight : 0);
  const label = (d: Dev) => d.name || d.def.ip;
  // Directions: rate busiest first, name A–Z, last_heard and first_seen newest first.
  if (sort === 'rate') list.sort((a, b) => rateOf(b) - rateOf(a) || label(a).localeCompare(label(b), undefined, { numeric: true }));
  else if (sort === 'name') list.sort((a, b) => label(a).localeCompare(label(b), undefined, { numeric: true }));
  else if (sort === 'last_heard') list.sort((a, b) => b.lastHeard - a.lastHeard);
  else list.sort((a, b) => b.firstSeen - a.firstSeen);
  const total = list.length;
  list = list.slice(offset, offset + limit);
  return json({ devices: list.map((d) => deviceJSON(d, now)), total });
}

// ---------- Settings ----------

/** mock_tls: on, off (certificate kept), never (no certificate yet) or file (your own). */
const TLS_MODE = P.get('mock_tls') ?? 'on';

// A demo copy beside an installed service starts on 15514, as in the owner's test.
const SYSLOG_PORT = P.get('mock_service_514') === '1' && P.get('mock_listen_514') !== '1' ? 15514 : 514;

let settings: Settings = {
  listeners: {
    udp: { enabled: true, addr: '0.0.0.0', port: SYSLOG_PORT },
    tcp: { enabled: true, addr: '0.0.0.0', port: SYSLOG_PORT },
    // Non-empty so the rejected-senders list has something to show.
    allowlist: ['10.0.0.0/8', '192.0.2.44/32', 'fd00:1::/64'],
    blocklist: (P.get('mock_blocked') ?? '').split(',').map((x) => x.trim()).filter(Boolean),
    max_devices: 10_000,
    new_device_burst: 5_000,
    new_devices_per_minute: 200,
    tls: {
      enabled: TLS_MODE === 'on' || TLS_MODE === 'file',
      addr: '0.0.0.0',
      port: 6514,
      allow_legacy_tls: P.get('mock_tls_legacy') === '1',
      cert_file: TLS_MODE === 'file' ? '/etc/woodshed/tls/fullchain.pem' : '',
      key_file: TLS_MODE === 'file' ? '/etc/woodshed/tls/privkey.pem' : '',
    },
  },
  storage: {
    data_dir: OS.startsWith('windows')
      ? 'C:\\ProgramData\\Woodshed'
      : OS.startsWith('linux')
        ? '/var/lib/woodshed'
        : '/Library/Application Support/Woodshed',
    retention_days: 30,
    retention_bytes: 20 * GiB,
    part_bytes: 100 * MiB,
  },
  ui: {
    lan_mode: P.get('mock_auth') === '1',
    port: 8514,
    cert_file: '',
    key_file: '',
    require_login_local: P.get('mock_require_local') === '1',
    extra_hostnames: [],
    trusted_hosts: [],
  },
  quiet: { quiet_after_seconds: 300, offline_after_seconds: 3600 },
  updates: { check: (['ask', 'on', 'off'].includes(P.get('mock_updates') ?? '') ? P.get('mock_updates') : 'ask') as UpdateCheck },
};

// ---------- The update check (docs/api.md → Update check) ----------

/** A release build with the update check only when mock_updates is set; otherwise a dev build. */
const UPDATES_AVAILABLE = P.has('mock_updates');
const VERSION = UPDATES_AVAILABLE ? '1.1.0' : '0.1.0';
const RELEASES = P.get('mock_releases') ?? (UPDATES_AVAILABLE ? 'https://github.com/gmccollu/woodshed/releases' : '');
const UPDATE_RESULT = P.get('mock_update_result') ?? 'newer';

export const updates = $state({
  /** What the next check finds: "newer" (1.2.0 is out), "latest" (this is the newest) or "error". */
  result: ['newer', 'latest', 'error'].includes(UPDATE_RESULT) ? UPDATE_RESULT : 'newer',
  lastCheck: null as number | null,
  lastResult: '' as '' | 'ok' | 'error',
  lastError: '',
  lastErrorKind: '',
  nextCheck: null as number | null,
  latest: null as UpdateInfo['latest'],
  dismissed: '',
  lastManual: 0,
});

function runUpdateCheck(now: number) {
  updates.lastCheck = now;
  updates.nextCheck = now + 24 * 3600_000 - 17 * MIN;
  if (updates.result === 'error') {
    updates.lastResult = 'error';
    updates.lastError = 'TLS certificate not trusted (a proxy that inspects HTTPS?)';
    updates.lastErrorKind = 'tls';
    updates.latest = null;
    return;
  }
  const v = updates.result === 'newer' ? '1.2.0' : VERSION;
  updates.lastResult = 'ok';
  updates.lastError = updates.lastErrorKind = '';
  updates.latest = { version: v, prerelease: false, url: `${RELEASES}/tag/v${v}` };
}

// On: the last check ran 3 h ago.
if (UPDATES_AVAILABLE && settings.updates?.check === 'on') runUpdateCheck(Date.now() - 3 * 3600_000);

function setUpdateCheck(check: UpdateCheck, now: number) {
  const was = settings.updates?.check;
  settings = { ...settings, updates: { check } };
  if (check === was) return;
  settingsRev++;
  if (check === 'on') {
    updates.nextCheck = now + 2000;
    setTimeout(() => {
      if (settings.updates?.check === 'on') runUpdateCheck(Date.now());
    }, 2000);
  } else {
    updates.nextCheck = null;
    updates.latest = null;
  }
}

const newer = (a: string, b: string) => {
  const p = (v: string) => v.split('-')[0].split('.').map(Number);
  const [x, y] = [p(a), p(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i];
  return false;
};

function updatesJSON(): UpdateInfo {
  const on = settings.updates?.check === 'on';
  const latest = on ? updates.latest : null;
  return {
    check: settings.updates?.check ?? 'ask',
    available: UPDATES_AVAILABLE,
    url: 'https://gmccollu.github.io/woodshed/releases.json',
    current: VERSION,
    last_check: updates.lastCheck ? new Date(updates.lastCheck).toISOString() : null,
    last_result: updates.lastResult,
    last_error: updates.lastError,
    last_error_kind: updates.lastErrorKind,
    next_check: on && updates.nextCheck ? new Date(updates.nextCheck).toISOString() : null,
    latest,
    update_available: !!latest && newer(latest.version, VERSION),
    dismissed_version: updates.dismissed,
  };
}

function updateBanners(): Status['banners'] {
  if (!UPDATES_AVAILABLE) return [];
  const u = updatesJSON();
  if (u.check === 'ask')
    return [
      {
        kind: 'update_prompt',
        level: 'info',
        action: 'update_choice',
        text: 'Check for new Woodshed versions once a day? It fetches one public file from gmccollu.github.io and sends nothing about this server.',
      },
    ];
  if (u.check === 'on' && u.update_available && u.latest && u.latest.version !== u.dismissed_version)
    return [
      {
        kind: 'update_available',
        level: 'info',
        action: 'update_dismiss',
        text: `Woodshed ${u.latest.version} is available (this is ${VERSION}).`,
        url: u.latest.url,
      },
    ];
  return [];
}

const isIPv4 = (s: string) =>
  /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(s) && s.split('.').every((p) => Number(p) <= 255);
const isIPv6 = (s: string) => s.includes(':') && /^[0-9a-f:.]+$/i.test(s) && (s.match(/::/g)?.length ?? 0) <= 1;
const isIP = (s: string) => isIPv4(s) || isIPv6(s);
const WILDCARD = ['0.0.0.0', '::'];
// mock_small_buffer=1: the OS granted a small UDP receive buffer (the udp_buffer_small banner, Linux).
const smallBuffer = P.get('mock_small_buffer') === '1';
// A DNS name (letters, digits, hyphens; labels up to 63, no leading or trailing hyphen).
const isHostname = (s: string) =>
  s.length <= 253 && s.split('.').every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(l)) && !/^\d+(\.\d+)*$/.test(s);
/** A Host header value: host, host:port, [v6] or [v6]:port. */
function isHostPort(s: string): boolean {
  const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(s) ?? /^([^:]+)(?::(\d+))?$/.exec(s);
  if (!m) return false;
  const [, host, port] = m;
  const okHost = s.startsWith('[') ? isIPv6(host) : isIPv4(host) || isHostname(host);
  return okHost && (port === undefined || (Number(port) >= 1 && Number(port) <= 65535));
}

// The settings ETag: bumped on every change (a save here, Block on a device, another tab).
let settingsRev = 1;
const settingsETag = () => `"s${settingsRev}"`;

function validate(s: Settings): Record<string, string> {
  const e: Record<string, string> = {};
  const port = (k: string, v: number, lo = 1) => {
    if (!Number.isInteger(v) || v < lo || v > 65535) e[k] = `Enter a port from ${lo} to 65535.`;
  };
  for (const proto of ['udp', 'tcp'] as const) {
    const l = s.listeners[proto];
    port(`listeners.${proto}.port`, l.port);
    if (!isIP(l.addr)) e[`listeners.${proto}.addr`] = 'Enter an IP address, or 0.0.0.0 / :: for all addresses.';
    else if (OS.startsWith('darwin') && !WILDCARD.includes(l.addr) && l.port < 1024)
      e[`listeners.${proto}.addr`] =
        'On macOS a port below 1024 can only be bound on all addresses (0.0.0.0 or ::). Use the sender allowlist to restrict senders.';
  }
  if (!s.listeners.udp.enabled && !s.listeners.tcp.enabled && !s.listeners.tls?.enabled)
    e['listeners.udp.enabled'] = 'Keep at least one listener on, or Woodshed receives nothing.';
  const t = s.listeners.tls;
  if (t) {
    port('listeners.tls.port', t.port);
    if (!isIP(t.addr)) e['listeners.tls.addr'] = 'Enter an IP address, or 0.0.0.0 / :: for all addresses.';
    else if (!e['listeners.tls.port'])
      for (const proto of ['udp', 'tcp'] as const) {
        const o = s.listeners[proto];
        const shared = o.addr === t.addr || WILDCARD.includes(o.addr) || WILDCARD.includes(t.addr);
        if (o.port === t.port && shared) e['listeners.tls.port'] = `Use a port other than the ${proto.toUpperCase()} listener's (${o.port}).`;
      }
    const abs = (f: string) => f.startsWith('/') || /^[A-Za-z]:\\/.test(f);
    if (t.cert_file && !abs(t.cert_file)) e['listeners.tls.cert_file'] = 'Use the full path to the certificate file.';
    if (t.key_file && !abs(t.key_file)) e['listeners.tls.key_file'] = 'Use the full path to the key file.';
    if (t.cert_file && !t.key_file && !e['listeners.tls.cert_file'])
      e['listeners.tls.key_file'] = "Set the key file too, or clear both to use Woodshed's own CA.";
    if (t.key_file && !t.cert_file && !e['listeners.tls.key_file'])
      e['listeners.tls.cert_file'] = "Set the certificate file too, or clear both to use Woodshed's own CA.";
    // Mock only: a path with "mismatch" in it is a certificate that doesn't go with the key.
    if (t.cert_file && t.key_file && /mismatch/.test(t.cert_file + t.key_file) && !e['listeners.tls.cert_file']) {
      e['listeners.tls.cert_file'] = "This certificate and key don't match.";
      e['listeners.tls.key_file'] = "This certificate and key don't match.";
    }
  }
  (s.listeners.blocklist ?? []).forEach((c, i) => {
    const [ip, bits, extra] = c.split('/');
    let bad = extra !== undefined || !isIP(ip);
    if (!bad && bits !== undefined) {
      const b = Number(bits);
      bad = bits === '' || !Number.isInteger(b) || b < 0 || b > (isIPv4(ip) ? 32 : 128);
    }
    if (bad) e[`listeners.blocklist[${i}]`] = 'Not an IP address or CIDR.';
  });
  s.listeners.allowlist.forEach((c, i) => {
    const [ip, bits, extra] = c.split('/');
    let bad = extra !== undefined || !isIP(ip);
    if (!bad && bits !== undefined) {
      const b = Number(bits);
      bad = bits === '' || !Number.isInteger(b) || b < 0 || b > (isIPv4(ip) ? 32 : 128);
    }
    if (bad) e[`listeners.allowlist[${i}]`] = 'Not an IP address or CIDR.';
  });
  const st = s.storage;
  if (!Number.isInteger(st.retention_days) || st.retention_days < 1 || st.retention_days > 3650)
    e['storage.retention_days'] = 'Keep logs for 1 to 3650 days.';
  if (!Number.isFinite(st.retention_bytes) || st.retention_bytes < GiB)
    e['storage.retention_bytes'] = 'The disk cap must be at least 1 GiB.';
  if (!Number.isFinite(st.part_bytes) || st.part_bytes < MiB || st.part_bytes > 4 * GiB)
    e['storage.part_bytes'] = 'Part size must be between 1 MiB and 4 GiB.';
  else if (st.part_bytes > st.retention_bytes) e['storage.part_bytes'] = 'Part size must be smaller than the disk cap.';
  if (st.data_dir !== settings.storage.data_dir) e['storage.data_dir'] = 'The data folder can only be changed in the config file.';
  port('ui.port', s.ui.port, 1024);
  if (s.ui.lan_mode && !authState.password) e['ui.lan_mode'] = 'Set a password before turning on LAN mode.';
  if (s.ui.require_login_local && !authState.password) e['ui.require_login_local'] = 'Set a password first.';
  const lim = (k: 'max_devices' | 'new_device_burst' | 'new_devices_per_minute', lo: number, hi: number) => {
    const v = s.listeners[k];
    if (!Number.isInteger(v) || v < lo || v > hi) e[`listeners.${k}`] = `Use a whole number from ${lo.toLocaleString()} to ${hi.toLocaleString()}.`;
  };
  lim('max_devices', 1, 1_000_000);
  lim('new_device_burst', 1, 1_000_000);
  lim('new_devices_per_minute', 1, 100_000);
  const cert = s.ui.cert_file ?? '';
  const key = s.ui.key_file ?? '';
  const abs = (f: string) => f.startsWith('/') || /^[A-Za-z]:\\/.test(f);
  if (cert && !abs(cert)) e['ui.cert_file'] = 'Use the full path to the certificate file.';
  if (key && !abs(key)) e['ui.key_file'] = 'Use the full path to the key file.';
  (s.ui.extra_hostnames ?? []).forEach((h, i) => {
    if (!(isHostname(h) || isIP(h))) e[`ui.extra_hostnames[${i}]`] = 'Not a host name or IP address. Leave out https:// and any port.';
  });
  (s.ui.trusted_hosts ?? []).forEach((h, i) => {
    if (!isHostPort(h)) e[`ui.trusted_hosts[${i}]`] = 'Not a host or host:port, such as logs.example.net:443.';
  });
  if (cert && !key && !e['ui.cert_file']) e['ui.key_file'] = 'Set the key file too, or clear both to use the generated certificate.';
  if (key && !cert && !e['ui.key_file']) e['ui.cert_file'] = 'Set the certificate file too, or clear both to use the generated certificate.';
  const q = s.quiet;
  if (!Number.isInteger(q.quiet_after_seconds) || q.quiet_after_seconds < 30)
    e['quiet.quiet_after_seconds'] = 'Use at least 30 seconds.';
  if (!Number.isInteger(q.offline_after_seconds) || q.offline_after_seconds <= q.quiet_after_seconds)
    e['quiet.offline_after_seconds'] = 'Offline must come after quiet.';
  if (s.updates && !['ask', 'on', 'off'].includes(s.updates.check)) e['updates.check'] = 'Must be "ask", "on" or "off".';
  return e;
}

// ---------- Traffic ----------

const RING_MAX = 5000;
const ring: GenLine[] = [];
let pendingFraction = 0;
let generatedThisSecond = 0;
let trueThisSecond = 0;
const spark: number[] = Array.from({ length: 60 }, (_, i) => Math.max(0, mock.rate * (0.8 + 0.25 * Math.sin(i / 6)) + (Math.random() - 0.5) * mock.rate * 0.15));
let sparkMinute = Math.floor(Date.now() / MIN);
let droppedByGuard = 0;
// UDP queue drops (mock_queue_full): a share of UDP traffic while the queue is "full", plus the earlier
// stalls the hourly history shows.
let droppedByQueue = mock.queueFull ? 1234 : 0;
// A fleet that's been running started when its oldest device was first seen.
let firstMessageAt = devs.size ? Math.min(...[...devs.values()].map((d) => d.firstSeen)) : 0;
const subs = new Set<LiveSub>();

function status(d: Dev, now: number): Device['status'] {
  const age = (now - d.lastHeard) / 1000;
  if (age <= settings.quiet.quiet_after_seconds) return 'online';
  if (age <= settings.quiet.offline_after_seconds) return 'quiet';
  return 'offline';
}

function cycleDevice(now: number) {
  const ap = [...devs.values()].find((d) => d.def.name === 'branch-ap-08');
  if (!ap) return;
  if (!mock.cycle) {
    ap.sending = true;
    return;
  }
  // 30 s each: sending -> quiet -> offline -> sending. The mock warps its last-heard
  // time so the dot changes without waiting for the real thresholds.
  const phase = Math.floor((now - START) / 30_000) % 4;
  if (phase === 0 || phase === 3) {
    ap.sending = true;
  } else if (ap.sending || (phase === 2 && status(ap, now) === 'quiet')) {
    ap.sending = false;
    const q = settings.quiet;
    ap.lastHeard = now - (phase === 1 ? q.quiet_after_seconds + 60 : q.offline_after_seconds + 600) * 1000;
  }
}

function emit(l: GenLine) {
  ring.push(l);
  if (ring.length > RING_MAX) ring.splice(0, ring.length - RING_MAX);
  for (const s of subs) s.offer(l);
}

function tick() {
  const now = Date.now();
  cycleDevice(now);

  if (mock.firstRun) return;

  const pick = senderPicker();
  if (!pick) return;
  const want = (mock.rate / 10) + pendingFraction;
  const whole = Math.floor(want);
  pendingFraction = want - whole;
  // Above 200 msg/s only a slice is generated as real lines; the counters use the full rate.
  const make = Math.min(whole, 20);
  trueThisSecond += whole;
  for (let i = 0; i < whole; i++) {
    const d = pick();
    if (blockedBy(d.def.ip)) {
      // Refused at the listener: counted, not stored, not in the live tail.
      const c = blockedCounts.get(d.def.ip) ?? { n: 0, last: 0 };
      c.n++;
      c.last = now;
      blockedCounts.set(d.def.ip, c);
      continue;
    }
    d.lastHeard = now;
    d.total++;
    d.bytes += 140;
    if (i < make) {
      generatedThisSecond++;
      const l = line(d.def, new Date(now - 100 + Math.floor((i / make) * 100)));
      if (!mock.paused) emit(l);
    }
  }
  if (mock.paused) droppedByGuard += whole;
  else if (mock.queueFull) droppedByQueue += Math.ceil(whole * 0.03);
}

function secondTick() {
  for (const s of subs) s.flushSecond(generatedThisSecond ? trueThisSecond / generatedThisSecond : 1);
  generatedThisSecond = 0;
  trueThisSecond = 0;
  const minute = Math.floor(Date.now() / MIN);
  if (minute !== sparkMinute) {
    sparkMinute = minute;
    spark.shift();
    spark.push(mock.firstRun ? 0 : mock.rate * (0.9 + Math.random() * 0.2));
  } else if (!mock.firstRun) {
    spark[59] = spark[59] * 0.8 + mock.rate * (0.9 + Math.random() * 0.2) * 0.2;
  }
}

let firstTimer = 0;
export function sendFirstMessage() {
  if (!mock.firstRun) return;
  clearTimeout(firstTimer);
  const now = Date.now();
  firstMessageAt = now;
  devs.set(thisHost.ip, {
    def: thisHost,
    name: '',
    group: '',
    hidden: false,
    firstSeen: now,
    lastHeard: now,
    total: 1,
    bytes: 90,
    sending: true,
  });
  mock.firstRun = false;
  emit(testLine(new Date(now)));
  // The rest of the fleet "joins" a few seconds later so the dashboard has something to show.
  setTimeout(() => addFleet(Date.now(), true), 5000);
}

export function restartFirstRun() {
  devs.clear();
  ring.length = 0;
  firstMessageAt = 0;
  mock.firstRun = true;
  for (const i in spark) spark[i] = 0;
  const delay = n('mock_firstmsg', 12);
  if (delay > 0) firstTimer = window.setTimeout(sendFirstMessage, delay * 1000);
}

if (mock.firstRun) {
  for (const i in spark) spark[i] = 0;
  const delay = n('mock_firstmsg', 12);
  if (delay > 0) firstTimer = window.setTimeout(sendFirstMessage, delay * 1000);
} else {
  // Seed the ring so the live tail's backlog isn't empty on first load.
  const senders = [...devs.values()].filter((d) => d.sending);
  const now = Date.now();
  for (let i = 300; i > 0; i--) {
    const d = weighted(senders, (x) => x.def.weight);
    ring.push(line(d.def, new Date(now - i * 180)));
  }
}

if (!mock.firstRun && n('mock_devices', 0) > 0) setFleetSize(n('mock_devices', 0));

setInterval(tick, 100);
setInterval(secondTick, 1000);

// ---------- Live tail ----------

/** Filters as the mock applies them: a resolved severity set (null = all). */
interface MockFilters {
  devices?: string[];
  group?: string;
  ungrouped?: boolean;
  sev: Set<string> | null;
  q?: string;
}

/**
 * docs/api.md → Severity filters: `severities=0,3,unknown` wins over `min_severity=N`
 * (0…N plus unknown). Empty or missing means all. Throws on an invalid value.
 */
function sevFilter(u: URLSearchParams): Set<string> | null {
  const list = u.get('severities');
  if (list) {
    const parts = list.split(',').map((x) => x.trim()).filter(Boolean);
    if (parts.includes('none')) {
      if (parts.length > 1) throw new Error('"none" can\'t be combined with other severities');
      return new Set(); // matches nothing
    }
    for (const x of parts) if (!/^[0-7]$/.test(x) && x !== 'unknown') throw new Error(`invalid severity "${x}"`);
    return parts.length ? new Set(parts) : null;
  }
  const min = u.get('min_severity');
  if (min !== null && min !== '') {
    if (!/^[0-7]$/.test(min)) throw new Error(`invalid min_severity "${min}"`);
    return new Set([...Array(Number(min) + 1).keys()].map(String).concat('unknown'));
  }
  return null;
}

const sevKeyOf = (sev: number | null) => (isKnown(sev) ? String(sev) : 'unknown');

function groupOf(ip: string): string {
  return devs.get(ip)?.group ?? FLEET.find((d) => d.ip === ip)?.group ?? '';
}

function hiddenNow(ip: string): boolean {
  return devs.get(ip)?.hidden ?? !!FLEET.find((d) => d.ip === ip)?.hidden;
}

/** Device-level part of a filter, checked before generating a line's text. */
function deviceMatches(ip: string, f: MockFilters, searchHidden = false): boolean {
  if (f.devices?.length) return f.devices.includes(ip);
  if (searchHidden && hiddenNow(ip)) return false; // hidden devices only when named
  if (f.group || f.ungrouped) {
    const g = groupOf(ip);
    if (f.ungrouped ? g !== '' : g !== f.group) return false;
  }
  return true;
}

function matches(l: GenLine, f: MockFilters): boolean {
  // docs/api.md: hidden devices are left out of the live tail unless named in devices.
  if (!deviceMatches(l.device_id, f, true)) return false;
  if (f.sev && !f.sev.has(sevKeyOf(l.severity))) return false;
  if (f.q && !l.raw.toLowerCase().includes(f.q.toLowerCase())) return false;
  return true;
}

const SAMPLE_LIMIT = 50;

/** One open /api/live stream: SSE text pushed into a ReadableStream. */
class LiveSub {
  private sentThisSecond = 0;
  private matchedThisSecond = 0;
  private readonly filters: MockFilters;
  private readonly out: ReadableStreamDefaultController<Uint8Array>;
  constructor(filters: MockFilters, out: ReadableStreamDefaultController<Uint8Array>) {
    this.filters = filters;
    this.out = out;
  }

  private enc = new TextEncoder();
  write(text: string) {
    try {
      this.out.enqueue(this.enc.encode(text));
    } catch {
      subs.delete(this); // the reader went away
    }
  }

  send(type: string, data: unknown) {
    // Split the event across lines to exercise the parser (data is one JSON line).
    this.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);
  }

  replay() {
    for (const l of ring.filter((x) => matches(x, this.filters)).slice(-200)) this.send('message', l);
  }

  /** Matching lines a second, as of the last full second (scaled to the true rate). */
  private matchedRate = 0;

  offer(l: GenLine) {
    if (!matches(l, this.filters)) return;
    this.matchedThisSecond++;
    // Like the server: sample only when what matches this stream's filters is above ~50
    // lines a second, not when the overall rate is (a narrow filter gets every line).
    const sampling = this.matchedRate > SAMPLE_LIMIT;
    if (sampling && this.sentThisSecond >= SAMPLE_LIMIT) return;
    if (sampling && Math.random() > SAMPLE_LIMIT / Math.min(this.matchedRate, 200)) return;
    this.sentThisSecond++;
    this.send('message', l);
  }

  flushSecond(scale: number) {
    const rate = this.matchedThisSecond * scale;
    this.matchedRate = rate;
    if (rate > SAMPLE_LIMIT) this.send('sampled', { rate: Math.round(rate * 10) / 10, shown: this.sentThisSecond });
    this.sentThisSecond = 0;
    this.matchedThisSecond = 0;
  }
}

function liveResponse(u: URLSearchParams, sev: Set<string> | null, signal?: AbortSignal): Response {
  const filters: MockFilters = {
    devices: u.get('devices')?.split(',').filter(Boolean),
    group: u.get('group') ?? undefined,
    ungrouped: u.get('ungrouped') === 'true',
    sev,
    q: u.get('q') ?? undefined,
  };
  let sub: LiveSub | null = null;
  let beat = 0;
  const end = () => {
    if (sub) subs.delete(sub);
    clearInterval(beat);
  };
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      sub = new LiveSub(filters, controller);
      sub.write(': connected\n\n');
      sub.replay();
      subs.add(sub);
      // A heartbeat comment, as the server sends, so idle streams stay alive.
      beat = window.setInterval(() => sub?.write(': ping\n\n'), 15_000);
      signal?.addEventListener('abort', () => {
        end();
        try {
          controller.error(new DOMException('aborted', 'AbortError'));
        } catch {
          /* already closed */
        }
      });
    },
    cancel: end,
  });
  return new Response(body, { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
}

// ---------- Routes ----------

let weightCache = { at: 0, total: 1 };
function sendingWeight(now: number): number {
  if (now - weightCache.at > 1000) {
    let t = 0;
    for (const x of devs.values()) if (x.sending) t += x.def.weight;
    weightCache = { at: now, total: t || 1 };
  }
  return weightCache.total;
}

function deviceJSON(d: Dev, now: number): Device {
  // A blocked sender's messages are refused, so nothing is received from it.
  const running = d.sending && !mock.firstRun && !blockedBy(d.def.ip);
  const share = d.def.weight / sendingWeight(now);
  return {
    id: d.def.ip,
    ip: d.def.ip,
    name: d.name,
    group: d.group,
    hidden: d.hidden,
    first_seen: new Date(d.firstSeen).toISOString(),
    last_heard: new Date(d.lastHeard).toISOString(),
    status: blockedBy(d.def.ip) ? 'blocked' : status(d, now),
    blocked: !!blockedBy(d.def.ip),
    msgs_per_min: running ? Math.round(share * mock.rate * 60 * (0.9 + Math.random() * 0.2)) : 0,
    total_msgs: d.total,
    bytes_on_disk: d.bytes,
    tls: deviceTls(d.def.ip, now),
  };
}

/** Who holds a port this copy wants, if anyone (mock only). */
function holderOf(proto: 'udp' | 'tcp', port: number): Partial<Status['listeners'][number]> | null {
  if (mock.service514 && port === 514)
    return { holder: 'woodshed (pid 4242)', holder_kind: 'woodshed_service', holder_pid: 4242, holder_ui_url: 'http://localhost:8514/' };
  if (mock.clash && proto === 'tcp' && port === 514) return { holder: 'syslogd (pid 312)' };
  return null;
}

function statusJSON(): Status {
  const l = settings.listeners;
  const listeners: Status['listeners'] = [];
  for (const proto of ['udp', 'tcp'] as const) {
    const c = l[proto];
    if (!c.enabled) continue;
    const h = holderOf(proto, c.port);
    listeners.push({ proto, addr: c.addr, port: c.port, ok: !h, error: h ? 'bind: address already in use' : '', ...(h ?? {}) });
  }
  if (l.tls?.enabled) listeners.push({ proto: 'tls', addr: l.tls.addr, port: l.tls.port, ok: true, error: '' });
  const banners: Status['banners'] = [];
  const down = listeners.filter((x) => !x.ok);
  if (down.length) {
    const ports = down.map((x) => `${x.proto.toUpperCase()} ${x.port}`).join(' and ');
    const woodshed = down.some((x) => x.holder_kind === 'woodshed_service');
    banners.push({
      kind: 'listener_bind',
      action: 'retry_listeners',
      level: 'error',
      text: woodshed
        ? `${ports} ${down.length > 1 ? 'are' : 'is'} in use by another Woodshed (the installed service).`
        : `${ports} is in use by syslogd (pid 312). Stop the other syslog service, or move the listener to another port in Settings, then press Retry.`,
    });
  }
  {
    const e = estimateFor(settings.storage.retention_bytes);
    if (e.estimated_days !== null && e.estimated_days < settings.storage.retention_days)
      banners.push({
        kind: 'retention_cap',
        action: '',
        level: 'warn',
        text: `At the current rate the ${Math.round(settings.storage.retention_bytes / GiB)} GiB cap keeps about ${Math.round(e.estimated_days)} days, less than the ${settings.storage.retention_days}-day setting.`,
      });
  }
  if (P.get('mock_ui_port_busy') === '1')
    banners.push({
      kind: 'ui_port_busy',
      action: '',
      level: 'warn',
      text: "The installed Woodshed service is running but can't open its web page, because this copy is using port 8514. Stop this copy to use the service.",
    });
  if (mock.deviceLimit || activeDevices(Date.now()) >= settings.listeners.max_devices)
    banners.push({
      kind: 'device_limit',
      action: '',
      level: 'warn',
      text: `New senders are being refused: ${activeDevices(Date.now()).toLocaleString()} devices sent in the last 10 minutes and the limit is ${settings.listeners.max_devices.toLocaleString()}. Their messages count as dropped.${probe.bannerNote}`,
    });
  if (smallBuffer)
    banners.push({
      kind: 'udp_buffer_small',
      action: '',
      level: 'warn',
      text: 'The OS gave the UDP listener a 208 KiB receive buffer; Woodshed asked for 32 MiB. Bursts of messages may be dropped before Woodshed sees them. In a container, raise net.core.rmem_max on the host; otherwise check /etc/sysctl.d/60-woodshed.conf is applied.',
    });
  banners.push(...tlsBanners());
  if (mock.queueFull && l.udp.enabled)
    banners.push({
      kind: 'udp_queue_full',
      action: '',
      level: 'warn',
      text: `${droppedByQueue.toLocaleString('en-US')} UDP messages were dropped in the last hour because writing to disk fell behind (the queue holds ${QUEUE_CAP.toLocaleString('en-US')}). Check the disk, or raise listeners.udp_queue_messages.`,
    });
  if (mock.paused)
    banners.push({
      kind: 'writes_paused',
      action: '',
      level: 'error',
      text: `Writes are paused: the data volume has 0.8 GiB free and there are no old logs left to delete. ${droppedByGuard.toLocaleString()} messages dropped so far. Free some disk space and writing resumes on its own.`,
    });
  banners.push(...updateBanners());
  return {
    version: VERSION,
    build: 'abc1234',
    os: OS,
    data_dir: settings.storage.data_dir,
    started_at: new Date(STARTED).toISOString(),
    first_message_at: firstMessageAt ? new Date(firstMessageAt).toISOString() : null,
    udp_rcvbuf_bytes: smallBuffer ? 212_992 : OS.startsWith('darwin') ? 7_454_720 : 33_554_432,
    udp_rcvbuf_requested_bytes: 32 * MiB,
    releases_url: RELEASES,
    kernel_drops_visible: OS.startsWith('linux'),
    ...(mock.lan ? { ui_cert_fingerprint: CERT_FP } : {}),
    listeners,
    host_ips: ['10.1.0.50', '192.168.64.1', 'fd00::50'],
    banners,
  };
}

// The retention estimate: raw bytes over 24 h at the mock rate (about 140 bytes a line),
// divided by a measured compression ratio. Null on a first run (less than 1 h of data).
const RATIO = 9.2;
function bytesPerDay(): number | null {
  if (mock.firstRun || P.get('mock_young') === '1') return null;
  return Math.round((mock.rate * 86400 * 140) / RATIO);
}
function estimateFor(capBytes: number) {
  const bpd = bytesPerDay();
  const days = bpd ? Math.round((capBytes / bpd) * 10) / 10 : null;
  return { estimated_days: days, bytes_per_day: bpd, compression_ratio: bpd ? RATIO : null };
}

const QUEUE_CAP = 100_000;

// The syslog UDP queue: a few hundred waiting at the busiest moment of each hour, scaled by the rate,
// and with mock_queue_full a stall at the top of every sixth hour that fills it.
function queueJSON(now: number): Stats['udp_queue'] {
  const u = settings.listeners.udp;
  if (!u.enabled) return [];
  const hours = Math.min(24, Math.floor(now / 3600_000) - Math.floor(STARTED / 3600_000) + 1);
  const nowHour = Math.floor(now / 3600_000);
  const scale = Math.max(1, mock.rate / 40);
  const by = Array.from({ length: hours }, (_, i) => {
    const h = nowHour - (hours - 1 - i);
    const base = Math.round((30 + ((h * 7919) % 97) + (h % 3 === 0 ? 120 : 0)) * scale);
    if (mock.queueFull && (h % 6 === 0 || i === hours - 1)) return QUEUE_CAP;
    return Math.min(QUEUE_CAP, base);
  });
  const depth = mock.queueFull ? QUEUE_CAP - 40 : mock.paused ? 0 : Math.round(3 * scale);
  return [
    {
      listener: 'udp',
      port: u.port,
      capacity_messages: QUEUE_CAP,
      capacity_bytes: 64 * MiB,
      depth,
      high_water_24h: Math.max(...by),
      dropped_24h: droppedByQueue,
      high_water_by_hour: by,
    },
  ];
}

function statsJSON(now: number): Stats {
  const visible = [...devs.values()].filter((d) => !d.hidden && !blockedBy(d.def.ip));
  const st = visible.map((d) => status(d, now));
  const used = [...devs.values()].reduce((s, d) => s + d.bytes, 0);
  return {
    msgs_per_sec: mock.firstRun ? 0 : Math.round(mock.rate * (0.92 + Math.random() * 0.16) * 10) / 10,
    sparkline: spark.map((x) => Math.round(x * 10) / 10),
    devices: {
      total: visible.length,
      online: st.filter((s) => s === 'online').length,
      quiet: st.filter((s) => s === 'quiet').length,
      offline: st.filter((s) => s === 'offline').length,
    },
    disk: {
      used_bytes: used,
      cap_bytes: settings.storage.retention_bytes,
      free_bytes: mock.paused ? 0.8 * GiB : 400e9,
      days_kept: devs.size > 1 ? settings.storage.retention_days : firstMessageAt ? 1 : 0,
      ...(() => {
        const e = estimateFor(settings.storage.retention_bytes);
        return { ...e, limited_by: e.estimated_days === null ? null : e.estimated_days < settings.storage.retention_days ? 'cap' : 'age' } as const;
      })(),
    },
    dropped_24h: droppedByGuard + droppedByQueue,
    kernel_dropped_24h: OS.startsWith('linux') ? 12 : null,
    truncated_24h: devs.size > 1 ? 3 : 0,
    rejected_24h: rejected(now).reduce((n, r) => n + r.count_24h, 0),
    dropped_by_reason: { paused: droppedByGuard, write_error: 0, refused: 0, queue_full: droppedByQueue },
    udp_queue: queueJSON(now),
  };
}

// Senders outside the allowlist (IPv4 only in the mock). Counts grow while the mock runs.
const OUTSIDERS = [
  { ip: '198.51.100.7', base: 118, per_min: 6 },
  { ip: '203.0.113.50', base: 41, per_min: 2 },
  { ip: '192.0.2.200', base: 6, per_min: 0.2 },
];

function v4(ip: string): number | null {
  if (!isIPv4(ip)) return null;
  return ip.split('.').reduce((n, p) => n * 256 + Number(p), 0);
}

/** The blocklist entry that covers ip, or '' (IPv4 CIDRs; IPv6 by exact address). */
function blockedBy(ip: string): string {
  for (const c of settings.listeners.blocklist ?? []) {
    const [net, bits] = c.split('/');
    if (net === ip && (bits === undefined || bits === '32' || bits === '128')) return c;
    const n = v4(ip);
    const base = v4(net);
    if (n === null || base === null || bits === undefined) continue;
    const b = Number(bits);
    const mask = b === 0 ? 0 : (0xffffffff << (32 - b)) >>> 0;
    if (((n & mask) >>> 0) === ((base & mask) >>> 0)) return c;
  }
  return '';
}

/** Messages refused per blocked sender (mock counters). */
const blockedCounts = new Map<string, { n: number; last: number }>();
// Senders blocked from the start (mock_blocked) have refusals already counted, as if blocked a
// while ago, so the refused list shows them on the first poll instead of only after the next.
for (const d of FLEET) if (blockedBy(d.ip)) blockedCounts.set(d.ip, { n: 40 + Math.round(d.weight * 20), last: START - 20_000 });

function allowed(ip: string): boolean {
  const n = v4(ip);
  return settings.listeners.allowlist.some((c) => {
    const [net, bits = '32'] = c.split('/');
    const base = v4(net);
    if (base === null || n === null) return false;
    const b = Number(bits);
    const mask = b === 0 ? 0 : (0xffffffff << (32 - b)) >>> 0;
    return ((n & mask) >>> 0) === ((base & mask) >>> 0);
  });
}

function rejected(now: number): RejectedSender[] {
  if (mock.firstRun) return [];
  const mins = (now - START) / MIN;
  const out: RejectedSender[] = settings.listeners.allowlist.length
    ? OUTSIDERS.filter((o) => !allowed(o.ip)).map((o, i) => ({
        ip: o.ip,
        count_24h: Math.round(o.base + o.per_min * mins),
        last_seen: new Date(now - (i * 47 + 3) * 1000).toISOString(),
        reason: 'allowlist',
      }))
    : [];
  for (const [ip, c] of blockedCounts) {
    if (blockedBy(ip)) out.push({ ip, count_24h: c.n, last_seen: new Date(c.last).toISOString(), reason: 'blocked' });
  }
  // One host opening more TCP connections than the per-source limit allows.
  out.push({ ip: '10.9.0.66', count_24h: Math.round(2_310 + 40 * mins), last_seen: new Date(now - 9000).toISOString(), reason: 'per_source' });
  return out.sort((a, b) => b.count_24h - a.count_24h);
}

// ---------- TLS syslog listener (docs/api.md → TLS syslog listener) ----------

const DAY = 24 * 60 * MIN;
/** SPEC §10.3.3: both certificates end by this date. */
const TLS_CAP = Date.parse('2037-12-31T23:59:59Z');
const iso = (t: number) => new Date(t).toISOString().replace(/\.\d{3}Z$/, 'Z');

/** Fake fingerprints: upper-case hex pairs, as the server sends them. */
function fingerprint(bytes: number): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (b) => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
}

/** The names Woodshed would put in a new certificate (hostname, .local, search domain, localhost, extra names). */
const BASE_NAMES = ['localhost', 'logs-01', 'logs-01.example.net', 'logs-01.local'];
const hostNames = () => [...new Set([...BASE_NAMES, ...(mock.tlsNames ? ['edge-logs.example.net'] : []), ...settings.ui.extra_hostnames.filter((h) => !isIP(h))])];

function makeCa(at: number): TlsCa {
  const day = iso(at).slice(0, 10);
  return { subject: `CN=Woodshed CA logs-01 ${day}`, not_before: iso(at), not_after: iso(TLS_CAP), sha256: fingerprint(32), sha1: fingerprint(20) };
}

type Leaf = Omit<TlsCert, 'missing_names'>;

function makeLeaf(at: number, names = hostNames()): Leaf {
  return {
    subject: 'CN=logs-01.example.net',
    issuer: wsCa?.subject ?? '',
    not_before: iso(at),
    not_after: iso(Math.min(at + 3652 * DAY, TLS_CAP)),
    sha256: fingerprint(32),
    dns_names: [...names].sort(),
    ip_addresses: ['10.1.0.50', '127.0.0.1', '192.168.64.1', '::1', 'fd00::50'],
  };
}

// The certificate Woodshed made (kept when TLS is turned off). mock_tls=never: none yet.
const TLS_MADE = START - 12 * DAY;
let wsCa: TlsCa | null = TLS_MODE === 'never' ? null : makeCa(TLS_MADE);
let wsLeaf: Leaf | null = TLS_MODE === 'never' ? null : makeLeaf(TLS_MADE, BASE_NAMES);
/** The expiring certificate's end, while mock.tlsExpiring is on. */
const SOON = START + 41 * DAY;

/** mock_tls=file: the user's own certificate, from another CA. */
const FILE_CERT: TlsCert = {
  subject: 'CN=logs.example.net',
  issuer: 'CN=Example Issuing CA 2, O=Example Corp',
  not_before: iso(START - 30 * DAY),
  not_after: iso(START + 367 * DAY),
  sha256: fingerprint(32),
  dns_names: ['logs.example.net'],
  ip_addresses: [],
  missing_names: [],
};

const isWindowsOs = () => OS.startsWith('windows');

function tlsCertJSON(): TlsCert | null {
  const t = settings.listeners.tls;
  if (t?.cert_file) return { ...FILE_CERT, not_after: mock.tlsExpiring ? iso(SOON) : FILE_CERT.not_after };
  if (!wsLeaf) return null;
  return {
    ...wsLeaf,
    not_after: mock.tlsExpiring ? iso(SOON) : wsLeaf.not_after,
    missing_names: hostNames().filter((h) => !wsLeaf!.dns_names.includes(h)),
  };
}

function tlsJSON(): TlsState {
  const t = settings.listeners.tls!;
  const file = !!t.cert_file;
  return {
    enabled: t.enabled,
    port: t.port,
    source: file ? 'file' : 'woodshed',
    allow_legacy_tls: t.allow_legacy_tls,
    ca: file ? null : wsCa,
    cert: tlsCertJSON(),
    firewall: isWindowsOs() ? { state: mock.tlsFirewall, command: 'woodshed tls on' } : { state: 'unknown', command: '' },
  };
}

const ymd = (s: string) => s.slice(0, 10);

function tlsBanners(): Status['banners'] {
  const t = settings.listeners.tls;
  if (!t?.enabled) return [];
  const out: Status['banners'] = [];
  const cert = tlsCertJSON();
  if (t.allow_legacy_tls)
    out.push({ kind: 'tls_legacy', level: 'warn', action: '', text: "TLS 1.0 and 1.1 are allowed for older senders. Turn this off once they're updated." });
  if (cert && Date.parse(cert.not_after) - Date.now() < 60 * DAY)
    out.push({
      kind: 'tls_cert_expiring',
      level: 'warn',
      action: t.cert_file ? '' : 'tls_renew',
      text: t.cert_file
        ? `Your TLS syslog certificate expires on ${ymd(cert.not_after)}. Replace the certificate and key files before then.`
        : `The TLS syslog certificate expires on ${ymd(cert.not_after)}. Renew it, then nothing changes on your devices.`,
    });
  if (cert && cert.missing_names.length)
    out.push({
      kind: 'tls_cert_names',
      level: 'warn',
      action: 'tls_renew',
      text: `The TLS certificate doesn't name ${cert.missing_names.join(', ')}. Devices that check the server name will refuse it. Renew it to add the name.`,
    });
  const fw = tlsJSON().firewall;
  if (isWindowsOs() && fw.state !== 'ok') {
    const why: Record<string, string> = {
      missing: 'there is no Windows firewall rule for it',
      disabled: 'its Windows firewall rule is turned off',
      wrong_port: 'its Windows firewall rule is for another port',
      unknown: "Woodshed can't read its Windows firewall rule",
    };
    out.push({
      kind: 'tls_firewall',
      level: 'warn',
      action: '',
      text: `Devices may not reach TLS port ${t.port}: ${why[fw.state] ?? 'the firewall may block it'}. Run ${fw.command} in an administrator prompt.`,
    });
  }
  return out;
}

/** Per-device TLS stats: a few fleet devices send over TLS (or try to). */
function deviceTls(ip: string, now: number): DeviceTls | null {
  if (!wsLeaf && !settings.listeners.tls?.cert_file) return null;
  const mins = (now - START) / MIN;
  const ok = (version: string, cipher: string, conns: number, lastMs: number): DeviceTls => ({
    connections_24h: conns,
    version,
    cipher,
    last_connected: iso(now - lastMs),
    failures_24h: 0,
    last_failure: null,
  });
  switch (ip) {
    case '10.1.0.1':
      return ok('TLS 1.3', 'TLS_AES_128_GCM_SHA256', 4, 3 * 60 * MIN);
    case '10.1.0.2':
      return { ...ok('TLS 1.2', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 6, 41 * MIN), failures_24h: 2, last_failure: { time: iso(now - 5 * 60 * MIN), reason: 'timeout', detail: '' } };
    case '10.1.0.20':
      return ok('TLS 1.3', 'TLS_CHACHA20_POLY1305_SHA256', 288, 2 * MIN);
    case '10.8.0.1':
      // An older sender that offers only TLS 1.0: it connects once allow_legacy_tls is on.
      if (settings.listeners.tls?.allow_legacy_tls) return ok('TLS 1.0', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 3, 4 * MIN);
      return {
        connections_24h: 0,
        version: '',
        cipher: '',
        last_connected: null,
        failures_24h: Math.round(8_640 + 6 * mins),
        last_failure: { time: iso(now - 7_000), reason: 'version', detail: 'tls: client offered only unsupported versions: [301]' },
      };
    default:
      return null;
  }
}

/** GET /api/tls/failures: senders whose handshakes failed in the last 24 h, most failures first. */
function tlsFailures(now: number): TlsFailure[] {
  if (mock.firstRun || (!wsLeaf && !settings.listeners.tls?.cert_file)) return [];
  const mins = (now - START) / MIN;
  const out: TlsFailure[] = [
    { ip: '198.51.100.23', count_24h: Math.round(2_880 + 6 * mins), last_seen: iso(now - 4_000), reason: 'cert_rejected', detail: 'remote error: tls: unknown certificate authority', device_id: '' },
    { ip: '10.2.0.20', count_24h: Math.round(611 + 2 * mins), last_seen: iso(now - 26_000), reason: 'not_tls', detail: 'first record does not look like a TLS handshake', device_id: '10.2.0.20' },
    { ip: '203.0.113.80', count_24h: 37, last_seen: iso(now - 52 * MIN), reason: 'timeout', detail: 'no complete handshake within 10 s', device_id: '' },
    { ip: '192.0.2.81', count_24h: 12, last_seen: iso(now - 3 * 60 * MIN), reason: 'cipher', detail: 'tls: no cipher suite supported by both client and server', device_id: '' },
    { ip: '10.1.0.2', count_24h: 2, last_seen: iso(now - 5 * 60 * MIN), reason: 'timeout', detail: 'no complete handshake within 10 s', device_id: '10.1.0.2' },
  ];
  if (!settings.listeners.tls?.allow_legacy_tls)
    out.push({ ip: '10.8.0.1', count_24h: Math.round(8_640 + 6 * mins), last_seen: iso(now - 7_000), reason: 'version', detail: 'tls: client offered only unsupported versions: [301]', device_id: '10.8.0.1' });
  return out.sort((a, b) => b.count_24h - a.count_24h);
}

function caDownload(format: 'pem' | 'der'): Response {
  const der = crypto.getRandomValues(new Uint8Array(812));
  if (format === 'der')
    return new Response(der, {
      status: 200,
      headers: { 'Content-Type': 'application/pkix-cert', 'Content-Disposition': 'attachment; filename="woodshed-ca.cer"' },
    });
  const b64 = btoa(String.fromCharCode(...der)).replace(/.{64}/g, '$&\n');
  return new Response(`-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`, {
    status: 200,
    headers: { 'Content-Type': 'application/x-pem-file', 'Content-Disposition': 'attachment; filename="woodshed-ca.pem"' },
  });
}

// ---------- Exports ----------

const H = 60 * MIN;
const EXPIRE_MS = 24 * H;

interface MockExport extends ExportInfo {
  estimate: number;
}

const noFilters = (): ExportInfo['filters'] => ({ group: '', ungrouped: false, severities: [], q: '', regex: false, case: false, app: [], host: [], exclude: '' });
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

const exportsList: MockExport[] = [
  {
    id: 'exp_7Hq2', created: ago(23 * H + 10 * MIN), ready_at: ago(23 * H), expires_at: ago(23 * H - EXPIRE_MS),
    devices: ['10.1.0.1', '10.1.0.2'], from: ago(48 * H), to: ago(24 * H),
    state: 'ready', progress: 1, lines: 1_204_332, size_bytes: 48 * MiB, error: '', estimate: 0,
    filters: { ...noFilters(), severities: [3, 4], q: 'deny' },
  },
  {
    id: 'exp_3kPz', created: ago(5 * H), ready_at: null, expires_at: null,
    devices: [], from: ago(7 * 24 * H), to: ago(5 * H),
    state: 'failed', progress: 0.4, lines: 0, size_bytes: 0, error: 'Not enough free disk space to build the zip.', estimate: 0,
    filters: { ...noFilters(), group: 'DMZ' },
  },
  {
    id: 'exp_9aLm', created: ago(30 * H), ready_at: ago(29.9 * H), expires_at: ago(5.9 * H),
    devices: ['10.8.0.1'], from: ago(32 * H), to: ago(31 * H),
    state: 'expired', progress: 1, lines: 8_812, size_bytes: 0, error: '', estimate: 0,
    filters: { ...noFilters(), q: 'link (up|down)', regex: true },
  },
];

function estimate(b: { devices: string[]; from: string; to: string; severities?: unknown[] }) {
  const span = Math.max(0, Date.parse(b.to) - Date.parse(b.from));
  let lines = Math.round((span / STEP) * shareOf(b.devices));
  // An upper bound from the index: severity and text filters can only shrink it.
  if (b.severities?.length) lines = Math.round(lines * Math.min(1, b.severities.length / 3));
  const days = Math.max(1, Math.ceil(span / (24 * H)));
  return { lines, bytes: lines * 142, files: b.devices.length * days };
}

/** One build at a time; the rest wait in the queue. */
function exportTick() {
  const now = Date.now();
  for (const e of exportsList) if (e.state === 'ready' && e.expires_at && now > Date.parse(e.expires_at)) e.state = 'expired';
  let cur = exportsList.find((e) => e.state === 'building');
  if (!cur) {
    cur = [...exportsList].reverse().find((e) => e.state === 'queued');
    if (cur) cur.state = 'building';
  }
  if (!cur) return;
  cur.progress = Math.min(1, cur.progress + 0.25 / mock.exportSecs);
  cur.lines = Math.round(cur.estimate * 0.8 * cur.progress);
  cur.size_bytes = Math.round(cur.lines * 32);
  if (mock.exportFail && cur.progress >= 0.4) {
    cur.state = 'failed';
    cur.error = 'Not enough free disk space to build the zip.';
  } else if (cur.progress >= 1) {
    cur.state = 'ready';
    cur.ready_at = new Date(now).toISOString();
    cur.expires_at = new Date(now + EXPIRE_MS).toISOString();
  }
}
setInterval(exportTick, 250);

/** Download tickets: opaque → export, issuing session's secret, expiry. */
const tickets = new Map<string, { id: string; secret: string; until: number }>();

const exportJSON = (e: MockExport): ExportInfo => {
  const { estimate: _e, ...rest } = e;
  void _e;
  return rest;
};

function history(): StorageHistoryEntry[] {
  const out: StorageHistoryEntry[] = [];
  const day = 24 * 60 * MIN;
  const ips = ['10.1.0.1', '10.1.0.2', '10.1.0.10', '10.8.0.1'];
  for (let i = 0; i < 8; i++) {
    const t = new Date(Date.now() - i * day - 3 * 60 * MIN);
    const old = new Date(t.getTime() - 31 * day).toISOString().slice(0, 10);
    const ip = ips[i % ips.length];
    out.push({
      time: t.toISOString(),
      file: `logs/${ip}/${old}.log.gz`,
      device_id: ip,
      bytes: Math.round((8 + Math.random() * 30) * MiB),
      reason: i === 5 ? 'cap' : 'age',
    });
  }
  return out;
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
const err = (status: number, error: string) => json({ error }, status);

// ---------- Search ----------

/** Lines scanned per request before the 10 s budget "runs out" (slow-scan mode: far fewer). */
const scanBudget = () => (mock.slowScan ? 2500 : 120_000);

/** A filter as search, the summary and exports apply it (docs/api.md → Search, and the 1.1 filters). */
interface LineFilter {
  from: number;
  to: number;
  dev: MockFilters & { exclude?: string[] };
  sev: Set<string> | null;
  fac: Set<string> | null;
  /** q and exclude, compiled for the syntax. */
  q: (raw: string) => boolean;
  ex: ((raw: string) => boolean) | null;
  fields: (f: { app: string; host: string }) => boolean;
  /** No q, exclude, app, host, their exclude forms, facility or severity filter (the index histogram's rule). */
  unfiltered: boolean;
}

/** The facility of a raw message from its PRI (0-23), or "unknown". */
function facilityOf(raw: string): string {
  const m = /^<(\d{1,3})>/.exec(raw);
  return m && Number(m[1]) <= 191 ? String(Number(m[1]) >> 3) : 'unknown';
}

const FACILITY_LABELS = ['kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'];
const SEV_LABELS = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'];

/** facilities=0,4,unknown | none (docs/api.md, 1.1). Throws on an invalid value. */
function facFilter(v: string): Set<string> | null {
  const parts = v.split(',').map((x) => x.trim()).filter(Boolean);
  if (!parts.length) return null;
  if (parts.includes('none')) {
    if (parts.length > 1) throw new Error('facilities: none can\'t be combined with other values');
    return new Set();
  }
  for (const x of parts) if (x !== 'unknown' && !(/^\d{1,2}$/.test(x) && Number(x) <= 23)) throw new Error(`facilities: "${x}" is not a facility (0 to 23, unknown, or none on its own)`);
  return new Set(parts.map((x) => (x === 'unknown' ? x : String(Number(x)))));
}

const listParam = (u: URLSearchParams, k: string) => (u.get(k) ?? '').split(',').map((x) => x.trim()).filter(Boolean);
const normApp = (x: string) => x.replace(/^%/, '').toLowerCase();
const appMatch = (pats: string[], app: string) => {
  const a = normApp(app);
  return !!a && pats.some((p) => (p.endsWith('*') ? a.startsWith(p.replace(/\*+$/, '')) : a === p));
};

/** A substring (or regex, or terms) matcher for q or exclude; throws an Error with the server's message. */
function textMatcher(v: string, syntax: string, isRe: boolean, cs: boolean): ((raw: string) => boolean) | null {
  if (!v) return null;
  if (isRe) {
    let re: RegExp;
    try {
      re = new RegExp(v, cs ? '' : 'i');
    } catch (e) {
      // RE2's message style; the JS engine's detail follows.
      throw new Error(`error parsing regexp: ${(e as Error).message.replace(/^Invalid regular expression: /, '')}`);
    }
    return (raw) => re.test(raw);
  }
  if (syntax === 'terms') {
    const n = parseTerms(v);
    return n ? (raw) => matchTerms(n, raw, cs) : null;
  }
  const lv = v.toLowerCase();
  return cs ? (raw) => raw.includes(v) : (raw) => raw.toLowerCase().includes(lv);
}

/** Reads every filter parameter of search and the summary; a string is the 400's message. */
function lineFilter(u: URLSearchParams, now: number): LineFilter | string {
  const type = u.get('type') ?? 'syslog';
  if (type !== 'syslog') return `type: unknown data type "${type}".`;
  const syntax = u.get('syntax') ?? 'text';
  if (syntax !== 'text' && syntax !== 'terms') return `syntax must be text or terms, not "${syntax}"`;
  const isRe = u.get('regex') === 'true';
  const cs = u.get('case') === 'true';
  if (isRe && syntax === 'terms') return TERMS_AND_REGEX;
  let sev: Set<string> | null;
  let fac: Set<string> | null;
  try {
    sev = sevFilter(u);
    fac = facFilter(u.get('facilities') ?? '');
  } catch (e) {
    return (e as Error).message;
  }
  const q = u.get('q') ?? '';
  const exclude = u.get('exclude') ?? '';
  let qm: ((raw: string) => boolean) | null;
  let exm: ((raw: string) => boolean) | null;
  try {
    qm = textMatcher(q, syntax, isRe, cs);
  } catch (e) {
    return (e as Error).message;
  }
  try {
    exm = textMatcher(exclude, syntax, isRe, cs);
  } catch (e) {
    return `exclude: ${(e as Error).message}`;
  }
  const apps = listParam(u, 'app').map(normApp);
  const hosts = listParam(u, 'host').map((x) => x.toLowerCase());
  const xapps = listParam(u, 'exclude_app').map(normApp);
  const xhosts = listParam(u, 'exclude_host').map((x) => x.toLowerCase());
  const fields = (f: { app: string; host: string }) => {
    if (hosts.length && !hosts.includes(f.host.toLowerCase())) return false;
    if (apps.length && !appMatch(apps, f.app)) return false;
    // A line without a program/tag (or hostname) is never left out by the exclude forms.
    if (xhosts.length && f.host && xhosts.includes(f.host.toLowerCase())) return false;
    if (xapps.length && f.app && appMatch(xapps, f.app)) return false;
    return true;
  };
  const to = u.has('to') ? Date.parse(u.get('to')!) : now;
  const from = u.has('from') ? Date.parse(u.get('from')!) : to - 24 * H;
  if (Number.isNaN(from) || Number.isNaN(to)) return '"from" and "to" must be RFC 3339 times.';
  if (!(from < to)) return '"from" must be before "to".';
  const group = u.get('group') ?? undefined;
  const ungrouped = u.get('ungrouped') === 'true';
  if (group && ungrouped) return 'group and ungrouped=true are alternatives; send one';
  return {
    from,
    to,
    dev: { devices: u.get('devices')?.split(',').filter(Boolean), group, ungrouped, sev, exclude: listParam(u, 'exclude_devices') },
    sev,
    fac,
    q: qm ?? (() => true),
    ex: exm,
    fields,
    unfiltered: !qm && !exm && !apps.length && !hosts.length && !xapps.length && !xhosts.length && !sev && !fac,
  };
}

/** The device part: search's selection (hidden only when named), then exclude_devices wins. */
const devicePasses = (ip: string, f: LineFilter) => deviceMatches(ip, f.dev, true) && !f.dev.exclude?.includes(ip);

/** Every filter on one stored line; the text and header are generated only once the device passes. */
function linePasses(l: GenLine, f: LineFilter): { app: string; host: string } | null {
  if (f.sev && !f.sev.has(sevKeyOf(l.severity))) return null;
  if (f.fac && !f.fac.has(facilityOf(l.raw))) return null;
  if (!f.q(l.raw)) return null;
  if (f.ex?.(l.raw)) return null;
  const fl = fieldsOf(l.raw);
  return f.fields(fl) ? fl : null;
}

/** The cursor signature: every parameter except the cursor, limit and the summary's own budget. */
function signature(u: URLSearchParams): string {
  const s = new URLSearchParams(u);
  for (const k of ['cursor', 'limit', 'budget_ms']) s.delete(k);
  s.sort();
  return [...s.toString()].reduce((h, c) => (Math.imul(h, 31) + c.charCodeAt(0)) >>> 0, 7).toString(36);
}

function searchRoute(u: URLSearchParams, now: number): Response {
  const f = lineFilter(u, now);
  if (typeof f === 'string') return err(400, f);
  const order = u.get('order') === 'asc' ? 'asc' : 'desc';
  const limit = Math.min(5000, Math.max(1, Number(u.get('limit') || 500)));
  // The cursor is tied to the other parameters, as on the real server.
  const sig = signature(u);
  const lo = Math.ceil(f.from / STEP);
  const hi = Math.ceil(Math.min(f.to, now) / STEP) - 1;
  let i = order === 'desc' ? hi : lo;
  const cur = u.get('cursor');
  if (cur) {
    const [idx, s2] = cur.split('.');
    if (s2 !== sig) return err(400, 'The cursor belongs to a different search.');
    i = Number(idx);
  }
  const step = order === 'desc' ? -1 : 1;
  const inRange = (k: number) => k >= lo && k <= hi;
  const results: (GenLine & { ref: string; app: string; host: string })[] = [];
  const files = new Set<string>();
  let scanned = 0;
  const budget = scanBudget();
  const t0 = performance.now();
  for (; inRange(i) && results.length < limit && scanned < budget; i += step) {
    scanned++;
    const d = deviceAt(i);
    if (!devicePasses(d.ip, f)) continue;
    files.add(`${d.ip}/${Math.floor((i * STEP) / (24 * H))}`);
    const l = lineAt(i);
    const fl = linePasses(l, f);
    if (fl) results.push({ ...l, ...fl, ref: `h${i}` });
  }
  const exhausted = !inRange(i);
  return json({
    results,
    next_cursor: exhausted ? '' : `${i}.${sig}`,
    scanned_bytes: scanned * 142,
    scanned_files: files.size,
    elapsed_ms: Math.round(performance.now() - t0) + (mock.slowScan ? 9800 : 40),
    partial: !exhausted && results.length < limit,
  });
}

// ---------- Events v2: schema, summary (docs/api.md, 1.1) ----------

const SCHEMA = {
  types: [
    {
      type: 'syslog',
      label: 'Syslog',
      default: true,
      fields: [
        { key: 'device', label: 'Device', param: 'devices', exclude_param: 'exclude_devices', domain: null },
        {
          key: 'severity', label: 'Severity', param: 'severities', exclude_param: '',
          domain: [...SEV_LABELS.map((l, i) => ({ value: String(i), label: l })), { value: 'unknown', label: 'unknown' }],
        },
        {
          key: 'facility', label: 'Facility', param: 'facilities', exclude_param: '',
          domain: [...FACILITY_LABELS.map((l, i) => ({ value: String(i), label: l })), { value: 'unknown', label: 'unknown' }],
        },
        { key: 'host', label: 'Host', param: 'host', exclude_param: 'exclude_host', domain: null },
        { key: 'app', label: 'Program/tag', param: 'app', exclude_param: 'exclude_app', domain: null },
      ],
    },
  ],
};
const FIELD_KEYS = SCHEMA.types[0].fields.map((x) => x.key);

/** Mock slow summary (mock_slow_summary=1): each request counts only this many stored lines. */
const summaryLines = (budgetMs: number) => (mock.slowSummary ? 1200 : Math.round((budgetMs / 10_000) * 120_000));

/** SPEC §10.1.2: the bucket for a range, giving at most 120 buckets. */
function defaultBucket(rangeMs: number): number {
  const S = 1000, M = 60 * S, HR = 60 * M, D = 24 * HR;
  const table: [number, number][] = [[2 * M, 1], [10 * M, 5], [30 * M, 15], [2 * HR, 60], [10 * HR, 300], [30 * HR, 900], [5 * D, 3600],
    [10 * D, 7200], [30 * D, 21600], [120 * D, 86400]];
  for (const [upTo, b] of table) if (rangeMs <= upTo) return b;
  return 604800;
}

/** Bucket starts are multiples of the size since the epoch; 7-day buckets start on Mondays (4 days after it). */
const bucketStart = (t: number, sizeMs: number) => {
  const off = sizeMs === 604_800_000 ? 4 * 86_400_000 : 0;
  return Math.floor((t - off) / sizeMs) * sizeMs + off;
};

interface ValueTally {
  label: string;
  count: number;
}
interface SummaryState {
  sig: string;
  /** The next stored line to count (newest first); lo - 1 once done. */
  next: number;
  seq: number;
  used: number;
  matched: number;
  scannedFiles: Set<string>;
  hist: Map<number, number>;
  fields: Map<string, { values: Map<string, ValueTally>; none: number; overflow: number }>;
}
const summaries = new Map<string, SummaryState>();
const SUMMARY_TTL = 10 * MIN;
const MAX_DISTINCT = 10_000;

function keepSummary(id: string, s: SummaryState, now: number) {
  s.used = now;
  summaries.delete(id);
  summaries.set(id, s);
  for (const [k, v] of summaries) if (now - v.used > SUMMARY_TTL) summaries.delete(k);
  while (summaries.size > 8) summaries.delete(summaries.keys().next().value!); // least recently used out first
}

const devLabel = (ip: string) => devs.get(ip)?.name || FLEET.find((d) => d.ip === ip)?.name || ip;

function summaryRoute(u: URLSearchParams, now: number): Response {
  const f = lineFilter(u, now);
  if (typeof f === 'string') return err(400, f);
  const fieldsArg = u.get('fields');
  const want = fieldsArg === null || fieldsArg === '' ? FIELD_KEYS : fieldsArg === 'none' ? [] : fieldsArg.split(',').map((x) => x.trim()).filter(Boolean);
  for (const k of want) if (!FIELD_KEYS.includes(k)) return err(400, `fields: unknown field "${k}".`);
  const top = u.has('top') ? Number(u.get('top')) : 10;
  if (!Number.isInteger(top) || top < 1 || top > 50) return err(400, `top must be an integer from 1 to 50, not "${u.get('top')}"`);
  const wantHist = u.get('histogram') !== 'false';
  const budgetMs = u.has('budget_ms') ? Number(u.get('budget_ms')) : 2000;
  if (!Number.isInteger(budgetMs) || budgetMs < 1 || budgetMs > 10_000) return err(400, `budget_ms must be an integer from 1 to 10000, not "${u.get('budget_ms')}"`);
  const bucketSec = u.has('bucket') ? Number(u.get('bucket')) : defaultBucket(f.to - f.from);
  const bucketMs = bucketSec * 1000;
  const allowed = [1, 5, 15, 60, 300, 900, 3600, 7200, 21600, 86400, 604800];
  if (!allowed.includes(bucketSec)) return err(400, `bucket must be one of ${allowed.join(', ')} seconds, not "${u.get('bucket')}"`);
  const firstB = bucketStart(f.from, bucketMs);
  const nBuckets = Math.ceil((f.to - firstB) / bucketMs);
  if (nBuckets > 1000) return err(400, `bucket=${bucketSec} gives ${nBuckets} buckets over this range; the limit is 1,000. Pick a larger bucket.`);

  const sig = signature(u);
  const lo = Math.ceil(f.from / STEP);
  const hi = Math.ceil(Math.min(f.to, now) / STEP) - 1;
  const indexHist = wantHist && f.unfiltered && bucketSec >= 60;
  const needScan = want.length > 0 || !indexHist;

  let id = '';
  let st: SummaryState;
  const cur = u.get('cursor');
  if (cur) {
    const [cid, seq, s2] = cur.split('.');
    const got = summaries.get(cid);
    if (!got || now - got.used > SUMMARY_TTL || String(got.seq) !== seq) {
      probe.expiredSummaries++;
      return err(400, 'This summary expired; start it again.');
    }
    if (s2 !== sig) return err(400, 'The cursor belongs to a different summary: keep every parameter the same as on the first request.');
    id = cid;
    st = got;
  } else {
    id = Math.random().toString(36).slice(2, 10);
    st = { sig, next: hi, seq: 0, used: now, matched: 0, scannedFiles: new Set(), hist: new Map(), fields: new Map() };
    for (const k of want) st.fields.set(k, { values: new Map(), none: 0, overflow: 0 });
  }

  const t0 = performance.now();
  let scanned = 0;
  const files = new Set<string>();
  if (needScan) {
    const budget = summaryLines(budgetMs);
    const tally = (key: string, value: string, label: string) => {
      const fs = st.fields.get(key);
      if (!fs) return;
      if (!value) {
        fs.none++;
        return;
      }
      // Host and program/tag group ignoring case (and a leading % for tags), as their filters match.
      const k = key === 'host' ? value.toLowerCase() : key === 'app' ? normApp(value) : value;
      const v = fs.values.get(k);
      if (v) v.count++;
      else if (fs.values.size >= MAX_DISTINCT) fs.overflow++;
      else fs.values.set(k, { label: key === 'device' ? `${value}\u0000${label}` : value, count: 1 });
    };
    for (; st.next >= lo && scanned < budget; st.next--) {
      scanned++;
      const i = st.next;
      const d = deviceAt(i);
      if (!devicePasses(d.ip, f)) continue;
      files.add(`${d.ip}/${Math.floor((i * STEP) / (24 * H))}`);
      const l = lineAt(i);
      const fl = linePasses(l, f);
      if (!fl) continue;
      st.matched++;
      const b = bucketStart(i * STEP, bucketMs);
      st.hist.set(b, (st.hist.get(b) ?? 0) + 1);
      tally('device', d.ip, devLabel(d.ip));
      tally('severity', sevKeyOf(l.severity), '');
      tally('facility', facilityOf(l.raw), '');
      tally('host', fl.host, '');
      tally('app', fl.app, '');
    }
  } else st.next = lo - 1;
  for (const x of files) st.scannedFiles.add(x);
  const done = st.next < lo;
  // Every line from st.next + 1 on is counted, and line i was received at i × STEP.
  const countedFrom = done ? f.from : Math.min(f.to, Math.max(f.from, (st.next + 1) * STEP));

  let histogram: unknown;
  if (wantHist) {
    const counts = new Map<number, number>();
    let approxFrom = -Infinity;
    if (indexHist) {
      // From the "stats and checkpoints": every line in range, without reading text.
      for (let i = hi; i >= lo; i--) {
        if (!devicePasses(deviceAt(i).ip, f)) continue;
        const b = bucketStart(i * STEP, bucketMs);
        counts.set(b, (counts.get(b) ?? 0) + 1);
      }
      // Older than the per-minute stats (24 h) a cut edge bucket is spread from checkpoints.
      approxFrom = now - 24 * H;
    }
    const buckets = [];
    for (let k = 0; k < nBuckets; k++) {
      const start = firstB + k * bucketMs;
      const end = start + bucketMs;
      const edge = (start < f.from || end > f.to) && start < approxFrom && bucketSec < 86400;
      const count = indexHist ? (counts.get(start) ?? 0) : end <= countedFrom ? null : (st.hist.get(start) ?? 0);
      buckets.push({ start: new Date(start).toISOString(), count, approx: indexHist && edge && (count ?? 0) > 0 });
    }
    histogram = { bucket_seconds: bucketSec, source: indexHist ? 'index' : 'scan', buckets };
  }

  const fieldsOut = want.map((key) => {
    const desc = SCHEMA.types[0].fields.find((x) => x.key === key)!;
    const fs = st.fields.get(key)!;
    const all = [...fs.values.entries()].map(([k, v]) => {
      const [value, devName] = key === 'device' ? v.label.split('\u0000') : [v.label, ''];
      const label = desc.domain ? (desc.domain.find((x) => x.value === k)?.label ?? k) : key === 'device' ? devName : value;
      return { value: desc.domain ? k : value, label, count: v.count, filterable: !value.includes(',') && !(key === 'app' && value.endsWith('*')) };
    });
    all.sort((a, b) => b.count - a.count || (a.value < b.value ? -1 : a.value > b.value ? 1 : 0));
    const values = desc.domain ? all : all.slice(0, top);
    const listed = values.reduce((s, v) => s + v.count, 0);
    const withValue = all.reduce((s, v) => s + v.count, 0) + fs.overflow;
    return {
      key, label: desc.label, values, other: withValue - listed, none: fs.none, distinct: fs.values.size,
      distinct_capped: fs.values.size >= MAX_DISTINCT && fs.overflow > 0,
    };
  });

  let matched = st.matched;
  if (!needScan && histogram) matched = (histogram as { buckets: { count: number }[] }).buckets.reduce((s, b) => s + b.count, 0);
  st.seq++;
  if (done) summaries.delete(id);
  else keepSummary(id, st, now);
  return json({
    type: 'syslog',
    from: new Date(f.from).toISOString(),
    to: new Date(f.to).toISOString(),
    matched,
    counted_from: new Date(countedFrom).toISOString(),
    ...(histogram ? { histogram } : {}),
    fields: fieldsOut,
    next_cursor: done ? '' : `${id}.${st.seq}.${sig}`,
    partial: !done,
    scanned_bytes: scanned * 142,
    scanned_files: files.size,
    elapsed_ms: Math.round(performance.now() - t0) + (mock.slowSummary ? 2000 : needScan ? 30 : 2),
  });
}

/** Ends every summary's running counts now (the panel's "expire summaries"), so the next cursor is a 400. */
export function expireSummaries() {
  summaries.clear();
}

// ---------- Saved searches (docs/api.md, 1.1) ----------

interface MockSaved {
  id: string;
  name: string;
  type: string;
  created: string;
  updated: string;
  query: SavedQuery;
  version: number;
}

const savedList: MockSaved[] = [];
function seedSaved() {
  const t = new Date(Date.now() - 3 * 24 * H).toISOString();
  const add = (name: string, query: SavedQuery) =>
    savedList.push({ id: `ss_${Math.random().toString(16).slice(2, 10)}`, name, type: 'syslog', created: t, updated: t, query, version: 1 });
  add('Edge denies', { q: 'deny NOT 10.1.0.255', syntax: 'terms', devices: ['10.1.0.1', '10.1.0.2'], range: { last: '1h' } });
  add('Auth failures', { q: 'failed', app: ['sshd'], devices: ['10.2.0.20', '10.9.9.9'], range: { last: '24h' } });
  add('Switch port flaps', { q: 'flap', group: 'HQ', exclude_app: ['lldpd'], range: { last: '7d' } });
}
seedSaved();

const SAVED_LIMIT = 200;
const knownDevice = (ip: string) => devs.has(ip) || FLEET.some((d) => d.ip === ip);

function savedJSON(s: MockSaved) {
  const devices = s.query.devices ?? [];
  const group = s.query.group ?? '';
  return {
    id: s.id, name: s.name, type: s.type, created: s.created, updated: s.updated,
    query: {
      q: '', syntax: 'text', regex: false, case: false, exclude: '', devices: [], group: '', ungrouped: false, exclude_devices: [],
      severities: [], facilities: [], app: [], exclude_app: [], host: [], exclude_host: [], order: 'desc', range: { last: '1h' },
      ...s.query,
    },
    missing_devices: devices.filter((d) => !knownDevice(d)),
    missing_group: !!group && !FLEET.some((d) => d.group === group) && ![...devs.values()].some((d) => d.group === group),
  };
}
const savedEtag = (s: MockSaved) => `"${s.id}-${s.version}"`;

/** Validates a saved-search body; returns the dotted-key errors (none: {}). */
function validateSaved(b: { name?: unknown; type?: unknown; query?: SavedQuery }, selfId = ''): { errors: Record<string, string>; conflict?: string } {
  const e: Record<string, string> = {};
  const name = typeof b.name === 'string' ? b.name.trim() : '';
  if (!name) e.name = 'Give the search a name.';
  else if ([...name].length > 80) e.name = 'At most 80 characters.';
  if (b.type !== undefined && b.type !== 'syslog') e.type = `Unknown data type "${String(b.type)}".`;
  const q = b.query ?? {};
  const syntax = q.syntax ?? 'text';
  if (syntax !== 'text' && syntax !== 'terms') e['query.syntax'] = 'Must be text or terms.';
  if (q.regex && syntax === 'terms') e['query.syntax'] = TERMS_AND_REGEX;
  else {
    for (const [k, v] of [['query.q', q.q], ['query.exclude', q.exclude]] as const) {
      try {
        textMatcher(v ?? '', syntax, !!q.regex, !!q.case);
      } catch (x) {
        e[k] = (x as Error).message;
      }
    }
  }
  for (const k of ['devices', 'exclude_devices', 'app', 'exclude_app', 'host', 'exclude_host', 'severities', 'facilities'] as const) {
    const v = q[k];
    if (v !== undefined && (!Array.isArray(v) || v.length > 1000)) e[`query.${k}`] = 'A list of at most 1,000 items.';
  }
  if (q.group && q.ungrouped) e['query.ungrouped'] = 'group and ungrouped are alternatives; send one.';
  const r = q.range;
  if (r && 'last' in r) {
    const m = /^(\d+)([mhd])$/.exec(r.last);
    const mins = m ? Number(m[1]) * ({ m: 1, h: 60, d: 1440 } as const)[m[2] as 'm' | 'h' | 'd'] : 0;
    if (!m || mins < 1 || mins > 400 * 1440) e['query.range.last'] = 'A whole number of m, h or d, from 1m to 400d.';
  } else if (r) {
    const f = Date.parse(r.from), t = Date.parse(r.to);
    if (Number.isNaN(f)) e['query.range.from'] = 'Must be an RFC 3339 time.';
    if (Number.isNaN(t)) e['query.range.to'] = 'Must be an RFC 3339 time.';
    else if (!(f < t)) e['query.range.to'] = 'Must be after "from".';
  }
  if (Object.keys(e).length) return { errors: e };
  const clash = savedList.find((s) => s.id !== selfId && s.name.toLowerCase() === name.toLowerCase());
  if (clash) return { errors: {}, conflict: `A saved search named "${clash.name}" already exists.` };
  return { errors: {} };
}

function savedRoute(method: string, p: string, u: URLSearchParams, body: unknown, ifMatch: string | null, now: number): Response | null {
  if (p === '/api/saved-searches') {
    if (method === 'GET') {
      const type = u.get('type') ?? 'syslog';
      if (type !== 'syslog') return err(400, `type: unknown data type "${type}".`);
      return json([...savedList].sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' })).map(savedJSON));
    }
    if (method === 'POST') {
      const b = (body ?? {}) as { name?: string; type?: string; query?: SavedQuery };
      const v = validateSaved(b);
      if (Object.keys(v.errors).length) return json({ error: 'Some fields need fixing.', errors: v.errors }, 400);
      if (v.conflict) return err(409, v.conflict);
      if (savedList.length >= SAVED_LIMIT) return err(409, `There are already ${SAVED_LIMIT} saved searches; delete one first.`);
      const t = new Date(now).toISOString();
      const s: MockSaved = { id: `ss_${Math.random().toString(16).slice(2, 10)}`, name: b.name!.trim(), type: 'syslog', created: t, updated: t, query: b.query ?? {}, version: 1 };
      savedList.push(s);
      return json(savedJSON(s), 201, { ETag: savedEtag(s) });
    }
    return null;
  }
  const m = /^\/api\/saved-searches\/([^/]+)$/.exec(p);
  if (!m) return null;
  const id = decodeURIComponent(m[1]);
  const k = savedList.findIndex((s) => s.id === id);
  if (k < 0) return err(404, `No saved search with id "${id}".`);
  const s = savedList[k];
  if (method === 'GET') return json(savedJSON(s), 200, { ETag: savedEtag(s) });
  if (method === 'DELETE') {
    savedList.splice(k, 1);
    return new Response(null, { status: 204 });
  }
  if (method === 'PUT') {
    if (ifMatch && ifMatch !== '*' && ifMatch !== savedEtag(s)) return err(409, 'This saved search changed since you loaded it.');
    const b = (body ?? {}) as { name?: string; type?: string; query?: SavedQuery };
    const v = validateSaved(b, id);
    if (Object.keys(v.errors).length) return json({ error: 'Some fields need fixing.', errors: v.errors }, 400);
    if (v.conflict) return err(409, v.conflict);
    s.name = b.name!.trim();
    s.query = b.query ?? {};
    s.updated = new Date(now).toISOString();
    s.version++;
    return json(savedJSON(s), 200, { ETag: savedEtag(s) });
  }
  return null;
}

async function route(method: string, url: URL, body: unknown, header: string | null, signal?: AbortSignal, ifMatch: string | null = null): Promise<Response> {
  const p = url.pathname;
  const now = Date.now();
  const changing = !['GET', 'HEAD', 'OPTIONS'].includes(method);
  if (p !== '/api/live') {
    if (changing) probe.lastWriteHeader = header;
    else probe.lastGetHeader = header;
  }

  if (method === 'GET' && p === '/healthz') return json({ ok: true });
  if (method === 'GET' && p === '/api/session') {
    const body = JSON.stringify(sessionJSON(header));
    probe.sessionBodies.push(body);
    return new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } });
  }
  if (method === 'POST' && p === '/api/login') {
    if (!authOn()) return err(400, 'Login is off: LAN mode and require_login_local are both off.');
    const locked = lockout(now);
    if (locked) return locked;
    const recent = authState.failures.filter((t) => now - t < 15 * 60_000).length;
    if (recent >= 5 && now - authState.lastAttempt < 1000) return retryLater(1, 'Slow down.');
    authState.lastAttempt = now;
    if ((body as { password?: string })?.password !== authState.password) {
      recordFailure(now);
      return lockout(now) ?? err(401, 'Wrong password.');
    }
    authState.failures = [];
    mock.loggedIn = true;
    authState.secret = newToken();
    return json({ ...sessionJSON(authState.secret), session_secret: authState.secret });
  }
  if (method === 'POST' && p === '/api/logout') {
    mock.loggedIn = false;
    authState.secret = '';
    return new Response(null, { status: 204 });
  }
  const ticketed = method === 'GET' && /^\/api\/exports\/[^/]+\/download$/.test(p) && url.searchParams.has('ticket');
  if (authOn() && !PUBLIC.includes(p) && !ticketed) {
    // docs/api.md: the cookie and the X-Woodshed-Session header together; either alone is a 401.
    if (!hasSession(header)) return err(401, 'Log in first.');
  }
  if (method === 'PUT' && p === '/api/password') {
    const b = (body ?? {}) as { current?: string; new?: string };
    if (authState.password) {
      const locked = lockout(now);
      if (locked) return locked;
      if (b.current !== authState.password) {
        recordFailure(now);
        return err(403, 'The current password is wrong.');
      }
    }
    const len = new TextEncoder().encode(b.new ?? '').length;
    if (len < 8 || len > 1024)
      return json({ error: 'That password is not allowed.', errors: { new: 'Use 8 to 1024 characters.' } }, 400);
    // docs/api.md: the first password also turns on require_login_local.
    if (!authState.password) settings.ui.require_login_local = true;
    authState.password = b.new ?? '';
    return new Response(null, { status: 204 });
  }
  if (method === 'GET' && p === '/api/status') return json(statusJSON());
  if (method === 'POST' && p === '/api/listeners/retry') {
    await sleep(500);
    mock.clash = false; // pretend the other process was stopped
    return new Response(null, { status: 204 });
  }
  if (method === 'GET' && p === '/api/live') {
    probe.lastLiveHeader = header;
    probe.livePaths.push(url.pathname + url.search);
    let sev: Set<string> | null;
    try {
      sev = sevFilter(url.searchParams);
    } catch (e) {
      return err(400, (e as Error).message);
    }
    return liveResponse(url.searchParams, sev, signal);
  }
  if (method === 'GET' && p === '/api/stats') return json(statsJSON(now));
  if (method === 'GET' && p === '/api/devices') return devicesRoute(url.searchParams, now);
  if (method === 'GET' && p === '/api/groups') {
    const counts = new Map<string, number>();
    for (const d of devs.values()) if (d.group && !d.hidden) counts.set(d.group, (counts.get(d.group) ?? 0) + 1);
    return json([...counts].sort((a, b) => a[0].localeCompare(b[0])).map(([name, devices]) => ({ name, devices })));
  }
  const dm = p.match(/^\/api\/devices\/([^/]+)$/);
  if (dm && method === 'PATCH') {
    const d = devs.get(decodeURIComponent(dm[1]));
    if (!d) return err(404, 'No such device.');
    const b = (body ?? {}) as Partial<Device>;
    if (b.name !== undefined && b.name.length > 64) return err(400, 'Names can be at most 64 characters.');
    if (b.group !== undefined && b.group.length > 32) return err(400, 'Groups can be at most 32 characters.');
    if (b.name !== undefined) d.name = b.name.trim();
    if (b.group !== undefined) d.group = b.group.trim();
    if (b.hidden !== undefined) d.hidden = b.hidden;
    if (b.blocked !== undefined) {
      if (typeof b.blocked !== 'boolean') return err(400, 'blocked must be true or false.');
      const ip = d.def.ip;
      const own = (c: string) => c === ip || c === `${ip}/32` || c === `${ip}/128`;
      const list = settings.listeners.blocklist;
      if (b.blocked && !list.some(own)) list.push(`${ip}/${ip.includes(':') ? 128 : 32}`);
      if (!b.blocked) settings.listeners.blocklist = list.filter((c) => !own(c));
      settingsRev++;
      const dev = deviceJSON(d, now);
      const by = blockedBy(ip);
      return json(!b.blocked && by ? { ...dev, blocked_by: by } : dev);
    }
    return json(deviceJSON(d, now));
  }
  if (method === 'GET' && p === '/api/settings') return json(settings, 200, { ETag: settingsETag() });
  if (method === 'PUT' && p === '/api/settings') {
    probe.lastIfMatch = ifMatch;
    // A PUT without If-Match is accepted (scripts); a stale one is refused.
    if (ifMatch !== null && ifMatch !== settingsETag()) return err(409, 'settings changed since you loaded them');
    const s = body as Settings;
    const errors = validate(s);
    if (Object.keys(errors).length) return json({ errors }, 400);
    const wasLan = settings.ui.lan_mode;
    const restarting = wasLan !== s.ui.lan_mode || settings.ui.port !== s.ui.port;
    // A PUT without updates keeps it (docs/api.md).
    const check = s.updates?.check ?? settings.updates?.check ?? 'ask';
    settings = structuredClone({ ...s, updates: settings.updates });
    if (check !== settings.updates?.check) setUpdateCheck(check, now);
    settingsRev++;
    // docs/api.md: turning TLS on for the first time without cert_file creates the CA and certificate.
    if (settings.listeners.tls?.enabled && !settings.listeners.tls.cert_file && !wsCa) {
      await sleep(500);
      wsCa = makeCa(now);
      wsLeaf = makeLeaf(now);
    }
    if (wasLan !== s.ui.lan_mode) {
      // The real server restarts at the new address; the mock just switches modes and keeps
      // this browser logged in, as if it had already logged in there.
      mock.lan = s.ui.lan_mode;
      // The real server restarts at a new origin, where this browser has no secret yet. The
      // mock keeps the origin, so it keeps the current session (if any) rather than invent one.
    }
    // mock_put_no_etag=1: a server that sends no ETag with the save (the UI reads it again).
    return json(restarting ? { ...settings, restarting: true } : settings, 200, P.get('mock_put_no_etag') === '1' ? {} : { ETag: settingsETag() });
  }
  if (method === 'GET' && p === '/api/updates') return json(updatesJSON());
  if (method === 'PUT' && p === '/api/updates') {
    const c = (body as { check?: string })?.check;
    if (c !== 'on' && c !== 'off') return json({ error: 'check must be "on" or "off".', errors: { check: 'Must be "on" or "off".' } }, 400);
    setUpdateCheck(c, now);
    return json(updatesJSON());
  }
  if (method === 'POST' && p === '/api/updates/check') {
    if (!UPDATES_AVAILABLE || settings.updates?.check !== 'on') return err(409, 'The update check is off. Turn it on first.');
    const wait = 60_000 - (now - updates.lastManual);
    if (updates.lastManual && wait > 0) return retryLater(Math.ceil(wait / 1000), 'A check ran less than a minute ago; try again shortly.');
    updates.lastManual = now;
    setTimeout(() => runUpdateCheck(Date.now()), 1200);
    return new Response(null, { status: 202 });
  }
  if (method === 'POST' && p === '/api/updates/dismiss') {
    const v = (body as { version?: string })?.version ?? '';
    if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(v)) return err(400, 'version must be a version, e.g. 1.2.0');
    updates.dismissed = v;
    return new Response(null, { status: 204 });
  }
  if (method === 'GET' && p === '/api/storage/history') return json(history());
  if (method === 'GET' && p === '/api/storage/estimate') {
    const n = Number(url.searchParams.get('retention_bytes'));
    if (!Number.isFinite(n) || n <= 0) return err(400, 'retention_bytes must be a positive number of bytes.');
    return json(estimateFor(n));
  }
  if (method === 'GET' && p === '/api/rejected') return json(rejected(now));
  if (method === 'GET' && p === '/api/tls') return json(tlsJSON());
  if (method === 'GET' && p === '/api/tls/failures') return json(tlsFailures(now));
  if (method === 'POST' && p === '/api/tls/renew') {
    if (settings.listeners.tls?.cert_file) return err(409, 'This server uses your own certificate; replace the files instead.');
    if (!wsCa) return err(409, "TLS hasn't been turned on yet, so there's no certificate to renew.");
    await sleep(700); // a new RSA key takes a moment
    const newCa = (body as { new_ca?: unknown })?.new_ca === true;
    if (newCa) wsCa = makeCa(now);
    wsLeaf = makeLeaf(now);
    mock.tlsExpiring = false;
    return json(tlsJSON());
  }
  const caDl = /^\/api\/tls\/ca\.(pem|der)$/.exec(p);
  if (caDl && method === 'GET') {
    if (settings.listeners.tls?.cert_file) return err(404, 'This server uses your own certificate; get its CA from whoever issued it.');
    if (!wsCa) return err(404, "TLS hasn't been turned on yet, so there's no CA certificate.");
    return caDownload(caDl[1] as 'pem' | 'der');
  }
  if (method === 'GET' && p === '/api/search') return searchRoute(url.searchParams, now);
  if (method === 'GET' && p === '/api/search/schema') return json(SCHEMA);
  if (method === 'GET' && p === '/api/search/summary') return summaryRoute(url.searchParams, now);
  if (p.startsWith('/api/saved-searches')) {
    const r = savedRoute(method, p, url.searchParams, body, ifMatch, now);
    if (r) return r;
  }
  if (method === 'GET' && p === '/api/context') {
    const m = /^h(\d+)$/.exec(url.searchParams.get('ref') ?? '');
    if (!m) return err(404, 'That line is no longer stored.');
    const i = Number(m[1]);
    const before = Math.min(500, Number(url.searchParams.get('before') ?? 50));
    const after = Math.min(500, Number(url.searchParams.get('after') ?? 50));
    const ip = deviceAt(i).ip;
    const lastIdx = Math.floor(now / STEP);
    const lo: number[] = [];
    for (let j = i - 1; lo.length < before && j > i - 400_000; j--) if (deviceAt(j).ip === ip) lo.push(j);
    const hi: number[] = [];
    for (let j = i + 1; hi.length < after && j <= lastIdx; j++) if (deviceAt(j).ip === ip) hi.push(j);
    const idx = [...lo.reverse(), i, ...hi];
    // History starts 40 days back in the mock; the newest stored line is "now".
    const firstIdx = Math.ceil((now - 40 * 24 * H) / STEP);
    let older = false;
    for (let j = (idx[0] ?? i) - 1; j >= firstIdx && j > (idx[0] ?? i) - 400_000; j--) if (deviceAt(j).ip === ip) { older = true; break; }
    let newer = false;
    for (let j = idx[idx.length - 1] + 1; j <= lastIdx; j++) if (deviceAt(j).ip === ip) { newer = true; break; }
    return json({
      lines: idx.map((j) => {
        const l = lineAt(j);
        return { ...l, ...fieldsOf(l.raw), ref: `h${j}` };
      }),
      hit_index: lo.length,
      at_start: !older,
      at_end: !newer,
    });
  }
  if (method === 'POST' && (p === '/api/exports' || p === '/api/exports/estimate')) {
    const b = (body ?? {}) as {
      all_devices?: boolean; devices?: string[]; group?: string; ungrouped?: boolean; from?: string; to?: string;
      severities?: unknown[]; q?: string; regex?: boolean; case?: boolean; app?: string[]; host?: string[]; exclude?: string;
      type?: string; syntax?: 'text' | 'terms'; facilities?: (number | string)[]; exclude_devices?: string[]; exclude_app?: string[]; exclude_host?: string[];
    };
    // devices, group or ungrouped: resolved as the build would (hidden devices only when named).
    probe.lastExportBody = JSON.stringify(b);
    const f: MockFilters = { devices: b.devices, group: b.group || undefined, ungrouped: !!b.ungrouped, sev: null };
    const anySelector = b.all_devices || !!b.devices?.length || !!b.group || !!b.ungrouped;
    const ids = anySelector ? FLEET.map((d) => d.ip).filter((ip) => deviceMatches(ip, f, true) && !b.exclude_devices?.includes(ip)) : [];
    if (b.type !== undefined && b.type !== 'syslog') return err(400, `type: unknown data type "${b.type}".`);
    if (b.regex && b.syntax === 'terms') return err(400, TERMS_AND_REGEX);
    if (b.syntax === 'terms') {
      for (const [what, v] of [['', b.q], ['exclude: ', b.exclude]] as const) {
        try {
          parseTerms(v ?? '');
        } catch (e) {
          return err(400, `${what}${(e as Error).message}`);
        }
      }
    }
    try {
      facFilter((b.facilities ?? []).join(','));
    } catch (e) {
      return err(400, (e as Error).message);
    }
    if (!ids.length) return err(400, 'Pick at least one device (by list, group or ungrouped).');
    if (!b.from || !b.to || !(Date.parse(b.from) < Date.parse(b.to))) return err(400, '"from" must be before "to".');
    for (const x of b.severities ?? []) if (!(x === 'unknown' || (Number.isInteger(x) && (x as number) >= 0 && (x as number) <= 7))) return err(400, `invalid severity ${JSON.stringify(x)}`);
    for (const [what, v] of [['', b.q], ['exclude: ', b.exclude]] as const) {
      if (!b.regex || !v) continue;
      try {
        new RegExp(v);
      } catch (e) {
        return err(400, `${what}error parsing regexp: ${(e as Error).message.replace(/^Invalid regular expression: /, '')}`);
      }
    }
    for (const k of ['app', 'host'] as const) if (b[k] !== undefined && !Array.isArray(b[k])) return err(400, `${k} must be a list of strings`);
    const est = estimate({ devices: ids, from: b.from, to: b.to, severities: b.severities });
    if (p === '/api/exports/estimate') return json(est);
    const e: MockExport = {
      id: `exp_${Math.random().toString(36).slice(2, 6)}`, created: new Date(now).toISOString(),
      devices: b.all_devices ? ids : b.devices?.length ? b.devices : [], from: b.from, to: b.to,
      state: 'queued', progress: 0, lines: 0, size_bytes: 0, error: '', estimate: est.lines, ready_at: null, expires_at: null,
      filters: {
        group: b.group ?? '', ungrouped: !!b.ungrouped, severities: (b.severities ?? []) as ExportInfo['filters']['severities'],
        q: b.q ?? '', regex: !!b.regex, case: !!b.case,
        app: b.app ?? [], host: b.host ?? [], exclude: b.exclude ?? '',
        type: 'syslog', syntax: b.syntax ?? 'text', facilities: (b.facilities ?? []) as ExportInfo['filters']['facilities'],
        exclude_devices: b.exclude_devices ?? [], exclude_app: b.exclude_app ?? [], exclude_host: b.exclude_host ?? [],
      },
    };
    exportsList.unshift(e);
    return json({ id: e.id }, 202);
  }
  if (method === 'GET' && p === '/api/exports') return json(exportsList.map(exportJSON));
  const tk = p.match(/^\/api\/exports\/([^/]+)\/ticket$/);
  if (tk && method === 'POST') {
    const e = exportsList.find((x) => x.id === decodeURIComponent(tk[1]));
    if (!e || e.state === 'expired') return err(404, 'No such export.');
    if (e.state !== 'ready') return err(409, 'That export is not ready yet.');
    const t = newToken();
    tickets.set(t, { id: e.id, secret: authState.secret, until: now + 60_000 });
    probe.lastTicketUrl = `/api/exports/${encodeURIComponent(e.id)}/download?ticket=${t}`;
    return json({ url: probe.lastTicketUrl });
  }
  const ex = p.match(/^\/api\/exports\/([^/]+)(\/download)?$/);
  if (ex) {
    const k = exportsList.findIndex((e) => e.id === decodeURIComponent(ex[1]));
    const e = exportsList[k];
    if (!e) return err(404, 'No such export.');
    if (method === 'GET' && ex[2]) {
      // A ticket: single-use, 60 s, bound to the session (and its cookie) and to this export.
      const t = url.searchParams.get('ticket');
      if (t !== null) {
        const tk2 = tickets.get(t);
        tickets.delete(t);
        if (!tk2 || tk2.until < now || tk2.id !== e.id || (authOn() && (!mock.loggedIn || tk2.secret !== authState.secret)))
          return err(401, 'That download link has expired. Ask for a new one.');
      }
      probe.downloads.push({ id: e.id, ticket: t !== null, status: 200 });
      if (e.state === 'expired') return err(404, 'That export has expired.');
      if (e.state !== 'ready') return err(409, 'That export is not ready yet.');
      const name = `woodshed-${e.from.slice(0, 16).replace(/:/g, '')}-${e.to.slice(0, 16).replace(/:/g, '')}.zip`;
      return new Response('mock export', {
        status: 200,
        headers: { 'Content-Type': 'application/zip', 'Content-Disposition': `attachment; filename="${name}"` },
      });
    }
    if (method === 'GET') return json(exportJSON(e));
    if (method === 'DELETE') {
      exportsList.splice(k, 1); // cancels a queued or building one, deletes a finished one
      return new Response(null, { status: 204 });
    }
  }
  return err(404, `No route for ${method} ${p}.`);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const mockTransport: Transport = {
  async fetch(path, init) {
    const url = new URL(path, location.origin);
    const method = (init?.method ?? 'GET').toUpperCase();
    const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
    await sleep(mock.latency * (0.5 + Math.random()));
    if (mock.slowScan && url.pathname === '/api/search') await sleep(700);
    if (mock.slowSummary && url.pathname === '/api/search/summary') await sleep(150);
    const header = probe.cookieOnly ? null : new Headers(init?.headers).get('X-Woodshed-Session');
    return route(method, url, body, header, init?.signal ?? undefined, new Headers(init?.headers).get('If-Match'));
  },
  async download(path) {
    // Like a browser download: the cookie goes along, the X-Woodshed-Session header can't.
    const res = await mockTransport.fetch(path, { headers: {} });
    probe.lastDownloadStatus = res.status;
    if (!res.ok) return;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(await res.blob());
    a.download = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') ?? '')?.[1] ?? 'woodshed-export.zip';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  },
};
