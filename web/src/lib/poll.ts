// The SNMP poller's shapes and helpers (SPEC §12, docs/api.md → 1.3): poll targets, the test
// poll, the series behind the device page's charts and the Events timeline strips, and the
// formatters they share. Pure functions only, so `npm test` runs them under plain node.

// ---------- Types (docs/api.md → 1.3) ----------

export type PollVersion = '1' | '2c' | '3';
/** A target's state.status (docs/api.md → Poll targets). */
export type PollStatus = 'ok' | 'failing' | 'backing_off' | 'disabled' | 'pending';
export type PollPreset = 'system' | 'system-info' | 'interfaces';
/** In the contract's order (docs/api.md: "system", "system-info", "interfaces"), which bodies keep. */
export const PRESETS: { key: PollPreset; label: string; hint: string }[] = [
  { key: 'system', label: 'System', hint: 'Uptime, CPU and memory (HOST-RESOURCES where the device has it), every interval' },
  { key: 'system-info', label: 'System info', hint: 'sysName, sysDescr and sysObjectID, hourly' },
  { key: 'interfaces', label: 'Interfaces', hint: 'Traffic, packets, errors, discards and oper status per interface, every interval' },
];

export interface PollCustom {
  oid: string;
  kind: 'scalar' | 'walk';
  label: string;
  /** Walks only, 1–1,024 (default 128); 0 for a scalar. */
  max_rows: number;
}

export interface PollTargetState {
  status: PollStatus | (string & {});
  last_attempt: string | null;
  last_ok: string | null;
  failing_since: string | null;
  backoff_s: number;
  error: string;
  rtt_ms: number | null;
  engine_id: string;
  sys_name: string;
  sys_descr: string;
  hc_counters: boolean;
  host_resources: boolean;
  interfaces_polled: number;
  interfaces_total: number;
}

/** "all" (up to max_interfaces), or ifNames and indexes. */
export type PollInterfaces = 'all' | (string | number)[];

export interface PollTarget {
  id: string;
  address: string;
  port: number;
  device_id: string;
  enabled: boolean;
  version: PollVersion;
  community_set: boolean;
  v3_user: string;
  interval_s: number;
  timeout_ms: number;
  retries: number;
  presets: PollPreset[];
  interfaces: PollInterfaces;
  max_interfaces: number;
  /**
   * Interfaces kept within max_interfaces before the rest (SPEC §12.11 #3: "interfaces the user
   * pinned"). Not in docs/api.md yet; a server without it omits it.
   */
  pinned?: (string | number)[];
  custom: PollCustom[];
  state: PollTargetState;
}

/** POST/PUT /api/poll/targets and POST /api/poll/test: fields left out take the Settings defaults. */
export interface PollTargetInput {
  address: string;
  port?: number;
  device_id?: string;
  enabled?: boolean;
  version: PollVersion;
  /** Write-only. Left out on PUT: the stored one is kept. */
  community?: string;
  v3_user?: string;
  interval_s?: number;
  timeout_ms?: number;
  retries?: number;
  presets?: PollPreset[];
  interfaces?: PollInterfaces;
  max_interfaces?: number;
  pinned?: (string | number)[];
  custom?: PollCustom[];
}

export interface PollTestStep {
  step: string;
  ok: boolean;
  detail: string;
  rtt_ms: number | null;
}
export type PollExit = 'ok' | 'no_answer' | 'auth' | 'partial';
export interface PollTestResult {
  ok: boolean;
  exit: PollExit | (string & {});
  steps: PollTestStep[];
}

/** One bucket of a series. count 0 is "not measured": a gap, never zero. */
export interface PollPoint {
  start: string;
  avg: number | null;
  max: number | null;
  count: number;
}
export interface PollSeries {
  key: string;
  label: string;
  unit: string;
  points: PollPoint[];
}
export interface PollMarker {
  /** Timeline markers name their device. */
  device_id?: string;
  time: string;
  /** "restart", or "oper" for an interface going down or up (SPEC §12.11 #2). */
  kind: 'restart' | 'oper' | (string & {});
  /** Restarts: "1" a reboot, "0" the agent only, "?" can't tell. */
  reboot?: '1' | '0' | '?' | (string & {});
  detail: string;
  /** Oper markers: the interface, its new status and the one before (docs/api.md); detail says it too. */
  if?: string;
  oper?: string;
  was?: string;
}
export interface PollSeriesResponse {
  device_id: string;
  bucket_seconds: number;
  source: 'files' | 'rollup' | (string & {});
  series: PollSeries[];
  markers: PollMarker[];
  partial: boolean;
  next_cursor: string;
}
export interface PollTimeline {
  /** At most 4, the busiest; bucket_seconds as requested (the histogram's). */
  devices: { device_id: string; series: PollSeries[] }[];
  markers: PollMarker[];
  more: number;
  bucket_seconds?: number;
}

export interface PollNowPeak {
  now: number | null;
  peak: number | null;
  peak_at: string | null;
}
export interface PollInterfaceRow {
  index: number;
  name: string;
  alias: string;
  oper: string;
  speed_mbps: number | null;
  in_bps: number | null;
  out_bps: number | null;
  peak_in_bps: number | null;
  peak_out_bps: number | null;
  in_err_d: number | null;
  out_err_d: number | null;
  in_disc_d: number | null;
  out_disc_d: number | null;
  oper_changes: number;
}
export interface PollDevicePanel {
  device_id: string;
  target_id: string;
  address: string;
  system: {
    sys_name: string;
    sys_descr: string;
    uptime_s: number | null;
    last_restart: string | null;
    cpu: PollNowPeak | null;
    mem_used_pct: PollNowPeak | null;
  };
  interfaces: PollInterfaceRow[];
  /** The 4 busiest in the range: the default chart set. */
  charted: string[];
  interfaces_left_out: number;
  /** Restarts and every interface's oper changes in the range, charted or not (docs/api.md, at most 100). */
  markers: PollMarker[];
}

export interface PollSettings {
  interval_s: number;
  timeout_ms: number;
  retries: number;
  concurrency: number;
  max_interfaces: number;
  max_targets: number;
  presets: PollPreset[];
}
export const POLL_RANGES = {
  interval_s: [30, 600],
  timeout_ms: [200, 10_000],
  retries: [0, 5],
  concurrency: [1, 256],
  max_interfaces: [1, 1024],
  max_targets: [1, 5000],
} as const;

/** GET /api/poll. */
export interface PollState {
  targets: number;
  answering: number;
  failing: number;
  backing_off: number;
  last_cycle: string | null;
  hour: { cycles: number; failures: Record<string, number>; overruns: number; unmatched: number };
}

// ---------- Limits (SPEC §12.1, §12.10 #9) ----------

export const MAX_CUSTOM = 32;
export const MAX_ROWS = 1024;
export const DEFAULT_ROWS = 128;
/** The device page charts at most this many interfaces at once (SPEC §12.10 #12). */
export const MAX_CHARTED = 8;
/** The default chart set: the busiest interfaces. */
export const DEFAULT_CHARTED = 4;
/** The timeline's strips: at most this many devices (SPEC §12.5). */
export const MAX_STRIP_DEVICES = 4;
/** Markers drawn per strip or chart; the rest are counted (SPEC §12.11 #2). */
export const MARKER_CAP = 40;
/** At most 16 series per /api/poll/series request. */
export const MAX_SERIES = 16;

// ---------- Formatting ----------

const nf = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });
const nf1 = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 });

/** Bits per second, SI ("812 Mb/s", "1.2 Gb/s", "640 b/s"); "–" when not measured. */
export function bps(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '–';
  const units = ['b/s', 'kb/s', 'Mb/s', 'Gb/s', 'Tb/s'];
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${n < 0 ? '-' : ''}${v >= 100 || i === 0 ? nf.format(v) : nf1.format(v)} ${units[i]}`;
}

/** An interface speed in Mb/s ("1 Gb/s", "100 Mb/s"); "–" when unknown. */
export function speed(mbps: number | null | undefined): string {
  if (!mbps) return '–';
  return bps(mbps * 1e6);
}

/** Uptime in seconds as "12 d 3 h", "3 h 5 min", "4 min 10 s", "42 s". */
export function uptime(s: number | null | undefined): string {
  if (s === null || s === undefined || !Number.isFinite(s) || s < 0) return '–';
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = Math.floor(s % 60);
  if (d) return `${d} d ${h} h`;
  if (h) return `${h} h ${m} min`;
  if (m) return `${m} min${sec ? ` ${sec} s` : ''}`;
  return `${sec} s`;
}

export const pct = (n: number | null | undefined) => (n === null || n === undefined || !Number.isFinite(n) ? '–' : `${nf.format(n)} %`);
export const count = (n: number | null | undefined) => (n === null || n === undefined || !Number.isFinite(n) ? '–' : nf.format(n));
/** A delta with its sign ("+12", "+0"); "–" when not measured. */
export const delta = (n: number | null | undefined) => (n === null || n === undefined || !Number.isFinite(n) ? '–' : `+${nf.format(n)}`);

/** A value in a series' unit. */
export function inUnit(unit: string, n: number | null | undefined): string {
  if (unit === 'bit/s') return bps(n);
  if (unit === '%') return pct(n);
  if (unit === 's') return uptime(n);
  return count(n);
}

export const STATUS_LABEL: Record<string, string> = {
  ok: 'answering',
  failing: 'not answering',
  backing_off: 'backing off',
  disabled: 'off',
  pending: 'not polled yet',
};
export const statusLabel = (s: string) => STATUS_LABEL[s] ?? s;
/** The status dot for a target: ok green, failing and backing off red, the rest grey. */
export const statusTone = (s: string): 'ok' | 'bad' | 'warn' | 'none' =>
  s === 'ok' ? 'ok' : s === 'failing' ? 'warn' : s === 'backing_off' ? 'bad' : 'none';

export const EXIT_LABEL: Record<string, string> = {
  ok: 'Everything answered.',
  no_answer: 'No answer.',
  auth: 'Authentication or privacy failed.',
  partial: 'It answered, but some parts are not supported.',
};
export const exitLabel = (e: string) => EXIT_LABEL[e] ?? e;

export const STEP_LABEL: Record<string, string> = {
  discovery: 'v3 discovery',
  system: 'System',
  system_info: 'System info',
  'system-info': 'System info',
  host_resources: 'CPU and memory',
  interfaces: 'Interfaces',
  hc_counters: '64-bit counters',
  custom: 'Custom OIDs',
};
export const stepLabel = (s: string) => STEP_LABEL[s] ?? (s.startsWith('oid') ? `OID ${s.replace(/^oid[.:]?/, '')}` : s);

/** The failure statuses of GET /api/poll's hour.failures, labelled. */
export const FAILURE_LABEL: Record<string, string> = {
  timeout: 'timed out',
  unreachable: 'unreachable',
  auth_failed: 'wrong auth',
  unknown_user: 'unknown user',
  unknown_engine: 'unknown engine',
  not_in_time: 'not in time',
  decrypt_failed: "can't decrypt",
  error: 'SNMP error',
  overrun: 'overrun',
};

/** A marker's text: "edge-fw-01: rebooted (sysUpTime and hrSystemUptime reset)". */
export function markerTitle(m: PollMarker, name?: string): string {
  const who = name ? `${name}: ` : '';
  if (m.kind === 'restart') {
    const what = m.reboot === '1' ? 'rebooted' : m.reboot === '0' ? 'SNMP agent restarted' : 'restart (the device may have rebooted)';
    return `${who}${what}${m.detail ? ` (${m.detail})` : ''}`;
  }
  if (m.kind === 'oper') {
    const what = m.if && m.oper ? `${m.if} ${m.oper}` : m.detail;
    // The server's detail is already "eth3 down (was up)": use it as it is rather than repeat the change.
    if (m.detail && what && m.detail.startsWith(what)) return `${who}${m.detail}`;
    const was = m.was ? ` (was ${m.was})` : '';
    return `${who}${what || 'interface status changed'}${was}${m.if && m.oper && m.detail && m.detail !== what && !was ? ` (${m.detail})` : ''}`;
  }
  return `${who}${m.kind}${m.detail ? `: ${m.detail}` : ''}`;
}

/** Caps markers per strip, restarts first, so a flapping interface can't hide a reboot. */
export function capMarkers(ms: PollMarker[], cap = MARKER_CAP): { shown: PollMarker[]; hidden: number } {
  if (ms.length <= cap) return { shown: ms, hidden: 0 };
  const restarts = ms.filter((m) => m.kind === 'restart');
  const rest = ms.filter((m) => m.kind !== 'restart');
  const shown = [...restarts.slice(0, cap), ...rest.slice(0, Math.max(0, cap - restarts.length))].sort(
    (a, b) => Date.parse(a.time) - Date.parse(b.time),
  );
  return { shown, hidden: ms.length - shown.length };
}

// ---------- The form ----------

const isIPv4 = (s: string) => /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(s) && s.split('.').every((p) => Number(p) <= 255 && String(Number(p)) === p);
const isIPv6 = (s: string) => s.includes(':') && /^[0-9a-f:.]+$/i.test(s) && (s.match(/::/g)?.length ?? 0) <= 1 && !s.includes(':::');
/** An IP address (no names: nothing is looked up, SPEC §12.10 #9). */
export const isIP = (s: string) => isIPv4(s) || isIPv6(s);
/** A numeric OID: at least two arcs, dotted, an optional leading dot. */
export const isOID = (s: string) => /^\.?\d+(\.\d+)+$/.test(s.trim());

/** "all", or "eth1, eth2, 7" → ["eth1", "eth2", 7]. Numbers are ifIndexes. */
export function parseInterfaces(text: string): PollInterfaces {
  const t = text.trim();
  if (!t || t.toLowerCase() === 'all') return 'all';
  return parseList(t);
}
export function parseList(text: string): (string | number)[] {
  const out: (string | number)[] = [];
  for (const x of text.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean)) {
    const v = /^\d+$/.test(x) ? Number(x) : x;
    if (!out.includes(v)) out.push(v);
  }
  return out;
}
export const interfacesText = (v: PollInterfaces | undefined) => (v === undefined || v === 'all' ? '' : v.join(', '));

/** The form's client-side checks (the server checks again; its 400 names the same keys). */
export function targetErrors(t: PollTargetInput, opts: { creating: boolean; communitySet?: boolean } = { creating: true }): Record<string, string> {
  const e: Record<string, string> = {};
  if (!t.address.trim()) e.address = 'Enter the IP address to poll.';
  else if (!isIP(t.address.trim())) e.address = 'Enter an IP address; names are not looked up.';
  if (t.port !== undefined && !(Number.isInteger(t.port) && t.port >= 1 && t.port <= 65535)) e.port = 'Use a port from 1 to 65535.';
  if (t.device_id !== undefined && t.device_id.trim() && !isIP(t.device_id.trim())) e.device_id = 'A device is named by its IP address.';
  if (t.version === '3') {
    if (!t.v3_user) e.v3_user = 'Choose a v3 user (Settings → SNMP traps holds them).';
  } else if (t.community === '' || (t.community === undefined && (opts.creating || !opts.communitySet))) {
    e.community = 'Enter the community.';
  }
  const [lo, hi] = POLL_RANGES.interval_s;
  if (t.interval_s !== undefined && !(t.interval_s >= lo && t.interval_s <= hi)) e.interval_s = `Use ${lo} s to ${hi / 60} min.`;
  if (t.max_interfaces !== undefined && !(Number.isInteger(t.max_interfaces) && t.max_interfaces >= 1 && t.max_interfaces <= 1024))
    e.max_interfaces = 'Use 1 to 1,024.';
  if (Array.isArray(t.interfaces) && !t.interfaces.length) e.interfaces = 'List at least one interface, or poll all.';
  const custom = t.custom ?? [];
  if (custom.length > MAX_CUSTOM) e.custom = `At most ${MAX_CUSTOM} custom OIDs.`;
  custom.forEach((c, i) => {
    if (!isOID(c.oid)) e[`custom[${i}].oid`] = 'Enter a numeric OID, such as 1.3.6.1.2.1.1.3.0.';
    if (c.kind === 'walk' && !(Number.isInteger(c.max_rows) && c.max_rows >= 1 && c.max_rows <= MAX_ROWS))
      e[`custom[${i}].max_rows`] = `Use 1 to ${MAX_ROWS} rows.`;
    if (c.label.length > 64) e[`custom[${i}].label`] = 'At most 64 characters.';
  });
  if (t.presets && !t.presets.length && !custom.length) e.presets = 'Choose a preset or add a custom OID.';
  return e;
}

// ---------- Series and charts ----------

/** The headline series for the device page's charts (one request). */
export const HEADLINE_KEYS = ['cpu', 'mem_used_pct', 'in_bps', 'out_bps', 'errors_d', 'discards_d'] as const;
export const ifKey = (name: string, what: 'in_bps' | 'out_bps' | 'in_err_d' | 'out_err_d' | 'in_disc_d' | 'out_disc_d' | 'oper') =>
  `if.${name}.${what}`;
/** in_bps and out_bps for each charted interface, in requests of at most MAX_SERIES keys. */
export function ifSeriesBatches(names: string[]): string[][] {
  const keys = names.flatMap((n) => [ifKey(n, 'in_bps'), ifKey(n, 'out_bps')]);
  const out: string[][] = [];
  for (let i = 0; i < keys.length; i += MAX_SERIES) out.push(keys.slice(i, i + MAX_SERIES));
  return out;
}

/** The interfaces to chart: the server's busiest (charted), then picks; at most MAX_CHARTED. */
export function chartSet(defaults: string[], picked: string[], removed: string[]): string[] {
  const out: string[] = [];
  for (const n of [...defaults.slice(0, DEFAULT_CHARTED), ...picked]) if (!removed.includes(n) && !out.includes(n)) out.push(n);
  return out.slice(0, MAX_CHARTED);
}

/** Toggles an interface on the charts: off if charted, on if there's room. */
export function toggleCharted(current: string[], name: string, defaults: string[], picked: string[], removed: string[]) {
  if (current.includes(name)) {
    return { picked: picked.filter((x) => x !== name), removed: defaults.includes(name) ? [...removed, name] : removed, full: false };
  }
  if (current.length >= MAX_CHARTED) return { picked, removed, full: true };
  return { picked: defaults.includes(name) ? picked : [...picked, name], removed: removed.filter((x) => x !== name), full: false };
}

/**
 * A series' values by bucket index over [start, start + n × size): the bucket's avg (or, with
 * total, avg × count, a delta series' sum in the bucket); null where not measured (count 0 or
 * no point), so the line breaks there instead of dropping to zero.
 */
export function aligned(points: PollPoint[], start: number, sizeMs: number, n: number, total = false): (number | null)[] {
  const out: (number | null)[] = Array(n).fill(null);
  for (const p of points) {
    const i = Math.round((Date.parse(p.start) - start) / sizeMs);
    if (i < 0 || i >= n || !p.count || p.avg === null) continue;
    out[i] = total ? p.avg * p.count : p.avg;
  }
  return out;
}

/** Adds two aligned series; a bucket is measured when either is. */
export function sumAligned(a: (number | null)[], b: (number | null)[]): (number | null)[] {
  return a.map((x, i) => (x === null && b[i] === null ? null : (x ?? 0) + (b[i] ?? 0)));
}

/** The bucket starts a series' points imply: the earliest point to `to`. */
export function bucketsOf(from: string, to: string, sizeS: number, points: PollPoint[][] = []): { start: number; n: number; size: number } {
  const size = sizeS * 1000;
  const first = Math.min(Date.parse(from), ...points.flat().map((p) => Date.parse(p.start)));
  const start = Math.floor(first / size) * size;
  const n = Math.max(1, Math.ceil((Date.parse(to) - start) / size));
  return { start, n, size };
}

/** The smallest "nice" number at or above n (1, 2, 2.5, 5 × 10^k). */
export function niceCeil(n: number): number {
  if (!(n > 0)) return 1;
  const p = 10 ** Math.floor(Math.log10(n));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= n) return m * p;
  return 10 * p;
}

/**
 * An SVG path through the values on a width × height box (y up from the bottom, top = max),
 * one point per bucket at its middle. A null breaks the line; a measured bucket alone between
 * gaps is a short flat stroke, so it still shows.
 */
export function linePath(values: (number | null)[], width: number, height: number, max: number): string {
  const n = values.length;
  if (!n || !(max > 0)) return '';
  const step = width / n;
  const y = (v: number) => +(height - (Math.min(Math.max(v, 0), max) / max) * height).toFixed(2);
  const x = (i: number) => +((i + 0.5) * step).toFixed(2);
  let d = '';
  for (let i = 0; i < n; i++) {
    const v = values[i];
    if (v === null) continue;
    const prev = i > 0 ? values[i - 1] : null;
    const next = i < n - 1 ? values[i + 1] : null;
    if (prev === null) {
      d += `M${x(i)} ${y(v)}`;
      if (next === null) d += `h${Math.max(1, +(step * 0.6).toFixed(2))}`;
    } else d += `L${x(i)} ${y(v)}`;
  }
  return d;
}

/** The strips the timeline shows for one device's series: traffic in/out together, the rest one each. */
export function stripsOf(series: PollSeries[]): { key: string; label: string; unit: string; series: PollSeries[] }[] {
  const traffic = series.filter((s) => s.key === 'in_bps' || s.key === 'out_bps');
  const out: { key: string; label: string; unit: string; series: PollSeries[] }[] = [];
  if (traffic.length) out.push({ key: 'traffic', label: 'Traffic in / out', unit: 'bit/s', series: traffic });
  for (const s of series) {
    if (traffic.includes(s)) continue;
    const label = s.key === 'cpu' ? 'CPU' : s.key === 'errors_d' ? 'Errors' : s.key === 'discards_d' ? 'Discards' : s.label || s.key;
    out.push({ key: s.key, label, unit: s.unit, series: [s] });
  }
  return out;
}

/** One line of a chart (PollChart.svelte). */
export interface ChartLine {
  label: string;
  /** A CSS colour (var(--chart-N)). */
  color: string;
  /** Out-direction lines are dashed. */
  dash?: boolean;
  values: (number | null)[];
}
export const CHART_COLORS = Array.from({ length: 8 }, (_, i) => `var(--chart-${i + 1})`);

/** A delta series (errors, discards): chart its sum per bucket, not its average. */
export const isDelta = (key: string) => key.endsWith('_d') || key.endsWith('.in_err_d') || key.endsWith('.out_err_d');

// ---------- the forms' request bodies (shared with the request fixture test) ----------

/** The poll form's fields (PollForm.svelte). */
export interface PollFormState {
  address: string;
  port: number;
  /** The device the data goes to, when otherDevice is set. */
  device: string;
  otherDevice: boolean;
  enabled: boolean;
  version: PollVersion;
  /** Write-only: "" keeps a stored community on an edit. */
  community: string;
  v3User: string;
  interval: number;
  timeoutMs: number;
  retries: number;
  presets: PollPreset[];
  ifMode: 'all' | 'list';
  ifList: string;
  maxIf: number;
  pinned: string;
  custom: PollCustom[];
}

/** The form for a target (an edit) or a new one: prefilled from the target, else the Settings defaults. */
export function newPollForm(t: PollTarget | null, defaults: PollSettings | null, address = '', device = ''): PollFormState {
  return {
    address: t?.address ?? address,
    port: t?.port ?? 161,
    device: t && t.device_id !== t.address ? t.device_id : device && device !== address ? device : '',
    otherDevice: !!t && t.device_id !== t.address,
    enabled: t?.enabled ?? true,
    version: t?.version ?? '2c',
    community: '',
    v3User: t?.v3_user ?? '',
    interval: t?.interval_s ?? defaults?.interval_s ?? 60,
    timeoutMs: t?.timeout_ms ?? defaults?.timeout_ms ?? 2000,
    retries: t?.retries ?? defaults?.retries ?? 1,
    presets: [...(t?.presets ?? defaults?.presets ?? ['system', 'system-info', 'interfaces'])],
    ifMode: t && t.interfaces !== 'all' ? 'list' : 'all',
    ifList: t ? interfacesText(t.interfaces) : '',
    maxIf: t?.max_interfaces ?? defaults?.max_interfaces ?? 64,
    pinned: (t?.pinned ?? []).join(', '),
    custom: (t?.custom ?? []).map((c) => ({ ...c })),
  };
}

/** Whether an edit keeps a stored v1/v2c community (the field left empty keeps it). */
export const keepsCommunity = (f: PollFormState, t: PollTarget | null) => !!t?.community_set && t.version !== '3' && f.version !== '3';

/**
 * The body POST and PUT /api/poll/targets and POST /api/poll/test get from the form: every field
 * (the server's defaults apply only to a body that leaves one out); the community only when typed,
 * or on a new target, or when an edit switches from v3; v3_user only for v3.
 */
export function pollTargetBody(f: PollFormState, t: PollTarget | null): PollTargetInput {
  const b: PollTargetInput = {
    address: f.address.trim(),
    port: Number(f.port),
    device_id: f.otherDevice && f.device.trim() ? f.device.trim() : f.address.trim(),
    enabled: f.enabled,
    version: f.version,
    interval_s: Number(f.interval),
    timeout_ms: Number(f.timeoutMs),
    retries: Number(f.retries),
    presets: PRESETS.map((p) => p.key).filter((k) => f.presets.includes(k)),
    interfaces: f.ifMode === 'all' ? 'all' : parseInterfaces(f.ifList || ' '),
    max_interfaces: Number(f.maxIf),
    pinned: parseList(f.pinned),
    custom: f.custom.map((c) => ({ oid: c.oid.trim(), kind: c.kind, label: c.label.trim(), max_rows: c.kind === 'walk' ? Number(c.max_rows) : 0 })),
  };
  if (f.ifMode === 'list' && b.interfaces === 'all') b.interfaces = [];
  if (f.version === '3') b.v3_user = f.v3User;
  else if (f.community !== '' || !keepsCommunity(f, t)) b.community = f.community;
  return b;
}

/** Settings → Polling's fields (Settings.svelte). */
export interface PollSettingsForm {
  pollInterval: number;
  pollTimeoutMs: number;
  pollRetries: number;
  pollConcurrency: number;
  pollMaxIf: number;
  pollMaxTargets: number;
  pollPresets: PollPreset[];
}
const fin = (v: number | null) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
export function pollSettingsForm(p: PollSettings | undefined): PollSettingsForm {
  return {
    pollInterval: p?.interval_s ?? 60,
    pollTimeoutMs: p?.timeout_ms ?? 2000,
    pollRetries: p?.retries ?? 1,
    pollConcurrency: p?.concurrency ?? 32,
    pollMaxIf: p?.max_interfaces ?? 64,
    pollMaxTargets: p?.max_targets ?? 500,
    pollPresets: [...(p?.presets ?? ['system', 'system-info', 'interfaces'])],
  };
}
/** The "poll" object of the PUT /api/settings body (the rest of the body is the other sections' as loaded). */
export function pollSettingsBody(f: PollSettingsForm): PollSettings {
  return {
    interval_s: fin(f.pollInterval),
    timeout_ms: fin(f.pollTimeoutMs),
    retries: fin(f.pollRetries),
    concurrency: fin(f.pollConcurrency),
    max_interfaces: fin(f.pollMaxIf),
    max_targets: fin(f.pollMaxTargets),
    presets: PRESETS.map((p) => p.key).filter((k) => f.pollPresets.includes(k)),
  };
}
