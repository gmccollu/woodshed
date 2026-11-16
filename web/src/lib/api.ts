// Typed wrappers for the Woodshed HTTP API (docs/api.md). The UI talks to the
// server only through this module. In mock mode (VITE_MOCK=1) main.ts swaps the
// transport for the in-browser fake in ./mock, and nothing else changes.

import { SseParser, type SseEvent } from './sse';
import { ALL_SEVS, exportJson, sevParam, type SevKey } from './exportbody';
import type {
  PollDevicePanel,
  PollSeriesResponse,
  PollSettings,
  PollState,
  PollStatus,
  PollTarget,
  PollTargetInput,
  PollTestResult,
  PollTimeline,
} from './poll';
import type {
  EstimateByType,
  FlowFormat,
  FlowListenerSettings,
  FlowSearchResponse,
  FlowState,
  FlowTemplates,
  FlowTimeline,
  FlowTopParams,
  FlowTopResponse,
} from './flows';

export { ALL_SEVS, exportJson, sevParam, type SevKey };

// ---------- Types (docs/api.md) ----------

/** "tls" from 1.1: the TLS syslog listener (docs/api.md → TLS syslog listener); "snmp" from 1.2: the SNMP trap receiver. */
export type Proto = 'udp' | 'tcp' | 'tls' | 'snmp' | 'netflow' | 'ipfix';

export interface Listener {
  proto: Proto;
  addr: string;
  port: number;
  ok: boolean;
  error: string;
  /** Process holding the port, when the OS lets the server find out. */
  holder?: string;
  /**
   * docs/api.md (0d039ea): the holder is another Woodshed, the installed service or another
   * running copy; omitted (or "") otherwise. When the holder can't be seen (another user's
   * process), a running service is reported as the likely holder.
   */
  holder_kind?: 'woodshed_service' | 'woodshed' | '' | (string & {});
  holder_pid?: number;
  /** That Woodshed's UI address, when known. */
  holder_ui_url?: string;
}

export type BannerLevel = 'error' | 'warn' | 'info';

export type BannerKind =
  | 'listener_bind'
  | 'writes_paused'
  | 'low_disk'
  | 'ui_port_busy'
  | 'udp_buffer_small'
  | 'update_prompt'
  | 'update_available'
  | 'tls_legacy'
  | 'tls_cert_expiring'
  | 'tls_cert_names'
  | 'tls_firewall'
  | 'udp_queue_full'
  | 'snmp_firewall'
  | 'snmp_credentials'
  | 'snmp_mibs'
  | 'poll_unreachable'
  | 'poll_overrun'
  | 'flow_budget'
  | 'flow_templates'
  | 'flow_clock'
  | 'flow_firewall';
/** update_choice: Turn on / No thanks (PUT /api/updates); update_dismiss: hide this version (POST /api/updates/dismiss).
 *  tls_renew opens Settings → Syslog over TLS; it never renews by itself. */
export type BannerAction = '' | 'retry_listeners' | 'update_choice' | 'update_dismiss' | 'tls_renew';

export interface Banner {
  /** Unknown future kinds are shown like any other banner. */
  kind: BannerKind | (string & {});
  level: BannerLevel;
  text: string;
  action: BannerAction | (string & {});
  /** A link for the banner (update_available: the release page); omitted when empty. */
  url?: string;
}

export interface Status {
  version: string;
  build: string;
  os: string;
  data_dir: string;
  started_at: string;
  /** null until the first message is received; drives the Welcome page. */
  first_message_at: string | null;
  /** What the OS actually granted. */
  udp_rcvbuf_bytes: number;
  udp_rcvbuf_requested_bytes: number;
  /** Empty until the project has a public releases page. */
  releases_url: string;
  /** SHA-256 of the UI's HTTPS certificate (LAN mode), so users can check the browser's warning. Being added. */
  ui_cert_fingerprint?: string;
  kernel_drops_visible: boolean;
  listeners: Listener[];
  host_ips: string[];
  banners: Banner[];
}

export interface Stats {
  msgs_per_sec: number;
  /** msgs/sec averaged per minute, oldest first, last 60 minutes. */
  sparkline: number[];
  devices: { total: number; online: number; quiet: number; offline: number };
  disk: {
    used_bytes: number;
    cap_bytes: number;
    free_bytes: number;
    days_kept: number;
    /** On-disk bytes written over the last 24 h (raw / compression_ratio); null until there's 1 h of data. */
    bytes_per_day: number | null;
    /** Measured on this server's closed files (8 until it has closed one). */
    compression_ratio: number | null;
    /** cap_bytes / bytes_per_day, or null. */
    estimated_days: number | null;
    /** "cap" when the size cap, not the age limit, decides how long logs are kept. */
    limited_by: 'cap' | 'age' | null;
  };
  dropped_24h: number;
  /** Integer on Linux; null where the OS doesn't expose kernel UDP drops. */
  kernel_dropped_24h: number | null;
  truncated_24h: number;
  /** Messages from senders outside the allowlist. */
  rejected_24h: number;
  /** dropped_24h by reason (1.2), counted since the server started. */
  dropped_by_reason: DroppedByReason;
  /** One per enabled UDP listener (1.2). */
  udp_queue: UdpQueue[];
}

export interface DroppedByReason {
  /** The low-disk guard had paused writing. */
  paused: number;
  write_error: number;
  /** New senders over the device limits. */
  refused: number;
  /** A UDP listener's receive queue was full: writing to disk fell behind. */
  queue_full: number;
}

/** A UDP listener's receive queue (docs/api.md → UDP receive queue). */
export interface UdpQueue {
  /** "udp" (syslog), or "snmp" for the trap listener. */
  listener: string;
  /** 0 while the listener isn't bound. */
  port: number;
  capacity_messages: number;
  capacity_bytes: number;
  depth: number;
  high_water_24h: number;
  dropped_24h: number;
  /** The most messages waiting at once per hour, oldest first, the current hour last (up to 24). */
  high_water_by_hour: number[];
}

export interface RejectedSender {
  ip: string;
  count_24h: number;
  last_seen: string;
  /** The latest refusal's reason: not on the allowlist, or over the TCP connections-per-source limit. */
  reason: 'allowlist' | 'blocked' | 'per_source' | 'community' | (string & {});
}

export type DeviceStatus = 'online' | 'quiet' | 'offline' | 'blocked';

export interface Device {
  id: string;
  ip: string;
  name: string;
  group: string;
  hidden: boolean;
  first_seen: string;
  last_heard: string;
  status: DeviceStatus;
  msgs_per_min: number;
  total_msgs: number;
  bytes_on_disk: number;
  /** On the blocklist: its messages are refused and counted; its existing logs stay searchable. */
  blocked: boolean;
  /** On a PATCH that unblocked the device's own address: the broader blocklist entry that still covers it. */
  blocked_by?: string;
  /** TLS syslog stats (1.1); null until the device has tried TLS. Older servers omit it. */
  tls?: DeviceTls | null;
  /** 1.2: the data types the device has files of on disk ("syslog", "trap"). Older servers omit it. */
  types?: string[];
  /** 1.2: stored lines (records) per data type. total_msgs counts every type. */
  lines_by_type?: Record<string, number>;
  /** 1.3: the device has a poll target (SPEC §12.5). Older servers omit it. */
  polled?: boolean;
  /** 1.3, when polled: the target's state.status. */
  poll_status?: PollStatus | (string & {});
}

/** Why a TLS handshake failed (SPEC §10.3.4). Unknown future reasons are shown as given. */
export type TlsFailureReason = 'cert_rejected' | 'version' | 'cipher' | 'not_tls' | 'timeout' | 'closed' | 'busy' | 'other';

export interface DeviceTls {
  connections_24h: number;
  /** The last successful connection's, such as "TLS 1.3"; "" if none succeeded. */
  version: string;
  cipher: string;
  last_connected: string | null;
  failures_24h: number;
  last_failure: { time: string; reason: TlsFailureReason | (string & {}); detail: string } | null;
}

export type DevicePatch = Partial<Pick<Device, 'name' | 'group' | 'hidden' | 'blocked'>>;

export interface LogLine {
  received: string;
  device_id: string;
  /** 0 emerg … 7 debug, or null when the message had no parseable PRI. */
  severity: number | null;
  raw: string;
}

export interface SampledNotice {
  rate: number;
  shown: number;
}


export interface LiveFilters {
  devices?: string[];
  group?: string;
  /** Only devices with no group. An alternative to `group`. */
  ungrouped?: boolean;
  /** Severity set; undefined or all = every severity. */
  severities?: SevKey[];
  q?: string;
}

export interface SearchParams {
  q: string;
  regex?: boolean;
  /** Case-sensitive match (default insensitive). */
  case?: boolean;
  devices?: string[];
  group?: string;
  ungrouped?: boolean;
  from?: string;
  to?: string;
  severities?: SevKey[];
  order?: 'desc' | 'asc';
  limit?: number;
  cursor?: string;
  /** Programs/tags from the header, ignoring case; a trailing "*" is a prefix, a leading "%" optional. */
  app?: string[];
  /** Hostnames from the header (not the sender IP), ignoring case. */
  host?: string[];
  /** Leave out lines matching this; regex and case apply as for q. */
  exclude?: string;
  /** 1.1: the data type; "syslog" is the default and the only one. */
  type?: string;
  /** 1.1: "terms" reads q and exclude as boolean terms (SPEC §10.1.3); "text" (default) is the 1.0 meaning. */
  syntax?: Syntax;
  /** 1.1: facilities 0–23 and "unknown"; empty = all, ["none"] = nothing. */
  facilities?: FacKey[];
  /** 1.1: leave these devices out (after devices, group and ungrouped). */
  exclude_devices?: string[];
  /** 1.1: leave out lines whose program/tag (or hostname) matches one of these, as app (host) matches. */
  exclude_app?: string[];
  exclude_host?: string[];
  /**
   * 1.2: another data type's own filter parameters (type=trap: snmp_versions, pdus, trap_oid, …), by
   * parameter name as the schema gives them; each list is sent comma-separated, empty lists aren't sent.
   */
  filters?: Record<string, string[]>;
}

export type Syntax = 'text' | 'terms';
/** A syslog facility 0 (kern) … 23 (local7), "unknown" (no parseable PRI), or "none" (matches nothing). */
export type FacKey = number | 'unknown' | 'none';

export interface SearchResult extends LogLine {
  ref: string;
  /** The parsed program/tag ("" when the header has none). */
  app: string;
  /** The parsed header hostname ("" when the header has none). */
  host: string;
}

/** 1.2 (docs/api.md → Data types: type=trap): one varbind, with names from the current MIB set. */
export interface TrapVarbind {
  oid: string;
  /** "ifOperStatus.3", or "" when the MIB set has no name for it. */
  name: string;
  /** int, str, hex, oid, ip, c32, g32, ticks, c64, opaque, null, nosuchobject, nosuchinstance, endofmibview. */
  type: string;
  /** Always a string. */
  value: string;
  /** An int's named value from a MIB ("down"), or an oid value's name; "" when none. */
  value_name?: string;
}

/** A trap result's fields, decoded from the stored record. */
export interface TrapFields {
  version: '1' | '2c' | '3' | (string & {});
  pdu: string;
  trap_oid: string;
  trap_name: string;
  enterprise: string;
  /** Integers for v1 traps, null otherwise. */
  generic: number | null;
  specific: number | null;
  /** "#3f9a1c07" (a community's hash prefix) or a v3 user name. */
  cred: string;
  status: string;
  error: string;
  /** TimeTicks, or null when the trap had none. */
  uptime: number | null;
  /** A retransmitted inform. */
  dup: boolean;
  varbinds: TrapVarbind[];
}

/** One type=trap result; raw is the stored record (SPEC §11.2.4). */
export interface TrapResult {
  received: string;
  device_id: string;
  type: 'trap';
  ref: string;
  raw: string;
  fields: TrapFields;
}

/** A result of any data type: syslog results have no `type`. */
export type AnyResult = SearchResult | TrapResult;

export const isTrap = (r: AnyResult): r is TrapResult => (r as TrapResult).type === 'trap';

export interface SearchResponse {
  results: SearchResult[];
  /** Empty when the range is exhausted. */
  next_cursor: string;
  scanned_bytes: number;
  scanned_files: number;
  elapsed_ms: number;
  /** The 10 s budget ran out: keep asking with next_cursor. */
  partial: boolean;
}

export interface ContextResponse {
  lines: SearchResult[];
  hit_index: number;
  /** No older / newer stored lines for that device. */
  at_start: boolean;
  at_end: boolean;
}

/** Devices by list, group, ungrouped or all (at least one must select a device); filters as for search. */
export interface ExportRequest {
  /** Every non-hidden device. */
  all_devices?: boolean;
  devices?: string[];
  group?: string;
  ungrouped?: boolean;
  from: string;
  to: string;
  severities?: SevKey[];
  q?: string;
  regex?: boolean;
  case?: boolean;
  app?: string[];
  host?: string[];
  exclude?: string;
  type?: string;
  syntax?: Syntax;
  facilities?: FacKey[];
  exclude_devices?: string[];
  exclude_app?: string[];
  exclude_host?: string[];
  /** 1.2: the data types in the zip; the server's default is ["syslog"]. Filters apply only to an export of one type. */
  types?: string[];
  /** 1.2, with types ["trap"]: the trap filters by parameter name (trap_oid, status, …), sent as top-level JSON lists. */
  trap?: Record<string, string[]>;
  /** 2.0: the flow filters (types ["flow"]), sent as top-level lists like the trap filters. */
  flow?: Record<string, string[]>;
  /** 2.0: which flow files the zip holds (left out for the default, both). */
  flow_formats?: FlowFormat[];
  kind?: 'export';
}

/**
 * 1.2: the incident bundle (SPEC §11.3): everything stored in [at − before, at + after), cut at
 * now. Exactly one device choice; no filters, and no from/to.
 */
export interface BundleRequest {
  kind: 'bundle';
  /** RFC 3339, not in the future. */
  at: string;
  /** Durations, 0s–7d each, at least one non-zero ("30m", "1h30m"). */
  before: string;
  after: string;
  /** Every non-hidden device with a stored record of any type in the window. */
  active_devices?: boolean;
  devices?: string[];
  group?: string;
  ungrouped?: boolean;
  /** [] = every type with data in the window. */
  types: string[];
  /** 2.0: which flow files the zip holds (left out for the default, both). */
  flow_formats?: FlowFormat[];
}

export interface ExportFilters {
  group: string;
  ungrouped: boolean;
  severities: SevKey[];
  q: string;
  regex: boolean;
  case: boolean;
  app: string[];
  host: string[];
  exclude: string;
  /** 1.1; older servers omit them. */
  type?: string;
  syntax?: Syntax;
  facilities?: FacKey[];
  exclude_devices?: string[];
  exclude_app?: string[];
  exclude_host?: string[];
  /** 1.2: "export" or "bundle"; older servers omit it. */
  kind?: 'export' | 'bundle';
  /** 1.2: the data types, resolved ("syslog", "trap"). */
  types?: string[];
  /** 1.2, an export of traps with trap filters: the lists given (MIB names resolved). */
  trap?: Record<string, string[]>;
  /** 1.2, a bundle: the moment and the sides in canonical form ("30m", "1h15m", "0s"). from/to are the window. */
  at?: string;
  before?: string;
  after?: string;
  /** 1.2, a bundle: the devices were "every device active in the window". */
  active_devices?: boolean;
}

export interface ExportEstimate {
  lines: number;
  bytes: number;
  files: number;
  /** 2.0: per type, flows as records (docs/api.md → Exports and bundles). Older servers omit it. */
  by_type?: EstimateByType;
}

export type ExportState = 'queued' | 'building' | 'ready' | 'failed' | 'expired';

export interface ExportInfo {
  id: string;
  created: string;
  devices: string[];
  from: string;
  to: string;
  state: ExportState;
  /** 0…1 while building. */
  progress: number;
  lines: number;
  size_bytes: number;
  error: string;
  /** Set once the export is ready. */
  ready_at: string | null;
  expires_at: string | null;
  /** Echoes the request's filters. */
  filters: ExportFilters;
}

export interface ListenerSettings {
  enabled: boolean;
  addr: string;
  port: number;
}

/** listeners.tls (1.1): cert_file and key_file both empty means Woodshed's own CA. */
export interface TlsListenerSettings extends ListenerSettings {
  /** Also accept TLS 1.0 and 1.1, for older senders. */
  allow_legacy_tls: boolean;
  cert_file: string;
  key_file: string;
}

export interface Settings {
  listeners: {
    udp: ListenerSettings;
    tcp: ListenerSettings;
    /** Older servers omit it. */
    tls?: TlsListenerSettings;
    /** 1.2: the SNMP trap receiver. Older servers omit it; a PUT without it keeps it. */
    snmp?: SnmpListenerSettings;
    /** 2.0: the flow collector (NetFlow v5/v9 and IPFIX). Older servers omit it; a PUT without it keeps it. */
    flow?: FlowListenerSettings;
    allowlist: string[];
    /** Senders refused at the listener (IPs or CIDRs); checked before the allowlist and wins. */
    blocklist: string[];
    /** Sender limits against floods of fake source addresses (docs/api.md). */
    max_devices: number;
    new_device_burst: number;
    new_devices_per_minute: number;
  };
  storage: {
    data_dir: string;
    retention_days: number;
    retention_bytes: number;
    part_bytes: number;
    /** 2.0: the flow budget; 0 means 40 % of retention_bytes. Older servers omit it. */
    flow_budget_bytes?: number;
  };
  /**
   * cert_file/key_file: paths to a user certificate for LAN mode; empty = self-signed.
   * extra_hostnames: more names for the self-signed certificate; trusted_hosts: more Host
   * names to accept (host or host:port, for a reverse proxy). Older servers omit both.
   */
  ui: {
    lan_mode: boolean;
    port: number;
    cert_file: string;
    key_file: string;
    require_login_local: boolean;
    extra_hostnames: string[];
    trusted_hosts: string[];
  };
  quiet: { quiet_after_seconds: number; offline_after_seconds: number };
  /** The update check (1.1). Older servers omit it; a PUT without it keeps it. */
  updates?: { check: UpdateCheck };
  /** 1.3: the poller's defaults (docs/api.md → 1.3). Older servers omit it; a PUT without it keeps it. */
  poll?: PollSettings;
}

export type UpdateCheck = 'ask' | 'on' | 'off';

/** GET /api/updates (docs/api.md → Update check). */
export interface UpdateInfo {
  check: UpdateCheck;
  /** false in a build that can't check (not a release version, or no releases page). */
  available: boolean;
  /** The one file the check fetches. */
  url: string;
  current: string;
  last_check: string | null;
  last_result: '' | 'ok' | 'error';
  /** A short message Woodshed writes itself. */
  last_error: string;
  last_error_kind: string;
  /** null unless check is "on". */
  next_check: string | null;
  /** null until a check succeeds, and while check isn't "on". */
  latest: { version: string; prerelease: boolean; url: string } | null;
  update_available: boolean;
  dismissed_version: string;
}

// ---------- TLS (docs/api.md → TLS syslog listener) ----------

export interface TlsCa {
  subject: string;
  not_before: string;
  not_after: string;
  /** "AB:CD:…", upper-case hex pairs of the DER certificate. */
  sha256: string;
  sha1: string;
}

export interface TlsCert {
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  sha256: string;
  dns_names: string[];
  ip_addresses: string[];
  /** Host DNS names the certificate doesn't cover (drives the tls_cert_names banner). */
  missing_names: string[];
}

export type TlsFirewallState = 'ok' | 'missing' | 'disabled' | 'wrong_port' | 'unknown';

export interface TlsState {
  enabled: boolean;
  port: number;
  /** "woodshed": its own CA; "file": cert_file and key_file. */
  source: 'woodshed' | 'file';
  allow_legacy_tls: boolean;
  /** null with source "file", and until TLS is first turned on. */
  ca: TlsCa | null;
  /** null until a certificate exists. */
  cert: TlsCert | null;
  /** command is "" except on Windows, where it's the command to run as an administrator. */
  firewall: { state: TlsFirewallState | (string & {}); command: string };
}

export interface TlsFailure {
  ip: string;
  count_24h: number;
  last_seen: string;
  reason: TlsFailureReason | (string & {});
  /** The TLS error text or the alert. */
  detail: string;
  /** Set when the sender is also a known device. */
  device_id: string;
}

export type DeletionReason = 'age' | 'cap' | 'low_disk';

// ---------- SNMP traps (docs/api.md → SNMP trap listener, SNMP state, SNMP v3 users; 1.2) ----------

/** listeners.snmp. communities are "#<hash8>" from the server; sending one back keeps it, a plain string adds one. */
export interface SnmpListenerSettings extends ListenerSettings {
  answer_informs: boolean;
  communities: string[];
  /** "" means the mibs folder in the data folder. */
  mib_dir: string;
  /** "" means the generated one. */
  engine_id: string;
}

export interface SnmpMibError {
  file: string;
  line: number;
  message: string;
}

export interface SnmpMibs {
  dir: string;
  files: number;
  names: number;
  loaded_at: string;
  errors: SnmpMibError[];
  warnings?: SnmpMibError[];
}

export interface SnmpState {
  enabled: boolean;
  port: number;
  engine: { id: string; boots: number; time: number };
  counts_24h: {
    received: number;
    informs_answered: number;
    replies_rate_limited: number;
    discovery_reports: number;
    /** v3 clock relearns (SPEC §11.8 #28). */
    time_resyncs?: number;
    /** Only statuses with a count. */
    by_status: Record<string, number>;
  };
  mibs: SnmpMibs;
  /** As for TLS: always "unknown" off Windows. */
  firewall: { state: TlsFirewallState | (string & {}); command: string };
}

export interface SnmpFailure {
  ip: string;
  count_24h: number;
  last_seen: string;
  /** The latest failure's status (auth_failed, malformed, …). */
  status: string;
  /** The user, engine or decoding error; never key material. */
  detail: string;
  device_id: string;
  time_resyncs_24h?: number;
}

export type SnmpAuth = 'none' | 'md5' | 'sha' | 'sha-224' | 'sha-256' | 'sha-384' | 'sha-512';
export type SnmpPriv = 'none' | 'des' | 'aes-128' | 'aes-192' | 'aes-256';
export type SnmpKeyExt = 'draft' | 'alt';

export interface SnmpUser {
  name: string;
  level: 'noAuthNoPriv' | 'authNoPriv' | 'authPriv' | (string & {});
  auth: SnmpAuth | (string & {});
  priv: SnmpPriv | (string & {});
  key_ext: SnmpKeyExt | (string & {});
  engine_ids: string[];
  auth_set: boolean;
  priv_set: boolean;
  /** "localized" when engine_ids is set and only the localized keys are kept. */
  stored: 'passphrase' | 'localized' | (string & {});
  /** False when the credentials file can't be decrypted here: the user needs its passphrases again. */
  readable: boolean;
  /** The protocols Settings labels weak (md5, sha, des). */
  weak?: string[];
}

/** POST /api/snmp/users and PUT /api/snmp/users/{name}. An empty passphrase keeps the stored one (unless the protocol changes). */
export interface SnmpUserInput {
  name: string;
  auth: SnmpAuth;
  auth_pass?: string;
  priv: SnmpPriv;
  priv_pass?: string;
  key_ext: SnmpKeyExt;
  engine_ids: string[];
}

export interface StorageHistoryEntry {
  time: string;
  file: string;
  device_id: string;
  bytes: number;
  reason: DeletionReason;
}

// ---------- Errors ----------

export interface Session {
  mode: 'localhost' | 'lan';
  auth_required: boolean;
  authenticated: boolean;
  password_set: boolean;
}

/** POST /api/login also returns the session secret, once (docs/api.md → Session secret). */
export interface LoginResponse extends Session {
  session_secret: string;
}

export class ApiError extends Error {
  readonly status: number;
  /** Per-field messages from a 400 (e.g. PUT /api/settings), keyed by dotted path ("listeners.allowlist[2]"). */
  readonly fields: Record<string, string>;
  /** Seconds from a Retry-After header (429 on login), else 0. */
  readonly retryAfter: number;

  constructor(status: number, message: string, fields: Record<string, string> = {}, retryAfter = 0) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.fields = fields;
    this.retryAfter = retryAfter;
  }
}

/** Retry-After is either delay-seconds or an HTTP date (RFC 9110 §10.2.3). */
function retryAfterSeconds(h: string | null): number {
  if (!h) return 0;
  const n = Number(h);
  if (Number.isFinite(n)) return Math.max(0, Math.ceil(n));
  const t = Date.parse(h);
  return Number.isNaN(t) ? 0 : Math.max(0, Math.ceil((t - Date.now()) / 1000));
}

// ---------- Session secret and 401 handling ----------
//
// docs/api.md: when login is required, every /api/ request needs the session cookie AND an
// X-Woodshed-Session header with the secret from POST /api/login. The cookie isn't port-
// scoped; localStorage is scoped to the exact origin (scheme, host and port), so the secret
// lives there, under a key per origin, and is read on every request (a logout in another
// tab takes effect here too).

const SECRET_KEY = `woodshed.session.${location.origin}`;
export const SESSION_HEADER = 'X-Woodshed-Session';

export function sessionSecret(): string {
  try {
    return localStorage.getItem(SECRET_KEY) ?? '';
  } catch {
    return '';
  }
}

export function setSessionSecret(secret: string): void {
  try {
    if (secret) localStorage.setItem(SECRET_KEY, secret);
    else localStorage.removeItem(SECRET_KEY);
  } catch {
    /* storage unavailable (private mode): requests will get 401 and show the login */
  }
}

/** Headers for an /api/ request: the session secret when there is one. */
function authHeaders(): Record<string, string> {
  const s = sessionSecret();
  return s ? { [SESSION_HEADER]: s } : {};
}

let onUnauthorized: (() => void) | null = null;

/** Called on any 401 from a route that needs a session, so the app can show the login form. */
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

function unauthorized(): void {
  setSessionSecret('');
  onUnauthorized?.();
}

const SESSION_ROUTES = ['/api/session', '/api/login', '/api/logout'];

// ---------- Transport ----------

export interface Transport {
  fetch(path: string, init?: RequestInit): Promise<Response>;
  /** Mock mode only: there's no server behind a plain download link. */
  download?(path: string): Promise<void>;
}

const browserTransport: Transport = {
  fetch: (path, init) => fetch(path, { credentials: 'same-origin', ...init }),
};

let transport: Transport = browserTransport;

/** True when a download link must go through the transport (mock mode). */
export const downloadsViaTransport = () => !!transport.download;
export const transportDownload = (path: string) => transport.download?.(path);

export function setTransport(t: Transport): void {
  transport = t;
}

async function request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  return (await requestFull<T>(method, path, body, undefined, signal)).data;
}

/** request(), with extra request headers and the response's headers. */
async function requestFull<T>(
  method: string,
  path: string,
  body?: unknown,
  extra?: Record<string, string>,
  signal?: AbortSignal,
): Promise<{ data: T; headers: Headers }> {
  const headers: Record<string, string> = { Accept: 'application/json', ...authHeaders(), ...extra };
  const init: RequestInit = { method, headers, signal };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
    headers['Content-Type'] = 'application/json';
  }
  let res: Response;
  try {
    res = await transport.fetch(path, init);
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e;
    throw new ApiError(0, `no connection: ${(e as Error).message}`);
  }
  if (res.status === 204) return { data: undefined as T, headers: res.headers };
  const text = await res.text();
  let data: unknown = undefined;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      if (res.ok) throw new ApiError(res.status, `Unexpected reply from ${path}.`);
    }
  }
  if (!res.ok) {
    const d = (data ?? {}) as { error?: string; errors?: Record<string, string> };
    const fields = d.errors && typeof d.errors === 'object' ? d.errors : {};
    const msg = d.error || (Object.keys(fields).length ? 'Some settings need fixing.' : `${res.status} ${res.statusText}`);
    if (res.status === 401 && !SESSION_ROUTES.includes(path.split('?')[0])) unauthorized();
    throw new ApiError(res.status, msg, fields, retryAfterSeconds(res.headers.get('Retry-After')));
  }
  return { data: data as T, headers: res.headers };
}

function query(params: Record<string, string | number | boolean | string[] | undefined>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === '') continue;
    if (Array.isArray(v)) {
      if (v.length) q.set(k, v.join(','));
    } else q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : '';
}

// ---------- Routes ----------

export const getSession = () => request<Session>('GET', '/api/session');
export const login = (password: string) => request<LoginResponse>('POST', '/api/login', { password });
export const logout = () => request<void>('POST', '/api/logout');
export const putPassword = (current: string, next: string) =>
  request<void>('PUT', '/api/password', { current, new: next });

export const getStatus = () => request<Status>('GET', '/api/status');
export const retryListeners = () => request<void>('POST', '/api/listeners/retry');
export const getStats = () => request<Stats>('GET', '/api/stats');
export const getRejected = () => request<RejectedSender[]>('GET', '/api/rejected');

export type DeviceSort = 'rate' | 'name' | 'last_heard' | 'first_seen';

export interface DeviceQuery {
  limit?: number;
  offset?: number;
  /** Server default is rate (busiest first). */
  sort?: DeviceSort;
  /** Substring of id, IP or name (case-insensitive). */
  q?: string;
  group?: string;
  ungrouped?: boolean;
  /** Server default is include. */
  hidden?: 'include' | 'only' | 'exclude';
  /** The server takes this like hidden (default include); not in docs/api.md yet, see the report. */
  blocked?: 'include' | 'only' | 'exclude';
  /** 1.2, both or neither (RFC 3339): only devices with a stored record of any type in [active_from, active_to). */
  active_from?: string;
  active_to?: string;
}

export interface DevicePage {
  devices: Device[];
  total: number;
}

/** A group and its number of non-hidden devices (ungrouped devices aren't listed). */
export interface GroupInfo {
  name: string;
  devices: number;
}

export const getGroups = () => request<GroupInfo[]>('GET', '/api/groups');

export const getDevices = (p: DeviceQuery = {}, signal?: AbortSignal) =>
  request<DevicePage>(
    'GET',
    `/api/devices${query({ ...p, q: p.q || undefined, group: p.group || undefined, ungrouped: p.ungrouped ? true : undefined })}`,
    undefined,
    signal,
  );
export const patchDevice = (id: string, patch: DevicePatch) =>
  request<Device>('PATCH', `/api/devices/${encodeURIComponent(id)}`, patch);

export const searchPath = (p: SearchParams) =>
  `/api/search${query({
    q: p.q,
    regex: p.regex ? true : undefined,
    case: p.case ? true : undefined,
    devices: p.devices,
    group: p.group,
    ungrouped: p.ungrouped ? true : undefined,
    from: p.from,
    to: p.to,
    severities: p.severities ? sevParam(p.severities) : undefined,
    app: p.app,
    host: p.host,
    exclude: p.exclude,
    ...newFilterParams(p),
    order: p.order,
    limit: p.limit,
    cursor: p.cursor,
  })}`;
export const search = (p: SearchParams, signal?: AbortSignal) =>
  request<SearchResponse>('GET', searchPath(p), undefined, signal);
export const getContext = (ref: string, before = 50, after = 50) =>
  request<ContextResponse>('GET', `/api/context${query({ ref, before, after })}`);

/** The 1.1 filter parameters, as /api/search and /api/search/summary take them (sent only when set). */
function newFilterParams(p: SearchParams): Record<string, string | string[] | undefined> {
  return {
    type: p.type && p.type !== 'syslog' ? p.type : undefined,
    syntax: p.syntax === 'terms' ? 'terms' : undefined,
    facilities: p.facilities?.length ? p.facilities.map(String) : undefined,
    exclude_devices: p.exclude_devices,
    exclude_app: p.exclude_app,
    exclude_host: p.exclude_host,
    ...Object.fromEntries(Object.entries(p.filters ?? {}).map(([k, v]) => [k, v.length ? v : undefined])),
  };
}

// ---------- Events v2: schema, summary, saved searches (docs/api.md, 1.1) ----------

export interface FieldDomainValue {
  value: string;
  label: string;
}

export interface FieldDescriptor {
  key: string;
  label: string;
  /** The filter parameter a value is added to, exactly as its `value`. */
  param: string;
  /** The parameter that excludes a value; "" for a field with a domain (send the complement in `param`). */
  exclude_param: string;
  /** The complete value set of a closed field (severity, facility), or null. */
  domain: FieldDomainValue[] | null;
}

export interface DataType {
  type: string;
  label: string;
  default: boolean;
  fields: FieldDescriptor[];
}

export interface SearchSchema {
  types: DataType[];
}

export const getSchema = (signal?: AbortSignal) => request<SearchSchema>('GET', '/api/search/schema', undefined, signal);

export interface SummaryParams extends Omit<SearchParams, 'order' | 'limit'> {
  /** Field keys from the schema; undefined = all, [] = none (the histogram alone). */
  fields?: string[];
  top?: number;
  histogram?: boolean;
  bucket?: number;
  budget_ms?: number;
  /** 2.0, type=flow: what each histogram bucket's count holds (default flows). */
  metric?: 'flows' | 'bytes' | 'packets';
}

export interface HistogramBucket {
  start: string;
  /** null: not counted yet (before counted_from). */
  count: number | null;
  /** Spread from checkpoints: show "≈" in the tooltip. */
  approx: boolean;
  /** 2.0, flows: the bucket's bytes exported and scaled. */
  bytes?: number;
  bytes_scaled?: number | null;
}

export interface Histogram {
  bucket_seconds: number;
  source: 'index' | 'scan';
  buckets: HistogramBucket[];
}

export interface FieldValueCount {
  value: string;
  label: string;
  count: number;
  /** False for a value `param` can't express (one with a comma, say). */
  filterable: boolean;
  /** 2.0, flows: the value's bytes (count is flows). */
  bytes?: number;
  bytes_scaled?: number | null;
}

export interface FieldSummary {
  key: string;
  label: string;
  values: FieldValueCount[];
  other: number;
  none: number;
  distinct: number;
  distinct_capped: boolean;
}

export interface SummaryResponse {
  type: string;
  from: string;
  to: string;
  matched: number;
  /** The counts are exact for [counted_from, to); equals from once complete. Flows carry progress instead (SPEC §13.3). */
  counted_from: string;
  /** 2.0, flows: blocks and records read so far, and the flow-time span fully read. */
  progress?: import('./flows').FlowProgress;
  /** Absent with histogram=false. */
  histogram?: Histogram;
  fields: FieldSummary[];
  next_cursor: string;
  partial: boolean;
  scanned_bytes: number;
  scanned_files: number;
  elapsed_ms: number;
}

/** The bucket sizes `bucket=` accepts, in seconds (SPEC §10.1.2). */
export const BUCKETS = [1, 5, 15, 60, 300, 900, 3600, 7200, 21600, 86400, 604800];

export const summaryPath = (p: SummaryParams) =>
  `/api/search/summary${query({
    q: p.q,
    regex: p.regex ? true : undefined,
    case: p.case ? true : undefined,
    devices: p.devices,
    group: p.group,
    ungrouped: p.ungrouped ? true : undefined,
    from: p.from,
    to: p.to,
    severities: p.severities ? sevParam(p.severities) : undefined,
    app: p.app,
    host: p.host,
    exclude: p.exclude,
    ...newFilterParams(p),
    fields: p.fields === undefined ? undefined : p.fields.length ? p.fields : 'none',
    top: p.top,
    histogram: p.histogram === false ? false : undefined,
    bucket: p.bucket,
    metric: p.metric,
    budget_ms: p.budget_ms,
    cursor: p.cursor,
  })}`;
export const getSummary = (p: SummaryParams, signal?: AbortSignal) =>
  request<SummaryResponse>('GET', summaryPath(p), undefined, signal);

/** The message of a 400 for a summary whose running counts the server no longer has. */
export const SUMMARY_EXPIRED = 'This summary expired; start it again.';

export type SavedRange = { last: string } | { from: string; to: string };

/** A saved search's parameters (docs/api.md → Saved searches). Missing keys take their defaults. */
export interface SavedQuery {
  q?: string;
  syntax?: Syntax;
  regex?: boolean;
  case?: boolean;
  exclude?: string;
  devices?: string[];
  group?: string;
  ungrouped?: boolean;
  exclude_devices?: string[];
  severities?: (SevKey | 'none')[];
  facilities?: FacKey[];
  app?: string[];
  exclude_app?: string[];
  host?: string[];
  exclude_host?: string[];
  order?: 'desc' | 'asc';
  range?: SavedRange;
  /** 1.2: a non-syslog type's own filters (type=trap: snmp_versions, trap_oid, status, …), as lists. */
  [param: string]: unknown;
}

export interface SavedSearch {
  id: string;
  name: string;
  type: string;
  created: string;
  updated: string;
  query: SavedQuery;
  /** Device IDs in query.devices the server doesn't know (any more); worked out on every read. */
  missing_devices: string[];
  /** query.group has no devices. */
  missing_group: boolean;
}

export interface SavedSearchBody {
  name: string;
  type?: string;
  query: SavedQuery;
}

export const listSavedSearches = (type = 'syslog') =>
  request<SavedSearch[]>('GET', `/api/saved-searches${query({ type })}`);

export async function getSavedSearch(id: string): Promise<{ saved: SavedSearch; etag: string }> {
  const { data, headers } = await requestFull<SavedSearch>('GET', `/api/saved-searches/${encodeURIComponent(id)}`);
  return { saved: data, etag: headers.get('ETag') ?? '' };
}

export const createSavedSearch = (b: SavedSearchBody) => request<SavedSearch>('POST', '/api/saved-searches', b);

/** Saves with If-Match when etag is set; a stale one is a 409 (isConflict). */
export async function updateSavedSearch(id: string, b: SavedSearchBody, etag = ''): Promise<{ saved: SavedSearch; etag: string }> {
  const { data, headers } = await requestFull<SavedSearch>(
    'PUT',
    `/api/saved-searches/${encodeURIComponent(id)}`,
    b,
    etag ? { 'If-Match': etag } : undefined,
  );
  return { saved: data, etag: headers.get('ETag') ?? '' };
}

export const deleteSavedSearch = (id: string) => request<void>('DELETE', `/api/saved-searches/${encodeURIComponent(id)}`);

export const createExport = (r: ExportRequest) => request<{ id: string }>('POST', '/api/exports', exportJson(r));
export const estimateExport = (r: ExportRequest, signal?: AbortSignal) =>
  request<ExportEstimate>('POST', '/api/exports/estimate', exportJson(r), signal);
/** 1.2: the incident bundle is an export with kind "bundle"; same queue, list, download and expiry. */
export const createBundle = (b: BundleRequest) => request<{ id: string }>('POST', '/api/exports', b);
export const estimateBundle = (b: BundleRequest, signal?: AbortSignal) =>
  request<ExportEstimate>('POST', '/api/exports/estimate', b, signal);
export const listExports = () => request<ExportInfo[]>('GET', '/api/exports');
export const deleteExport = (id: string) => request<void>('DELETE', `/api/exports/${encodeURIComponent(id)}`);
export const exportDownloadUrl = (id: string) => `/api/exports/${encodeURIComponent(id)}/download`;
/**
 * A one-use, 60 s download URL (docs/api.md): a browser download can't send the
 * X-Woodshed-Session header, so the ticket stands in for it. Ask for a new one each time.
 */
export const exportTicket = (id: string) =>
  request<{ url: string }>('POST', `/api/exports/${encodeURIComponent(id)}/ticket`);

/** Settings with the ETag they were read or saved at ("" if the server sent none). */
export interface VersionedSettings {
  settings: Settings;
  etag: string;
}

export async function getSettings(): Promise<VersionedSettings> {
  const { data, headers } = await requestFull<Settings>('GET', '/api/settings');
  return { settings: data, etag: headers.get('ETag') ?? '' };
}

/**
 * Saves the whole object with If-Match: the ETag it was read at. A stale ETag gets a 409
 * (isConflict). `restarting`: the UI server restarts at a new address just after this reply.
 */
export async function putSettings(s: Settings, etag: string): Promise<VersionedSettings & { restarting: boolean }> {
  const { data, headers } = await requestFull<Settings & { restarting?: boolean }>('PUT', '/api/settings', s, etag ? { 'If-Match': etag } : undefined);
  const { restarting, ...settings } = data;
  return { settings, etag: headers.get('ETag') ?? '', restarting: restarting === true };
}

/** A save refused because the settings changed since they were read (409). */
export const isConflict = (e: unknown) => e instanceof ApiError && e.status === 409;
export const getUpdates = () => request<UpdateInfo>('GET', '/api/updates');
/** The banner's Turn on / No thanks, and the Settings switch. */
export const putUpdates = (check: 'on' | 'off') => request<UpdateInfo>('PUT', '/api/updates', { check });
/** Check now: 409 unless the check is on, 429 (retryAfter) within a minute of the last one. */
export const checkUpdatesNow = () => request<void>('POST', '/api/updates/check');
/** Hide the update_available banner for this version, for everyone. */
export const dismissUpdate = (version: string) => request<void>('POST', '/api/updates/dismiss', { version });
export const getStorageHistory = () => request<StorageHistoryEntry[]>('GET', '/api/storage/history');

export interface StorageEstimate {
  estimated_days: number | null;
  bytes_per_day: number | null;
  compression_ratio: number | null;
}
/** The retention estimate for a cap that hasn't been saved yet (docs/api.md). */
export const getStorageEstimate = (retentionBytes: number, signal?: AbortSignal) =>
  request<StorageEstimate>('GET', `/api/storage/estimate${query({ retention_bytes: Math.round(retentionBytes) })}`, undefined, signal);

// ---------- 2.0: flows (docs/api.md → 2.0) ----------

/** /api/search with type=flow: flow records (the filters go in p.filters). */
export const searchFlows = (p: SearchParams, signal?: AbortSignal) =>
  request<FlowSearchResponse>('GET', searchPath({ ...p, type: 'flow' }), undefined, signal);
export const getFlows = (signal?: AbortSignal) => request<FlowState>('GET', '/api/flows', undefined, signal);
export const getFlowTemplates = (device: string, signal?: AbortSignal) =>
  request<FlowTemplates>('GET', `/api/flows/templates${query({ device })}`, undefined, signal);
export const getFlowTop = (p: FlowTopParams, signal?: AbortSignal) =>
  request<FlowTopResponse>(
    'GET',
    `/api/flows/top${query({
      by: p.by,
      metric: p.metric,
      top: p.top,
      from: p.from,
      to: p.to,
      devices: p.devices,
      group: p.group,
      ungrouped: p.ungrouped ? true : undefined,
      exclude_devices: p.exclude_devices,
      ...Object.fromEntries(Object.entries(p.filters ?? {}).map(([k, v]) => [k, v.length ? v : undefined])),
      budget_ms: p.budget_ms,
      cursor: p.cursor,
    })}`,
    undefined,
    signal,
  );
export const getFlowTimeline = (
  p: { devices?: string[]; group?: string; ungrouped?: boolean; from: string; to: string; bucket?: number; metric?: 'bytes' | 'flows' },
  signal?: AbortSignal,
) =>
  request<FlowTimeline>(
    'GET',
    `/api/flows/timeline${query({ devices: p.devices, group: p.group, ungrouped: p.ungrouped ? true : undefined, from: p.from, to: p.to, bucket: p.bucket, metric: p.metric })}`,
    undefined,
    signal,
  );

export const getTls = () => request<TlsState>('GET', '/api/tls');
export const getSnmp = () => request<SnmpState>('GET', '/api/snmp');
export const reloadMibs = () => request<SnmpMibs>('POST', '/api/snmp/mibs/reload');
export const getSnmpFailures = () => request<SnmpFailure[]>('GET', '/api/snmp/failures');
export const getSnmpUsers = () => request<SnmpUser[]>('GET', '/api/snmp/users');
export const createSnmpUser = (u: SnmpUserInput) => request<SnmpUser>('POST', '/api/snmp/users', u);
export const updateSnmpUser = (name: string, u: SnmpUserInput) =>
  request<SnmpUser>('PUT', `/api/snmp/users/${encodeURIComponent(name)}`, u);
export const deleteSnmpUser = (name: string) => request<void>('DELETE', `/api/snmp/users/${encodeURIComponent(name)}`);
/** new_ca: also replace the CA, so every device must import the new one. 409 with source "file". */
// ---------- 1.3: the SNMP poller (docs/api.md → 1.3) ----------

export const getPollTargets = () => request<PollTarget[]>('GET', '/api/poll/targets');
/** One target with its ETag (for If-Match on a change). */
export async function getPollTarget(id: string): Promise<{ target: PollTarget; etag: string }> {
  const { data, headers } = await requestFull<PollTarget>('GET', `/api/poll/targets/${encodeURIComponent(id)}`);
  return { target: data, etag: headers.get('ETag') ?? '' };
}
export const createPollTarget = (t: PollTargetInput) => request<PollTarget>('POST', '/api/poll/targets', t);
/** Saves with If-Match when etag is set; a stale one is a 409 (isConflict). A missing community keeps the stored one. */
export async function updatePollTarget(id: string, t: PollTargetInput, etag = ''): Promise<{ target: PollTarget; etag: string }> {
  const { data, headers } = await requestFull<PollTarget>(
    'PUT',
    `/api/poll/targets/${encodeURIComponent(id)}`,
    t,
    etag ? { 'If-Match': etag } : undefined,
  );
  return { target: data, etag: headers.get('ETag') ?? '' };
}
export const deletePollTarget = (id: string) => request<void>('DELETE', `/api/poll/targets/${encodeURIComponent(id)}`);
/** Runs the configured poll once without saving: a target body, or {id} for a stored one. 429 beyond 10 a minute. */
export const testPoll = (t: PollTargetInput | { id: string }, signal?: AbortSignal) =>
  request<PollTestResult>('POST', '/api/poll/test', t, signal);
export const getPollState = () => request<PollState>('GET', '/api/poll');
export const getPollSeries = (p: { device: string; from: string; to: string; bucket?: number; series: string[]; cursor?: string }, signal?: AbortSignal) =>
  request<PollSeriesResponse>(
    'GET',
    `/api/poll/series${query({ device: p.device, from: p.from, to: p.to, bucket: p.bucket, series: p.series, cursor: p.cursor })}`,
    undefined,
    signal,
  );
export const getPollTimeline = (
  p: { devices?: string[]; group?: string; ungrouped?: boolean; from: string; to: string; bucket?: number },
  signal?: AbortSignal,
) =>
  request<PollTimeline>(
    'GET',
    `/api/poll/timeline${query({ devices: p.devices, group: p.group, ungrouped: p.ungrouped ? true : undefined, from: p.from, to: p.to, bucket: p.bucket })}`,
    undefined,
    signal,
  );
export const getPollDevice = (id: string, from: string, to: string, signal?: AbortSignal) =>
  request<PollDevicePanel>('GET', `/api/poll/device/${encodeURIComponent(id)}${query({ from, to })}`, undefined, signal);

export const renewTls = (newCa: boolean) => request<TlsState>('POST', '/api/tls/renew', { new_ca: newCa });
export const getTlsFailures = () => request<TlsFailure[]>('GET', '/api/tls/failures');

export type CaFormat = 'pem' | 'der';
export const CA_FILE: Record<CaFormat, string> = { pem: 'woodshed-ca.pem', der: 'woodshed-ca.cer' };

/**
 * Downloads the CA certificate. It's fetched with the session header and saved from the
 * response (docs/api.md), so no download ticket is needed. Throws ApiError (404: none yet,
 * or the server uses your own certificate).
 */
export async function downloadCa(format: CaFormat): Promise<void> {
  const path = `/api/tls/ca.${format}`;
  let res: Response;
  try {
    res = await transport.fetch(path, { headers: { ...authHeaders() } });
  } catch (e) {
    throw new ApiError(0, `no connection: ${(e as Error).message}`);
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      msg = ((await res.json()) as { error?: string }).error || msg;
    } catch {
      /* not JSON */
    }
    if (res.status === 401) unauthorized();
    throw new ApiError(res.status, msg);
  }
  const blob = await res.blob();
  const name = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') ?? '')?.[1] ?? CA_FILE[format];
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

export interface LiveHandlers {
  onMessage(line: LogLine): void;
  onSampled?(n: SampledNotice): void;
  onState?(state: 'open' | 'error' | 'closed'): void;
}

/** First reconnect delay; doubles after each failure up to LIVE_BACKOFF_MAX (with jitter). */
const LIVE_BACKOFF_MIN = 1000;
const LIVE_BACKOFF_MAX = 30_000;
/** docs/api.md: a heartbeat every 15 s, so 45 s with no bytes at all means the stream is dead. */
const LIVE_IDLE_MS = 45_000;

/**
 * Opens the live tail over fetch() (EventSource can't send the session header), parses the
 * SSE stream, and reconnects with backoff after errors or a dropped stream. A 401 ends it
 * and shows the login. Returns a close function.
 */
export function openLive(filters: LiveFilters, h: LiveHandlers): () => void {
  const path = `/api/live${query({
    devices: filters.devices,
    group: filters.group,
    ungrouped: filters.ungrouped ? true : undefined,
    severities: filters.severities ? sevParam(filters.severities) : undefined,
    q: filters.q,
  })}`;
  let closed = false;
  let ctrl: AbortController | null = null;
  let backoff = LIVE_BACKOFF_MIN;
  let timer = 0;

  const dispatch = (e: SseEvent) => {
    try {
      if (e.event === 'message') h.onMessage(JSON.parse(e.data) as LogLine);
      else if (e.event === 'sampled') h.onSampled?.(JSON.parse(e.data) as SampledNotice);
    } catch {
      /* skip a malformed event rather than stop the tail */
    }
  };

  const retryLater = () => {
    if (closed) return;
    h.onState?.('error');
    const wait = Math.min(LIVE_BACKOFF_MAX, backoff) * (0.8 + Math.random() * 0.4);
    backoff = Math.min(LIVE_BACKOFF_MAX, backoff * 2);
    timer = window.setTimeout(connect, wait);
  };

  async function connect() {
    if (closed) return;
    ctrl = new AbortController();
    const my = ctrl;
    let idle = 0;
    const bump = () => {
      clearTimeout(idle);
      idle = window.setTimeout(() => my.abort(), LIVE_IDLE_MS);
    };
    try {
      bump();
      const res = await transport.fetch(path, {
        headers: { Accept: 'text/event-stream', ...authHeaders() },
        cache: 'no-store',
        signal: my.signal,
      });
      if (res.status === 401) {
        clearTimeout(idle);
        h.onState?.('closed');
        unauthorized();
        return;
      }
      if (!res.ok || !res.body) throw new Error(`live tail: ${res.status}`);
      h.onState?.('open');
      backoff = LIVE_BACKOFF_MIN;
      const parser = new SseParser(dispatch);
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        bump();
        parser.push(dec.decode(value, { stream: true }));
      }
      parser.push(dec.decode());
      if (parser.retry !== null) backoff = Math.max(LIVE_BACKOFF_MIN, parser.retry);
      clearTimeout(idle);
      retryLater(); // the server ended the stream (restart, timeout): reconnect
    } catch (e) {
      clearTimeout(idle);
      if (closed) return;
      retryLater();
      void e;
    }
  }

  connect();
  return () => {
    closed = true;
    clearTimeout(timer);
    ctrl?.abort();
  };
}
