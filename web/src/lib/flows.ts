// Flows (NetFlow v5/v9 and IPFIX, SPEC §13, docs/api.md → 2.0): the API's shapes, the filter
// parameters, the Top views, and the formatters the Flows tab, the flow strip, the device page,
// Settings and the bundle share. Pure functions only, so `npm test` runs them under plain node.

import { formatDuration, parseDuration } from './bundle.ts';

export const FLOW = 'flow';

// ---------- Types (docs/api.md → 2.0) ----------

export interface FlowListenerSettings {
  enabled: boolean;
  addr: string;
  /** NetFlow v5 and v9 (any version is accepted on either port); 0 turns it off. */
  netflow_port: number;
  ipfix_port: number;
  /** A duration, "30m" (1 min to 24 h). */
  template_timeout: string;
  /** Up to 8 "<enterprise number>:<element ID>" strings; the first one a record has fills rule_id. */
  rule_id_ies: string[];
}

export interface FlowExtra {
  pen: number;
  id: number;
  hex: string;
}

/** A flow record's columns; null where the record doesn't have one (rule_id is ""). */
export interface FlowFields {
  start: string;
  end: string;
  src: string | null;
  src_port: number | null;
  dst: string | null;
  dst_port: number | null;
  proto: number | null;
  proto_name?: string;
  tcp_flags: string | null;
  packets: number | null;
  bytes: number | null;
  /** 1 unsampled, N for 1 in N, 0 unknown. */
  sampling: number;
  packets_scaled: number | null;
  bytes_scaled: number | null;
  in_if: number | null;
  in_if_name: string | null;
  out_if: number | null;
  out_if_name: string | null;
  domain: number;
  fw_event: string | null;
  nat_event: string | null;
  event_time: string | null;
  post_nat_src: string | null;
  post_nat_src_port: number | null;
  post_nat_dst: string | null;
  post_nat_dst_port: number | null;
  initiator_bytes: number | null;
  responder_bytes: number | null;
  initiator_packets: number | null;
  responder_packets: number | null;
  rev_bytes: number | null;
  rev_packets: number | null;
  rule_id: string;
  tos?: number | null;
  src_as?: number | null;
  dst_as?: number | null;
  next_hop?: string;
  time_source: 'exporter' | 'received' | (string & {});
  status: 'ok' | 'late' | 'no_template' | 'malformed' | (string & {});
  late?: boolean;
  extras: FlowExtra[];
}

export interface FlowResult {
  received: string;
  device_id: string;
  type: 'flow';
  ref: string;
  fields: FlowFields;
}

/** A partial flow answer's progress: blocks and records read of those the window can touch. */
export interface FlowProgress {
  blocks_done: number;
  blocks_total: number;
  records_done: number;
  records_total: number;
  /** Every block whose flows end after this has been read. */
  complete_from: string;
}

export interface FlowSearchResponse {
  results: FlowResult[];
  next_cursor: string;
  partial: boolean;
  elapsed_ms: number;
  scanned_bytes?: number;
  scanned_files?: number;
  progress?: FlowProgress;
}

export type FlowBy =
  | 'src'
  | 'dst'
  | 'conversation'
  | 'dst_port'
  | 'src_port'
  | 'proto'
  | 'in_if'
  | 'out_if'
  | 'post_nat_src'
  | 'post_nat_dst'
  | 'fw_event'
  | 'rule_id';
export type FlowMetric = 'bytes' | 'packets' | 'flows' | 'connections';

export interface FlowTopRow {
  key: string;
  label: string;
  flows: number;
  bytes: number;
  packets: number;
  bytes_scaled: number | null;
  packets_scaled: number | null;
  /** Some records behind it had unknown sampling: the scaled value is a lower bound ("≥"). */
  scaled_lower_bound: boolean;
  share: number;
  first: string;
  last: string;
  connections?: number;
}

export interface FlowTopResponse {
  by: FlowBy;
  metric: FlowMetric;
  from: string;
  to: string;
  total: { flows: number; bytes: number; packets: number; bytes_scaled: number | null; packets_scaled: number | null; scaled_complete: boolean; connections?: number };
  rows: FlowTopRow[];
  other: { flows: number; bytes: number; packets?: number; connections?: number };
  approx: boolean;
  progress: FlowProgress;
  partial: boolean;
  next_cursor: string;
  elapsed_ms: number;
}

export interface FlowTopParams {
  by: FlowBy;
  metric?: FlowMetric;
  top?: number;
  from: string;
  to: string;
  devices?: string[];
  group?: string;
  ungrouped?: boolean;
  exclude_devices?: string[];
  filters?: Record<string, string[]>;
  budget_ms?: number;
  cursor?: string;
}

export interface FlowTimelinePoint {
  start: string;
  bytes: number;
  bytes_scaled: number | null;
  flows: number;
}

export interface FlowTimeline {
  devices: { device_id: string; points: FlowTimelinePoint[] }[];
  more: number;
}

export interface FlowDomain {
  id: number;
  sampling: number;
  templates: number;
  last_template: string | null;
}

export interface FlowExporter {
  device_id: string;
  domains: FlowDomain[];
  records_per_sec: number;
  pending_bytes: number;
  counts_24h: { records: number; late: number; no_template: number; malformed: number; sequence_gaps: number; duplicates: number };
  clock_skew_ms: number;
  time_source: 'exporter' | 'received' | (string & {});
}

export interface FlowState {
  enabled: boolean;
  budget: { bytes: number; used_bytes: number; estimated_days: number | null };
  exporters: FlowExporter[];
}

export interface FlowTemplateField {
  pen: number;
  id: number;
  /** "" for an enterprise or unknown IE (shown as pen:id). */
  name: string;
  length: number;
}

export interface FlowTemplate {
  id: number;
  options: boolean;
  received: string;
  fields: FlowTemplateField[];
}

export interface FlowTemplates {
  device_id: string;
  domains: { id: number; templates: FlowTemplate[] }[];
}

/** A bundle manifest's per-device "flow" summary (docs/api.md → Exports and bundles), which the README's Flows block reads. */
export interface FlowBundleSummary {
  records: number;
  domains: number;
  /** Per observation domain: its sampling (1 unsampled, N, 0 unknown). */
  sampling: { domain: number; sampling: number }[];
  bytes: number;
  bytes_scaled: number | null;
  packets: number;
  packets_scaled: number | null;
  top_talkers: { key: string; share: number }[];
  top_dst_ports: { key: string; share: number }[];
  top_conversations: { key: string; share: number }[];
  fw_events: { created: number; deleted: number; denied: number };
  top_denied_sources: { key: string; count: number }[];
  top_denied_ports: { key: string; count: number }[];
  nat_connections: number;
  top_post_nat_sources: { key: string; share: number }[];
  sequence_gaps: number;
  /** Records lost before Woodshed, estimated from the gaps (null where unknown, as in the bundle preview). */
  lost_estimate: number | null;
  no_template: number;
  malformed: number;
}

/** /api/exports/estimate's by_type (2.0). */
export type EstimateByType = Record<string, { lines?: number; records?: number; bytes: number }>;

/** The zip's flow files (docs/api.md): both by default. */
export type FlowFormat = 'csv' | 'ipfix';
export const FLOW_FORMATS: FlowFormat[] = ['csv', 'ipfix'];
/** The body's flow_formats: left out for the default (both), so the other bodies stay as they were. */
export const flowFormatsBody = (f: FlowFormat[]): FlowFormat[] | undefined =>
  f.length === FLOW_FORMATS.length && FLOW_FORMATS.every((x) => f.includes(x)) ? undefined : FLOW_FORMATS.filter((x) => f.includes(x));

// ---------- the filters (docs/api.md → Flow search and top-N) ----------

export type FilterKind = 'addr' | 'port' | 'proto' | 'if' | 'fw' | 'nat' | 'text' | 'domain' | 'flags' | 'choice';

export interface FlowFilterDef {
  param: string;
  label: string;
  kind: FilterKind;
  /** The parameter that leaves values out, or "". */
  exclude: string;
  placeholder: string;
  /** Shown in the first row; the rest are under "More filters". */
  main?: boolean;
}

export const FLOW_FILTERS: FlowFilterDef[] = [
  { param: 'src', label: 'Source', kind: 'addr', exclude: 'exclude_src', placeholder: '10.20.0.0/16, 2001:db8::5', main: true },
  { param: 'dst', label: 'Destination', kind: 'addr', exclude: 'exclude_dst', placeholder: '198.51.100.7', main: true },
  { param: 'ip', label: 'Either address', kind: 'addr', exclude: 'exclude_ip', placeholder: '10.20.0.5', main: true },
  { param: 'dst_port', label: 'Destination port', kind: 'port', exclude: 'exclude_dst_port', placeholder: '443, 8000-8100', main: true },
  { param: 'proto', label: 'Protocol', kind: 'proto', exclude: 'exclude_proto', placeholder: 'tcp, udp, 47', main: true },
  { param: 'src_port', label: 'Source port', kind: 'port', exclude: 'exclude_src_port', placeholder: '53' },
  { param: 'port', label: 'Either port', kind: 'port', exclude: 'exclude_port', placeholder: '22, 3389' },
  { param: 'ip_any', label: 'Any address, pre- or post-NAT', kind: 'addr', exclude: '', placeholder: '192.0.2.10' },
  { param: 'fw_event', label: 'Firewall event', kind: 'fw', exclude: '', placeholder: 'denied, created' },
  { param: 'nat_event', label: 'NAT event', kind: 'nat', exclude: '', placeholder: 'nat44_session_create' },
  { param: 'post_nat_src', label: 'Post-NAT source', kind: 'addr', exclude: 'exclude_post_nat_src', placeholder: '192.0.2.10' },
  { param: 'post_nat_dst', label: 'Post-NAT destination', kind: 'addr', exclude: 'exclude_post_nat_dst', placeholder: '198.51.100.7' },
  { param: 'post_nat_ip', label: 'Post-NAT, either', kind: 'addr', exclude: 'exclude_post_nat_ip', placeholder: '192.0.2.0/24' },
  { param: 'post_nat_src_port', label: 'Post-NAT source port', kind: 'port', exclude: '', placeholder: '40000-40999' },
  { param: 'post_nat_dst_port', label: 'Post-NAT destination port', kind: 'port', exclude: '', placeholder: '443' },
  { param: 'rule_id', label: 'Rule ID', kind: 'text', exclude: 'exclude_rule_id', placeholder: 'from listeners.flow.rule_id_ies' },
  { param: 'in_if', label: 'Input interface', kind: 'if', exclude: 'exclude_in_if', placeholder: '3, eth3' },
  { param: 'out_if', label: 'Output interface', kind: 'if', exclude: 'exclude_out_if', placeholder: '1' },
  { param: 'domain', label: 'Observation domain', kind: 'domain', exclude: '', placeholder: '1, 256' },
  { param: 'tcp_flags', label: 'TCP flags (any of)', kind: 'flags', exclude: '', placeholder: 'syn, rst' },
  { param: 'sampled', label: 'Sampled', kind: 'choice', exclude: '', placeholder: 'yes, no, unknown' },
  { param: 'status', label: 'Status', kind: 'choice', exclude: '', placeholder: 'ok, late' },
];

/** Every flow filter parameter (include and exclude), as the page URL and saved searches hold them. */
export const FLOW_PARAMS: string[] = FLOW_FILTERS.flatMap((f) => (f.exclude ? [f.param, f.exclude] : [f.param]));

export const FW_EVENTS = ['created', 'deleted', 'denied', 'alert', 'update'];
export const PROTO_NAMES: Record<number, string> = { 1: 'icmp', 6: 'tcp', 17: 'udp', 47: 'gre', 50: 'esp', 58: 'icmpv6', 132: 'sctp' };
const PROTO_BY_NAME = Object.fromEntries(Object.entries(PROTO_NAMES).map(([n, s]) => [s, Number(n)]));
export const TCP_FLAGS = ['fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ece', 'cwr'];
const CHOICES: Record<string, string[]> = { sampled: ['yes', 'no', 'unknown'], status: ['ok', 'late', 'no_template', 'malformed'] };

const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
function isV4(s: string): boolean {
  const m = v4.exec(s);
  return !!m && m.slice(1).every((x) => Number(x) <= 255);
}
function isV6(s: string): boolean {
  if (!/^[0-9a-f:.]+$/i.test(s) || !s.includes(':')) return false;
  const dbl = s.split('::').length - 1;
  if (dbl > 1) return false;
  const parts = s.split(':');
  const last = parts[parts.length - 1];
  const tail4 = last.includes('.') ? (isV4(last) ? 2 : -99) : 0;
  const groups = parts.filter((p, i) => p !== '' && !(i === parts.length - 1 && last.includes('.')));
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return false;
  const n = groups.length + tail4;
  return tail4 >= 0 && (dbl ? n < 8 : n === 8);
}

/** An address or a CIDR prefix (IPv4 or IPv6). */
export function isAddrOrPrefix(s: string): boolean {
  const [a, len, more] = s.split('/');
  if (more !== undefined) return false;
  const six = isV6(a);
  if (!six && !isV4(a)) return false;
  if (len === undefined) return true;
  return /^\d{1,3}$/.test(len) && Number(len) <= (six ? 128 : 32);
}

/** A port (0–65535) or a range "8000-8100". */
export function isPortOrRange(s: string): boolean {
  const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(s);
  if (!m) return false;
  const a = Number(m[1]);
  const b = m[2] === undefined ? a : Number(m[2]);
  return a <= 65535 && b <= 65535 && a <= b;
}

/** What's wrong with one value of a filter, or "" (the server says the same with a 400; this puts it under the box). */
export function valueError(def: FlowFilterDef, v: string): string {
  const x = v.trim().toLowerCase();
  switch (def.kind) {
    case 'addr':
      return isAddrOrPrefix(x) ? '' : `"${v}" isn't an address or prefix (10.20.0.0/16, 2001:db8::/32).`;
    case 'port':
      return isPortOrRange(x) ? '' : `"${v}" isn't a port or range (443, 8000-8100).`;
    case 'proto':
      return x in PROTO_BY_NAME || (/^\d{1,3}$/.test(x) && Number(x) <= 255) ? '' : `"${v}" isn't a protocol: tcp, udp, icmp, icmpv6, gre, esp, sctp or 0–255.`;
    case 'fw':
      return FW_EVENTS.includes(x) || (/^\d{1,3}$/.test(x) && Number(x) <= 255) ? '' : `"${v}" isn't a firewall event: ${FW_EVENTS.join(', ')} or 0–255.`;
    case 'domain':
      return /^\d{1,10}$/.test(x) && Number(x) <= 4294967295 ? '' : `"${v}" isn't an observation domain or source ID.`;
    case 'flags':
      return TCP_FLAGS.includes(x) ? '' : `"${v}" isn't a TCP flag: ${TCP_FLAGS.join(', ')}.`;
    case 'choice':
      return CHOICES[def.param]?.includes(x) ? '' : `"${v}" isn't one of ${CHOICES[def.param]?.join(', ')}.`;
    case 'if':
      return x.length <= 256 ? '' : 'An interface name is at most 256 bytes.';
    case 'nat':
      return /^[a-z0-9_]+$/.test(x) ? '' : `"${v}" isn't a NAT event name or number.`;
    default:
      return '';
  }
}

/** A filter box's text as its list, split on commas and spaces. */
export const splitValues = (s: string) =>
  s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

/** The first problem in the boxes, by parameter, or {} when every value is fine. */
export function filterErrors(f: Record<string, string[]>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const def of FLOW_FILTERS)
    for (const p of def.exclude ? [def.param, def.exclude] : [def.param]) {
      const e = (f[p] ?? []).map((v) => valueError(def, v)).find(Boolean);
      if (e) out[p] = e;
    }
  return out;
}

// ---------- numbers ----------

const enUS = new Intl.NumberFormat('en-US');
const nf1 = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 });

/** Decimal bytes as flow tools print them: "1.8 kB", "312 MB", "1.9 TB". */
export function dbytes(n: number): string {
  const u = ['B', 'kB', 'MB', 'GB', 'TB', 'PB', 'EB'];
  let i = 0;
  let v = n;
  while (Math.abs(v) >= 1000 && i < u.length - 1) {
    v /= 1000;
    i++;
  }
  return `${i === 0 ? enUS.format(Math.round(v)) : nf1.format(v)} ${u[i]}`;
}

/** A count in short form: "840", "21.4 k", "21.4 M", "2.1 G". */
export function short(n: number): string {
  const u = ['', ' k', ' M', ' G', ' T', ' P'];
  let i = 0;
  let v = n;
  while (Math.abs(v) >= 1000 && i < u.length - 1) {
    v /= 1000;
    i++;
  }
  return i === 0 ? enUS.format(Math.round(v)) : `${nf1.format(v)}${u[i]}`;
}

/** "1:1000" for 1 in N, "unsampled", or "sampling unknown". */
export function samplingText(s: number): string {
  if (s === 1) return 'unsampled';
  if (!s) return 'sampling unknown';
  return `1:${enUS.format(s)}`;
}

const metricFmt = (metric: FlowMetric | 'bytes' | 'packets' | 'flows', n: number) => (metric === 'bytes' ? dbytes(n) : short(n));

/**
 * Exported and scaled together, never one silently for the other (SPEC §13.3): "312 MB exported
 * (≈ 312 GB at 1:1000)", "(≥ 1.2 GB scaled)" when some sampling was unknown, just "312 MB" when
 * nothing was sampled (scaled equals exported or isn't known at all).
 */
export function amountText(metric: 'bytes' | 'packets' | 'flows' | FlowMetric, exported: number, scaled: number | null, opts: { sampling?: number; lowerBound?: boolean } = {}): string {
  const e = metricFmt(metric, exported);
  if (scaled === null || scaled === undefined || (scaled === exported && !opts.lowerBound)) return e;
  const how = opts.sampling && opts.sampling > 1 ? ` at ${samplingText(opts.sampling)}` : ' scaled';
  return `${e} exported (${opts.lowerBound ? '≥' : '≈'} ${metricFmt(metric, scaled)}${how})`;
}

/** A share as "31 %" (one decimal under 10 %: "4.2 %", "<0.1 %"). */
export function shareText(share: number): string {
  const p = share * 100;
  if (p > 0 && p < 0.1) return '<0.1 %';
  return `${p < 10 ? nf1.format(p) : enUS.format(Math.round(p))} %`;
}

export function protoName(p: number | null | undefined, name?: string): string {
  if (p === null || p === undefined) return '';
  return name || PROTO_NAMES[p] || String(p);
}

// ---------- Top (GET /api/flows/top) ----------

export interface TopView {
  key: string;
  label: string;
  /** One or more tables, each its own request. */
  tables: { by: FlowBy; label: string; metric?: FlowMetric; filters?: Record<string, string[]> }[];
}

export const TOP_VIEWS: TopView[] = [
  { key: 'talkers', label: 'Talkers', tables: [{ by: 'src', label: 'Top talkers' }] },
  { key: 'ports', label: 'Destination ports', tables: [{ by: 'dst_port', label: 'Top destination ports' }] },
  { key: 'conversations', label: 'Conversations', tables: [{ by: 'conversation', label: 'Top conversations (both directions)' }] },
  {
    key: 'denied',
    label: 'Denied',
    tables: [
      { by: 'src', label: 'Top denied sources', metric: 'flows', filters: { fw_event: ['denied'] } },
      { by: 'dst', label: 'Top denied destinations', metric: 'flows', filters: { fw_event: ['denied'] } },
      { by: 'dst_port', label: 'Top denied ports', metric: 'flows', filters: { fw_event: ['denied'] } },
      { by: 'rule_id', label: 'Top denied rules', metric: 'flows', filters: { fw_event: ['denied'] } },
    ],
  },
];

export const TOP_BYS: { by: FlowBy; label: string }[] = [
  { by: 'src', label: 'Source' },
  { by: 'dst', label: 'Destination' },
  { by: 'conversation', label: 'Conversation' },
  { by: 'dst_port', label: 'Destination port' },
  { by: 'src_port', label: 'Source port' },
  { by: 'proto', label: 'Protocol' },
  { by: 'in_if', label: 'Input interface' },
  { by: 'out_if', label: 'Output interface' },
  { by: 'post_nat_src', label: 'Post-NAT source' },
  { by: 'post_nat_dst', label: 'Post-NAT destination' },
  { by: 'fw_event', label: 'Firewall event' },
  { by: 'rule_id', label: 'Rule ID' },
];
export const METRICS: { metric: FlowMetric; label: string }[] = [
  { metric: 'bytes', label: 'Bytes' },
  { metric: 'packets', label: 'Packets' },
  { metric: 'flows', label: 'Flows' },
  { metric: 'connections', label: 'Connections' },
];

/** The metric a Top request uses when none is picked: flows for denied events (they carry no bytes), else bytes. */
export function defaultMetric(filters: Record<string, string[]>): FlowMetric {
  const fw = filters.fw_event ?? [];
  return fw.length && fw.every((x) => x.toLowerCase() === 'denied' || x === '3') ? 'flows' : 'bytes';
}

/** A row's value for the metric (connections falls back to flows for an older answer). */
export const rowValue = (r: FlowTopRow, m: FlowMetric) => (m === 'connections' ? (r.connections ?? r.flows) : r[m]);
export const rowScaled = (r: FlowTopRow, m: FlowMetric) => (m === 'bytes' ? r.bytes_scaled : m === 'packets' ? r.packets_scaled : null);

/**
 * The filters a Top row stands for, to add to the search: a port key "tcp/443" is the port and
 * its protocol, a conversation "a ↔ b" is both addresses on both sides.
 */
export function rowFilters(by: FlowBy, key: string): Record<string, string[]> {
  switch (by) {
    case 'dst_port':
    case 'src_port': {
      const m = /^([a-z0-9]+)\/(\d+)$/i.exec(key);
      if (!m) return { [by]: [key] };
      return { proto: [m[1].toLowerCase()], [by]: [m[2]] };
    }
    case 'conversation': {
      const ab = key.split(/\s*↔\s*/).filter(Boolean);
      return ab.length === 2 ? { src: ab, dst: ab } : { ip: [key] };
    }
    case 'fw_event':
    case 'proto':
    case 'in_if':
    case 'out_if':
    case 'rule_id':
    case 'src':
    case 'dst':
    case 'post_nat_src':
    case 'post_nat_dst':
      return { [by]: [key] };
  }
}

/** Adds filters, keeping each list's existing values (any case) and adding the new ones. */
export function addFilters(cur: Record<string, string[]>, add: Record<string, string[]>): Record<string, string[]> {
  const out: Record<string, string[]> = { ...cur };
  for (const [k, vs] of Object.entries(add)) {
    const have = out[k] ?? [];
    out[k] = [...have, ...vs.filter((v) => !have.some((h) => h.toLowerCase() === v.toLowerCase()))];
  }
  return out;
}

// ---------- progress (SPEC §13.3: flows have no counted_from) ----------

/** "Counted 62 % of the window's flow records, newest first", or "" once complete. */
export function progressText(p: FlowProgress | undefined | null, partial: boolean): string {
  if (!p || !partial) return '';
  const of = p.records_total || p.blocks_total;
  const done = p.records_total ? p.records_done : p.blocks_done;
  const pct = of ? Math.min(99, Math.floor((done / of) * 100)) : 0;
  return `Counted ${pct} % of the window's flow records, newest first`;
}

// ---------- export and bundle ----------

const H4 = 4 * 3600_000;
/** SPEC §13.11 #6: "Leave flows out" is pre-selected for a window over 4 h whose flows are estimated above 1 GB. */
export const leaveFlowsOutByDefault = (windowMs: number, flowBytes: number) => windowMs > H4 && flowBytes > 1e9;

/** The flow part of an estimate, or null when it has none. */
export function flowEstimate(by: EstimateByType | undefined): { records: number; bytes: number } | null {
  const f = by?.flow;
  if (!f) return null;
  return { records: f.records ?? f.lines ?? 0, bytes: f.bytes };
}

/** The estimate's types in words: "12,400 syslog lines (1.7 MB), 575 SNMP traps (236 kB), 3.1 M flow records (52 MB)". */
export function byTypeText(by: EstimateByType | undefined, labels: Record<string, string> = TYPE_LABELS): string {
  if (!by) return '';
  return Object.entries(by)
    .filter(([, v]) => (v.records ?? v.lines ?? 0) > 0)
    .map(([t, v]) => {
      const n = v.records ?? v.lines ?? 0;
      const what = labels[t] ?? t;
      return `${t === FLOW ? short(n) : enUS.format(n)} ${what} (${dbytes(v.bytes)})`;
    })
    .join(', ');
}
export const TYPE_LABELS: Record<string, string> = { syslog: 'syslog lines', trap: 'SNMP traps', poll: 'poll records', flow: 'flow records' };

/** The server's 400 for a zip over the per-device flow record cap (docs/api.md), so the page can offer Leave flows out. */
export const isTooManyFlows = (msg: string) => /^Too many flow records for one zip/.test(msg);

// ---------- the README's Flows block (SPEC §13.4) ----------

const pad = '                 ';

function samplingPhrase(s: FlowBundleSummary['sampling']): string {
  return s
    .map((d) => (d.sampling === 1 ? `unsampled on domain ${d.domain}` : d.sampling ? `sampled 1 in ${enUS.format(d.sampling)} on domain ${d.domain}` : `sampling unknown on domain ${d.domain}`))
    .join(', ');
}

const shares = (xs: { key: string; share: number }[]) => xs.map((x) => `${x.key} ${Math.round(x.share * 100)} %`).join(', ');
const counts = (xs: { key: string; count: number }[]) => xs.map((x) => `${x.key} ${enUS.format(x.count)}`).join(', ');

/**
 * The per-device README's Flows block as SPEC §13.4 shows it, from the manifest summary's
 * "flow" object. Lines a device has nothing for (no firewall events, no NAT) are left out.
 */
export function flowReadme(s: FlowBundleSummary): string {
  const lines: string[] = [];
  const doms = `${enUS.format(s.domains)} observation domain${s.domains === 1 ? '' : 's'}`;
  const samp = samplingPhrase(s.sampling);
  lines.push(`    Flows        ${enUS.format(s.records)} records from ${doms}${samp ? `; ${samp}` : ''}`);
  const sc = (v: number | null, f: (n: number) => string) => (v !== null && v !== undefined ? ` (≈ ${f(v)} scaled)` : '');
  lines.push(`${pad}bytes ${dbytes(s.bytes)} exported${sc(s.bytes_scaled, dbytes)}, packets ${short(s.packets)}${sc(s.packets_scaled, short)}`);
  if (s.top_talkers.length) lines.push(`${pad}top talkers by bytes: ${shares(s.top_talkers)}`);
  if (s.top_dst_ports.length) lines.push(`${pad}top destination ports: ${shares(s.top_dst_ports)}`);
  if (s.top_conversations.length) lines.push(`${pad}top conversations: ${shares(s.top_conversations)}`);
  const fw = s.fw_events;
  if (fw.created || fw.deleted || fw.denied)
    lines.push(`${pad}firewall events: ${enUS.format(fw.created)} created, ${enUS.format(fw.deleted)} deleted, ${enUS.format(fw.denied)} denied`);
  const den = [
    s.top_denied_sources.length ? `top denied sources: ${counts(s.top_denied_sources)}` : '',
    s.top_denied_ports.length ? `top denied ports: ${counts(s.top_denied_ports)}` : '',
  ].filter(Boolean);
  if (den.length) lines.push(`${pad}${den.join('; ')}`);
  if (s.nat_connections)
    lines.push(
      `${pad}NAT: ${enUS.format(s.nat_connections)} translated connections${s.top_post_nat_sources.length ? `; top post-NAT sources: ${shares(s.top_post_nat_sources)}` : ''}`,
    );
  const lost = s.sequence_gaps && s.lost_estimate !== null ? ` (≈ ${enUS.format(s.lost_estimate)} records lost before Woodshed)` : '';
  lines.push(`${pad}sequence gaps ${enUS.format(s.sequence_gaps)}${lost}; waiting for a template ${enUS.format(s.no_template)}; malformed ${enUS.format(s.malformed)}`);
  return lines.join('\n');
}

// ---------- Settings → Flows ----------

export interface FlowSettingsForm {
  flowEnabled: boolean;
  flowAddr: string;
  flowNetflowPort: number;
  flowIpfixPort: number;
  /** As typed: "30m", "1h". */
  flowTimeout: string;
  /** One "<pen>:<id>" per line (commas and spaces also split). */
  flowRuleIes: string;
  /** 0: the default, 40 % of the storage cap. */
  flowBudgetGiB: number;
}

export const DEFAULT_FLOW: FlowListenerSettings = {
  enabled: false,
  addr: '0.0.0.0',
  netflow_port: 2055,
  ipfix_port: 4739,
  template_timeout: '30m',
  rule_id_ies: [],
};

const GIB = 1024 ** 3;

export function flowSettingsForm(l: FlowListenerSettings | undefined, budgetBytes: number | undefined): FlowSettingsForm {
  const s = l ?? DEFAULT_FLOW;
  return {
    flowEnabled: s.enabled,
    flowAddr: s.addr,
    flowNetflowPort: s.netflow_port,
    flowIpfixPort: s.ipfix_port,
    flowTimeout: s.template_timeout,
    flowRuleIes: (s.rule_id_ies ?? []).join('\n'),
    flowBudgetGiB: budgetBytes ? Math.round((budgetBytes / GIB) * 100) / 100 : 0,
  };
}

const num0 = (v: number | null) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

/** The rule-ID IEs as the body sends them: trimmed, in order, duplicates dropped. */
export const ruleIesOf = (text: string) => [...new Set(splitValues(text))];

/** listeners.flow as the form sends it. A timeout that parses goes in its canonical form ("1h30m"); one that doesn't is sent as typed (the server's 400 names it). */
export function flowListenerBody(f: FlowSettingsForm): FlowListenerSettings {
  const t = parseDuration(f.flowTimeout);
  return {
    enabled: f.flowEnabled,
    addr: f.flowAddr.trim(),
    netflow_port: num0(f.flowNetflowPort),
    ipfix_port: num0(f.flowIpfixPort),
    template_timeout: Number.isFinite(t) && t > 0 ? formatDuration(t) : f.flowTimeout.trim(),
    rule_id_ies: ruleIesOf(f.flowRuleIes),
  };
}

/** storage.flow_budget_bytes as the form sends it (0 keeps the default share). */
export const flowBudgetBody = (f: FlowSettingsForm) => Math.round(num0(f.flowBudgetGiB) * GIB);

/** The form's own checks, shown before saving (the server checks the same). */
export function flowFormErrors(f: FlowSettingsForm, retentionBytes: number): Record<string, string> {
  const e: Record<string, string> = {};
  for (const [k, v] of [['listeners.flow.netflow_port', f.flowNetflowPort], ['listeners.flow.ipfix_port', f.flowIpfixPort]] as const)
    if (!Number.isInteger(v) || v < 0 || v > 65535) e[k] = 'Use 0 (off) or a port from 1 to 65535.';
  if (f.flowEnabled && !num0(f.flowNetflowPort) && !num0(f.flowIpfixPort)) e['listeners.flow.ipfix_port'] = 'Turn at least one port on while flows are on.';
  if (f.flowEnabled && num0(f.flowNetflowPort) && num0(f.flowNetflowPort) === num0(f.flowIpfixPort)) e['listeners.flow.ipfix_port'] = 'Use two different ports, or 0 to turn one off.';
  const t = parseDuration(f.flowTimeout);
  if (!Number.isFinite(t) || t < 60_000 || t > 24 * 3600_000) e['listeners.flow.template_timeout'] = 'Use 1m to 24h, e.g. 30m.';
  const ies = ruleIesOf(f.flowRuleIes);
  if (ies.length > 8) e['listeners.flow.rule_id_ies'] = 'At most 8.';
  const bad = ies.find((x) => !ruleIeOk(x));
  if (bad) e['listeners.flow.rule_id_ies'] = `"${bad}" isn't <enterprise number>:<element ID>, e.g. 32473:7.`;
  const b = flowBudgetBody(f);
  if (b && (b < GIB || b > retentionBytes * 0.9)) e['storage.flow_budget_bytes'] = `Use 0 (40 % of the cap) or 1 GiB to ${Math.floor(((retentionBytes * 0.9) / GIB) * 10) / 10} GiB (90 % of the cap).`;
  return e;
}

/** "<enterprise number>:<element ID>": a 32-bit enterprise number and a 15-bit element ID. */
export function ruleIeOk(s: string): boolean {
  const m = /^(\d{1,10}):(\d{1,5})$/.exec(s);
  return !!m && Number(m[1]) <= 4294967295 && Number(m[2]) <= 32767;
}

/** A template field as the field list shows it: its IANA name, else "pen:id". */
export const ieLabel = (f: FlowTemplateField) => f.name || `${f.pen}:${f.id}`;
/** The rule_id_ies entry for a field (enterprise IEs only: no standard IE carries a rule ID). */
export const ieKey = (f: FlowTemplateField) => `${f.pen}:${f.id}`;

/** The budget's share of the cap ("40 % of the 20 GiB cap"). */
export function budgetOf(budgetBytes: number, retentionBytes: number): number {
  return budgetBytes > 0 ? budgetBytes : Math.round(retentionBytes * 0.4);
}

/** A flow record's line in the results: "10.20.0.5:51544 → 198.51.100.7:443". */
export function endpoint(addr: string | null, port: number | null): string {
  if (!addr) return '–';
  if (port === null || port === undefined) return addr;
  return addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`;
}

/** The firewall/NAT note for a result row: "denied", "deleted · NAT 192.0.2.10:40112". */
export function eventNote(f: FlowFields): string {
  const bits: string[] = [];
  if (f.fw_event) bits.push(f.fw_event);
  if (f.post_nat_src && (f.post_nat_src !== f.src || f.post_nat_src_port !== f.src_port)) bits.push(`NAT ${endpoint(f.post_nat_src, f.post_nat_src_port)}`);
  else if (f.nat_event) bits.push(f.nat_event);
  if (f.rule_id) bits.push(`rule ${f.rule_id}`);
  return bits.join(' · ');
}

/** The extras as "pen:id=hex", one each. */
export const extraText = (x: FlowExtra) => `${x.pen}:${x.id}=${x.hex}`;

/** The fields of a record for the detail view, in a readable order, the empty ones left out. */
export function detailRows(f: FlowFields): [string, string][] {
  const rows: [string, string | number | null | undefined][] = [
    ['Start', f.start],
    ['End', f.end],
    ['Event time', f.event_time],
    ['Source', endpoint(f.src, f.src_port)],
    ['Destination', endpoint(f.dst, f.dst_port)],
    ['Protocol', protoName(f.proto, f.proto_name) + (f.proto !== null && protoName(f.proto, f.proto_name) !== String(f.proto) ? ` (${f.proto})` : '')],
    ['TCP flags', f.tcp_flags],
    ['Packets', f.packets === null ? null : amountText('packets', f.packets, f.packets_scaled, { sampling: f.sampling })],
    ['Bytes', f.bytes === null ? null : amountText('bytes', f.bytes, f.bytes_scaled, { sampling: f.sampling })],
    ['Sampling', samplingText(f.sampling)],
    ['Input interface', f.in_if === null ? null : `${f.in_if}${f.in_if_name ? ` (${f.in_if_name})` : ''}`],
    ['Output interface', f.out_if === null ? null : `${f.out_if}${f.out_if_name ? ` (${f.out_if_name})` : ''}`],
    ['Observation domain', String(f.domain)],
    ['Firewall event', f.fw_event],
    ['NAT event', f.nat_event],
    ['Post-NAT source', f.post_nat_src ? endpoint(f.post_nat_src, f.post_nat_src_port) : null],
    ['Post-NAT destination', f.post_nat_dst ? endpoint(f.post_nat_dst, f.post_nat_dst_port) : null],
    ['Initiator bytes / packets', f.initiator_bytes === null ? null : `${dbytes(f.initiator_bytes)} / ${short(f.initiator_packets ?? 0)}`],
    ['Responder bytes / packets', f.responder_bytes === null ? null : `${dbytes(f.responder_bytes)} / ${short(f.responder_packets ?? 0)}`],
    ['Reverse bytes / packets', f.rev_bytes === null ? null : `${dbytes(f.rev_bytes)} / ${short(f.rev_packets ?? 0)}`],
    ['Rule ID', f.rule_id || null],
    ['ToS', f.tos ? String(f.tos) : null],
    ['AS', f.src_as || f.dst_as ? `${f.src_as ?? 0} → ${f.dst_as ?? 0}` : null],
    ['Next hop', f.next_hop || null],
    ['Times from', f.time_source === 'received' ? "Woodshed's received time (the exporter's clock was off, or the record had no time)" : 'the exporter'],
    ['Status', f.status === 'late' || f.late ? 'late: decoded when its template arrived' : f.status],
  ];
  return rows.filter((r): r is [string, string | number] => r[1] !== null && r[1] !== undefined && r[1] !== '').map(([k, v]) => [k, String(v)]);
}

// ---------- export bodies (the Export page's, and the request fixture's) ----------

/** The device choice of an export, as the Export page sends it. */
export type ExportWho = { all_devices: true } | { devices: string[] } | { group: string } | { ungrouped: true };

/**
 * "Every type" (2.0's default, SPEC §13.4): every type the server has, without filters; flows
 * unless left out, with flow_formats only when it isn't both.
 */
export function allTypesExport(who: ExportWho, from: string, to: string, allTypes: string[], withFlows: boolean, formats: FlowFormat[], xdev: string[]) {
  const types = allTypes.filter((x) => withFlows || x !== FLOW);
  const ff = flowFormatsBody(formats);
  return { ...who, from, to, types, exclude_devices: [...xdev], ...(ff && types.includes(FLOW) ? { flow_formats: ff } : {}) };
}

/** A flows-only export with the Flows tab's filters (they go in the body as top-level lists). */
export function flowExport(who: ExportWho, from: string, to: string, filters: Record<string, string[]>, formats: FlowFormat[], xdev: string[]) {
  const ff = flowFormatsBody(formats);
  return { ...who, from, to, types: [FLOW], exclude_devices: [...xdev], flow: { ...filters }, ...(ff ? { flow_formats: ff } : {}) };
}
