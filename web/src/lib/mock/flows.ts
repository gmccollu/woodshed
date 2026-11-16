// Flows for mock mode (docs/api.md → 2.0): deterministic flow records from three exporters, and
// the routes the UI reads them through (search and the summary with type=flow, /api/flows,
// /api/flows/top, /api/flows/timeline, /api/flows/templates). Record i is at i × FLOW_STEP and is a
// function of i alone, so every request over the same window reads the same records.
//
// The exporters (addresses are made up; public ones are RFC 5737 documentation addresses):
//   edge-fw-01 (10.1.0.1)    an event-style firewall over IPFIX, domain 1, unsampled: created, update,
//                            deleted (with initiator and responder totals) and denied events, NAT to
//                            192.0.2.10, a rule ID in an enterprise IE (32473:7)
//   core-sw-01 (10.1.0.10)   flow v9, source ID 256, sampled 1 in 1,000, interface names from options data
//   branch-fw-08 (10.8.0.1)  IPFIX biflows (RFC 5103 reverse counters), domain 1 unsampled and domain 2
//                            with no sampling information (scaled sums are lower bounds)
// URL parameters: mock_flows=0 (no flows and the listener off), mock_flow_partial=1 (each top-N and
// summary answers half the window first, then the rest with the cursor), mock_flow_huge=1 (the export
// estimate counts every record as 500, as a busy exporter would: the 4 h / 1 GB rule and the
// 20-million cap), mock_flow_banners=1 (the flow_budget, flow_templates and flow_clock banners).

import type { FieldDescriptor } from '../api';
import type { FlowFields, FlowResult, FlowState, FlowTemplates, FlowTopRow } from '../flows';
import { PROTO_NAMES } from '../flows';

const P = new URLSearchParams(location.search);
const MIN = 60_000;
const H = 60 * MIN;
const DAY = 24 * H;
export const FLOW_STEP = 2_000;
export const FLOW_DAYS = 10;
const ON = P.get('mock_flows') !== '0';

export const flowMock = {
  on: ON,
  partial: P.get('mock_flow_partial') === '1',
  huge: P.get('mock_flow_huge') === '1',
  banners: P.get('mock_flow_banners') === '1',
};

export const flowDefaults = () => ({ enabled: ON, addr: '0.0.0.0', flow_port: 2055, ipfix_port: 4739, template_timeout: '30m', rule_id_ies: ['32473:7'] });

export const FLOW_EXPORTERS = ['10.1.0.1', '10.1.0.10', '10.8.0.1'];

function hash(n: number, salt = 0): number {
  let h = (2166136261 ^ salt) >>> 0;
  for (let k = 0; k < 4; k++) {
    h ^= (n >>> (k * 8)) & 255;
    h = Math.imul(h, 16777619) >>> 0;
  }
  h ^= h >>> 13;
  h = Math.imul(h, 0x5bd1e995) >>> 0;
  return (h ^ (h >>> 15)) >>> 0;
}
const frac = (n: number, salt: number) => hash(n, salt) / 4294967296;
const pick = <T>(xs: readonly T[], n: number, salt: number) => xs[hash(n, salt) % xs.length];
/** A skewed pick: the first values come up far more often (top talkers stand out). */
const skew = <T>(xs: readonly T[], n: number, salt: number) => xs[Math.min(xs.length - 1, Math.floor(xs.length * frac(n, salt) ** 2.4))];

const INSIDE = ['10.20.0.5', '10.20.0.9', '10.20.1.17', '10.20.0.44', '10.20.2.8', '10.20.3.30', '10.20.0.71', '10.20.4.2'];
const SERVERS = ['198.51.100.7', '192.0.2.53', '203.0.113.80', '198.51.100.140', '192.0.2.200', '203.0.113.12'];
const SERVICES: [number, number][] = [[6, 443], [17, 53], [6, 443], [6, 22], [6, 80], [17, 123], [6, 443], [6, 3389], [1, 0]];
const DENIED_SRC = ['203.0.113.50', '198.51.100.23', '203.0.113.99', '192.0.2.171'];
const DENIED_PORTS = [23, 445, 3389, 23, 1433, 22];
const RULES = ['1042', '1107', '2001'];
const IFNAMES: Record<number, string> = { 1: 'eth1', 2: 'eth2', 3: 'eth3', 12: 'port12', 13: 'port13' };

export interface StoredFlow {
  i: number;
  ms: number;
  device: string;
  f: FlowFields;
}

function nullFields(): Omit<FlowFields, 'start' | 'end' | 'sampling' | 'domain' | 'time_source' | 'status' | 'extras' | 'rule_id'> {
  return {
    src: null, src_port: null, dst: null, dst_port: null, proto: null, tcp_flags: null, packets: null, bytes: null,
    packets_scaled: null, bytes_scaled: null, in_if: null, in_if_name: null, out_if: null, out_if_name: null,
    fw_event: null, nat_event: null, event_time: null, post_nat_src: null, post_nat_src_port: null, post_nat_dst: null, post_nat_dst_port: null,
    initiator_bytes: null, responder_bytes: null, initiator_packets: null, responder_packets: null, rev_bytes: null, rev_packets: null,
  };
}

const iso = (ms: number) => new Date(ms).toISOString();
const hex = (n: number, bytes: number) => n.toString(16).padStart(bytes * 2, '0');

/** Record i: which exporter, and every column as that exporter would send it. */
export function flowAt(i: number): StoredFlow {
  const ms = i * FLOW_STEP + (hash(i, 9) % FLOW_STEP);
  const r = hash(i, 1) % 10;
  const device = r < 5 ? '10.1.0.1' : r < 8 ? '10.1.0.10' : '10.8.0.1';
  const [proto, dport] = skew(SERVICES, i, 2);
  const src = skew(INSIDE, i, 3);
  const dst = skew(SERVERS, i, 4);
  const sport = 32768 + (hash(i, 5) % 28000);
  const dur = proto === 17 ? 200 + (hash(i, 6) % 2000) : 1000 + (hash(i, 6) % 55_000);
  const pk = 2 + Math.round(400 * frac(i, 7) ** 3);
  const by = pk * (60 + (hash(i, 8) % 1400));
  const flags = proto === 6 ? pick(['SAPF', 'SAF', 'SAPF', 'SR', 'SAPRF'], i, 10) : null;
  const seq = { pen: 32473, id: 1, hex: `${hex(i % 65536, 2)}${hex(hash(i, 11) % 65536, 2)}` };
  const base = { ...nullFields(), start: iso(ms - dur), end: iso(ms), time_source: 'exporter', status: (hash(i, 12) % 97 === 0 ? 'late' : 'ok') as FlowFields['status'] };
  if (device === '10.1.0.1') {
    // The event-style firewall: one record per event; denied ones carry only an event time.
    const ev = hash(i, 13) % 20;
    if (ev < 3) {
      const ds = skew(DENIED_SRC, i, 14);
      const dp = pick(DENIED_PORTS, i, 15);
      return {
        i, ms, device,
        f: {
          ...base, start: iso(ms), end: iso(ms), event_time: iso(ms), src: ds, src_port: 40000 + (hash(i, 16) % 20000), dst: '192.0.2.10', dst_port: dp, proto: 6,
          in_if: 1, in_if_name: 'eth1', out_if: 3, out_if_name: 'eth3', fw_event: 'denied', rule_id: RULES[2], sampling: 1, domain: 1,
          extras: [{ pen: 32473, id: 7, hex: hex(Number(RULES[2]), 4) }, seq],
        },
      };
    }
    const fw = ev < 11 ? 'created' : ev < 13 ? 'update' : 'deleted';
    const natp = 40000 + (hash(i, 17) % 9000);
    const ini = fw === 'deleted' ? by : null;
    const rule = RULES[hash(i, 18) % 2];
    return {
      i, ms, device,
      f: {
        ...base, start: fw === 'created' ? iso(ms) : base.start, end: iso(ms), event_time: iso(ms), src, src_port: sport, dst, dst_port: dport, proto,
        in_if: 3, in_if_name: 'eth3', out_if: 1, out_if_name: 'eth1', fw_event: fw, nat_event: fw === 'created' ? 'nat44_session_create' : fw === 'deleted' ? 'nat44_session_delete' : null,
        post_nat_src: '192.0.2.10', post_nat_src_port: natp, post_nat_dst: dst, post_nat_dst_port: dport,
        initiator_bytes: ini, responder_bytes: ini === null ? null : Math.round(ini * 3.4), initiator_packets: ini === null ? null : pk, responder_packets: ini === null ? null : Math.round(pk * 2.6),
        rule_id: rule, sampling: 1, domain: 1, extras: [{ pen: 32473, id: 7, hex: hex(Number(rule), 4) }, seq],
      },
    };
  }
  if (device === '10.1.0.10') {
    const inIf = pick([12, 13], i, 19);
    return {
      i, ms, device,
      f: {
        ...base, src, src_port: sport, dst, dst_port: dport, proto, tcp_flags: flags, packets: pk, bytes: by, sampling: 1000,
        packets_scaled: pk * 1000, bytes_scaled: by * 1000, in_if: inIf, in_if_name: IFNAMES[inIf], out_if: 2, out_if_name: IFNAMES[2],
        domain: 256, rule_id: '', tos: 0, next_hop: '10.1.0.2', extras: [seq],
      },
    };
  }
  // branch-fw-08: biflows; domain 2 has no sampling information.
  const dom = hash(i, 20) % 4 === 0 ? 2 : 1;
  return {
    i, ms, device,
    f: {
      ...base, src: src.replace('10.20.', '10.80.'), src_port: sport, dst, dst_port: dport, proto, tcp_flags: flags, packets: pk, bytes: by,
      rev_packets: Math.round(pk * 1.8), rev_bytes: Math.round(by * 5.2), sampling: dom === 2 ? 0 : 1,
      packets_scaled: dom === 2 ? null : pk, bytes_scaled: dom === 2 ? null : by, in_if: 1, in_if_name: 'eth1', out_if: 2, out_if_name: 'eth2',
      domain: dom, rule_id: '', extras: [seq],
    },
  };
}

export const flowResult = (s: StoredFlow): FlowResult => ({
  received: iso(s.ms + 40),
  device_id: s.device,
  type: 'flow',
  ref: `f${s.i}`,
  fields: { ...s.f, proto_name: s.f.proto === null ? undefined : (PROTO_NAMES[s.f.proto] ?? String(s.f.proto)), late: s.f.status === 'late' },
});

/** The record indexes whose flow end can fall in [from, to), oldest kept FLOW_DAYS. */
export function flowRange(from: number, to: number, now: number): { lo: number; hi: number } {
  if (!ON) return { lo: 1, hi: 0 };
  const first = Math.ceil((now - FLOW_DAYS * DAY) / FLOW_STEP);
  return { lo: Math.max(first, Math.floor(from / FLOW_STEP) - 1), hi: Math.min(Math.floor(now / FLOW_STEP) - 1, Math.floor(to / FLOW_STEP)) };
}

// ---------- the filter ----------

const FILTER_PARAMS = ['src', 'dst', 'ip', 'ip_any', 'src_port', 'dst_port', 'port', 'proto', 'in_if', 'out_if', 'domain', 'tcp_flags', 'sampled', 'status',
  'fw_event', 'nat_event', 'post_nat_src', 'post_nat_dst', 'post_nat_ip', 'post_nat_src_port', 'post_nat_dst_port', 'rule_id'];
const EXCLUDES = ['src', 'dst', 'ip', 'src_port', 'dst_port', 'port', 'proto', 'in_if', 'out_if', 'post_nat_src', 'post_nat_dst', 'post_nat_ip', 'rule_id'];
export const FLOW_ONLY_PARAMS = [...FILTER_PARAMS, ...EXCLUDES.map((k) => `exclude_${k}`)];

const v4n = (s: string) => s.split('.').reduce((a, x) => a * 256 + Number(x), 0);
function addrMatch(pats: string[], a: string | null): boolean {
  if (!a) return false;
  return pats.some((p) => {
    const [base, len] = p.split('/');
    if (len === undefined) return base.toLowerCase() === a.toLowerCase();
    if (a.includes(':') || base.includes(':')) return a.toLowerCase().startsWith(base.toLowerCase().replace(/::$/, ':'));
    const bits = Number(len);
    const mask = bits === 0 ? 0 : 2 ** 32 - 2 ** (32 - bits);
    return (v4n(a) & mask) >>> 0 === (v4n(base) & mask) >>> 0;
  });
}
function portMatch(pats: string[], p: number | null): boolean {
  if (p === null) return false;
  return pats.some((x) => {
    const [a, b] = x.split('-').map(Number);
    return p >= a && p <= (b ?? a);
  });
}
const PROTO_NUM: Record<string, number> = Object.fromEntries(Object.entries(PROTO_NAMES).map(([n, s]) => [s, Number(n)]));
const FLAG_LETTER: Record<string, string> = { fin: 'F', syn: 'S', rst: 'R', psh: 'P', ack: 'A', urg: 'U', ece: 'E', cwr: 'C' };

export interface FlowFilter {
  from: number;
  to: number;
  pass: (s: StoredFlow) => boolean;
}

const list = (u: URLSearchParams, k: string) => (u.get(k) ?? '').split(',').map((x) => x.trim()).filter(Boolean);
const AD = /^[0-9a-f:.]+(\/\d{1,3})?$/i;

/** The flow filter from the query, or the server's 400 message. */
export function flowFilter(u: URLSearchParams, now: number, devicePasses: (ip: string) => boolean): FlowFilter | string {
  if (u.get('q')) return 'q: flows have no text; use src, dst, ip, port or proto.';
  for (const k of ['severities', 'app', 'host', 'facilities', 'exclude_app', 'exclude_host', 'trap_oid', 'status_trap', 'pdus', 'snmp_versions'])
    if (u.get(k)) return `${k}: not a filter for flows.`;
  const from = Date.parse(u.get('from') ?? '') || now - H;
  const to = Date.parse(u.get('to') ?? '') || now;
  if (!(from < to)) return '"from" must be before "to".';
  const g: Record<string, string[]> = {};
  for (const k of FLOW_ONLY_PARAMS) {
    const v = list(u, k);
    if (v.length) g[k] = v;
  }
  for (const k of ['src', 'dst', 'ip', 'ip_any', 'post_nat_src', 'post_nat_dst', 'post_nat_ip'])
    for (const x of [...(g[k] ?? []), ...(g[`exclude_${k}`] ?? [])]) if (!AD.test(x)) return `${g[k]?.includes(x) ? k : `exclude_${k}`}: "${x}" isn't an address or prefix.`;
  for (const k of ['src_port', 'dst_port', 'port', 'post_nat_src_port', 'post_nat_dst_port'])
    for (const x of [...(g[k] ?? []), ...(g[`exclude_${k}`] ?? [])]) if (!/^\d{1,5}(-\d{1,5})?$/.test(x)) return `${k}: "${x}" isn't a port or range.`;
  const protos = (xs: string[] | undefined) => xs?.map((x) => (x.toLowerCase() in PROTO_NUM ? PROTO_NUM[x.toLowerCase()] : Number(x)));
  for (const x of [...(g.proto ?? []), ...(g.exclude_proto ?? [])]) if (!(x.toLowerCase() in PROTO_NUM) && !/^\d{1,3}$/.test(x)) return `proto: "${x}" isn't a protocol.`;
  const pr = protos(g.proto);
  const xpr = protos(g.exclude_proto);
  const lc = (xs: string[] | undefined) => xs?.map((x) => x.toLowerCase());
  const fw = lc(g.fw_event)?.map((x) => (['', 'created', 'deleted', 'denied', 'alert', 'update'][Number(x)] ?? x));
  const ifm = (pats: string[], idx: number | null, name: string | null) => pats.some((p) => p === String(idx) || p.toLowerCase() === name?.toLowerCase());
  const pass = (s: StoredFlow) => {
    const f = s.f;
    if (!devicePasses(s.device)) return false;
    const st = Date.parse(f.start);
    const en = Date.parse(f.end);
    if (!(en >= from && st < to)) return false;
    const has = (k: string, test: (v: string[]) => boolean) => !g[k] || test(g[k]);
    const not = (k: string, test: (v: string[]) => boolean) => !g[`exclude_${k}`] || !test(g[`exclude_${k}`]);
    if (!has('src', (v) => addrMatch(v, f.src)) || !not('src', (v) => addrMatch(v, f.src))) return false;
    if (!has('dst', (v) => addrMatch(v, f.dst)) || !not('dst', (v) => addrMatch(v, f.dst))) return false;
    const either = (v: string[]) => addrMatch(v, f.src) || addrMatch(v, f.dst);
    if (!has('ip', either) || !not('ip', either)) return false;
    if (!has('ip_any', (v) => either(v) || addrMatch(v, f.post_nat_src) || addrMatch(v, f.post_nat_dst))) return false;
    for (const k of ['post_nat_src', 'post_nat_dst'] as const) if (!has(k, (v) => addrMatch(v, f[k])) || !not(k, (v) => addrMatch(v, f[k]))) return false;
    const pn = (v: string[]) => addrMatch(v, f.post_nat_src) || addrMatch(v, f.post_nat_dst);
    if (!has('post_nat_ip', pn) || !not('post_nat_ip', pn)) return false;
    for (const k of ['src_port', 'dst_port'] as const) if (!has(k, (v) => portMatch(v, f[k])) || !not(k, (v) => portMatch(v, f[k]))) return false;
    const ep = (v: string[]) => portMatch(v, f.src_port) || portMatch(v, f.dst_port);
    if (!has('port', ep) || !not('port', ep)) return false;
    for (const k of ['post_nat_src_port', 'post_nat_dst_port'] as const) if (!has(k, (v) => portMatch(v, f[k]))) return false;
    if (pr && !pr.includes(f.proto ?? -1)) return false;
    if (xpr && xpr.includes(f.proto ?? -1)) return false;
    if (!has('in_if', (v) => ifm(v, f.in_if, f.in_if_name)) || !not('in_if', (v) => ifm(v, f.in_if, f.in_if_name))) return false;
    if (!has('out_if', (v) => ifm(v, f.out_if, f.out_if_name)) || !not('out_if', (v) => ifm(v, f.out_if, f.out_if_name))) return false;
    if (!has('domain', (v) => v.includes(String(f.domain)))) return false;
    if (!has('sampled', (v) => v.includes(f.sampling === 1 ? 'no' : f.sampling ? 'yes' : 'unknown'))) return false;
    if (!has('status', (v) => v.includes(f.status))) return false;
    if (!has('tcp_flags', (v) => v.some((x) => !!f.tcp_flags?.includes(FLAG_LETTER[x.toLowerCase()] ?? '?')))) return false;
    if (fw && !fw.includes(f.fw_event ?? '')) return false;
    if (!has('nat_event', (v) => lc(v)!.includes(f.nat_event ?? ''))) return false;
    if (!has('rule_id', (v) => v.includes(f.rule_id)) || !not('rule_id', (v) => v.includes(f.rule_id))) return false;
    return true;
  };
  return { from, to, pass };
}

// ---------- counting (SPEC §13.2.1: no double counting) ----------

/** What a record adds to the sums: deltas always; totals (initiator) only on the final deleted event. */
export function sums(f: FlowFields): { bytes: number; packets: number; bytesScaled: number | null; packetsScaled: number | null } {
  if (f.fw_event) {
    if (f.fw_event !== 'deleted' || f.initiator_bytes === null) return { bytes: 0, packets: 0, bytesScaled: 0, packetsScaled: 0 };
    return { bytes: f.initiator_bytes, packets: f.initiator_packets ?? 0, bytesScaled: f.initiator_bytes, packetsScaled: f.initiator_packets ?? 0 };
  }
  return { bytes: f.bytes ?? 0, packets: f.packets ?? 0, bytesScaled: f.sampling ? (f.bytes ?? 0) * f.sampling : null, packetsScaled: f.sampling ? (f.packets ?? 0) * f.sampling : null };
}
const isConn = (f: FlowFields) => !f.fw_event || f.fw_event === 'deleted' || f.fw_event === 'denied';

// ---------- the routes ----------

export interface Reply {
  status: number;
  body?: unknown;
}
const bad = (error: string): Reply => ({ status: 400, body: { error } });

function defaultBucket(rangeMs: number): number {
  const S = 1000, M = 60 * S, HR = 60 * M, D = 24 * HR;
  const table: [number, number][] = [[2 * M, 1], [10 * M, 5], [30 * M, 15], [2 * HR, 60], [10 * HR, 300], [30 * HR, 900], [5 * D, 3600], [10 * D, 7200], [30 * D, 21600], [120 * D, 86400]];
  for (const [upTo, b] of table) if (rangeMs <= upTo) return b;
  return 604800;
}

/** Newest first by flow end (records end at their own index's time, so index order is end order). */
function* walk(f: FlowFilter, now: number, asc = false): Generator<StoredFlow> {
  const { lo, hi } = flowRange(f.from, f.to, now);
  if (asc) for (let i = lo; i <= hi; i++) yield flowAt(i);
  else for (let i = hi; i >= lo; i--) yield flowAt(i);
}

const progressOf = (done: number, total: number, from: number, to: number, cutAt: number | null) => ({
  blocks_done: Math.ceil(done / 4096), blocks_total: Math.ceil(total / 4096), records_done: done, records_total: total,
  complete_from: iso(cutAt ?? from), _to: to,
});
const clean = <T extends { _to?: number }>(p: T) => {
  const { _to, ...rest } = p;
  void _to;
  return rest;
};

/** mock_flow_partial: the first answer counts only the newer half of the window (by flow end). */
function cutOf(u: URLSearchParams, f: FlowFilter): number | null {
  if (!flowMock.partial || u.get('cursor')) return null;
  return f.from + (f.to - f.from) / 2;
}

export function flowSearch(u: URLSearchParams, now: number, devicePasses: (ip: string) => boolean): Reply {
  if (u.get('context')) return bad('flows have no context.');
  const f = flowFilter(u, now, devicePasses);
  if (typeof f === 'string') return bad(f);
  const asc = u.get('order') === 'asc';
  const limit = Math.min(5000, Math.max(1, Number(u.get('limit') || 500)));
  const cur = u.get('cursor');
  const start = cur ? Number(cur.split('.')[0]) : null;
  const results: FlowResult[] = [];
  let next = '';
  let total = 0;
  for (const s of walk(f, now, asc)) {
    if (start !== null && (asc ? s.i < start : s.i > start)) continue;
    if (!f.pass(s)) continue;
    if (results.length === limit) {
      next = `${s.i}.f`;
      break;
    }
    results.push(flowResult(s));
    total++;
  }
  return { status: 200, body: { results, next_cursor: next, partial: false, elapsed_ms: 18, scanned_bytes: total * 18, scanned_files: 1, progress: clean(progressOf(1, 1, f.from, f.to, null)) } };
}

export const FLOW_SCHEMA: { type: string; label: string; default: boolean; fields: FieldDescriptor[] } = {
  type: 'flow',
  label: 'Flows',
  default: false,
  fields: [
    { key: 'device', label: 'Exporter', param: 'devices', exclude_param: 'exclude_devices', domain: null },
    { key: 'proto', label: 'Protocol', param: 'proto', exclude_param: 'exclude_proto', domain: null },
    { key: 'dst_port', label: 'Destination port', param: 'dst_port', exclude_param: 'exclude_dst_port', domain: null },
    { key: 'src_port', label: 'Source port', param: 'src_port', exclude_param: 'exclude_src_port', domain: null },
    { key: 'src', label: 'Source', param: 'src', exclude_param: 'exclude_src', domain: null },
    { key: 'dst', label: 'Destination', param: 'dst', exclude_param: 'exclude_dst', domain: null },
    { key: 'in_if', label: 'Input interface', param: 'in_if', exclude_param: 'exclude_in_if', domain: null },
    { key: 'out_if', label: 'Output interface', param: 'out_if', exclude_param: 'exclude_out_if', domain: null },
    {
      key: 'fw_event', label: 'Firewall event', param: 'fw_event', exclude_param: '',
      domain: ['created', 'deleted', 'denied', 'alert', 'update'].map((v) => ({ value: v, label: v })),
    },
    { key: 'nat_event', label: 'NAT event', param: 'nat_event', exclude_param: '', domain: null },
    { key: 'rule_id', label: 'Rule ID', param: 'rule_id', exclude_param: 'exclude_rule_id', domain: null },
    { key: 'domain', label: 'Observation domain', param: 'domain', exclude_param: '', domain: null },
    { key: 'sampled', label: 'Sampled', param: 'sampled', exclude_param: '', domain: [{ value: 'yes', label: 'sampled' }, { value: 'no', label: 'unsampled' }, { value: 'unknown', label: 'unknown' }] },
    {
      key: 'status', label: 'Status', param: 'status', exclude_param: '',
      domain: [{ value: 'ok', label: 'ok' }, { value: 'late', label: 'late' }, { value: 'no_template', label: 'waiting for a template' }, { value: 'malformed', label: 'malformed' }],
    },
  ],
};

function fieldValue(s: StoredFlow, key: string): [string, string] | null {
  const f = s.f;
  switch (key) {
    case 'device':
      return [s.device, s.device];
    case 'proto':
      return f.proto === null ? null : [String(f.proto), PROTO_NAMES[f.proto] ?? String(f.proto)];
    case 'dst_port':
    case 'src_port':
      return f[key] === null ? null : [String(f[key]), String(f[key])];
    case 'src':
    case 'dst':
    case 'fw_event':
    case 'nat_event':
      return f[key] ? [f[key]!, f[key]!] : null;
    case 'in_if':
      return f.in_if === null ? null : [String(f.in_if), f.in_if_name ? `${f.in_if} (${f.in_if_name})` : String(f.in_if)];
    case 'out_if':
      return f.out_if === null ? null : [String(f.out_if), f.out_if_name ? `${f.out_if} (${f.out_if_name})` : String(f.out_if)];
    case 'rule_id':
      return f.rule_id ? [f.rule_id, f.rule_id] : null;
    case 'domain':
      return [String(f.domain), String(f.domain)];
    case 'sampled':
      return f.sampling === 1 ? ['no', 'unsampled'] : f.sampling ? ['yes', 'sampled'] : ['unknown', 'unknown'];
    case 'status':
      return [f.status, f.status];
  }
  return null;
}

export function flowSummary(u: URLSearchParams, now: number, devicePasses: (ip: string) => boolean, devLabel: (ip: string) => string): Reply {
  const f = flowFilter(u, now, devicePasses);
  if (typeof f === 'string') return bad(f);
  const metric = u.get('metric') ?? 'flows';
  if (!['flows', 'bytes', 'packets'].includes(metric)) return bad('metric: flows, bytes or packets.');
  const fieldsArg = u.get('fields');
  const keys = FLOW_SCHEMA.fields.map((x) => x.key);
  const want = fieldsArg === null || fieldsArg === '' ? keys : fieldsArg === 'none' ? [] : fieldsArg.split(',').filter(Boolean);
  for (const k of want) if (!keys.includes(k)) return bad(`fields: unknown field "${k}".`);
  const top = u.has('top') ? Number(u.get('top')) : 10;
  const bucketMs = (u.has('bucket') ? Number(u.get('bucket')) : defaultBucket(f.to - f.from)) * 1000;
  const firstB = Math.floor(f.from / bucketMs) * bucketMs;
  const nB = Math.ceil((f.to - firstB) / bucketMs);
  if (nB > 1000) return bad(`bucket gives ${nB} buckets over this range; the limit is 1,000. Pick a larger bucket.`);
  const cut = cutOf(u, f);
  const tallies = new Map(want.map((k) => [k, { values: new Map<string, { label: string; count: number; bytes: number; scaled: number | null }>(), none: 0 }]));
  const hist = new Map<number, { count: number; bytes: number; scaled: number | null }>();
  let matched = 0;
  let total = 0;
  let done = 0;
  for (const s of walk(f, now)) {
    if (!f.pass(s)) continue;
    total++;
    const end = Date.parse(s.f.end);
    if (cut !== null && end < cut) continue;
    done++;
    matched++;
    const sm = sums(s.f);
    const b = Math.floor(Math.max(end, f.from) / bucketMs) * bucketMs;
    const h = hist.get(b) ?? { count: 0, bytes: 0, scaled: 0 };
    h.count += metric === 'bytes' ? sm.bytes : metric === 'packets' ? sm.packets : 1;
    h.bytes += sm.bytes;
    h.scaled = h.scaled === null || sm.bytesScaled === null ? null : h.scaled + sm.bytesScaled;
    hist.set(b, h);
    for (const [k, t] of tallies) {
      const v = fieldValue(s, k);
      if (!v) {
        t.none++;
        continue;
      }
      const e = t.values.get(v[0]) ?? { label: k === 'device' ? devLabel(v[0]) : v[1], count: 0, bytes: 0, scaled: 0 };
      e.count++;
      e.bytes += sm.bytes;
      e.scaled = e.scaled === null || sm.bytesScaled === null ? null : e.scaled + sm.bytesScaled;
      t.values.set(v[0], e);
    }
  }
  const buckets = [];
  for (let k = 0; k < nB; k++) {
    const st = firstB + k * bucketMs;
    const h = hist.get(st);
    const counted = cut === null || st + bucketMs > cut;
    buckets.push({ start: iso(st), count: counted ? (h?.count ?? 0) : null, approx: false, bytes: h?.bytes ?? 0, bytes_scaled: h ? h.scaled : 0 });
  }
  const fields = want.map((key) => {
    const desc = FLOW_SCHEMA.fields.find((x) => x.key === key)!;
    const t = tallies.get(key)!;
    const all = [...t.values.entries()].map(([value, e]) => ({ value, label: e.label, count: e.count, filterable: !value.includes(','), bytes: e.bytes, bytes_scaled: e.scaled }));
    all.sort((a, b) => b.count - a.count || (a.value < b.value ? -1 : 1));
    const values = desc.domain ? all : all.slice(0, top);
    const listed = values.reduce((s, v) => s + v.count, 0);
    const withValue = all.reduce((s, v) => s + v.count, 0);
    return { key, label: desc.label, values, other: withValue - listed, none: t.none, distinct: t.values.size, distinct_capped: false };
  });
  const partial = cut !== null;
  return {
    status: 200,
    body: {
      type: 'flow', from: iso(f.from), to: iso(f.to), matched, counted_from: iso(cut ?? f.from),
      histogram: { bucket_seconds: bucketMs / 1000, source: want.length || partial ? 'scan' : 'index', buckets },
      fields, next_cursor: partial ? 'fs.1' : '', partial, scanned_bytes: done * 18, scanned_files: 3, elapsed_ms: 140,
      progress: clean(progressOf(done, total, f.from, f.to, cut)),
    },
  };
}

const BYS = ['src', 'dst', 'conversation', 'dst_port', 'src_port', 'proto', 'in_if', 'out_if', 'post_nat_src', 'post_nat_dst', 'fw_event', 'rule_id'];

function keyOf(by: string, f: FlowFields): [string, string] | null {
  const pn = (p: number | null) => (p === null ? '' : (PROTO_NAMES[p] ?? String(p)));
  switch (by) {
    case 'conversation': {
      if (!f.src || !f.dst) return null;
      const [a, b] = [f.src, f.dst].sort((x, y) => (v4n(x) < v4n(y) ? -1 : 1));
      return [`${a} ↔ ${b}`, `${a} ↔ ${b}`];
    }
    case 'dst_port':
    case 'src_port':
      return f[by] === null ? null : [`${pn(f.proto)}/${f[by]}`, `${pn(f.proto)}/${f[by]}`];
    case 'proto':
      return f.proto === null ? null : [pn(f.proto), pn(f.proto)];
    case 'in_if':
      return f.in_if === null ? null : [String(f.in_if), f.in_if_name ?? String(f.in_if)];
    case 'out_if':
      return f.out_if === null ? null : [String(f.out_if), f.out_if_name ?? String(f.out_if)];
    case 'rule_id':
      return f.rule_id ? [f.rule_id, f.rule_id] : null;
    default: {
      const v = (f as unknown as Record<string, string | null>)[by];
      return v ? [v, v] : null;
    }
  }
}

export function flowTop(u: URLSearchParams, now: number, devicePasses: (ip: string) => boolean): Reply {
  const by = u.get('by') ?? 'src';
  if (!BYS.includes(by)) return bad(`by: one of ${BYS.join(', ')}.`);
  const f = flowFilter(u, now, devicePasses);
  if (typeof f === 'string') return bad(f);
  const fw = (u.get('fw_event') ?? '').toLowerCase();
  const metric = u.get('metric') || (fw === 'denied' ? 'flows' : 'bytes');
  if (!['bytes', 'packets', 'flows', 'connections'].includes(metric)) return bad('metric: bytes, packets, flows or connections.');
  const top = Math.min(100, Math.max(1, Number(u.get('top') || 10)));
  const cut = cutOf(u, f);
  type Acc = Omit<FlowTopRow, 'share'> & { conns: number; firstMs: number; lastMs: number };
  const acc = new Map<string, Acc>();
  const tot = { flows: 0, bytes: 0, packets: 0, bytes_scaled: 0 as number, packets_scaled: 0 as number, scaled_complete: true, connections: 0 };
  let total = 0;
  let done = 0;
  for (const s of walk(f, now)) {
    if (!f.pass(s)) continue;
    total++;
    if (cut !== null && Date.parse(s.f.end) < cut) continue;
    done++;
    const k = keyOf(by, s.f);
    const sm = by === 'conversation' && s.f.rev_bytes !== null
      ? { ...sums(s.f), bytes: (s.f.bytes ?? 0) + s.f.rev_bytes, packets: (s.f.packets ?? 0) + (s.f.rev_packets ?? 0) }
      : sums(s.f);
    const c = isConn(s.f) ? 1 : 0;
    tot.flows++;
    tot.connections += c;
    tot.bytes += sm.bytes;
    tot.packets += sm.packets;
    if (sm.bytesScaled === null) tot.scaled_complete = false;
    tot.bytes_scaled += sm.bytesScaled ?? sm.bytes;
    tot.packets_scaled += sm.packetsScaled ?? sm.packets;
    if (!k) continue;
    const st = Date.parse(s.f.start);
    const en = Date.parse(s.f.end);
    const a = acc.get(k[0]) ?? { key: k[0], label: k[1], flows: 0, bytes: 0, packets: 0, bytes_scaled: 0, packets_scaled: 0, scaled_lower_bound: false, first: '', last: '', conns: 0, firstMs: Infinity, lastMs: 0 };
    a.flows++;
    a.conns += c;
    a.bytes += sm.bytes;
    a.packets += sm.packets;
    a.bytes_scaled = (a.bytes_scaled ?? 0) + (sm.bytesScaled ?? sm.bytes);
    a.packets_scaled = (a.packets_scaled ?? 0) + (sm.packetsScaled ?? sm.packets);
    if (sm.bytesScaled === null) a.scaled_lower_bound = true;
    a.firstMs = Math.min(a.firstMs, st);
    a.lastMs = Math.max(a.lastMs, en);
    acc.set(k[0], a);
  }
  const val = (a: { flows: number; bytes: number; packets: number; conns?: number; connections?: number }) =>
    metric === 'flows' ? a.flows : metric === 'packets' ? a.packets : metric === 'connections' ? (a.conns ?? a.connections ?? 0) : a.bytes;
  const all = [...acc.values()].sort((x, y) => val(y) - val(x) || (x.key < y.key ? -1 : 1));
  const totalVal = val({ ...tot, conns: tot.connections }) || 1;
  const rows = all.slice(0, top).map((a) => ({
    key: a.key, label: a.label, flows: a.flows, bytes: a.bytes, packets: a.packets, connections: a.conns,
    bytes_scaled: a.bytes_scaled, packets_scaled: a.packets_scaled, scaled_lower_bound: a.scaled_lower_bound,
    share: val(a) / totalVal, first: iso(a.firstMs), last: iso(a.lastMs),
  }));
  const rest = all.slice(top);
  const partial = cut !== null;
  return {
    status: 200,
    body: {
      by, metric, from: iso(f.from), to: iso(f.to),
      total: { ...tot, bytes_scaled: tot.bytes_scaled, packets_scaled: tot.packets_scaled },
      rows,
      other: { flows: rest.reduce((s, a) => s + a.flows, 0), bytes: rest.reduce((s, a) => s + a.bytes, 0), packets: rest.reduce((s, a) => s + a.packets, 0), connections: rest.reduce((s, a) => s + a.conns, 0) },
      approx: false,
      progress: clean(progressOf(done, total, f.from, f.to, cut)),
      partial, next_cursor: partial ? 'ft.1' : '', elapsed_ms: partial ? 2000 : 320,
    },
  };
}

export function flowTimeline(u: URLSearchParams, now: number, selected: (ip: string) => boolean): Reply {
  const from = Date.parse(u.get('from') ?? '') || now - H;
  const to = Date.parse(u.get('to') ?? '') || now;
  const bucketMs = (Number(u.get('bucket')) || defaultBucket(to - from)) * 1000;
  const devs = FLOW_EXPORTERS.filter(selected);
  const per = new Map<string, Map<number, { bytes: number; scaled: number | null; flows: number }>>(devs.map((d) => [d, new Map()]));
  const { lo, hi } = flowRange(from, to, now);
  for (let i = lo; i <= hi; i++) {
    const s = flowAt(i);
    const m = per.get(s.device);
    if (!m) continue;
    const end = Date.parse(s.f.end);
    if (end < from || end >= to) continue;
    const b = Math.floor(end / bucketMs) * bucketMs;
    const sm = sums(s.f);
    const e = m.get(b) ?? { bytes: 0, scaled: 0, flows: 0 };
    e.bytes += sm.bytes;
    e.scaled = e.scaled === null || sm.bytesScaled === null ? (e.scaled ?? 0) + sm.bytes : e.scaled + sm.bytesScaled;
    e.flows++;
    m.set(b, e);
  }
  const busy = [...per.entries()].map(([d, m]) => ({ d, m, total: [...m.values()].reduce((s, e) => s + e.bytes, 0) })).sort((a, b) => b.total - a.total);
  return {
    status: 200,
    body: {
      devices: busy.slice(0, 4).map(({ d, m }) => ({
        device_id: d,
        points: [...m.entries()].sort((a, b) => a[0] - b[0]).map(([st, e]) => ({ start: iso(st), bytes: e.bytes, bytes_scaled: e.scaled, flows: e.flows })),
      })),
      more: Math.max(0, busy.length - 4),
    },
  };
}

export function flowState(now: number, budget: number, retention: number, enabled: boolean): FlowState {
  const b = budget || Math.round(retention * 0.4);
  const used = Math.round(b * 0.62);
  const ago = (ms: number) => iso(now - ms);
  return {
    enabled,
    budget: { bytes: b, used_bytes: ON ? used : 0, estimated_days: ON ? Math.round((b / (1.05 * 1024 ** 3)) * 10) / 10 : null },
    exporters: ON
      ? [
          {
            device_id: '10.1.0.1', domains: [{ id: 1, sampling: 1, templates: 3, last_template: ago(2.2 * MIN) }],
            records_per_sec: 1180.5, pending_bytes: 0,
            counts_24h: { records: 101_000_000, late: 120, no_template: 0, malformed: 0, sequence_gaps: 3, duplicates: 0 }, clock_skew_ms: 210, time_source: 'exporter',
          },
          {
            device_id: '10.1.0.10', domains: [{ id: 256, sampling: 1000, templates: 2, last_template: ago(40_000) }],
            records_per_sec: 310.2, pending_bytes: 0,
            counts_24h: { records: 26_800_000, late: 0, no_template: 0, malformed: 2, sequence_gaps: 0, duplicates: 0 }, clock_skew_ms: -40, time_source: 'exporter',
          },
          {
            device_id: '10.8.0.1', domains: [{ id: 1, sampling: 1, templates: 1, last_template: ago(4 * MIN) }, { id: 2, sampling: 0, templates: 1, last_template: ago(4 * MIN) }],
            records_per_sec: 205.9, pending_bytes: flowMock.banners ? 48_000 : 0,
            counts_24h: { records: 17_800_000, late: 4, no_template: flowMock.banners ? 312 : 0, malformed: 0, sequence_gaps: 0, duplicates: 12 },
            clock_skew_ms: flowMock.banners ? 4_020_000 : 900, time_source: flowMock.banners ? 'received' : 'exporter',
          },
        ]
      : [],
  };
}

const F = (pen: number, id: number, name: string, length: number) => ({ pen, id, name, length });
export function flowTemplates(device: string, now: number): Reply {
  const at = iso(now - 3 * MIN);
  const seqIe = F(32473, 1, '', 4);
  const t: Record<string, FlowTemplates['domains']> = {
    '10.1.0.1': [{
      id: 1,
      templates: [
        { id: 256, options: false, received: at, fields: [F(0, 8, 'sourceIPv4Address', 4), F(0, 12, 'destinationIPv4Address', 4), F(0, 7, 'sourceTransportPort', 2), F(0, 11, 'destinationTransportPort', 2), F(0, 4, 'protocolIdentifier', 1), F(0, 10, 'ingressInterface', 4), F(0, 14, 'egressInterface', 4), F(0, 233, 'firewallEvent', 1), F(0, 230, 'natEvent', 1), F(0, 225, 'postNATSourceIPv4Address', 4), F(0, 227, 'postNAPTSourceTransportPort', 2), F(0, 323, 'observationTimeMilliseconds', 8), F(0, 152, 'flowStartMilliseconds', 8), F(0, 231, 'initiatorOctets', 8), F(0, 232, 'responderOctets', 8), F(32473, 7, '', 4), seqIe] },
        { id: 257, options: false, received: at, fields: [F(0, 8, 'sourceIPv4Address', 4), F(0, 12, 'destinationIPv4Address', 4), F(0, 11, 'destinationTransportPort', 2), F(0, 4, 'protocolIdentifier', 1), F(0, 233, 'firewallEvent', 1), F(0, 323, 'observationTimeMilliseconds', 8), F(32473, 7, '', 4), seqIe] },
        { id: 258, options: true, received: at, fields: [F(0, 149, 'observationDomainId', 4), F(0, 160, 'systemInitTimeMilliseconds', 8)] },
      ],
    }],
    '10.1.0.10': [{
      id: 256,
      templates: [
        { id: 300, options: false, received: at, fields: [F(0, 8, 'sourceIPv4Address', 4), F(0, 12, 'destinationIPv4Address', 4), F(0, 7, 'sourceTransportPort', 2), F(0, 11, 'destinationTransportPort', 2), F(0, 4, 'protocolIdentifier', 1), F(0, 6, 'tcpControlBits', 1), F(0, 2, 'packetDeltaCount', 4), F(0, 1, 'octetDeltaCount', 4), F(0, 10, 'ingressInterface', 2), F(0, 14, 'egressInterface', 2), F(0, 22, 'flowStartSysUpTime', 4), F(0, 21, 'flowEndSysUpTime', 4), seqIe] },
        { id: 301, options: true, received: at, fields: [F(0, 10, 'ingressInterface', 2), F(0, 82, 'interfaceName', 16), F(0, 34, 'samplingInterval', 4), F(0, 35, 'samplingAlgorithm', 1)] },
      ],
    }],
    '10.8.0.1': [1, 2].map((d) => ({
      id: d,
      templates: [{ id: 400, options: false, received: at, fields: [F(0, 8, 'sourceIPv4Address', 4), F(0, 12, 'destinationIPv4Address', 4), F(0, 7, 'sourceTransportPort', 2), F(0, 11, 'destinationTransportPort', 2), F(0, 4, 'protocolIdentifier', 1), F(0, 1, 'octetDeltaCount', 8), F(0, 2, 'packetDeltaCount', 8), F(29305, 1, '', 8), F(29305, 2, '', 8), F(0, 152, 'flowStartMilliseconds', 8), F(0, 153, 'flowEndMilliseconds', 8), seqIe] }],
    })),
  };
  if (!device) return bad('device: required.');
  return { status: 200, body: { device_id: device, domains: ON ? (t[device] ?? []) : [] } };
}

/** Records per exporter whose flow end is in [from, to) (for device counts, active devices and estimates). */
export function flowCounts(from: number, to: number, now: number): Map<string, { n: number; bytes: number; first: number; last: number }> {
  const m = new Map<string, { n: number; bytes: number; first: number; last: number }>();
  const { lo, hi } = flowRange(from, to, now);
  if (hi < lo) return m;
  // Long windows by the exporters' shares (flowAt picks 5 : 3 : 2), so the mock never scans days of records.
  if (hi - lo > 20_000) {
    const total = hi - lo + 1;
    const first = Math.max(from, lo * FLOW_STEP);
    const last = Math.min(to, now, hi * FLOW_STEP);
    for (const [ip, share] of [['10.1.0.1', 0.5], ['10.1.0.10', 0.3], ['10.8.0.1', 0.2]] as const) {
      const n = Math.round(total * share);
      m.set(ip, { n, bytes: n * 64, first, last });
    }
    return m;
  }
  for (let i = lo; i <= hi; i++) {
    const s = flowAt(i);
    if (s.ms < from || s.ms >= to) continue;
    const e = m.get(s.device) ?? { n: 0, bytes: 0, first: s.ms, last: s.ms };
    e.n++;
    e.bytes += 64;
    e.first = Math.min(e.first, s.ms);
    e.last = Math.max(e.last, s.ms);
    m.set(s.device, e);
  }
  return m;
}

/** Every flow record stored now, per exporter (the device list's lines_by_type.flow). */
let allCache: { at: number; m: Map<string, { n: number; last: number }> } | null = null;
export function flowTotals(now: number): Map<string, { n: number; last: number }> {
  if (allCache && now - allCache.at < 30_000) return allCache.m;
  const c = flowCounts(now - FLOW_DAYS * DAY, now, now);
  const m = new Map([...c].map(([k, v]) => [k, { n: v.n, last: v.last }]));
  allCache = { at: now, m };
  return m;
}

export const FLOW_RECORD_CAP = 20_000_000;
/** The export estimate's flow part: records and bytes per device, scaled by mock_flow_huge. */
export function flowEstimate(devices: string[], from: number, to: number, now: number): { records: number; bytes: number; worst: [string, number] | null } {
  const c = flowCounts(from, to, now);
  const k = flowMock.huge ? 500 : 1;
  let records = 0;
  let worst: [string, number] | null = null;
  for (const d of devices) {
    const n = (c.get(d)?.n ?? 0) * k;
    records += n;
    if (n && (!worst || n > worst[1])) worst = [d, n];
  }
  return { records, bytes: records * 58, worst };
}

export function flowBanners(enabled: boolean, os: string): { kind: string; level: 'warn' | 'info'; action: ''; text: string }[] {
  const out: { kind: string; level: 'warn' | 'info'; action: ''; text: string }[] = [];
  if (!ON) return out;
  if (flowMock.banners) {
    out.push({ kind: 'flow_budget', level: 'info', action: '', text: 'Flows arrive at about 26 GB a day; their 8 GiB budget holds about 8 hours of them. Raise storage.flow_budget_bytes in Settings → Flows, or sample on the exporter.' });
    out.push({ kind: 'flow_templates', level: 'warn', action: '', text: "branch-fw-08 (10.8.0.1) has sent data for template 400 on domain 2 for 14 min without the template; 312 sets were stored raw. Check the exporter's template refresh (every few minutes is typical)." });
    out.push({ kind: 'flow_clock', level: 'warn', action: '', text: "branch-fw-08 (10.8.0.1)'s clock is 67 min off; its flows use the time Woodshed received them. Fix the exporter's clock (NTP)." });
  }
  if (enabled && os.startsWith('windows'))
    out.push({ kind: 'flow_firewall', level: 'warn', action: '', text: 'The Windows Firewall rule "Woodshed flows (UDP 4739)" is disabled, so exporters may be blocked. Run woodshed flow on in an administrator prompt.' });
  return out;
}
