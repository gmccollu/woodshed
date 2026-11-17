// The incident bundle (SPEC §11.3) in the UI: a moment, a window around it, the devices and the
// types, as the page URL holds them and as POST /api/exports takes them (kind "bundle"). No
// Svelte state and no imports with side effects, so `npm test` can run it under Node.

import type { BundleRequest, ExportFilters } from './api';
import type { Scope } from './scope';
import { fromInput, toInput } from './range.ts';

const SEC = 1000;
const MIN = 60 * SEC;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** Each side of the window is 0s to 7d (docs/api.md). */
export const MAX_SIDE_MS = 7 * DAY;

/** The API's defaults when before/after are left out (and the CLI's). */
export const DEFAULT_BEFORE = '30m';
export const DEFAULT_AFTER = '10m';

/**
 * The window presets (SPEC §11.3), before / after. 30 min / 10 min is the API's and the CLI's
 * default, so it's a preset too and the one a new bundle starts with.
 */
export const BUNDLE_PRESETS: { before: string; after: string; label: string }[] = [
  { before: '15m', after: '5m', label: '15 min / 5 min' },
  { before: '30m', after: '10m', label: '30 min / 10 min' },
  { before: '1h', after: '15m', label: '1 h / 15 min' },
  { before: '4h', after: '1h', label: '4 h / 1 h' },
  { before: '24h', after: '1h', label: '24 h / 1 h' },
];

// ----- durations -----

const UNIT: Record<string, number> = { ms: 1, s: SEC, m: MIN, h: HOUR, d: DAY };

/**
 * A duration as the API writes it ("15m", "1h30m", "0s", "7d"; units ms, s, m, h, d) in ms, or
 * NaN. Typing is forgiving: spaces, upper case, "min", "hours", "days" and so on, decimals
 * ("1.5h"), and a bare number is minutes ("45").
 */
export function parseDuration(text: string): number {
  let s = text.trim().toLowerCase().replace(/\s+/g, '');
  if (!s) return NaN;
  if (/^\d+(\.\d+)?$/.test(s)) return Math.round(Number(s) * MIN);
  s = s
    .replace(/(milliseconds?|msecs?)/g, 'ms')
    .replace(/(seconds?|secs?)/g, 's')
    .replace(/(minutes?|mins?)/g, 'm')
    .replace(/(hours?|hrs?)/g, 'h')
    .replace(/(days?)/g, 'd');
  if (!/^(\d+(\.\d+)?(ms|s|m|h|d))+$/.test(s)) return NaN;
  let total = 0;
  for (const m of s.matchAll(/(\d+(?:\.\d+)?)(ms|s|m|h|d)/g)) total += Number(m[1]) * UNIT[m[2]];
  return Math.round(total);
}

/** The canonical form the API echoes: "30m", "1h15m", "7d", "1d2h", "45s", "0s". */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '0s';
  let rest = Math.round(ms);
  let out = '';
  for (const [u, size] of [['d', DAY], ['h', HOUR], ['m', MIN], ['s', SEC], ['ms', 1]] as const) {
    const n = Math.floor(rest / size);
    if (n) out += `${n}${u}`;
    rest -= n * size;
  }
  return out;
}

/** In words for the page: "30 min", "1 h 15 min", "7 d", "45 s", "0 s". */
export function humanDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '0 s';
  let rest = Math.round(ms);
  const out: string[] = [];
  for (const [u, size] of [['d', DAY], ['h', HOUR], ['min', MIN], ['s', SEC], ['ms', 1]] as const) {
    const n = Math.floor(rest / size);
    if (n) out.push(`${n} ${u}`);
    rest -= n * size;
  }
  return out.join(' ');
}

/** A canonical string ("1h15m") in words ("1 h 15 min"); text that doesn't parse is shown as it is. */
export const durationWords = (s: string) => (Number.isFinite(parseDuration(s)) ? humanDuration(parseDuration(s)) : s);

/** The problem with one side of the window as typed, or "". */
export function sideError(which: 'Before' | 'After', text: string): string {
  const ms = parseDuration(text);
  if (!Number.isFinite(ms)) return `${which}: write a duration like 30m, 1h30m or 2d.`;
  if (ms > MAX_SIDE_MS) return `${which}: at most 7 days.`;
  return '';
}

// ----- the window -----

export interface BundleWindow {
  /** RFC 3339, [from, to). */
  from: string;
  to: string;
  /** at + after was later than now, so the window ends at now (the server does the same). */
  cut: boolean;
}

/**
 * [at − before, at + after), cut at now, or what's wrong with the request in words. `at` may
 * not be in the future; each side is 0s–7d and at least one is more than 0.
 */
export function bundleWindow(at: string, before: string, after: string, now = Date.now()): BundleWindow | string {
  const t = Date.parse(at);
  if (!at || Number.isNaN(t)) return 'Pick the moment the bundle is around.';
  if (t > now) return 'That moment is in the future. Pick a time up to now.';
  const e = sideError('Before', before) || sideError('After', after);
  if (e) return e;
  const b = parseDuration(before);
  const a = parseDuration(after);
  if (!b && !a) return 'Before or after has to be more than 0.';
  const end = t + a;
  const to = Math.min(end, now);
  const from = t - b;
  if (!(from < to)) return 'The window is empty: with nothing before the moment, it has to be in the past.';
  return { from: new Date(from).toISOString(), to: new Date(to).toISOString(), cut: end > now };
}

/** RFC 3339 without the ".000" milliseconds when there are none (the form the API echoes). */
export const rfc3339 = (ms: number) => new Date(ms).toISOString().replace(/\.000Z$/, 'Z');

// ----- the moment, typed in local time or UTC -----

/** An instant as the date and time fields show it (YYYY-MM-DD, HH:MM:SS), in local time or UTC. */
export function momentParts(iso: string, utc: boolean): { date: string; time: string } {
  const v = toInput(iso, utc);
  return { date: v.slice(0, 10), time: v.slice(11, 19) };
}

/**
 * The date and time fields back to an instant (RFC 3339, UTC), read as local time or UTC; ""
 * if they don't make a time. A local time a DST change skips is moved forward as the browser
 * does (02:30 on a spring-forward day is 03:30); a repeated one is its first occurrence.
 */
export function momentFromParts(date: string, time: string, utc: boolean): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return '';
  const tm = time || '00:00:00';
  if (!/^\d{2}:\d{2}(:\d{2})?$/.test(tm)) return '';
  const iso = fromInput(`${date}T${tm.length === 5 ? `${tm}:00` : tm}`, utc);
  return iso ? rfc3339(Date.parse(iso)) : '';
}

// ----- the request -----

export interface BundleForm {
  /** RFC 3339: the moment. */
  at: string;
  /** Durations as typed ("30m"); canonical in the request. */
  before: string;
  after: string;
  /** "all" means every device active in the window (active_devices). */
  scope: Scope;
  /** [] = every type with data in the window. */
  types: string[];
  /** 2.0: Leave flows out (SPEC §13.11 #6); not in the page URL. */
  noFlows?: boolean;
  /** 2.0: which flow files the zip holds; undefined = both (the default). */
  flowFormats?: ('csv' | 'ipfix')[];
}

export const newBundle = (at: string, scope: Scope = { mode: 'all', group: '', devices: [] }): BundleForm => ({
  at,
  before: DEFAULT_BEFORE,
  after: DEFAULT_AFTER,
  scope,
  types: [],
});

/**
 * POST /api/exports (and /estimate) with kind "bundle": exactly one device choice, canonical durations.
 * Leave flows out sends the other types by name (every type the server has but flows, or the chosen
 * one); flow_formats goes only with flows in and only when it isn't both.
 */
export function bundleBody(f: BundleForm, allTypes: string[] = []): BundleRequest {
  const who =
    f.scope.mode === 'devices'
      ? { devices: [...f.scope.devices] }
      : f.scope.mode === 'group'
        ? { group: f.scope.group }
        : f.scope.mode === 'ungrouped'
          ? { ungrouped: true }
          : { active_devices: true };
  const t = Date.parse(f.at);
  return {
    kind: 'bundle',
    at: Number.isNaN(t) ? f.at : rfc3339(t),
    before: formatDuration(parseDuration(f.before)),
    after: formatDuration(parseDuration(f.after)),
    ...who,
    types: f.noFlows ? (f.types.length ? f.types : allTypes).filter((t) => t !== 'flow') : [...f.types],
    ...(!f.noFlows && f.flowFormats && f.flowFormats.length === 1 && (!f.types.length || f.types.includes('flow')) ? { flow_formats: [...f.flowFormats] } : {}),
  };
}

/** The window preset these sides match, or -1 (custom). */
export function presetIndex(before: string, after: string): number {
  const b = parseDuration(before);
  const a = parseDuration(after);
  return BUNDLE_PRESETS.findIndex((p) => parseDuration(p.before) === b && parseDuration(p.after) === a);
}

// ----- in the page URL: #/events?bundle=<at>&bb=30m&ba=10m[&bdev=a,b | &bgroup=HQ | &bug=1][&btypes=trap] -----

/** The URL keys the bundle uses, so the trap filters (every other key) don't pick them up. */
export const BUNDLE_KEYS = ['bundle', 'bb', 'ba', 'bdev', 'bgroup', 'bug', 'btypes'];

export function bundleToQuery(f: BundleForm, q: URLSearchParams): void {
  q.set('bundle', f.at);
  q.set('bb', f.before);
  q.set('ba', f.after);
  if (f.scope.mode === 'devices') q.set('bdev', f.scope.devices.join(','));
  else if (f.scope.mode === 'group' && f.scope.group) q.set('bgroup', f.scope.group);
  else if (f.scope.mode === 'ungrouped') q.set('bug', '1');
  if (f.types.length) q.set('btypes', f.types.join(','));
}

export function bundleFromQuery(q: URLSearchParams): BundleForm | null {
  const at = q.get('bundle');
  if (at === null) return null;
  const list = (k: string) => (q.get(k) ?? '').split(',').map((x) => x.trim()).filter(Boolean);
  const scope: Scope = q.has('bdev')
    ? { mode: 'devices', group: '', devices: list('bdev') }
    : q.get('bgroup')
      ? { mode: 'group', group: q.get('bgroup')!, devices: [] }
      : q.get('bug') === '1'
        ? { mode: 'ungrouped', group: '', devices: [] }
        : { mode: 'all', group: '', devices: [] };
  return { at, before: q.get('bb') || DEFAULT_BEFORE, after: q.get('ba') || DEFAULT_AFTER, scope, types: list('btypes') };
}

// ----- narrowing in the preview -----

/**
 * A range picked on the histogram as the bundle's window: the moment stays where it is when it's
 * inside, and moves to the nearer edge when it isn't. Sides are whole milliseconds.
 */
export function narrowTo(at: string, from: string, to: string): { at: string; before: string; after: string } {
  const a = Date.parse(from);
  const b = Date.parse(to);
  const t = Math.min(Math.max(Date.parse(at), a), b);
  return { at: rfc3339(t), before: formatDuration(t - a), after: formatDuration(b - t) };
}

/**
 * The time under the pointer on the histogram: `frac` (0–1) across buckets that start at
 * `firstStart`, rounded down to the minute (to the second for buckets under a minute), and kept
 * inside [from, to) and not after now.
 */
export function pointTime(firstStart: string, bucketSeconds: number, buckets: number, frac: number, from: string, to: string, now = Date.now()): string {
  const span = bucketSeconds * SEC * buckets;
  const raw = Date.parse(firstStart) + Math.min(Math.max(frac, 0), 1) * span;
  const step = bucketSeconds < 60 ? SEC : MIN;
  const lo = Date.parse(from);
  const hi = Math.floor(Math.min(Date.parse(to) - 1, now) / step) * step;
  const t = Math.max(lo, Math.min(Math.floor(raw / step) * step, hi));
  return rfc3339(Math.floor(t / SEC) * SEC);
}

/** A device unchecked in the preview's list: the selection becomes the list of the rest. */
export function uncheckDevice(s: Scope, listed: string[], id: string): Scope {
  const cur = s.mode === 'devices' ? s.devices : listed;
  return { mode: 'devices', group: '', devices: cur.filter((x) => x !== id) };
}

/** A device checked in the preview's list: added to the list of chosen devices. */
export function checkDevice(s: Scope, listed: string[], id: string): Scope {
  const cur = s.mode === 'devices' ? s.devices : listed;
  return { mode: 'devices', group: '', devices: cur.includes(id) ? [...cur] : [...cur, id] };
}

// ----- words -----

const pad = (n: number) => String(n).padStart(2, '0');

/** "09:42" (with ":13" when there are seconds), and "11-13 " before it when it isn't today's date; local time or UTC. */
export function momentText(iso: string, utc: boolean, now = Date.now()): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const n = new Date(now);
  const [h, m, s, mo, da] = utc
    ? [d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds(), d.getUTCMonth() + 1, d.getUTCDate()]
    : [d.getHours(), d.getMinutes(), d.getSeconds(), d.getMonth() + 1, d.getDate()];
  const today = utc
    ? d.getUTCFullYear() === n.getUTCFullYear() && d.getUTCMonth() === n.getUTCMonth() && d.getUTCDate() === n.getUTCDate()
    : d.toDateString() === n.toDateString();
  return `${today ? '' : `${pad(mo)}-${pad(da)} `}${pad(h)}:${pad(m)}${s ? `:${pad(s)}` : ''}${utc ? ' UTC' : ''}`;
}

/** "30 min before, 10 min after" ("nothing before, …" for 0s). */
export function sidesText(before: string, after: string): string {
  const b = parseDuration(before);
  const a = parseDuration(after);
  const side = (ms: number, w: string, raw: string) => (!Number.isFinite(ms) ? `${raw} ${w}` : ms ? `${humanDuration(ms)} ${w}` : `nothing ${w}`);
  return `${side(b, 'before', before)}, ${side(a, 'after', after)}`;
}

/** "Bundle around 09:42 UTC, 30 min before, 10 min after": an export list entry, or the preview's title. */
export function bundleTitle(at: string, before: string, after: string, utc: boolean, now = Date.now()): string {
  return `Bundle around ${momentText(at, utc, now)}, ${sidesText(before, after)}`;
}

const TYPE_WORDS: Record<string, string> = { syslog: 'syslog', trap: 'SNMP traps', poll: 'SNMP polls', flow: 'flows' };

/** "every type with data", "syslog", "SNMP traps", "syslog and SNMP traps". */
export function typesText(types: string[] | undefined): string {
  if (!types?.length) return 'every type with data';
  const w = types.map((t) => TYPE_WORDS[t] ?? t);
  return w.length === 1 ? w[0] : `${w.slice(0, -1).join(', ')} and ${w[w.length - 1]}`;
}

/** Whether an export list entry is a bundle. */
export const isBundle = (f: ExportFilters | undefined) => f?.kind === 'bundle';
