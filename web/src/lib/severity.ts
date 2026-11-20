// Syslog severities (RFC 5424 §6.2.1). The API sends 0–7, or null when the message
// had no parseable PRI. Anything else outside 0–7 is also treated as "unknown",
// defensively.

import type { DevicePatch, SeverityName } from './api';

export const SEVERITIES = [
  { n: 0, short: 'emerg', name: 'Emergency' },
  { n: 1, short: 'alert', name: 'Alert' },
  { n: 2, short: 'crit', name: 'Critical' },
  { n: 3, short: 'err', name: 'Error' },
  { n: 4, short: 'warn', name: 'Warning' },
  { n: 5, short: 'notice', name: 'Notice' },
  { n: 6, short: 'info', name: 'Informational' },
  { n: 7, short: 'debug', name: 'Debug' },
] as const;

export function isKnown(sev: number | null | undefined): sev is number {
  return typeof sev === 'number' && Number.isInteger(sev) && sev >= 0 && sev <= 7;
}

export function sevLabel(sev: number | null | undefined): string {
  return isKnown(sev) ? SEVERITIES[sev].short : 'unknown';
}

export function sevClass(sev: number | null | undefined): string {
  return isKnown(sev) ? `sev-${sev}` : 'sev-u';
}

// ---- The severity filter (2.1, SPEC §13.10 decision 86) ----
// Settings holds the default (syslog.min_severity), each device's page its own setting
// (PATCH /api/devices/{id} min_severity, "default" to follow Settings). A level stores that
// severity and more severe ones; "debug" stores everything. Messages without a PRI are
// always stored, and traps, polls and flows aren't affected. Type-only imports, so the
// request fixture test can load this file under node.

/** The API's names, most severe first (warning, not warn). */
const NAMES: readonly SeverityName[] = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'];

/** The choices, from storing everything to the narrowest. */
export const FILTER_LEVELS: readonly SeverityName[] = [...NAMES].reverse();

/** What a level stores: "everything", "info and above", "emerg only" (the server's wording). */
export function filterPhrase(level: string | undefined): string {
  if (!level || level === 'debug') return 'everything';
  if (level === 'emerg') return 'emerg only';
  return `${level} and above`;
}

/** The severities a level leaves out, most severe first. */
export function leftOut(level: string | undefined): SeverityName[] {
  const n = NAMES.indexOf((level ?? 'debug') as SeverityName);
  return n < 0 ? [] : NAMES.slice(n + 1);
}

/** The select's label for a level: "Info and above (leaves out debug)". */
export function filterChoice(level: SeverityName): string {
  const p = filterPhrase(level);
  const out = leftOut(level);
  const cap = p[0].toUpperCase() + p.slice(1);
  if (out.length === 0) return `${cap} (debug and above)`;
  const list = out.length > 3 ? `${out[0]} to debug` : out.length === 1 ? out[0] : `${out.slice(0, -1).join(', ')} and ${out[out.length - 1]}`;
  return `${cap} (leaves out ${list})`;
}

/** Counts by severity, least severe first ("12,345 debug, 2 info"). */
export function countsText(by: Record<string, number> | undefined, fmt: (n: number) => string): string {
  return FILTER_LEVELS.filter((s) => (by?.[s] ?? 0) > 0)
    .map((s) => `${fmt(by![s])} ${s}`)
    .join(', ');
}

/** The device page's request body: its own level, or "default" to follow Settings. */
export function severityPatch(choice: SeverityName | 'default'): DevicePatch {
  return { min_severity: choice };
}

/** Settings → Storage's syslog object: the default for every device without its own. */
export function syslogSettingsBody(level: string): { min_severity: string } {
  return { min_severity: level };
}
