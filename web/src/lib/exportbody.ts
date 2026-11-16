// The export request body exactly as the Export page sends it (docs/api.md → Exports), and the
// severity parameter it shares with search. Type-only imports, so `npm test` (the request fixture)
// runs it under plain node.

import type { ExportRequest } from './api';

/** A syslog severity 0 (emerg) … 7 (debug), or "unknown" (no parseable PRI). */
export type SevKey = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 'unknown';
export const ALL_SEVS: SevKey[] = [0, 1, 2, 3, 4, 5, 6, 7, 'unknown'];

/**
 * The `severities=` value (docs/api.md → Severity filters): all selected → undefined (the
 * server's default is all), nothing selected → "none".
 */
export function sevParam(sel: SevKey[]): string | undefined {
  if (!sel.length) return 'none';
  if (ALL_SEVS.every((k) => sel.includes(k))) return undefined;
  return ALL_SEVS.filter((k) => sel.includes(k)).join(',');
}

/** Optional filters are sent only when they narrow the export (all severities = no filter). */
export function exportBody(r: ExportRequest): ExportRequest {
  const b: ExportRequest = { from: r.from, to: r.to };
  if (r.all_devices) b.all_devices = true;
  if (r.devices?.length) b.devices = r.devices;
  if (r.group) b.group = r.group;
  if (r.ungrouped) b.ungrouped = true;
  if (r.severities && r.severities.length && sevParam(r.severities)) b.severities = ALL_SEVS.filter((k) => r.severities!.includes(k));
  if (r.app?.length) b.app = r.app;
  if (r.host?.length) b.host = r.host;
  if (r.exclude) b.exclude = r.exclude;
  if (r.q || r.exclude) {
    if (r.q) b.q = r.q;
    if (r.regex) b.regex = true;
    if (r.case) b.case = true;
    if (r.syntax === 'terms') b.syntax = 'terms';
  }
  if (r.type && r.type !== 'syslog') b.type = r.type;
  if (r.facilities?.length) b.facilities = r.facilities;
  if (r.exclude_devices?.length) b.exclude_devices = r.exclude_devices;
  if (r.exclude_app?.length) b.exclude_app = r.exclude_app;
  if (r.exclude_host?.length) b.exclude_host = r.exclude_host;
  // 1.2: a syslog-only export leaves types out, so its body is exactly the 1.1 one.
  if (r.types?.length && !(r.types.length === 1 && r.types[0] === 'syslog')) b.types = [...r.types];
  return b;
}

/** The body as sent: exportBody's fields, plus the trap and flow filters as top-level lists (docs/api.md → Exports). */
export function exportJson(r: ExportRequest): Record<string, unknown> {
  const out: Record<string, unknown> = { ...exportBody(r) };
  for (const [k, v] of Object.entries(r.trap ?? {})) if (v.length) out[k] = [...v];
  for (const [k, v] of Object.entries(r.flow ?? {})) if (v.length) out[k] = [...v];
  if (r.flow_formats?.length) out.flow_formats = [...r.flow_formats];
  return out;
}
