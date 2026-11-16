// The UI's request bodies for the shared fixture (fixtures/ui-requests.json), built with the same
// functions the forms use. `npm test` checks the JSON equals what these build, so a form change
// that changes a body fails until the fixture (and the Go test that replays it against a real
// server) is updated. Pure, no Svelte state: it runs under plain node.
import { newPollForm, pollSettingsBody, pollSettingsForm, pollTargetBody, type PollSettings, type PollTarget, type PollTargetInput } from '../poll.ts';
import { userBody } from '../traps.ts';
import { allTypesExport, flowBudgetBody, flowExport, flowListenerBody, flowSettingsForm } from '../flows.ts';
import { bundleBody, newBundle } from '../bundle.ts';
import { exportJson } from '../exportbody.ts';

/** Placeholders the replay substitutes (strings in the JSON, numbers here). */
export const AGENT_PORT = 16161;
export const AGENT_V3_PORT = 16162;
export const PLACEHOLDERS: Record<number, string> = { [AGENT_PORT]: '{agent_port}', [AGENT_V3_PORT]: '{agent_v3_port}' };
/** 2.0: the flow listener's ports in the settings step (the replay picks free ones; never 2055 or 4739). */
export const FLOW_PORT = 12055;
export const FLOW_IPFIX_PORT = 14739;
const FLOW_PORTS: Record<number, string> = { [FLOW_PORT]: '{flow_port}', [FLOW_IPFIX_PORT]: '{flow_ipfix_port}' };
/** The types a 2.0 server lists (GET /api/search/schema), in its order: "Every type" sends these. */
export const ALL_TYPES = ['syslog', 'trap', 'poll', 'flow'];

export interface Step {
  name: string;
  method: 'POST' | 'PUT' | 'DELETE';
  path: string;
  body?: unknown;
  /** A whole-object PUT: the GET the form starts from; body holds only the keys the form changed. */
  merge_get?: string;
  /** The UI sends If-Match with the ETag of the GET named here (the form reads it when it opens). */
  if_match: boolean;
  etag_get?: string;
  /** Keep the created object's id under this name: later paths and bodies say {name}. */
  capture?: string;
}

/** A target as the server returns it after a body is saved (only the fields the form reads). */
function saved(id: string, b: PollTargetInput, prev: PollTarget | null = null): PollTarget {
  return {
    id,
    address: b.address,
    port: b.port ?? 161,
    device_id: b.device_id || b.address,
    enabled: b.enabled ?? true,
    version: b.version,
    // A body without a community keeps the stored one.
    community_set: b.version !== '3' && (b.community !== undefined ? b.community !== '' : !!prev?.community_set),
    v3_user: b.v3_user ?? '',
    interval_s: b.interval_s!,
    timeout_ms: b.timeout_ms!,
    retries: b.retries!,
    presets: b.presets!,
    interfaces: b.interfaces!,
    max_interfaces: b.max_interfaces!,
    pinned: b.pinned ?? [],
    custom: b.custom ?? [],
    state: {
      status: 'pending', last_attempt: null, last_ok: null, failing_since: null, backoff_s: 0, error: '', rtt_ms: null, engine_id: '',
      sys_name: '', sys_descr: '', hc_counters: false, host_resources: false, interfaces_polled: 0, interfaces_total: 0,
    },
  };
}

/** Port numbers back to their placeholders, as the JSON holds them. */
function withPlaceholders<T>(b: T): T {
  return JSON.parse(JSON.stringify(b), (k, v) =>
    k === 'port' && PLACEHOLDERS[v] ? PLACEHOLDERS[v] : (k === 'flow_port' || k === 'ipfix_port') && FLOW_PORTS[v] ? FLOW_PORTS[v] : v,
  );
}

export function buildSteps(): Step[] {
  const user = { name: 'monitor', auth: 'sha-256', priv: 'aes-128', keyExt: 'draft', engineIds: [] as string[] } as const;
  // Settings → Polling: the user changes every default (the form sends the whole poll object).
  const pf = pollSettingsForm(undefined);
  Object.assign(pf, { pollInterval: 30, pollTimeoutMs: 1500, pollRetries: 2, pollConcurrency: 16, pollMaxIf: 32, pollMaxTargets: 100 });
  const defaults: PollSettings = pollSettingsBody(pf);

  // Devices → Add polling (the form opens with the defaults just saved).
  const v2 = newPollForm(null, defaults, '127.0.0.1', '127.0.0.1');
  Object.assign(v2, { port: AGENT_PORT, version: '2c', community: 'fixture-community' });
  const v2body = pollTargetBody(v2, null);
  const v3 = newPollForm(null, defaults, '127.0.0.1', '127.0.0.1');
  Object.assign(v3, { port: AGENT_V3_PORT, version: '3', v3User: 'monitor', otherDevice: true, device: '127.0.0.2' });
  const v3body = pollTargetBody(v3, null);

  // Edit: every 60 s, one custom OID (sysUpTime.0) and one walk; the community is left empty (kept).
  const t1 = saved('{poll_id}', v2body);
  const ed = newPollForm(t1, defaults);
  ed.interval = 60;
  ed.custom = [
    { oid: '1.3.6.1.2.1.1.3.0', kind: 'scalar', label: 'uptime', max_rows: 0 },
    { oid: '1.3.6.1.2.1.2.2.1.2', kind: 'walk', label: 'ifDescr', max_rows: 128 },
  ];
  const edBody = pollTargetBody(ed, t1);

  // The device page's "Pin interfaces or raise the cap" opens the same form: pin two.
  const t2 = saved('{poll_id}', edBody, t1);
  const pin = newPollForm(t2, defaults);
  pin.pinned = 'eth1, 2';
  const pinBody = pollTargetBody(pin, t2);

  // 2.0, Settings → Flows: on, ports moved off the defaults, a 45 min template timeout, a rule-ID IE (typed, then
  // one added with "Use as rule ID"), and a 2 GiB budget.
  const ff = flowSettingsForm(undefined, 0);
  Object.assign(ff, { flowEnabled: true, flowPort: FLOW_PORT, flowIpfixPort: FLOW_IPFIX_PORT, flowTimeout: '45 min', flowRuleIes: '32473:7\n32473:9', flowBudgetGiB: 2 });
  const flowSettings = { listeners: { flow: flowListenerBody(ff) }, storage: { flow_budget_bytes: flowBudgetBody(ff) } };

  // 2.0, Export: "Every type" (the default) for one device and an hour, with flows and with Leave flows out; a
  // flows-only export from the Flows tab's "Export these results", CSV only. Bundles: IPFIX only, and flows left out.
  const dev = { devices: ['127.0.0.1'] };
  const from = '2026-11-16T09:00:00Z';
  const to = '2026-11-16T10:00:00Z';
  const all = exportJson(allTypesExport(dev, from, to, ALL_TYPES, true, ['csv', 'ipfix'], []));
  const allNoFlows = exportJson(allTypesExport(dev, from, to, ALL_TYPES, false, ['csv', 'ipfix'], []));
  const flowOnly = exportJson(flowExport(dev, from, to, { proto: ['tcp'], dst_port: ['443'], fw_event: ['denied'] }, ['csv'], []));
  const b = { ...newBundle('{at}', { mode: 'devices', group: '', devices: ['127.0.0.1'] }) };
  const bundleIpfix = bundleBody({ ...b, flowFormats: ['ipfix'] }, ALL_TYPES);
  const bundleNoFlows = bundleBody({ ...b, noFlows: true }, ALL_TYPES);

  return [
    { name: 'snmp_user_add', method: 'POST', path: '/api/snmp/users', if_match: false,
      body: userBody({ ...user, authPass: 'fixture-auth-pass', privPass: 'fixture-priv-pass' }) },
    { name: 'snmp_user_edit_keep_passphrases', method: 'PUT', path: '/api/snmp/users/monitor', if_match: false,
      body: userBody({ ...user, authPass: '', privPass: '' }) },
    { name: 'settings_poll_save', method: 'PUT', path: '/api/settings', merge_get: '/api/settings', if_match: true, etag_get: '/api/settings',
      body: { poll: defaults } },
    { name: 'poll_add_v2c', method: 'POST', path: '/api/poll/targets', if_match: false, capture: 'poll_id', body: withPlaceholders(v2body) },
    { name: 'poll_add_v3', method: 'POST', path: '/api/poll/targets', if_match: false, capture: 'poll_v3_id', body: withPlaceholders(v3body) },
    { name: 'poll_edit', method: 'PUT', path: '/api/poll/targets/{poll_id}', if_match: true, etag_get: '/api/poll/targets/{poll_id}',
      body: withPlaceholders(edBody) },
    { name: 'poll_test_body', method: 'POST', path: '/api/poll/test', if_match: false, body: withPlaceholders(v2body) },
    { name: 'poll_test_id', method: 'POST', path: '/api/poll/test', if_match: false, body: { id: '{poll_id}' } },
    { name: 'poll_pin', method: 'PUT', path: '/api/poll/targets/{poll_id}', if_match: true, etag_get: '/api/poll/targets/{poll_id}',
      body: withPlaceholders(pinBody) },
    { name: 'poll_delete_v3', method: 'DELETE', path: '/api/poll/targets/{poll_v3_id}', if_match: false },
    { name: 'poll_delete', method: 'DELETE', path: '/api/poll/targets/{poll_id}', if_match: false },
    { name: 'settings_flow_save', method: 'PUT', path: '/api/settings', merge_get: '/api/settings', if_match: true, etag_get: '/api/settings',
      body: withPlaceholders(flowSettings) },
    { name: 'export_estimate_every_type', method: 'POST', path: '/api/exports/estimate', if_match: false, body: all },
    { name: 'export_every_type', method: 'POST', path: '/api/exports', if_match: false, body: all },
    { name: 'export_estimate_leave_flows_out', method: 'POST', path: '/api/exports/estimate', if_match: false, body: allNoFlows },
    { name: 'export_flows_filtered_csv', method: 'POST', path: '/api/exports', if_match: false, body: flowOnly },
    { name: 'bundle_estimate_flows_ipfix', method: 'POST', path: '/api/exports/estimate', if_match: false, body: bundleIpfix },
    { name: 'bundle_leave_flows_out', method: 'POST', path: '/api/exports', if_match: false, body: bundleNoFlows },
  ];
}

export const NOTES = [
  'Generated from src/lib/fixtures/ui-requests.ts (the forms\' own body builders); npm test fails if this file and the builders differ.',
  'Placeholders: {agent_port} and {agent_v3_port} are the test agents\' UDP ports (JSON strings here; substitute numbers). {poll_id} and {poll_v3_id} are the ids returned by the steps with "capture".',
  'if_match: the UI sends If-Match with the ETag from GET etag_get (the forms read it when they open).',
  'Settings: the form PUTs the WHOLE settings object, rebuilt from GET /api/settings (fromForm(toForm(GET)) with the edits); body here is only the changed key ("poll"), to be deep-merged into the GET result (objects merge, arrays and scalars replace). The rebuild also drops read-only keys the GET returns (listeners.tls.password_set) and sends listeners.snmp.communities as their #hash8 values.',
  'Poll target bodies carry every field (the form fills the Settings defaults in when it opens); community is sent only when typed, or on a new target; an edit that leaves it empty omits it (kept). pinned (SPEC §12.11 #3) is always sent, [] when none.',
  'SNMP user: key_ext is "draft" unless priv is aes-192 or aes-256 (the form\'s choice is sent only then); empty passphrases are omitted (kept).',
  'Test poll of an edited target that keeps its stored community is sent as {"id": …} (the UI can\'t resend a community it never sees).',
  '2.0 flows: {flow_port} and {flow_ipfix_port} are two free UDP ports the replay picks (never 2055 or 4739); the settings step turns the flow listener on there. Export steps name device 127.0.0.1 and a fixed past hour; bundle steps\' at is {at} (the replay substitutes now minus 30 min, RFC 3339 UTC); "Every type" lists the types a 2.0 server has (syslog, trap, poll, flow), and Leave flows out lists them without flow. flow_formats is sent only when it isn\'t both; flow filters are top-level lists like the trap filters.',
];
