// The UI's request bodies for the shared fixture (fixtures/ui-requests.json), built with the same
// functions the forms use. `npm test` checks the JSON equals what these build, so a form change
// that changes a body fails until the fixture (and the Go test that replays it against a real
// server) is updated. Pure, no Svelte state: it runs under plain node.
import { newPollForm, pollSettingsBody, pollSettingsForm, pollTargetBody, type PollSettings, type PollTarget, type PollTargetInput } from '../poll.ts';
import { userBody } from '../traps.ts';
import { newSetupForm, snippetBody, type SetupFamily } from '../setup.ts';

/** Placeholders the replay substitutes (strings in the JSON, numbers here). */
export const AGENT_PORT = 16161;
export const AGENT_V3_PORT = 16162;
export const PLACEHOLDERS: Record<number, string> = { [AGENT_PORT]: '{agent_port}', [AGENT_V3_PORT]: '{agent_v3_port}' };

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
  return JSON.parse(JSON.stringify(b), (k, v) => (k === 'port' && PLACEHOLDERS[v] ? PLACEHOLDERS[v] : v));
}

/** The families the setup page's form needs (only the fields it reads), as GET /api/setup/families serves them. */
const SETUP_FAMILIES: SetupFamily[] = [
  { id: 'line-cli', label: '', what: ['syslog', 'trap', 'poll', 'flow'], verification: 'reference', reference: '', notes: [],
    transports: { syslog: ['udp', 'tcp', 'tls'], trap: ['v2c', 'v3'], poll: ['v2c', 'v3'], flow: ['netflow9', 'ipfix'] },
    choices: { syslog: ['source_interface', 'severity', 'facility'], trap: ['source_interface', 'v3_user', 'auth', 'priv'], poll: ['v3_user', 'auth', 'priv'], flow: ['source_interface'] } },
  { id: 'rsyslog', label: '', what: ['syslog'], verification: 'tested', reference: '', notes: [],
    transports: { syslog: ['udp', 'tcp', 'tls'] }, choices: { syslog: ['severity', 'facility'] } },
  { id: 'net-snmp', label: '', what: ['trap', 'poll'], verification: 'tested', reference: '', notes: [],
    transports: { trap: ['v2c', 'v3'], poll: ['v2c', 'v3'] },
    choices: { trap: ['v3_user', 'auth', 'priv'], poll: ['agent_port', 'v3_user', 'auth', 'priv'] } },
  { id: 'softflowd', label: '', what: ['flow'], verification: 'reference', reference: '', notes: [],
    transports: { flow: ['netflow9', 'ipfix'] }, choices: { flow: ['interface'] } },
];

/** Set up a device: the form as the user leaves it, and the body it sends. */
function setupSteps(): Step[] {
  const fam = (id: string) => SETUP_FAMILIES.find((f) => f.id === id)!;
  const rs = newSetupForm(fam('rsyslog'));
  Object.assign(rs, { transport: 'tls', severity: 'warning', facility: 'local4' });
  const trap = newSetupForm(fam('line-cli'), 'trap');
  // Switched to v3 with an interface and a user; the address picked from the list.
  Object.assign(trap, { transport: 'v3', sourceInterface: 'mgmt0', v3User: 'monitor', address: '127.0.0.1' });
  const poll = newSetupForm(fam('net-snmp'), 'poll');
  // A v2c form keeps a v3 user typed earlier, but doesn't send it.
  Object.assign(poll, { agentPort: '1161', v3User: 'left-from-v3' });
  const flow = newSetupForm(fam('softflowd'));
  Object.assign(flow, { transport: 'ipfix', iface: 'eth1' });
  return [
    { name: 'setup_snippet_rsyslog_tls', method: 'POST', path: '/api/setup/snippet', if_match: false, body: snippetBody(fam('rsyslog'), rs) },
    { name: 'setup_snippet_line_cli_trap_v3', method: 'POST', path: '/api/setup/snippet', if_match: false, body: snippetBody(fam('line-cli'), trap) },
    { name: 'setup_snippet_net_snmp_poll_v2c', method: 'POST', path: '/api/setup/snippet', if_match: false, body: snippetBody(fam('net-snmp'), poll) },
    { name: 'setup_snippet_softflowd_ipfix', method: 'POST', path: '/api/setup/snippet', if_match: false, body: snippetBody(fam('softflowd'), flow) },
  ];
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
    ...setupSteps(),
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
  'Set up a device: the body has only the choices that apply to the family, data type and transport, and only those set (the server fills in its defaults); it never carries a secret.',
];
