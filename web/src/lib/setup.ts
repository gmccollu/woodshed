// The Set up a device page (SPEC §13.5, docs/api.md "Setup helper"): the families the server
// offers, the choices form, and the request body it sends. Pure, no Svelte state: the request
// fixture (fixtures/ui-requests.ts) builds its bodies with snippetBody under plain node.

export type What = 'syslog' | 'trap' | 'poll' | 'flow';
export type Verification = 'tested' | 'lab_checked' | 'reference';
export type Choice = 'source_interface' | 'interface' | 'severity' | 'facility' | 'v3_user' | 'auth' | 'priv' | 'agent_port';

/** GET /api/setup/families, one entry. */
export interface SetupFamily {
  id: string;
  label: string;
  what: What[];
  verification: Verification;
  checked_on?: string;
  reference: string;
  transports: Partial<Record<What, string[]>>;
  choices: Partial<Record<What, Choice[]>>;
  notes: string[];
}

/** POST /api/setup/snippet body. Empty choices are left out (the server's defaults). */
export interface SnippetBody {
  family: string;
  what: What;
  transport?: string;
  address?: string;
  source_interface?: string;
  interface?: string;
  severity?: string;
  facility?: string;
  v3_user?: string;
  auth?: string;
  priv?: string;
  agent_port?: number;
}

export interface SnippetPart {
  kind: 'file' | 'command' | 'cli' | 'steps';
  path: string;
  title: string;
  text: string;
}

/** POST /api/setup/snippet response. */
export interface Snippet {
  family: string;
  what: What;
  transport: string;
  address: string;
  verification: Verification;
  checked_on?: string;
  reference: string;
  does: string;
  text: string;
  parts: SnippetPart[];
  notes: string[];
  check: string;
  placeholders: string[];
  addresses: string[];
}

export const WHAT_LABEL: Record<What, string> = { syslog: 'Syslog', trap: 'SNMP traps', poll: 'SNMP polling', flow: 'Flows' };

export const TRANSPORT_LABEL: Record<string, string> = {
  udp: 'UDP',
  tcp: 'TCP',
  tls: 'TLS',
  v2c: 'SNMPv2c',
  v3: 'SNMPv3',
  v9: 'flow v9 (RFC 3954)',
  ipfix: 'IPFIX (RFC 7011)',
};

export const SEVERITIES: { id: string; label: string }[] = [
  { id: 'emerg', label: 'Emergency (0)' },
  { id: 'alert', label: 'Alert (1)' },
  { id: 'crit', label: 'Critical (2)' },
  { id: 'err', label: 'Error (3)' },
  { id: 'warning', label: 'Warning (4)' },
  { id: 'notice', label: 'Notice (5)' },
  { id: 'info', label: 'Informational (6)' },
  { id: 'debug', label: 'Debug (7)' },
];

export const FACILITIES = ['local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'];
export const AUTHS: { id: string; label: string }[] = [
  { id: 'sha-256', label: 'SHA-256' },
  { id: 'sha', label: 'SHA-1' },
];
export const PRIVS: { id: string; label: string }[] = [{ id: 'aes-128', label: 'AES-128' }];

export const VERIFICATION_LABEL: Record<Verification, string> = { tested: 'Tested', lab_checked: 'Lab-checked', reference: 'Reference only' };

/** What each level means, next to the badge. */
export function verificationText(v: Verification, checkedOn = ''): string {
  if (v === 'tested') return 'CI applies this snippet to the real tool against a running Woodshed and checks that the data arrives.';
  if (v === 'lab_checked') return `Applied by hand on lab equipment${checkedOn ? ` on ${checkedOn}` : ''}, not in CI.`;
  return "Reference only: not tested on a device; check your device's documentation.";
}

/** The page's form. Strings throughout, as the inputs hold them. */
export interface SetupForm {
  family: string;
  what: What;
  transport: string;
  address: string;
  sourceInterface: string;
  iface: string;
  severity: string;
  facility: string;
  v3User: string;
  auth: string;
  priv: string;
  agentPort: string;
}

export function newSetupForm(f: SetupFamily, what?: What): SetupForm {
  const w = what && f.what.includes(what) ? what : f.what[0];
  return {
    family: f.id,
    what: w,
    transport: f.transports[w]?.[0] ?? '',
    address: '',
    sourceInterface: '',
    iface: '',
    severity: 'info',
    facility: '',
    v3User: '',
    auth: 'sha-256',
    priv: 'aes-128',
    agentPort: '',
  };
}

/** The choices that apply to the form's family, data type and transport (the v3 ones only with v3). */
export function activeChoices(f: SetupFamily | undefined, form: SetupForm): Choice[] {
  const cs = f?.choices[form.what] ?? [];
  return cs.filter((c) => form.transport === 'v3' || !['v3_user', 'auth', 'priv'].includes(c));
}

/** The request body: only the choices that apply, and only when set. */
export function snippetBody(f: SetupFamily | undefined, form: SetupForm): SnippetBody {
  const b: SnippetBody = { family: form.family, what: form.what };
  if (form.transport) b.transport = form.transport;
  if (form.address.trim()) b.address = form.address.trim();
  const on = new Set(activeChoices(f, form));
  if (on.has('source_interface') && form.sourceInterface.trim()) b.source_interface = form.sourceInterface.trim();
  if (on.has('interface') && form.iface.trim()) b.interface = form.iface.trim();
  if (on.has('severity') && form.severity) b.severity = form.severity;
  if (on.has('facility') && form.facility) b.facility = form.facility;
  if (on.has('v3_user') && form.v3User.trim()) b.v3_user = form.v3User.trim();
  if (on.has('auth') && form.auth) b.auth = form.auth;
  if (on.has('priv') && form.priv) b.priv = form.priv;
  if (on.has('agent_port') && form.agentPort.trim()) b.agent_port = Number(form.agentPort.trim());
  return b;
}

/** The form's state in the page's URL (#/device-setup?family=…&what=…), so a link opens it. */
export function formQuery(form: SetupForm): string {
  const p = new URLSearchParams({ family: form.family, what: form.what, transport: form.transport });
  return p.toString();
}
