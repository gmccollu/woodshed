// Vendor-neutral fake syslog traffic for mock mode. Hosts and IPs are made up;
// public addresses come from the RFC 5737 documentation ranges.

export type Kind = 'fw' | 'sw' | 'vpn' | 'srv' | 'ap';

export interface MockDeviceDef {
  ip: string;
  name: string;
  group: string;
  kind: Kind;
  /** Share of the traffic while the device is sending. 0 = silent. */
  weight: number;
  hidden?: boolean;
}

export const FLEET: MockDeviceDef[] = [
  { ip: '10.1.0.1', name: 'edge-fw-01', group: 'HQ', kind: 'fw', weight: 30 },
  { ip: '10.1.0.2', name: 'edge-fw-02', group: 'HQ', kind: 'fw', weight: 28 },
  { ip: '10.1.0.10', name: 'core-sw-01', group: 'HQ', kind: 'sw', weight: 4 },
  { ip: '10.1.0.11', name: 'core-sw-02', group: 'HQ', kind: 'sw', weight: 3 },
  { ip: '10.1.0.20', name: 'vpn-gw-01', group: 'HQ', kind: 'vpn', weight: 3 },
  { ip: '10.1.0.30', name: 'auth-srv-01', group: 'HQ', kind: 'srv', weight: 2 },
  { ip: '10.7.0.1', name: 'branch-fw-07', group: 'Branches', kind: 'fw', weight: 0 },
  { ip: '10.7.0.2', name: 'branch-sw-07', group: 'Branches', kind: 'sw', weight: 1 },
  { ip: '10.8.0.1', name: 'branch-fw-08', group: 'Branches', kind: 'fw', weight: 6 },
  { ip: '10.8.0.5', name: 'branch-ap-08', group: 'Branches', kind: 'ap', weight: 2 },
  { ip: '10.2.0.1', name: 'dmz-fw-01', group: 'DMZ', kind: 'fw', weight: 0 },
  { ip: '10.2.0.20', name: 'dmz-web-01', group: 'DMZ', kind: 'srv', weight: 3 },
  { ip: '192.0.2.44', name: '', group: '', kind: 'srv', weight: 1 },
  { ip: 'fd00:1::5', name: 'lab-sw-01', group: 'Lab', kind: 'sw', weight: 1, hidden: true },
];

const pick = <T>(a: readonly T[]): T => a[Math.floor(Math.random() * a.length)];
const int = (lo: number, hi: number) => lo + Math.floor(Math.random() * (hi - lo + 1));
const inside = () => `10.1.${int(1, 9)}.${int(2, 254)}`;
const outside = () => `${pick(['192.0.2', '198.51.100', '203.0.113'])}.${int(1, 254)}`;
const mac = () =>
  ['02', ...Array.from({ length: 5 }, () => int(0, 255).toString(16).padStart(2, '0'))].join(':');

type Template = [severity: number, weight: number, app: string, text: () => string];

// Messages the smoke checks need on demand (probe.emit), not by chance: they're rare in the
// random traffic. The same templates are part of that traffic too.
/** A literal line break right after the tag (seen on real hardware). */
const LEADING_BREAK: Template = [5, 2, 'scand', () => { const v = int(900, 999); return `\nscanner: future version ${v + 1}, current version ${v}`; }];
/** Multi-line output (CR/LF). */
const EMBEDDED_BREAK: Template = [6, 2, 'backup', () => `job finished\r\nfiles ${int(100, 9000)}\r\nexit status 0\r\n`];
export const SPECIAL = {
  'leading-break': { kind: 'fw', t: LEADING_BREAK },
  'embedded-break': { kind: 'srv', t: EMBEDDED_BREAK },
} as const satisfies Record<string, { kind: Kind; t: Template }>;
export type Special = keyof typeof SPECIAL;

const TEMPLATES: Record<Kind, Template[]> = {
  fw: [
    [6, 40, 'fwd', () => `conn opened tcp ${inside()}:${int(49152, 65535)} -> ${outside()}:${pick([443, 443, 80, 22, 8443])}`],
    [6, 35, 'fwd', () => `conn closed tcp ${inside()}:${int(49152, 65535)} duration 0:00:${String(int(0, 59)).padStart(2, '0')} bytes ${int(200, 900000)}`],
    [6, 10, 'fwd', () => `conn opened udp ${inside()}:${int(49152, 65535)} -> ${outside()}:53`],
    [5, 6, 'fwd', () => { const a = inside(); const p = int(49152, 65535); return `nat translation created ${a}/${p} to 203.0.113.9/${p}`; }],
    [4, 6, 'fwd', () => `deny udp ${outside()}:5353 -> 10.1.0.255:5353 by acl outside_in`],
    [4, 2, 'fwd', () => `deny tcp ${outside()}:${int(1024, 65535)} -> 10.1.0.1:23 by acl outside_in`],
    // %FAC-N-MNEMONIC tags (made up), for the Program/tag filter's prefix match (%FW-6-*).
    [6, 8, '%FW-6-302013', () => `session built tcp ${inside()}:${int(49152, 65535)} -> ${outside()}:443`],
    [4, 3, '%FW-4-106023', () => `session denied udp ${outside()}:${int(1024, 65535)} -> 10.1.0.1:161`],
    [3, 0.6, 'ha', () => 'failover: peer heartbeat missed on link1'],
    [2, 0.1, 'sysmon', () => `cpu usage ${int(95, 99)}% for 60 s`],
    // Some devices put a literal line break after the tag (seen on real hardware).
    LEADING_BREAK,
  ],
  sw: [
    [5, 20, 'portd', () => `port 1/${int(1, 48)} up 1000 full`],
    [5, 10, 'portd', () => `port 1/${int(1, 48)} down`],
    [4, 10, 'portd', () => `port 1/${int(1, 48)} link flap detected (${int(3, 9)} in 60 s)`],
    [6, 30, 'stpd', () => `topology change on vlan ${pick([10, 20, 30, 100])}`],
    [4, 6, 'l2d', () => `mac ${mac()} moving between port 1/${int(1, 24)} and port 1/${int(25, 48)}`],
    [7, 24, 'lldpd', () => `neighbor update on port 1/${int(1, 48)}`],
  ],
  vpn: [
    [6, 40, 'ikev2', () => `tunnel peer ${outside()} rekey complete`],
    [5, 30, 'vpnd', () => `user ${pick(['alice', 'bob', 'chen', 'dana', 'eli'])} connected from ${outside()} assigned 10.20.0.${int(2, 250)}`],
    [6, 20, 'vpnd', () => `user ${pick(['alice', 'bob', 'chen', 'dana', 'eli'])} disconnected after ${int(1, 480)} min`],
    [4, 10, 'ikev2', () => `tunnel peer ${outside()} dead peer detection timeout, retrying`],
  ],
  srv: [
    [6, 30, `sshd[${int(1000, 9999)}]`, () => `Accepted publickey for deploy from 10.1.4.${int(2, 60)} port ${int(40000, 60000)}`],
    [5, 6, `sshd[${int(1000, 9999)}]`, () => `Failed password for invalid user admin from ${outside()} port ${int(40000, 60000)}`],
    [6, 20, `CRON[${int(1000, 9999)}]`, () => '(root) CMD (/usr/local/bin/backup.sh)'],
    [7, 30, 'app', () => `cache hit ratio 0.${int(80, 99)} over ${int(1000, 9000)} requests`],
    [4, 6, 'kernel', () => 'conntrack table 90% full'],
    [3, 2, 'app', () => `upstream 10.2.0.${int(20, 30)}:8080 timed out after 30 s`],
    // Multi-line output (CR/LF) and a stray control character.
    EMBEDDED_BREAK,
    [4, 0.5, 'app', () => `disk check \x07 attention: ${int(85, 95)}% used`],
    // A huge single message (exercises the 8 KiB row cap) and spoofing characters (bidi
    // override, zero-width space) that the UI must show rather than apply.
    [7, 0.15, 'app', () => `payload dump: ${'0123456789abcdef'.repeat(1300)}`],
    [5, 0.6, 'ftpd', () => `file uploaded by user\u200b01: invoice\u202efdp.exe`],
  ],
  ap: [
    [6, 50, 'wlan', () => `client ${mac()} associated ssid corp-wifi rssi -${int(45, 80)}`],
    [6, 30, 'wlan', () => `client ${mac()} disassociated reason ${int(1, 8)}`],
    [5, 10, 'radio', () => `channel changed ${pick([36, 40, 44])} -> ${pick([100, 104, 149])} (radar)`],
    [4, 10, 'wlan', () => `client ${mac()} failed authentication`],
    // Chatty debug it can't be told not to send: the mock's severity filter keeps it out (2.1).
    [7, 120, 'wlan', () => `dbg: probe req from ${mac()} rssi -${int(45, 90)} ch ${pick([1, 6, 11, 36])}`],
    [7, 60, 'radio', () => `dbg: noise floor -${int(88, 97)} dBm, utilization ${int(3, 60)}%`],
  ],
};

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function bsdTime(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${MONTHS[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

function weighted<T>(items: T[], w: (t: T) => number): T {
  const total = items.reduce((s, t) => s + w(t), 0);
  let r = Math.random() * total;
  for (const t of items) {
    r -= w(t);
    if (r <= 0) return t;
  }
  return items[items.length - 1];
}

export interface GenLine {
  received: string;
  device_id: string;
  severity: number | null;
  raw: string;
  // 2.0 marks (docs/api.md → Search → Marks).
  truncated?: boolean;
  incomplete?: boolean;
  frame_arrived?: number;
  frame_length?: number;
}

/** One message from the given device. ~1% come without a PRI, so severity is unknown. */
export function line(dev: MockDeviceDef, at: Date): GenLine {
  const host = dev.name || `host-${dev.ip.split('.').pop()}`;
  if (Math.random() < 0.01) {
    return { received: at.toISOString(), device_id: dev.ip, severity: null, raw: `${host} -- MARK --` };
  }
  return format(dev, at, weighted(TEMPLATES[dev.kind], (t) => t[1]));
}

/** One of the SPECIAL messages from the given device (of that message's kind). */
export function specialLine(name: Special, dev: MockDeviceDef, at: Date): GenLine {
  return format(dev, at, SPECIAL[name].t);
}

function format(dev: MockDeviceDef, at: Date, [sev, , app, text]: Template): GenLine {
  const host = dev.name || `host-${dev.ip.split('.').pop()}`;
  const facility = dev.kind === 'srv' ? (app.startsWith('sshd') ? 4 : 1) : 23; // auth, user, local7
  const pri = facility * 8 + sev;
  const raw =
    dev.kind === 'srv'
      ? `<${pri}>1 ${at.toISOString()} ${host} ${app.replace(/\[.*/, '')} ${app.match(/\[(\d+)\]/)?.[1] ?? '-'} - - ${text()}`
      : `<${pri}>${bsdTime(at)} ${host} ${app}: ${text()}`;
  return { received: at.toISOString(), device_id: dev.ip, severity: sev, raw };
}

export function testLine(at: Date): GenLine {
  return {
    received: at.toISOString(),
    device_id: '127.0.0.1',
    severity: 6,
    raw: `<14>${bsdTime(at)} this-host woodshed-test: Hello from Woodshed`,
  };
}

/**
 * The header's program/tag and hostname, as the server parses them (docs/api.md → Search:
 * app and host), for the two shapes the mock writes: RFC 5424 and "Mmm dd hh:mm:ss host tag: ".
 */
export function fieldsOf(raw: string): { app: string; host: string } {
  const m5 = /^<\d{1,3}>1 \S+ (\S+) (\S+) /.exec(raw);
  if (m5) return { host: m5[1] === '-' ? '' : m5[1], app: m5[2] === '-' ? '' : m5[2] };
  const m3 = /^<\d{1,3}>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d (\S+) ([^\s[:]+)(?:\[\d+\])?:/.exec(raw);
  if (m3) return { host: m3[1], app: m3[2] };
  return { app: '', host: '' };
}

export { weighted, int };
