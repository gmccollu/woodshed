# Changelog

All notable changes to Woodshed. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/). Release notes on GitHub are taken from this file
(`scripts/release-notes.sh`), so set a section's date before tagging it.

## [2.0.0] - unreleased

### Added
- A flow collector (flow v5, flow v9 (RFC 3954) and IPFIX (RFC 7011)), off until you turn it on in **Settings → Flows** or with `woodshed flow on`
  (flow v5 and v9 on UDP 2055, IPFIX on UDP 4739; each port reads every version). Templates and options data per exporter
  and observation domain, interface names from options data, variable-length and enterprise-specific fields (kept as
  they came), data that arrived before its template decoded when it comes (marked late), and malformed or undecodable
  data kept, never dropped silently. Sequence gaps (loss before Woodshed) and duplicates are counted per exporter. See
  [docs/user-guide.md](docs/user-guide.md#collecting-flows).
- Flow records whose times are far from when they arrived (more than 1 h ahead or 24 h behind: a broken exporter
  clock or uptime, or a decoding bug) are kept as sent and counted per exporter, with the largest offset each way, in
  `GET /api/flows` (`time_offsets_24h`, `time_offsets_1h`), the device page, **Settings → Flows** and `woodshed flow
  status`; a `flow_time` banner names an exporter with 10 or more in the last hour, and the bundle README's Flows
  block gets a "times off arrival" line.
- IPFIX sequence numbers: each exporter's observation domain learns whether it numbers a message by the records sent
  before it (RFC 7011) or counting its own records too, and whether options records count, so an exporter of the
  second kind no longer shows a false sequence gap per multi-message export; a real loss still counts.
  `GET /api/flows` gives the learned `seq_mode` per domain (`"rfc"` or `"after"`), and `woodshed flow status` notes
  an `after` domain. A run of messages behind the expected number is an exporter restart (also for v5 and v9).
- Firewall-event, NAT and bidirectional records are first-class: `fw_event` (created, deleted, denied, …),
  `nat_event`, post-NAT addresses and ports, initiator and responder counters and RFC 5103 reverse counters are
  columns and filters, sums follow a no-double-count rule for event records, and a rule or ACL ID can be read from
  the enterprise field an exporter uses (`listeners.flow.rule_id_ies`, e.g. `"32473:7"`), or for flow v9 from a
  vendor-range field type (`"0:40003"`); **Settings → Flows** lists each exporter's fields with **Use as rule ID**.
- Sampling is kept per record and shown: counts exported and, where the rate is known, scaled, never scaled
  silently.
- **Events → Flows**: the results, the field panel, the histogram, and a **Top** panel (talkers, destination ports,
  conversations, and **Denied**: top denied sources, destinations, ports and rules), each value a filter. Searches
  use flow time (a record matches when its start-to-end overlaps the window). The other tabs get a flow strip under
  the histogram for the selected exporters. Device pages show their flow counts.
- `woodshed search --type flow` (with `--src`, `--dst-port`, `--proto`, `--fw-event` and the other flow filters),
  `woodshed flows top`, `woodshed flow on|off|status` (status checks the config as `woodshed run` does), a Flows row
  in `woodshed status`, `woodshed send --proto flow-v5|flow-v9|ipfix` (with `--events` and `--biflow`) and `woodshed
  bench --proto ipfix`.
- Exports and incident bundles cover every data type: the UI's Export now defaults to all types (the API's default
  stays syslog), and bundles include flows when there are any in the window, as `flows/<device>/flows.csv`,
  `flows.ipfix` (an RFC 5655 IPFIX file; flow v9 vendor-range fields are in it as enterprise fields under enterprise
  number 0, and it reads back record for record) and, when there are undecoded sets, `raw.txt`. The bundle README
  gains a Flows block per device (top talkers, ports, conversations, firewall events, top denied sources and ports, NAT,
  and the sequence gaps counted in the window, by when the datagrams arrived). **Leave flows out** is offered before building, pre-selected for a long window with large flows; a
  zip holds at most 20 million flow records per device.
- **Set up a device** (**Connect** in the menu): the configuration a device needs to send Woodshed its syslog (UDP,
  TCP or TLS), SNMP traps (v2c or v3) or flows, or to let Woodshed poll it, filled in with this server's addresses,
  ports and TLS certificate name. Six families, named by syntax rather than brand: a line-oriented CLI, a set-style
  CLI, Linux rsyslog, Linux net-snmp (`snmpd` and `snmptrap`), Linux softflowd and a web UI checklist. Secrets are
  always placeholders, and each snippet says what it does, how to check it worked, and how it's verified: the rsyslog,
  net-snmp and softflowd snippets are **Tested** (CI applies them to the real tools against a running Woodshed), the
  others are **Reference only**. See [docs/user-guide.md](docs/user-guide.md#setting-up-devices).
- `woodshed setup families` and `woodshed setup snippet --family … --what …` print the same from a terminal.
- API: `GET /api/setup/families` and `POST /api/setup/snippet` (or `GET` with query parameters); see docs/api.md
  "Device setup helper".

### Changed
- Woodshed now has a second, binary on-disk format beside its plain text files: flows are stored as compact columnar
  segments (`logs/<device>/flows/*.wsf`, about 20 bytes a record), read through Events, `woodshed search`, or the
  CSV and IPFIX exports. Syslog, trap and poll files are unchanged.
- Retention: flows have their own budget, `storage.flow_budget_bytes`, 40 % of the storage cap by default. While they
  exceed it the oldest flows are deleted first, fair-shared between exporters, before any other data; the low-disk
  guard deletes flows first too. With no flows nothing changes.
- The index migrates once (schema 9: `flow_segments`, `flow_minute`, and the flow collector's counts per exporter and
  minute in the stats tables). Downgrading to 1.x keeps every syslog, trap and poll file and loses access to flows. A
  2.0.0-rc1 binary can't open a schema-9 index ("newer than this build supports"): after running this version, don't
  go back to rc1 with the same data folder.
- A restart keeps each flow exporter's last 24 hours (records, late, without a template, malformed, sequence gaps,
  duplicates, times off arrival), its last-seen time and its sampling and interface names in `GET /api/flows`,
  `woodshed flow status` and the device page. Templates aren't kept: records after a restart wait for the exporter's
  next template, as before, so one changed while Woodshed was down is never decoded with the old layout.
- Top lists by bytes (or any metric) leave out keys with none of it, such as denied-only sources and rule IDs at 0
  bytes, and say how many: `zero_omitted` in `GET /api/flows/top`, "4 with 0 bytes not shown" in `woodshed flows top`,
  the Top and Denied views and the bundle README ("at least N" when counting was approximate); `woodshed flows top`
  exits 0 when records matched but every key had 0. Shares under 10 % in the README get a decimal and tiny ones read
  "<0.1 %", as in the Top view, instead of "0 %".
- `woodshed send` over UDP (syslog, traps and flows) keeps sending when the receiver restarts: a refusal (ICMP port
  unreachable) after the first second is reported in the summary (when, and how many, a lower bound on the loss) and
  the datagram sent again. A port that refuses from the start still stops it at once ("nothing is listening"). On
  Windows a UDP refusal is never detected, so a send there never stops for one.
- `woodshed snmp status` and `woodshed tls status` check the config first, as `woodshed run`, `reindex` and `flow
  status` do: a config the server wouldn't start with is reported (exit 1) instead of shown as a status.

### Fixed
- An octet-counted TCP or TLS message whose sender closed or reset the connection before its advertised length arrived
  was stored as if it were complete (`50 <13>short` then EOF looked exactly like `9 <13>short`); present since 1.0.
  What arrived is still kept, and now marked incomplete with both lengths: on its stored line
  (`<13>short \#incomplete=9/50`), in search results, the live tail and `woodshed search --json` (`incomplete`,
  `frame_arrived`, `frame_length`), and in Events, so exports and bundles carry it too. The same goes for a message
  Woodshed cut by closing the connection (the frame timeout, an eviction, shutdown), which was counted as truncated
  instead. A frame of which only the count arrived, or only part of its count, is counted (before, `6 <13>ab50` then
  a close stored "50" as a message). A newline-framed last line the sender's reset ended is incomplete too; one without
  its LF before a clean close stays a complete message, since newline framing can't tell it from a cut one. A torn
  last line kept after a crash is marked incomplete.
- `truncated` (the dashboard, the per-device stats, the bundle's losses) now counts only messages cut at the max
  message size, and such a line is marked `\#truncated`. Each TCP and TLS listener counts incomplete frames and frame
  timeouts in `/api/stats` (`tcp_frames`) and on **About**. Older Woodshed versions show a marker as text at the end of
  the message, so there a message cut inside its header can show a wrong app or host, and a regex anchored with `$`
  doesn't match a marked line; lines stored before 2.0 have none.

### Security
- The flow listener opens no port until it's turned on; on Windows its firewall rules are installed disabled. The
  sender allowlist, blocklist and new-sender limits apply to exporters as to any sender.

### Performance
- IPFIX at 50,000 records a second for 10 minutes (30 records a packet, 2 domains) with UDP syslog at 5,000 msg/s
  beside it: all 30 million records and 3 million messages stored, 0.43 of a core and 153 MiB peak RSS for the whole
  pipeline, 20.4 bytes per stored record; a 150,000 records/s burst for 10 s lost nothing. Top talkers over 18 million
  records took under 0.8 s, and a one-address search's first page 0.1 s. Measured in-process with `woodshed bench
  --proto ipfix --rate 50000 --duration 10m --syslog-rate 5000` (the sender in a child process) on a 14-core
  laptop; the reference-spec (4 vCPU) runner and the lab's 24-hour run will replace these before release.

## [1.3.0] - 2026-11-17

### Added
- SNMP polling of the devices you choose, off until you add one under **Devices → Polling** (**Add polling** on a
  device, or **Add by address**): every 60 s by default (30 s to 10 min), Woodshed asks each device for its uptime,
  its interfaces' traffic, packets (unicast, multicast, broadcast), errors, discards and up/down state, and CPU and
  memory where it has the HOST-RESOURCES MIB, plus up to 32 custom OIDs or walks of your own. SNMPv1, v2c and v3
  (every protocol the trap receiver has, as the non-authoritative side, with engine discovery). Only standard MIBs, so
  it works the same on any vendor's gear. See [docs/user-guide.md](docs/user-guide.md#polling-devices-snmp).
- Rates are worked out as each answer is stored, with the raw counters kept beside them: a 32-bit counter's wrap
  counts only when the rate it gives is plausible, and a counter reset, a renamed interface or an agent restart
  leaves a gap rather than a spike. Restarts are found from `sysUpTime` (and v3 `engineBoots`), and told apart from
  reboots with `hrSystemUptime` where the device has it.
- Each device gets a page with a **Polling** panel: uptime and the last restart, five small charts (CPU, memory,
  total traffic, the four busiest interfaces, errors and discards), the interface table (click a row to chart it), and
  restart and up/down markers. **Events** shows traffic, CPU and error strips under the histogram for the selected
  polled devices, with the same markers across both.
- **Test poll** (in the form, or `woodshed poll test ADDRESS` from a terminal) runs the device's poll once and says
  step by step what answered and what's missing, without saving anything.
- Poll records are a third data type, `poll`, in each device's `poll` folder, with the same rotation, compression,
  retention and index as syslog and traps. `woodshed search --type poll --field kind=restart --last 7d` lists
  restarts; exports and incident bundles get `poll/<device>/system.csv`, `interfaces.csv` and `oids.csv`, and the
  bundle README gains a Polls line per device and merges a poll restart with a coldStart trap into one reboot.
- **Settings → Polling** holds the defaults, how many devices are polled at once, and the last hour's cycles,
  failures and skipped cycles. Banners say when polled devices stop answering or polling can't keep up.
  `woodshed status` gains a Polling row.

### Fixed
- After a restart or reboot, the poller read a device's interface list once, as the agent came up, and then not for
  an hour, so an interface that appeared a little later (a bridge, a tunnel, a line card) went unpolled for that
  hour (in the lab, one that appeared 20 s after the agent). It now looks again about 1, 2 and 5 polls after the
  restart, and between the hourly looks whenever the device's interface count or `ifTableLastChange` changes (read
  in the poll's existing request, so it costs no extra one). A device without `ifTableLastChange` is polled as before.
- A sender on `::1`, or on an IPv4-compatible IPv6 address (`::a.b.c.d`), was stored but never listed as a device,
  so nothing it sent could be found (since 1.1). It's listed now. To find what such a sender sent before the upgrade,
  run `woodshed reindex` once.
- The device page's Polling panel showed up/down changes only for the interfaces on its charts, so an interface that
  went down off the chart (often the one that matters) left no trace there. Every interface's changes, the restarts
  and the reboots now mark every chart and are listed under them, newest first, with **Chart** for an interface that
  isn't on the chart.
- A chart marker's text no longer repeats the change ("eth3 down (was up)", not "eth3 down (eth3 down (was up))").
- Incident bundles counted every poll restart as a reboot: three restarts of the SNMP agent alone read "Reboots 3".
  Only restarts that may have been the device's count now; with agent-only ones the README says "Restarts 3
  (0 reboots)", still listing each, and `woodshed bundle`'s summary says "restarts 3, reboots 0".
- Incident bundles counted a coldStart or warmStart trap as a reboot even when the polls around it showed the device
  kept running (in the lab, two agent restarts in one poll interval read "Restarts 3 (1 reboot)"); it's now an agent
  restart, and that README reads "Restarts 2 (0 reboots)".
- A restart found because the uptime rose by less than the time since the last poll was described as "sysUpTime
  reset". It now says "sysUpTime rose less than the time since the last poll", the same on the charts, in the README
  and in the CSV.
- The device page's memory chart says that on Linux with net-snmp "used" includes the page cache (an idle host can
  show about 90 %); the figure is still the agent's own. The user guide says so too, and the user guide and FAQ
  explain why a single cycle's rate can read a few percent off while totals are exact.

### Security
- Polls are the second kind of outbound traffic (after the opt-in update check): SNMP `Get`, `GetNext` and `GetBulk`
  only, only to the addresses and ports an administrator configured, from one ephemeral UDP socket that exists only
  while a device is polled. With no polled devices nothing is sent. The poller can't build a `Set` (a test checks
  it). Communities are kept in the SNMP credentials store, write-only, and appear in poll records only as a hash
  prefix; replies are accepted only from the polled address and port.

### Performance
- Polling 500 devices with 64 interfaces each every 60 s (v2c) took 0.07 of a core and 129 MiB of memory for the
  whole server, every cycle on time; with syslog at 10,000 msg/s beside it, 0.26 of a core, and 600,000 of 600,000
  messages stored. 100 devices every 30 s with v3 authPriv (SHA-256, AES-128): 0.03 of a core (0.24 with the syslog
  run, again with nothing lost). Measured in-process on a 14-core laptop with the test agents in another
  process (`TestPollLoad`); the reference-spec (4 vCPU) runner and lab numbers will replace these before release.

## [1.2.0] - 2026-11-16

### Added
- An SNMP trap receiver, off until you turn it on in **Settings → SNMP traps** or with `woodshed snmp on` (UDP 162):
  SNMPv1, v2c and v3 traps and informs. Each trap is stored as one decoded line in the device's `traps` folder, with
  its values, the names known from the built-in set and a folder of MIB files, and the raw packet in base64.
  Malformed packets and failed v3 traps are kept too, with their status. Informs are answered once stored, at most
  100 replies a second per sender. See [docs/user-guide.md](docs/user-guide.md#receiving-snmp-traps).
- v3 users are managed in Settings: MD5, SHA-1 and SHA-2 authentication, DES and AES-128/192/256 privacy (with both
  AES-192/256 key formats), weak protocols labelled. Passphrases are write-only, encrypted for the service's account
  on Windows and readable only by it elsewhere, and never on a command line, in a log or an export. An optional
  community list refuses v1/v2c traps with other communities; communities are stored only as a hash prefix and
  masked in the stored packet.
- **Events** has a **Syslog | SNMP traps** switch: traps get their own fields (version, PDU, trap, enterprise,
  generic and specific trap, community or user, status), filters that take OIDs, OID prefixes or MIB names, a decoded
  view, the histogram and saved searches. `woodshed search --type trap` does the same from a terminal.
- **Settings → SNMP traps** shows Woodshed's v3 engine ID, the MIB folder and its errors (**Reload MIBs**), the last
  24 hours by status, and the senders whose traps fail, with the reason. A v3 device that restarts without raising its
  boot counter has its clock relearned (counted per sender) instead of losing its traps; `v3_strict_time = true`
  keeps the protocol's strict rule.
- `woodshed snmp on|off|status`: turns the receiver and its firewall rule on or off (Windows: the installer's
  "Woodshed SNMP traps (UDP 162)" rule, added turned off; Linux: ufw or firewalld when active), and prints the
  receiver's state. `woodshed status` shows it too.
- `woodshed bench --proto trap` measures the whole trap pipeline (v1, v2c, v3, informs) and checks that every trap
  arrived exactly once.
- The device page counts every type of record, and a device that sends only traps is online.
- API: `type=trap` on search, summary, context and saved searches; `/api/snmp`, `/api/snmp/failures`,
  `/api/snmp/mibs/reload` and `/api/snmp/users`; `listeners.snmp` in settings; `types` and `kind` on exports, which
  put traps in a `traps/` folder; each device's `types` and `lines_by_type`; the storage history's `type`; banner
  kinds `snmp_firewall`, `snmp_credentials` and `snmp_mibs`; the refusal reason `community`
  ([docs/api.md](docs/api.md)).
- `woodshed search` searches the stored logs from the command line with the Events engine: the same text, Terms and
  Regex modes and every filter (devices, groups, severities, facilities, programs/tags, hosts, their exclusions, and
  `--field KEY=V` / `--not-field KEY=V` for any field), compressed days included. Output is the stored lines, the
  messages alone (`--raw`), NDJSON (`--json`), lines around each match (`--context N`) or a count, with a summary on
  standard error and grep-style exit codes. It reads the data folder directly and never writes to it, so it works
  beside the running service, with the UI off, or with the service stopped. See
  [docs/user-guide.md](docs/user-guide.md#searching-from-the-command-line).
- UDP messages wait in a queue between the network and the disk, so a slow write (an fsync, a file rotation, a
  compression pass) no longer makes the operating system drop them. The queue holds 100,000 messages or 64 MiB per UDP
  listener (`listeners.udp_queue_messages` and `udp_queue_bytes` in the config file); when it's full, messages are
  dropped and counted for their device, with an event once a minute and a banner ("writing to disk fell behind").
- **About** shows the UDP queue: its capacity, what's waiting now, and the most messages waiting in each of the last
  24 hours, so a recurring stall shows up. If messages go missing while the queue never fills, they were lost before
  Woodshed read them.
- The dashboard and About split dropped messages by reason: writes paused (low disk), write errors, refused new
  senders, and a full UDP queue.
- API: `/api/stats` gains `dropped_by_reason` and `udp_queue`; banner kind `udp_queue_full` ([docs/api.md](docs/api.md)).
- `woodshed bench` reports the UDP queue's high-water mark and drops, and says whether every missing message was
  counted. `--stall-every` and `--stall-for` fake a slow disk, and `--udp-queue-messages` sets the queue's size.
- `woodshed send` can send SNMP traps and informs for testing (`--proto trap`): SNMPv1, v2c and v3 at every
  security level, with MD5, SHA-1 or SHA-2 authentication and DES or AES-128/192/256 privacy. Informs wait for each
  answer and report round-trip times and timeouts. Communities and passphrases are read from a file or an
  environment variable, never from the command line.
- Incident bundles: pick a moment and get every record Woodshed stored around it, syslog and SNMP traps, from every
  device that sent anything then (or chosen devices, a group), in one zip. Start one with **Bundle around this** on
  an Events line, a point on the histogram, or **Export → Around a time** (windows of 15 min before / 5 after, 30 min / 10 min,
  1 h / 15 min, 4 h / 1 h, 24 h / 1 h, or your own; the time in local time or UTC). A preview shows the window in
  Events, the devices and the size first. The README opens with a summary per device: counts by severity and by trap,
  first and last, reboots (coldStart and warmStart traps), gaps when Woodshed or a listener was down, and Woodshed's
  own drops and truncations; `manifest.json` has the same numbers as JSON. See
  [docs/user-guide.md](docs/user-guide.md#incident-bundles).
- `woodshed bundle --at <time>` builds the same zip from the data folder, with the service running or stopped: the
  access rules of `woodshed search`, read-only, never overwriting a file. It prints the zip's path, size and SHA-256
  and a line per device, so a remote colleague can be asked for one command and one zip.
- **Export** can export SNMP traps, or both types, from the UI.
- API: `kind: "bundle"` on `POST /api/exports` and `/api/exports/estimate` (`at`, `before`, `after`,
  `active_devices`); `active_from` and `active_to` on `GET /api/devices` ([docs/api.md](docs/api.md#the-incident-bundle)).

### Changed
- The index migrates once at the first start (each file's data type, the traps' own counters). Syslog files, their
  place and their format don't change; to go back to 1.1, move `index.db` aside and run 1.1's `woodshed reindex`,
  which ignores the `traps` folders.
- Retention, the size cap and the low-disk guard count a device's syslog and traps together, oldest file first.
- When Woodshed stops, it stores the UDP messages still queued first, for at most a third of the shutdown time
  (5 seconds for the service); any left then are counted as dropped.

### Fixed
- `PUT /api/snmp/users/{name}` accepts the object exactly as GET returns it (its read-only fields are ignored), and
  `key_ext: "draft"` is accepted with any privacy protocol, so the Settings form and a GET → PUT round trip work.
- `woodshed tls status` shows failure times in UTC, and on Linux says what `tls on` opened in ufw or firewalld
  instead of the generic "open the port" hint.
- 1.2.0-rc1 only: on Windows, UDP syslog and SNMP traps cost about a CPU core at a few hundred messages a second,
  because every message woke the UDP queue's second thread. A message that arrives on its own is now stored straight
  away; bursts still go through the queue, so a slow disk is absorbed as before.

### Known issues
- On some Windows machines Woodshed uses much more CPU than elsewhere at moderate rates (up to most of a core at
  100–500 messages a second, mostly kernel time, on one lab VM with endpoint protection; about 1–2% on a plain Windows
  machine at 500/s). Nothing is lost. 1.0 behaved the same way there; the cause is being traced.


## [1.1.0] - 2026-11-14

### Added
- Opt-in update check: asks once, off unless you turn it on, one GET of the public releases file a day, never
  installs anything.
- `woodshed update-check on|off|ask` sets it from the command line, and silent installs set it with
  `WOODSHED_UPDATE_CHECK` (an MSI property; an environment variable for the pkg, deb and rpm). See
  [docs/install.md](docs/install.md#the-update-check-on-many-machines).
- Events has a field panel beside the results: the top devices, severities, facilities, hosts and programs/tags for
  the current search, with exact counts over a stated span. Click a value to filter on it, Alt-click or "−" to leave
  it out.
- A histogram above the results shows the matches over time. Drag across it to zoom into a range; Back zooms out.
  Unfiltered searches draw it straight from the index, so it's instant.
- Text | Terms | Regex: Terms mode takes words and "quoted phrases" with AND, OR, NOT and parentheses. Text mode and
  every existing link keep their 1.0 meaning.
- Saved searches: save, open, rename and delete named searches, shared by everyone who can open the UI. They're kept
  in `index.db`, and `woodshed reindex` keeps them.
- New filters on search and export: facility, and leaving out devices, programs/tags or hosts. Exports record them in
  `manifest.json` and `README.txt`.
- API: `GET /api/search/summary`, `GET /api/search/schema`, `/api/saved-searches`, and the `type`, `syntax`,
  `facilities`, `exclude_devices`, `exclude_app` and `exclude_host` parameters ([docs/api.md](docs/api.md)).
- Syslog over TLS (RFC 5425) on TCP 6514, off until you turn it on in **Settings → Listeners → Syslog over TLS** or
  with `woodshed tls on`. TLS 1.2 and 1.3 with modern cipher suites; an option allows TLS 1.0 and 1.1 for older
  senders. Everything after the handshake works as TCP does: the same framing, limits, storage and device identity.
- Woodshed makes its own small CA and a server certificate the first time TLS is turned on. Devices import the CA
  (download it as PEM or DER in Settings, and compare the SHA-256 or SHA-1 fingerprint), so renewing the server
  certificate needs no change on them. Both last until 2037-12-31 at most, for older devices' date handling, and
  never change on their own: banners warn 60 days before either expires and when the computer gets a DNS name the
  certificate doesn't cover. Renew and Replace CA are in Settings and `woodshed tls renew [--new-ca]`. You can use
  your own certificate and key instead.
- Per-device TLS stats (connections, version and cipher, failed handshakes and why) on the Devices page, and a list of
  senders whose TLS handshakes fail (an untrusted CA, no version in common, plain syslog sent to the TLS port).
- `woodshed tls on|off|renew|status`. On Windows the installers add a firewall rule for TLS 6514, turned off, which
  `tls on` turns on; on Linux `tls on` opens the port in ufw or firewalld when one is active, and `tls off` removes
  only what it added. `woodshed status` shows the TLS certificate's fingerprints.
- `woodshed send --proto tls --ca FILE` (or `--insecure`) checks a TLS setup the way a device would, and `woodshed
  bench --proto tls` measures it.
- The install guide, user guide and FAQ cover TLS, and warn that some firewalls block traffic while a TCP or TLS log
  host is unreachable or its certificate fails.

### Changed
- The 15 min, 1 h, 24 h and 7 d presets end at the next whole minute, so their time buckets line up.

### Fixed
- Stopping Woodshed no longer waits up to 5 seconds when a browser connected to the UI just before.

### Known issues
- On Windows in a language other than English, the "TLS firewall rule is off" banner doesn't appear (the rule's
  state reads as unknown). `woodshed tls on` still turns the rule on.

## [1.0.1] - 2026-11-14

### Fixed
- TCP connections are now kept open for 24 hours without a message, not 10 minutes, so senders that don't notice a
  closed connection no longer lose messages; set it with `listeners.tcp_idle_timeout` (1m to 168h).
- A sender at its TCP connections-per-address (or per-/64) limit, for example after rebooting without closing its
  connections, now replaces its own connection idle longest instead of being refused. Keepalives are set
  explicitly on every TCP connection, so connections to a vanished sender close within minutes.
- The install guide and user guide now warn that some firewalls block traffic while their TCP syslog server is
  unreachable, unless a "permit traffic when the log host is down" option is set; UDP has no such risk.
- A portable copy or `woodshed run` no longer warns that it "will compete for ports" with the installed service when
  it uses other ports. It checks the service's actual ports (its run-state file or config, when readable, else its
  defaults), names the ports that clash, and says "may" when it could only compare with the defaults.
- New FAQ entry, linked from the README: why not tcpdump, rsyslog, syslog-ng or Graylog?

## [1.0.0] - 2026-11-13

The first release: a syslog server you can install on Windows, macOS or Linux in a minute, that keeps every message
as plain files within a disk budget and has a web UI for watching, searching and exporting logs.

### Renamed from Woodpile
- The release candidates were called Woodpile; from 1.0.0 it's Woodshed. Everything carries the new name: the
  program (`woodshed`), the services (`woodshed.service`, `com.woodshed.daemon`, `Woodshed` running as
  `NT SERVICE\Woodshed`), the accounts, folders, packages and download names, and the UI's cookies and header (so
  a browser logs in again once).
- Installing Woodshed over a Woodpile release candidate replaces it: the MSI upgrades over the Woodpile MSI (whose
  uninstall removes the `Woodpile` service), the deb and rpm remove the `woodpile` package (Conflicts/Replaces,
  Obsoletes), and the pkg stops the `com.woodpile.daemon` daemon and removes its plist, program and app.
- The deb now says "stopped and disabled the old Woodpile service" when it replaces a running Woodpile, as the rpm
  already did.
- The old data isn't moved or deleted. Woodshed starts with its own data folder and default settings; the Woodpile
  one (`/var/lib/woodpile` and `/etc/woodpile`, `/Library/Application Support/Woodpile`, `C:\ProgramData\Woodpile`)
  stays where it is. The installer and `woodshed status` say where, and you can delete it when you no longer need it
  ([docs/install.md](docs/install.md#moving-from-woodpile)).
- `woodshed install` refuses while a Woodpile service is still installed, and prints the command that removes it.

### Known issues
- The installers and binaries aren't code-signed yet, so Windows SmartScreen and macOS Gatekeeper ask once.
- On Windows and macOS the OS doesn't expose kernel UDP drops, so the UI says that instead of showing 0.

### Fixed during the release candidates (affected rc1 and rc2 only)
- A sustained flood from many spoofed source addresses could make size-based retention delete the busiest real
  device's history. Retention now splits the cap by each device's 7-day history and keeps established devices'
  last two days.
- A flood cycling through more than 10,000 previously seen source addresses could slow ingest to about 12,000
  messages a second. Known senders are now readmitted at a bounded rate, and active ones are never refused.
- Windows, `woodshed run`: a data folder another local user created beforehand could be accepted, and the installer
  had a race while replacing one. The folder is now created protected, and a foreign one is moved aside.
- Hidden devices with no name or group could reappear unhidden after 24 hours without logs.

### Receiving
- Listens on UDP and TCP port 514 straight away, on IPv4 and IPv6, with no setup.
- TCP framing (octet counting or newline) is detected per message. Messages up to 64 KiB; longer ones are
  truncated and counted, never dropped.
- Lenient parsing of RFC 5424, RFC 3164 and the usual non-compliant variants (missing PRI, odd timestamps, BOMs).
  The raw message is always stored exactly as received.
- Optional sender allowlist (IPs or CIDRs); refused senders are counted and shown.
- If port 514 is taken, the UI still starts and shows which port, the error and, where the OS tells, the program
  holding it, with a **Retry** button.
- Asks for a 32 MiB UDP receive buffer; the Linux packages raise `net.core.rmem_max` so it gets it.

### Storage
- Plain text files, one folder per device and one file per day (UTC): `logs/<device>/<day>.log`, gzipped once
  closed. Each line is the received time, the sender and the raw message.
- Files close at 100 MiB or midnight UTC, whichever comes first.
- Retention by age and total size (30 days / 20 GiB by default), plus a low-disk guard that keeps 5% of the volume
  free (at least 1 GiB, at most 10 GiB) and pauses writing, counting what it drops, rather than fill the disk. Every deletion is recorded and shown in Settings → Storage history.
- A SQLite index of files and time ranges, rebuildable from the files with `woodshed reindex`.

### Web UI
- Welcome page: this machine's addresses, the listener status and a test command; it notices the first message.
- Dashboard: message rate with a sparkline, devices online and quiet, disk use against the cap, dropped messages,
  device tiles with a last-heard dot, group tabs and a live tail with server-side filters.
- Devices: rename, group or hide senders; first and last seen and totals.
- Events (called Search in the release candidates; old `#/search` links still work): browse or filter every stored
  message, compressed days included. Filters: text or regular expression, case on or off, program/tag (with `*`
  for a prefix, such as `%FW-6-*`), header hostname, exclude, devices or groups, time range and severities. It opens
  on the last hour with no text, so it browses everything. Host and Program/tag columns; click a value to filter by
  it. Results stream in, with ±50 lines of context around a hit.
- The live tail has **Open in Events**: the same devices, severities and text over the last hour.
- Export: a zip of the raw lines for chosen devices and a time range (or exactly what Events showed, with the same
  filters), with a manifest (line counts, SHA-256, the filters, gaps when Woodshed wasn't running), Woodshed's own
  events and a README that states the filters.
- Settings that apply without a restart: listeners, allowlist, retention, file size, quiet thresholds, LAN mode.
- Light and dark modes.

### Security
- The UI listens on `127.0.0.1:8514` only by default.
- LAN mode: HTTPS with a self-signed certificate (or your own) and a password (Argon2id). Sessions need both a
  cookie and a per-session secret header, so a stolen cookie alone is useless. Failed logins back off per address
  and per network, and a browser that logged in before stays remembered. `woodshed reset-password` recovers a
  forgotten password.
- Setting a password also turns on "require login on this machine", so other local users can't change settings;
  it can be turned off.
- No outbound connections, no telemetry and no update checks; a test asserts that no code path dials out.
- Runs with the least privilege each OS allows: a `woodshed` system user with only `CAP_NET_BIND_SERVICE` (Linux),
  the virtual account `NT SERVICE\Woodshed` (Windows), a hidden `_woodshed` user (macOS).

### Installing
- Installers: MSI for Windows (x64 and ARM64), a universal `.pkg` for macOS, `.deb` and `.rpm` for Linux (amd64 and
  arm64). Each sets up the service, starts it and keeps the logs on upgrade and uninstall unless you ask to delete
  them.
- Portable archives (`.zip`, `.tar.gz`) for every OS: unpack, double-click `woodshed`, and the data goes in
  `woodshed-data` next to it.
- `woodshed install` / `uninstall` set up the same service without a package.
- `woodshed status` run without root (or administrator rights on Windows) says plainly that it can't read the
  config and gives the command that can (`sudo woodshed status`), and still shows the service's state and the UI.
- Command line: `run`, `install`, `uninstall`, `status`, `reindex`, `reset-password`, `send` (numbered test
  messages), `bench` (sustained throughput) and `version`.

### Known limitations
- The installers and binaries aren't signed yet, so Windows SmartScreen and macOS Gatekeeper ask once before running
  them (see the [FAQ](https://github.com/gmccollu/woodshed/blob/main/FAQ.md)).
- On Windows and macOS the OS doesn't expose kernel UDP drops; the UI says so instead of showing 0.
- No TLS syslog, alerts or forwarding yet (planned after 1.0).
