# Woodshed user guide

Woodshed collects the log messages (syslog) that your devices send, keeps them as plain files on this computer, and
shows them in a web page where you can watch, search and export them. This page gets you from download to a support
zip. For details, see the [install guide](install.md) and the [FAQ](../FAQ.md).

Downloads are on the [releases page](https://github.com/gmccollu/woodshed/releases).

## 1. Start Woodshed

Pick one: the installer keeps Woodshed running in the background, including after a restart; portable runs it only
while its window is open, with nothing installed (good for a quick look or a laptop on site).

| | Installer (runs as a service) | Portable (nothing installed) |
|---|---|---|
| **Windows** | Download `woodshed_X.Y.Z_windows_amd64.msi` (`_arm64` for ARM PCs) and double-click it. | Download `woodshed_X.Y.Z_windows_amd64.zip`, right-click it → **Extract All**, then double-click `woodshed.exe` in the extracted folder. |
| **macOS** | Download `woodshed_X.Y.Z_macos_universal.pkg` and double-click it. | Download `woodshed_X.Y.Z_darwin_universal.tar.gz`, double-click it to unpack, then double-click `woodshed`. |
| **Linux** | `sudo apt install ./woodshed_X.Y.Z_amd64.deb` (Debian, Ubuntu) or `sudo dnf install ./woodshed-X.Y.Z-1.x86_64.rpm` (Fedora, RHEL). | `tar xzf woodshed_X.Y.Z_linux_amd64.tar.gz`, then `cd` into the folder and run `sudo ./woodshed`. |

The first time, your computer may warn you because Woodshed isn't signed yet:

- **Windows:** "Windows protected your PC" → **More info** → **Run anyway**. If asked whether to allow Woodshed
  through the firewall, choose **Allow** (portable mode only; the installer sets the firewall up itself).
- **macOS:** if it says it "can't be opened", open **System Settings → Privacy & Security**, scroll down and click
  **Open Anyway**.

Then open <http://localhost:8514/> in a browser on the same computer. (Portable mode opens it for you.) Later, the installer's
launcher gets you back there: **Woodshed** in the Start menu (Windows), in Applications or Launchpad (macOS), or in
your desktop's app menu (Linux). The
**Setup** page shows the addresses your devices should send to and whether Woodshed is listening.

## 2. Point a device at it

In each device's logging or syslog settings, set the syslog server to one of the addresses on the Setup page,
port 514, UDP (or TCP if the device offers it). Save, and make the device log something (log in to it, or change
a setting). The Setup page says when the first message arrives.

> **Firewalls and TCP or TLS:** some firewalls stop passing traffic while their TCP or TLS syslog server can't be
> reached, or its certificate fails, unless an option such as "permit traffic when the log host is down" is set.
> Check that option before you choose TCP or TLS. UDP has no such risk.

Over TCP, Woodshed keeps a quiet connection open for 24 hours, because some devices don't notice a closed
connection until their next message fails, and lose messages until they reconnect. To change it, set
`tcp_idle_timeout` under `[listeners]` in the config file ([where it is](install.md#where-things-live); for example
`"48h"`, between `"1m"` and `"168h"`) and restart Woodshed. A long timeout doesn't lock devices out: a device that
restarts without closing its connections gets back in by replacing its own idle ones, Woodshed notices a vanished
device within a few minutes (TCP keepalives), and when every connection slot is in use, the one idle longest is
closed to let a new device in.

No device handy? Send a test message from the Woodshed computer:

```sh
woodshed send --message "hello"          # in the portable folder: ./woodshed send ... (woodshed.exe on Windows)
```

If nothing arrives, see [Devices can't reach it](../FAQ.md#devices-cant-reach-woodshed) in the FAQ.

### Sending syslog over TLS

**Sending syslog over TLS.** Use this when a device should encrypt its logs on the way. It's off until you turn it
on.

1. In **Settings → Listeners**, turn on **Syslog over TLS** (TCP port 6514). On Windows, also run `woodshed tls on`
   once in an administrator prompt, so the firewall lets devices in; Settings shows the command if it's needed.
2. Download Woodshed's **CA certificate** from the same section: **PEM** if the device wants the certificate as text
   to paste, **DER (.cer)** if it wants a file to upload.
3. On the device, import it as a **trusted CA certificate** (often called a trust anchor or a CA certificate).
   Compare the fingerprint the device shows with the one in Settings.
4. Point the device's syslog at this computer, **TCP port 6514 with TLS** (the setting may be called secure,
   encrypted or TLS syslog).
5. If the device can check the server's name, give it one of the DNS names Settings lists for the certificate, not
   an IP address: many devices check names only. Then check on the Dashboard that messages arrive.

**Before you turn on TCP or TLS logging on a firewall:** some firewalls block traffic through them when a TCP or TLS
syslog server can't be reached, or its certificate fails, unless a "permit traffic when the log host is down" option
is set. Check that option first.

If a device can't connect, **Settings → TLS** shows each sender's failed handshakes and why: the CA isn't trusted,
there's no TLS version in common, or plain syslog was sent to the TLS port.

To check the setup from another computer before you change a device, send a test message the way a device would,
trusting only the downloaded CA:

```sh
woodshed send --host <this computer's DNS name> --proto tls --ca woodshed-ca.pem --message "hello over TLS"
```

The certificate doesn't change on its own. **Renew** in Settings makes a new one signed by the same CA, so devices
need nothing; **Replace CA** makes a new CA, and every device must import it again. Woodshed warns 60 days before
either expires, and when the computer gets a DNS name the certificate doesn't cover. More in the install guide:
[TLS syslog: firewall and certificate](install.md#tls-syslog-firewall-and-certificate).

### Receiving SNMP traps

Woodshed can also receive SNMP traps and informs (v1, v2c and v3) and keep them beside the device's syslog. It's off
until you turn it on, so an upgrade opens no new port.

1. In **Settings → SNMP traps**, turn the receiver on (UDP port 162). On Windows, also run `woodshed snmp on` once in
   an administrator prompt, so the firewall lets devices in; Settings shows the command if it's needed. On a server
   without a browser, `sudo woodshed snmp on` turns it on (see [the install guide](install.md#snmp-traps-firewall)).
2. Point each device's trap destination (sometimes called a trap receiver, notification target or SNMP manager) at
   this computer, UDP port 162, with the version and credentials below.
3. Make the device send one (many devices have a "send test trap" button; unplugging a cable sends linkDown), then
   open **Events → SNMP traps**.

Port 162 needs the same privileges as 514. Another program often holds it already (an OS trap service, such as
`snmptrapd` on Linux or the **SNMP Trap** service on Windows): the listener banner names the holder. Stop that
service, or pick another port in Settings and set it on the devices too.

**v1 and v2c (communities).** By default every community is accepted. To accept only some, add them under
**Communities** in Settings; a trap with any other community is then refused, counted under **Settings → Refused
senders** (reason "community") and not stored. A community is often also a device's read (or write) password, so
Woodshed never shows or stores it: Settings and the stored traps show only `#` and the first 8 hex digits of its
SHA-256 (`cred=#3f9a1c07`), and the copy of the packet in each record has the community's bytes replaced by `*`.

**v3 (users).** Add each user the devices send as under **v3 users**: the name, the authentication protocol and
passphrase, and the privacy protocol and passphrase (8 to 256 characters each). The passphrases are write-only:
Settings shows only "set". MD5, SHA-1 and DES are labelled weak, because they are, but older gear often has nothing
else, so they're accepted. AES-192 and AES-256 have two incompatible key formats in the wild: if a device's traps
fail with "can't decrypt", switch the user's **key extension** between *draft* (the default) and *alt*. If you list
the **engine IDs** the user's devices use, Woodshed keeps only keys made for those engines and forgets the
passphrases, so a leaked file can't reveal a passphrase used elsewhere; leave the list empty if you add devices
often.

Credentials are never in the config file, on a command line or in an export. They're kept in the data folder, in
`snmp-users.json` (readable only by the service's account) on macOS and Linux, and encrypted for the service's
account in `snmp-users.dat` on Windows. Moving the data folder to another Windows machine leaves the users listed
but unreadable: a banner asks for their passphrases again.

**Informs and the engine ID.** An inform is a trap the device wants acknowledged. Woodshed answers it once the
inform is stored, so an inform is never acknowledged and then lost; a retransmission (the same request within a
minute) is stored again and marked `dup=1`. Replies are limited to 100 a second per sender and 1,000 in all, so a
forged sender address can't use Woodshed to flood someone. For v3 informs, Woodshed's own **engine ID** (shown in
Settings, with a copy button) is the one devices must use; most devices discover it by themselves. Turn **Answer
informs** off to store informs without answering them.

**Names (MIBs).** Woodshed stores OIDs as numbers and adds the names it knows: the standard traps (coldStart,
warmStart, linkDown, linkUp, authenticationFailure), sysUpTime, snmpTrapOID and the interface table. For your
devices' own traps, copy their MIB files (`*.mib`, `*.my`, `*.txt`) into the `mibs` folder in the data folder (or
the folder set in Settings) and press **Reload MIBs**. Woodshed reads only the names and the named numbers from them;
it isn't a MIB compiler. A file that doesn't load is listed with its line number, and the others still load. Events
names every trap from the current MIB set, older ones included.

**If a device sends but nothing shows**, look at **Settings → SNMP traps → Senders with failures** (or
`woodshed snmp status`): it lists each failing sender with the reason, such as an unknown user, a wrong passphrase
("wrong auth"), the wrong security level, or packets that don't decode. Failed and malformed traps are stored too,
with their status, because a device sending broken traps is evidence. A v3 device that restarts without raising its
boot counter would fail the protocol's time check; Woodshed keeps those traps (status `not_in_time`) and relearns the
device's clock, and the list counts each relearning. Set `v3_strict_time = true` under `[listeners.snmp]` in the
config file for the protocol's strict rule instead.

To test from another computer, send traps the way a device would (secrets from files or environment variables,
never on the command line):

```sh
woodshed send --proto trap --host 192.0.2.50 --count 10                          # v2c, community "public"
woodshed send --proto trap --host 192.0.2.50 --snmp-version 3 --user monitor \
    --auth sha-256 --auth-pass-file auth.txt --priv aes-128 --priv-pass-file priv.txt --inform
```

`--inform` waits for each answer and reports the round trips. `woodshed bench --proto trap` measures the whole trap
pipeline on this computer, in a temporary folder.

### Polling devices (SNMP)

Woodshed can also ask the devices you choose for a few numbers every minute: uptime, each interface's traffic,
packets, errors, discards and up/down state, and CPU and memory where the device has them. They're kept as evidence
beside the device's syslog and traps, graphed on its page and on the Events timeline, and a restart or reboot is
marked. It's off until you add a device, and with none added Woodshed sends nothing.

1. Turn on SNMP on the device (read-only is enough: Woodshed only reads, and can't send a `Set`), with a community
   (v1, v2c) or a v3 user, and allow this computer's address.
2. In **Devices**, press **Add polling** on the device's row (its address filled in), or **Add by address** for one
   Woodshed hasn't heard from yet. Pick the version and the community, or a v3 user from **Settings → SNMP traps**
   (the same users the trap receiver uses). If the device sends syslog from one address and answers SNMP on another
   (a management address), put the polled address under address and the syslog address under device, so everything
   stays in one device folder.
3. Press **Test poll**. It runs the poll once, without saving, and shows each step: v3 discovery, the system group,
   HOST-RESOURCES, the interfaces (and whether they have 64-bit counters), and each custom OID. Fix what it reports,
   then **Save**. Polling starts within one interval.

From a terminal, `woodshed poll test 192.0.2.1 --community-file comm.txt` does the same from wherever you run it
(secrets from files or `WOODSHED_SNMP_COMMUNITY`, `_AUTH_PASS`, `_PRIV_PASS`, never on the command line); add
`--version 3 --v3-user monitor --auth sha-256 --auth-pass-file auth.txt --priv aes-128 --priv-pass-file priv.txt` for
v3. It exits 0 when everything answered, 1 for no answer, 3 for an authentication or privacy error and 4 when some
OIDs aren't supported.

**What's polled.** Every 60 s by default (30 s to 10 min per device), with only standard MIBs:
- *system*: `sysUpTime`, and from HOST-RESOURCES `hrSystemUptime`, the processors' load (averaged) and RAM used and
  size. Devices without HOST-RESOURCES show "CPU and memory: not available on this device".
- *interfaces*: for every interface up to the limit (64 by default), the 64-bit in and out octets and unicast,
  multicast and broadcast packets, errors, discards, up/down state and the discontinuity time; names, aliases and
  speeds hourly. A device without 64-bit counters (or SNMPv1) gets the 32-bit ones, and its page warns that rates
  above about 115 Mb/s at a 5-minute interval can be wrong. Over the limit, Woodshed polls the interfaces you
  **pinned**, then the ones that are up, fastest first; the device page says how many were left out.
- *system-info*: `sysName`, `sysDescr` and `sysObjectID`, hourly.
- *custom OIDs* (up to 32 per device): a value (`1.3.6.1.4.1.…0`) or a walk of a table column (up to 128 rows by
  default). Counters become rates; numbers are kept as values; text is kept but not graphed.

**Rates and restarts.** Traffic is stored as bits per second, packets as packets per second and errors as the number
since the last poll, worked out as each answer arrives, with the raw counters on the same line. A 32-bit counter
that went down counts as a wrap only when the result is believable for the interface's speed; anything else (a
counter reset, a renamed interface, a changed discontinuity time, an agent restart) leaves a gap rather than a spike,
marked `disc=1`. When `sysUpTime` goes down (not its normal wrap after 497 days), or goes up clearly less than the
time since the last poll (a second restart soon after the first), the agent restarted; it's a **reboot** when
`hrSystemUptime` went down too. Without HOST-RESOURCES the marker says "the device may have
rebooted". Restarts show on the device page, on the Events timeline and in incident bundles, where a coldStart trap
within 2 minutes of a poll restart is the same reboot.

**When a device stops answering**, each failed poll is recorded with its reason (`timeout`, `auth_failed`,
`unknown_user`, `not_in_time`, …) so "it didn't answer from 10:02 to 10:09" is evidence too. After 3 failures in a row
Woodshed polls it less often, doubling up to every 10 minutes, and goes back to normal at its first answer. After 10
minutes a banner names it. Woodshed accepts answers only from the address and port it polled; an agent that answers
from another address is ignored, and Test poll says so.

**Where it's kept.** Polls are a third kind of record, in `logs/<device>/poll/<day>.log` beside the syslog and
traps, with the same rotation, compression and retention (they count towards the device's share). One device with 24
interfaces at 60 s writes about 17 MB a day uncompressed and about 1.4 MB once the day's file is compressed
(measured, see SPEC §12.11). Search them like anything else: `woodshed search --type poll --field kind=restart --last
7d` lists restarts, and exports and bundles get CSV files per device (`poll/<device>/system.csv`, `interfaces.csv`,
`oids.csv`).

**Settings → Polling** holds the defaults for new devices, how many devices are polled at once (32), the per-device
interface limit and the limit on polled devices (500), and the last hour's cycles, failures and skipped cycles. If
cycles are skipped because polling couldn't keep up, a banner suggests a longer interval or more devices at once.

### Collecting flows

Woodshed can also collect flow records, flow v5 and v9 (RFC 3954) and IPFIX (RFC 7011), so "who talked to whom, on which ports, how
much, and what the firewall denied" around an outage sits beside the device's syslog, traps and polls. It's an
evidence collector for a window of time, not long-term traffic analytics. It's off until you turn it on, so an
upgrade opens no new port.

1. In **Settings → Flows**, turn the listener on: UDP 2055 for flow v5 and v9 and 4739 for IPFIX by default (each port reads
   every version, so an exporter pointed at the "wrong" one still works; set either to 0 to close it). On Windows,
   also run `woodshed flow on` once in an administrator prompt so the firewall lets exporters in (the rules
   "Woodshed flows (UDP 2055)" and "(UDP 4739)" are installed disabled). On a server without a browser,
   `sudo woodshed flow on` turns it on (see [the install guide](install.md#flows-firewall)).
2. On each exporter (a router, a switch, a firewall, or `softflowd` on a Linux host), set the flow exporter or
   collector to this computer and the port, flow v9 or IPFIX if it offers them, v5 otherwise.
3. Open **Events → Flows**. Exporters usually send templates every few minutes, so the first records of a v9 or IPFIX
   exporter can take that long to decode (they wait, and are decoded when the template arrives).

**What's kept.** Each record's addresses, ports, protocol, TCP flags, packets and bytes, interfaces (with names when
the exporter sends them as options data), AS numbers, next hop, VLAN, its flow start and end, and for event-style
firewall exporters the firewall event (`created`, `deleted`, `denied`, …), the NAT event, the post-NAT addresses and
ports, the initiator and responder counters and RFC 5103 reverse counters. Fields Woodshed has no column for,
enterprise-specific ones included, are kept as they came and shown as `pen:id=hex`. The exporter's source address is
the device; the exporter's own address fields are kept but never used to pick the device.

**Sampling is shown, never hidden.** Every record keeps the sampling rate in force when it arrived (`1` unsampled,
`N` for 1 in N, `0` when the exporter said nothing). Counts are shown as exported and, where the rate is known,
scaled: "312 MB exported (≈ 312 GB at 1:1000)". A total that includes records with unknown sampling is a lower bound,
shown with "≥".

**Firewall events without double counting.** Event-style exporters send a record when a connection is created, one
when it's torn down (with its totals), and one for each denied connection. Byte and packet sums count totals only on
the final record (`deleted`), so a connection isn't counted twice; `created`, `update` and `denied` records keep their
counts but add nothing. **Top → Denied** ranks denied sources, destinations, ports and rules (by flows: denials carry
no bytes).

**Rule IDs.** No standard IPFIX field carries an ACL or rule ID; exporters that send one use an enterprise-specific
field. **Settings → Flows** lists each exporter's template fields: find the one that holds the rule (its
`<enterprise number>:<element ID>`), add it under **Rule ID fields**, and new records fill `rule_id` from it (filter
with `rule_id=…`, or Top by rule).

**Time.** Searches use flow time: a record matches a window when its start-to-end overlaps it, so "the flows around
the outage" means when the traffic happened, not when the exporter got round to sending it. A record with only an
event time (a denial) is at that moment. An exporter whose clock is more than an hour off has its records stamped
with the time they arrived (its own times are kept), and a banner names it.

**Waiting and broken data.** Data that arrives before its template waits (up to 32 MiB in all, 1 MiB per exporter,
for the template timeout, 30 minutes) and is decoded with its original time, marked `late`. If the template never
comes, the data is kept undecoded (`status=no_template`), and so are malformed packets (`status=malformed`), never
dropped silently. When the template turns up later in the same hour, searches, Top and exports decode the kept data
on read (marked `late`), and `woodshed reindex --flows-redecode` (with the service stopped) rewrites the segments with
it decoded. Sequence numbers show loss between the exporter and Woodshed: **Settings → Flows** and
`woodshed flow status` give each exporter's gaps, duplicates, late and undecoded counts.

**Where it's kept.** Flows are a fourth kind of data, stored as compact columnar segments, one per device per hour
(`logs/<device>/flows/<YYYY-MM-DD>T<HH>.wsf`), at about 20 bytes a record (an exporter sending 1,000 records a second
writes about 1.7 GB a day). Unlike the other files they aren't plain text: read them through Events, `woodshed
search --type flow`, or an export, whose `flows.csv` is plain text and whose `flows.ipfix` any IPFIX tool reads.
Flows have their own **budget**, 40 % of the storage cap by default (`storage.flow_budget_bytes`): past it the oldest
flows are deleted first, before any other data, and the low-disk guard deletes flows first too, so a busy exporter
can't push out its own syslog. Settings says how many days the budget holds at the current rate.

**From a terminal:**

```sh
woodshed search --type flow --src 10.20.0.0/16 --dst-port 443 --last 1h      # one CSV row per record
woodshed search --type flow --fw-event denied --count --last 24h
woodshed flows top --by src --last 1h                                         # top talkers, exported and scaled
woodshed flows top --by dst-port --fw-event denied --last 24h                 # top denied ports
woodshed flow status                                                          # each exporter's rate, templates, gaps
```

To test from another computer, `woodshed send --proto ipfix --host 192.0.2.50 --count 1000` (or `flow-v9`,
`flow-v5`) sends generated records, `--events` sends firewall-event records, and `woodshed bench --proto ipfix`
measures the whole flow pipeline on this computer, in a temporary folder.

## 3. Watch

The **Dashboard** shows each device as a tile with a coloured dot (green: heard from in the last 5 minutes, amber:
quiet, red: not heard from in an hour), the message rate and disk use, and a **live tail** of the newest messages.
Click a device to follow only that one (click it again to see all), or type in the box at the top to filter
the devices and messages. On the **Devices** page you can give a device a friendly name and a group.

### Dropped messages

The **Dropped** card counts the messages Woodshed received but couldn't store in the last 24 hours, and **About**
splits them by reason: writing paused because the disk is nearly full, a failed write, new senders over the device
limits, or a full UDP queue.

**"UDP messages were dropped in the last hour because writing to disk fell behind"** (a yellow banner): UDP has no
way to tell a device to slow down, so Woodshed reads each UDP message off the network at once and queues it until the
disk takes it. The queue holds 100,000 messages (about 10 seconds at 10,000 messages a second) or 64 MiB. If the disk
stalls for longer than that, new messages are dropped and counted, for their device, instead of vanishing unseen.
What to do:

- Check the disk Woodshed writes to: is it failing, nearly full, or shared with something that writes a lot (a
  backup, an antivirus scan, another log server)? A local SSD is best.
- Look at **About → UDP receive queue**: it shows the most messages waiting at once in each of the last 24 hours. A
  full bar at the same time every day or every hour points at a scheduled job.
- If the stalls are short and expected, give the queue more room: set `udp_queue_messages` (1,000 to 2,000,000) or,
  for large messages, `udp_queue_bytes` (1 MiB to 1 GiB) under `[listeners]` in the config file
  ([where it is](install.md#where-things-live)) and restart Woodshed. The banner names the limit that filled.
- If a device reports missing messages while this queue never fills, they were lost before Woodshed read them: in the
  computer's network buffer (see the receive buffer on **About**) or on the network. Use TCP or TLS for devices where
  every message matters.

The banner goes away an hour after the last drop. When Woodshed stops, it first stores what's in the queue.

## 4. Find the log files

Every message is kept, exactly as it arrived, in plain text: one folder per device and one file per day (UTC).
Older days are compressed (`.log.gz`). SNMP traps go in a `traps` folder inside the device's folder, with the same
file names, so the syslog files hold only syslog. Each trap is one line: the received time, the sender and the
decoded trap, for example

```
2026-11-14T09:30:58.112Z 192.0.2.1 v=2c pdu=trap id=4711 cred=#3f9a1c07 status=ok uptime=8641234 trap=1.3.6.1.6.3.1.1.5.3(linkDown) vb=1.3.6.1.2.1.2.2.1.8.3(ifOperStatus.3):int:2(down) raw=MIGTAgEB…
```

with the version, the PDU, the community hash or v3 user, the status, the trap, one `vb=` per value (OID, name,
type, value), and `raw=`, the whole packet in base64 (the community masked).

| | Installer | Portable |
|---|---|---|
| Windows | `C:\ProgramData\Woodshed\logs\` (open it as an administrator) | `woodshed-data\logs\` next to `woodshed.exe` |
| macOS | `/Library/Application Support/Woodshed/logs/` (needs `sudo`) | `woodshed-data/logs/` next to `woodshed` |
| Linux | `/var/lib/woodshed/logs/` (needs `sudo`) | `woodshed-data/logs/` next to `woodshed` |

By default Woodshed keeps 30 days or 20 GB, whichever comes first, and never fills the disk, counting syslog and
traps together. Change it in **Settings → Storage**.

## 5. Events: browse and filter everything stored

**Events** shows every stored message, not just the live tail: all devices, all days, older compressed days
included. It opens on the last hour, newest first. Leave the text box empty to browse, or narrow it down:

- **Text**: lines containing it. The switch beside the box says how it's read (see below); **Aa Case** matches upper
  and lower case exactly.
- **Program/tag**: the program or tag in the message header, such as `sshd` or `kernel`. Separate several with
  commas. End one with `*` to match the start (`ssh*`, `%FW-6-*`); the leading `%` of a tag is optional.
- **Host**: the hostname in the message header, such as `web-01`. To pick by sender address, use the device menu.
- **Exclude**: leave out lines matching this. The Text, Terms or Regex switch and Case apply here too.
- **Devices**, **time range**, **severities** and **oldest or newest first**.

Press **Search** (or Enter) to apply. Click a value in the **Host** or **Program/tag** column to add it to that
filter. Click a line to see the lines around it.

### Text, Terms or Regex

- **Text** (the default): the box is one piece of text, found anywhere in the message. `deny tcp` finds exactly
  that phrase.
- **Terms**: words and `"quoted phrases"`, each found anywhere in the message, joined by `AND`, `OR` and `NOT`.
  Two words side by side mean AND. `NOT` applies to the term right after it, then AND, then OR, so
  `a OR b c` means "a, or both b and c". Use `( )` to group: `deny AND (tcp OR udp) NOT 10.0.0.1`.
  - Only upper-case `AND`, `OR` and `NOT` are operators; `and`, `or` and `not` are ordinary words. To search for the
    word AND itself, quote it: `"AND"`.
  - Quote a term that has spaces or brackets in it: `"(pid 312)"`. Inside quotes, write `\"` for a quote and
    `\\` for a backslash. A quote inside a word is ordinary, so `user="bob"` is one word.
  - `NOT x` on its own finds every line without x.
  - Up to 32 words and phrases and 8 levels of brackets. A mistake is shown under the box with its position, for
    example `Missing ")" for the "(" at character 6.`
  - Only the words and phrases that aren't under a NOT are highlighted.
- **Regex**: a regular expression (RE2 syntax), such as `deny (tcp|udp)`.

### Fields

The **Fields** panel beside the results counts, for the current search and time range, the values of each field:
device, severity, facility, host and program/tag. Each field shows its top 10 values (severity and facility show
every value that appears), then how many others there are.

- Click a value to show only lines with it. Values of one field add up (this host or that one); different fields
  narrow each other (this host and this program).
- **Alt-click** (Option-click on a Mac) a value, or press its **−** button, to leave it out instead. The **+** button
  does the same as a click, for touch screens and the keyboard.
- The filters you've added are shown as chips at the top of the panel. Click one to remove it.
- **(none)** counts lines with no hostname or program/tag in their header. It can't be clicked: no filter picks
  those lines yet.

The counts are exact, never estimated. Woodshed reads the matching lines newest first and says how much it has
counted so far: "Counted 14:02–15:00 of 12:00–15:00" means every line from 14:02 on is counted. It keeps counting
for up to a minute of scanning; on a long range over busy devices it then stops and offers **Count the rest**. A
narrower range, or fewer devices, makes it faster.

### Histogram

Above the results, a histogram shows the matching lines over time. The bar size depends on the range: 1-minute bars
for the last hour, 15-minute bars for 24 hours, 2-hour bars for 7 days. Hover over a bar to see its time and count.

- **Drag across the bars** (or click one) to search just that stretch of time. Your browser's **Back** button zooms out
  again.
- Without text, program/tag, host, facility or severity filters, the histogram comes straight from the index and is
  complete at once ("from the index"). Bars that are estimated from the index say "≈" when you hover over them.
- With filters, the histogram fills in as the lines are counted, newest first. Bars that aren't counted yet are
  hatched.

### Saved searches

The **Saved** menu keeps searches on the server, so everyone who can open this Woodshed sees the same list.

- **Save as…** names the current search (up to 80 characters; names are unique, ignoring case). It keeps the text and
  how it's read, the devices, filters, severities, order and time range. A quick pick like "1 h" stays relative: it
  means the last hour whenever you open it. The raw view and line wrapping aren't saved.
- Click a saved search to open it. The form shows its name, and **changed** once you edit something; **Save** then
  updates it.
- Each saved search has buttons to copy a link to it, rename it and delete it.
- A saved search never changes behind your back. If a device it names is no longer known (forgotten, say), it's shown
  struck through as "no longer known" and the search runs with the rest. A device that sends again is found again.
- They're kept in Woodshed's index, which `woodshed reindex` keeps. Up to 200 can be saved.

The search, including the time range you dragged to and the saved search you opened, is part of the page's address,
so you can bookmark a view or send the link to someone. Links to the old **Search** page (`#/search`) still work.

From the Dashboard, **Open in Events** on the live tail opens Events with the same devices, severities and text,
over the last hour.

When the SNMP receiver is on (or traps are stored), a switch at the top picks **Syslog** or **SNMP traps**. For traps,
each result shows the time, the device, the trap name and its values on one line; click it for the decoded trap
(every value with its name) and the traps around it. The fields panel lists the trap's own fields: version, PDU, trap,
enterprise, generic and specific trap (v1), community or user, and status. The text box searches the decoded trap,
never the base64 copy. Trap filters take numbers or names: **Trap** `linkDown`, or `1.3.6.1.4.1.32473.*` for every
trap under an enterprise.

### Searching from the command line

`woodshed search` runs the same search from a terminal, on every OS, with the UI off, in LAN mode, or with the
service stopped. It reads the data folder directly (compressed days included) and never writes to it, so it's safe
beside the running service. It needs the rights to read that folder: `sudo` (or the service account, `sudo -u
woodshed`; `_woodshed` on macOS) on macOS and Linux, an administrator prompt on Windows. A portable copy searches the
`woodshed-data` folder next to it.

```
sudo woodshed search "link down"                          # the last 24 hours, oldest first
sudo woodshed search --last 1h --devices 192.0.2.10 --severities 0,1,2,3
sudo woodshed search --terms 'deny AND NOT 203.0.113.7' --app '%FW-*' --context 3
sudo woodshed search --from "2026-11-14 08:00" --to "2026-11-14 09:00" --json > morning.ndjson
sudo woodshed search --field host=edge-fw-01 --not-field severity=7 --count
```

- **What to find:** the text (`QUERY`) means what it means in Events: plain text by default, `--terms` for Terms,
  `--regex` for Regex, `--case` to match case, `--exclude TEXT` to leave lines out.
- **Filters:** `--devices`, `--group`, `--ungrouped`, `--exclude-devices`, `--severities`, `--facilities`, `--app`,
  `--host` and their `--exclude-` forms, exactly as in Events. `--field KEY=V1,V2` and `--not-field KEY=V1,V2` take
  any field Events lists (device, severity, facility, host, app). Devices are given by address (`192.0.2.10`,
  `2001:db8::5`).
- **Time:** `--last 15m|1h|24h|7d` (the default is 24 hours), or `--from` and `--to` as RFC 3339
  (`2026-11-14T09:30:00Z`), your local time (`"2026-11-14 09:30"`, or UTC with `--utc`), `now`, or `-15m`.
- **Order and amount:** oldest first, like a log file (`--order desc` for newest first); every match unless
  `--limit N`. There's no time limit: Ctrl-C stops it and keeps what was printed.
- **Output:** each match as its stored line (`<received> <device> <message>`, one line per match, safe to pipe into
  grep); `--raw` prints only the message, as it arrived; `--json` prints one JSON object per line, like the API;
  `--context N` adds N lines before and after each match from the same file, with `>` before each match and `--`
  between groups; `--count` prints only the number. A summary, `N matches, M MiB read from F files in Ts`, goes to
  standard error, so standard output holds only matches.
- **Exit status:** 0 when something matched, 1 when nothing did, 2 for a mistake in the command (the message names
  the flag, or the character position in the query), 3 when the data folder can't be read, 4 when there's no data
  folder or index, 130 after Ctrl-C.

- **Traps:** `--type trap` searches the SNMP traps, with their fields: `--field trap_oid=linkDown`,
  `--field status=auth_failed`, `--not-field version=1`, `--field cred=monitor`. Syslog's flags (`--severities`,
  `--app` and so on) don't apply to traps, and say so. `--json` prints each trap decoded, like the API.

```
sudo woodshed search --type trap --last 1h --field trap_oid=linkDown,linkUp
sudo woodshed search --type trap --field 'trap_oid=1.3.6.1.4.1.32473.*' --devices 192.0.2.10 --json
```

Run `woodshed search --help` for every flag.

## 6. Export logs for support

To send logs to someone (a colleague, a vendor's support team):

1. In **Events**, click **Export these results** (the zip holds what the page shows, filters included); or open
   **Export** and pick the devices, the time range and any filters.
2. Click **Build the zip**, wait until it's ready, then click **Download**.
3. Attach the zip to your email or ticket.

The zip holds the log lines (plain text, one file per device per day), a manifest with line counts and checksums,
Woodshed's own events for that time (so the reader can tell "the device sent nothing" from "Woodshed wasn't
running"), and a short README. Exports are deleted after 24 hours.

**Types** picks what the zip holds: syslog (the default), SNMP traps, or both. Traps go in a `traps` folder in the
zip, and the README explains the trap lines. Filters apply to one type at a time, so with both types the zip holds
everything in the range. ("Export these results" from Events with SNMP traps showing exports the traps.)

### Incident bundles

When something happened at a known time (a link went down, a firewall rebooted, users lost the VPN at 09:42), an
**incident bundle** collects the evidence around it in one zip: every record Woodshed stored in a window around the
moment, syslog and SNMP traps, from every device that sent anything then, with a summary per device at the top of the
README. It needs no filters: it's everything around the moment, so nothing that turns out to matter is left out.

Start one from:

- **Events:** click a line, then **Bundle around this** (or right-click the line); the moment is that line's received
  time. Or click **Bundle around a moment** above the histogram, then click the time you want on it.
- **Export → Around a time:** type the moment in your local time or in UTC (the same Local/UTC switch as the time
  range), and pick the window: 15 min before and 5 after, 30 min / 10 min (the default), 1 h / 15 min, 4 h / 1 h,
  24 h / 1 h, or **Custom**. Then **Build the bundle**, or **Preview in Events** first.

The preview is Events itself, showing the bundle's window: the histogram and the fields panel (so you can see what's
there), the devices that sent anything in it with their counts, and the size estimate. Drag across the histogram to
narrow the window, untick devices to leave them out, then click **Build the bundle**. Text or field filters typed
there change only what's shown: the bundle always holds everything in the window. It builds in Export's list like
any export (marked **Bundle**), and is deleted 24 hours after it's ready.

The README starts like this (the times are UTC; the header gives your local offset):

```
Incident bundle around 2026-11-14 09:42:00 UTC (30 min before, 10 min after)
Window: 2026-11-14 09:12:00 to 09:52:00 UTC (local time UTC-05:00)
Devices: 2, every device that sent anything in the window. Types: syslog, SNMP traps.
Communities in traps are shown as a hash prefix and masked in raw=, by design.

edge-fw-01 (192.0.2.1), group HQ
  Syslog       2,408 messages, first 09:12:00.014, last 09:51:59.880
               crit 2, err 41, warning 310, notice 1,022, info 1,033 (none of emerg, alert, debug, unknown)
  SNMP traps   7: linkDown 3, linkUp 3, coldStart 1; first 09:30:11.000, last 09:31:02.000
  Reboots      1: 09:30:58.250 (coldStart trap)
  Gaps         none of 1 s or more (Woodshed and its listeners were up the whole window)
  Losses       dropped 0, truncated 0 (Woodshed's own counts; kernel UDP drops aren't visible on this OS)

core-sw-02 (192.0.2.2)
  Syslog       318 messages, first 09:12:04.120, last 09:51:40.007
               ...
```

- **Reboots** come from coldStart and warmStart traps, so they show only for devices that send traps.
- **Gaps** are the times Woodshed wasn't running or a listener was down, from Woodshed's own events, so "the device
  sent nothing" can be told apart from "Woodshed wasn't listening".
- **Losses** are what Woodshed itself dropped or cut short (a full queue, a paused disk, an over-long message).

The zip also has the records (`logs/<device>/<day>.log` for syslog, `traps/<device>/<day>.log` for traps),
`manifest.json` with every file's SHA-256 and the summary as JSON, and `woodshed-events.log`.

**From the command line,** `woodshed bundle` builds the same zip from the data folder, with the service running or
stopped, the UI off or in LAN mode. Like `woodshed search` it only reads the data folder and needs the rights to read
it (`sudo`, or an administrator prompt on Windows). It's the one command to ask a remote colleague for:

```
sudo woodshed bundle --at "2026-11-14 09:42"                        # 30 min before, 10 after, every active device
sudo woodshed bundle --at -15m --before 1h --after 15m --group HQ  # around 15 minutes ago, the HQ group's devices
sudo woodshed bundle --at 2026-11-14T14:42:00Z --devices 192.0.2.1,192.0.2.2 --types syslog
sudo woodshed bundle --at now --before 4h --after 0s --out edge-reboot.zip
```

- `--at` takes RFC 3339 (`2026-11-14T14:42:00Z`), your local time (`"2026-11-14 09:42"`, or UTC with `--utc`), `now`,
  or `-15m`. `--before` and `--after` take `15m`, `1h`, `1h30m`, `7d` or `0s` (up to 7 days each). The window ends at
  now at the latest.
- The devices: every device that sent anything in the window (the default, `--active`), `--devices` (by address,
  silent or hidden ones too), `--group` or `--ungrouped`. `--types syslog,trap` limits the types (default: every type
  with data in the window).
- The zip is written to the current folder as `woodshed-bundle-<host>-<time>.zip` unless `--out` names it, and an
  existing file is never overwritten.
- It prints the zip's path, its size and SHA-256, the window, and one line per device:

  ```
  /home/admin/woodshed-bundle-logs-01-20261114T144200Z.zip
    1.2 MiB (1,262,431 bytes), SHA-256 4f1c…
    2026-11-14 14:12:00 to 2026-11-14 14:52:00 UTC: 2,733 records from 2 devices (syslog, SNMP traps)
    edge-fw-01 (192.0.2.1), group HQ: syslog 2,408, SNMP traps 7, reboots 1, dropped 0, truncated 0
    core-sw-02 (192.0.2.2): syslog 318, SNMP traps 0, reboots 0, dropped 0, truncated 0
    gaps: none of 1 s or more (Woodshed and its listeners were up the whole window)
  ```
- **Exit status:** 0 when the zip was written, 1 when the window held nothing (and no zip is written), 2 for a mistake
  in the command or when the `--out` file already exists, 3 when the data folder can't be read, 4 when there's no
  data folder or index, 130 after Ctrl-C (the partial zip is removed).

Run `woodshed bundle --help` for every flag.


## 7. Updates

The first time you open the UI, a banner asks whether Woodshed may check for new versions once a day.
**Turn on** lets it fetch one public file a day (nothing about your installation is sent); **No thanks** keeps it
off and it won't ask again. You can change this in **Settings → Updates**, which also shows the last check. When a
newer version is out, a banner links to its release page. Woodshed never updates itself: to upgrade, download the
new installer from the releases page and run it, and your settings and logs are kept.

## 8. Stop or remove it

- **Portable:** close its window (or press Ctrl-C). Your logs stay in `woodshed-data`.
- **Installer:** see [Uninstall](../FAQ.md#how-do-i-uninstall-it) in the FAQ. Uninstalling keeps your logs unless
  you ask for them to be deleted.

Other machines can't open this page unless you turn on **LAN mode** (Settings → UI access), which needs a password
and uses HTTPS. See the [FAQ](../FAQ.md#can-i-open-the-ui-from-another-computer).
