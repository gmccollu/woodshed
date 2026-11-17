# Woodshed — v1 spec (draft)

Woodshed is a syslog server you can install on any Windows, macOS or Linux machine in a minute. It stores
every message it receives as plain files, keeps them within a disk budget, and has a clean web UI for
watching, searching and exporting logs.

Status: draft for review. Decisions marked **(decided)** came from the project owner. Those marked
**decided (coordinator, date, owner-delegated)** are calls the coordinating agent made under the owner's delegation;
the owner can still overrule them. Everything else is a proposal and can change.

## 1. Goals and non-goals

**Goals**
- Simple install: one installer per OS, it runs as a service, and it listens straight away with no setup.
- Reliable: it never silently loses data it can see, never fills the disk, and survives reboots.
- Portable logs: plain text files that any tool (grep, an editor, a SIEM import) can read, and a one-click
  export for sending to someone else.
- A UI that's pleasant to look at and fast to read.
- A codebase that's easy to extend (TLS, alerts and forwarding are next).

**Non-goals for v1**
- Not a SIEM: no correlation, dashboards-as-code or long-term analytics.
- No multi-user accounts or roles.
- No forwarding or relaying to other systems.
- No outbound network connections of any kind **(decided)**. 1.1 adds one exception, the opt-in update check (§10.2)
  **(decided, 2026-11-13)**.

## 2. Decisions so far

| Topic | Decision |
|---|---|
| Platforms | Windows, macOS and Linux at equal polish in v1 **(decided)** |
| UI access | Bound to localhost by default. Optional LAN mode, which requires a password and HTTPS **(decided)** |
| Storage | Plain files per device per day, plus a small SQLite index for time ranges **(decided)** |
| v1 scope | Core server, dashboard and live tail, search and export zip **(decided)** |
| Throughput | 10,000 msg/s sustained on 4 cores / 8 GB / SSD with no drops **(decided)** |
| Device identity | Source IP, with a friendly name and group set in the UI **(decided)** |
| Repo / license | Personal github.com account, MIT **(decided)** |
| Device config helper | Not in v1 **(decided)** |
| Telemetry / updates | None. No outbound connections; the version and a releases link are shown in the UI **(decided)**. From 1.1: still no telemetry, plus an opt-in update check that asks once, makes one plain HTTPS GET of the public releases file a day when on, and never downloads or installs anything (§10.2) **(decided, 2026-11-13)** |
| Update check details (1.1) | `updates.check` = ask / on / off, `ask` on fresh installs, upgrades and portable; the URL is the existing Pages file `releases.json`; User-Agent `Woodshed` with no version; no query, cookies or conditional headers; proxy from the environment; no redirects; only `internal/updatecheck` may dial (§10.2) **decided (coordinator, 2026-11-13, owner-delegated)** |
| TLS syslog (1.1) | Off by default, one Settings switch, TCP 6514 by default (port configurable) **(decided, 2026-11-13)**. TLS 1.2 and 1.3 (1.0/1.1 only behind `allow_legacy_tls`); no SNI, ALPN or client certificate needed; Woodshed's own RSA-2048 CA and leaf (until 2037-12-31, the leaf 10 y at most), changed only on an explicit renew; the same framing and limits as TCP; the MSI ships its firewall rule disabled, and `woodshed tls on` enables it (§10.3); the details are **decided (coordinator, 2026-11-13, owner-delegated)** |
| Events v2 (1.1) | Field panel and histogram over the same files and index. Field counts are exact over a stated span (newest first), never sampled. The histogram comes from the stats and checkpoints when the query is unfiltered, from the same scan otherwise. Boolean terms only with `syntax=terms`, so 1.0 links keep their meaning. Saved searches live in `index.db`. Every endpoint takes `type` (only `syslog` in 1.1) (§10.1) **decided (coordinator, 2026-11-13, owner-delegated)** |
| Data types (1.2) | Traps get their own files in `logs/<device>/traps/`, same naming and line envelope; syslog's files are unchanged; one retention and disk guard over every type (§11.1) **decided (coordinator, 2026-11-14, owner-delegated)** |
| SNMP traps (1.2) | UDP 162, off by default; v1, v2c, v3 USM (MD5, SHA-1, SHA-2; DES, AES-128/192/256); informs answered once stored; communities stored as a hash prefix and masked in the raw PDU; identity by source IP; v3 credentials in DPAPI on Windows, a 0600 file on macOS and Linux (§11.2) **decided (coordinator, 2026-11-14, owner-delegated)** |
| Incident bundle and CLI search (1.2) | The bundle is an export (`kind: "bundle"`) with per-type folders, syslog kept in `logs/`; `woodshed search` and `woodshed bundle` read the data folder directly and read-only (§11.3, §11.4) **decided (coordinator, 2026-11-14, owner-delegated)** |
| UDP queue (1.2) | A bounded queue per UDP socket (100,000 messages / 64 MiB), drops counted as `queue_full`; readers never touch the disk (§11.5) **decided (coordinator, 2026-11-14, owner-delegated)** |
| SNMP poller (1.3) | A third data type `poll` (text lines in `logs/<device>/poll/`), rates computed at write time with raw counters kept; restarts and reboots from sysUpTime, hrSystemUptime and engineBoots; targets configured per device with credentials in the 1.2 store; graphs on the Events timeline and a device page panel; three CSVs per device in bundles (§12) **decided (coordinator, 2026-11-15, owner-delegated)** |
| Flows (2.0) | Flow v5/v9 and IPFIX on UDP 2055/4739, off by default; a fourth data type `flow` in columnar segments (`logs/<device>/flows/<day>T<hour>.wsf`) with block indexes; flow-time queries, top-N with exported and scaled counts; a flow budget (40 % of the cap); CSV and IPFIX files in the zip; a setup helper named by syntax family, never by vendor (§13) **decided (coordinator, 2026-11-16, owner-delegated)** |
| First run | Zero-config: listens immediately, and the UI opens on a welcome page **(decided)** |
| Port 514 in use | The listener fails with a clear error; the UI still starts and explains the clash **(decided)** |
| UI port | 8514 on localhost (§5) **(decided)** |
| Linux UDP buffer | The deb/rpm raises `net.core.rmem_max` to 32 MiB through a sysctl drop-in (§3.1) **(decided)** |
| Rotation | Close at 100 MiB or midnight UTC, gzip, keep 30 days / 20 GB (§3.4) **(decided)** |
| Sizes | "GB" in this spec means GiB (1 GiB guard floor, 20 GiB cap) |
| Low-disk reserve | max(1 GiB, min(5% of the volume, 10 GiB)): 1 GiB on a 10 GB volume, 5 GiB on 100 GB, 10 GiB on 460 GB and 4 TB (§3.4) **(decided, 2026-11-11)** |
| Retention fairness | Over the size cap or under the low-disk reserve, delete first from devices first seen in the last 24 h, then from established devices over their share, then oldest-first. Shares split the cap by each device's average bytes a day over the last 7 days (1 KiB floor; no share below a tenth of an equal split). Every device established for over 24 h keeps its last min(retention days, 2) calendar days; the size cap never takes them, the low-disk guard only once every newer device's data is gone. A device sending over half of the last 24 h's bytes gets a warn event, at most hourly (§3.4) **(decided, 2026-11-11, revised for rc2)** |
| Devices cleanup | A device with no files left, no name, no group and not hidden, quiet for 24 h, is forgotten: index row, folder, and its exemption from the new-sender rate **(decided, 2026-11-11)** |
| `reindex` as root | Refused when the data folder belongs to another user; run it as that user (`sudo -u woodshed woodshed reindex`). Index files that are links or not regular files are refused **(decided, 2026-11-11)** |
| New-sender limits | At most 10,000 *active* senders (`max_devices`): a sender quiet for 10 min has its file closed early (its next message appends to the same file) and its memory freed, so the cap counts senders heard in about the last 10 min. Senders with no logs yet also need a token, first from their network's bucket (a /24, or a /48 for IPv6: burst 256, then 20 a minute), then from the global one (burst 5,000, then 200 a minute), so one network can't keep everyone else out and a new install on a 5,000-device network admits everyone at once; random sources spread over many networks can still drain the global bucket, and the sender allowlist is the answer to that. A sender with logs on disk is always admitted: at the cap it takes the least recently heard sender's slot (that sender's file is parked, not lost). While the cap is full, known senders that aren't in memory are readmitted at up to 500 a second (each evicts the least recently heard sender, whose file is parked); beyond that they're refused (reason `churn`); a sender already in memory is never refused. The cap and the global bucket are live settings. Refused messages count as dropped and raise the `device_limit` banner **(decided, 2026-11-11)** |
| Checkpoints | Every 1 MiB, or every minute once 64 KiB has been written since the last one |
| Durability | Plain `fsync` on every OS (on macOS that survives process and OS crashes, not necessarily power loss) |
| Late messages | A message for a day that's already closed goes into the current file with its own timestamp; files never reopen |
| Hidden devices | Stay hidden if they send again; the Devices page's hidden list shows their last-heard time |
| Stats | Per-minute buckets for 24 h, hourly buckets for 7 days |
| File modes | Log files 0640, directories 0750 |
| UDP buffer on macOS | macOS refuses (rather than caps) requests above `kern.ipc.maxsockbuf` (8 MiB), so the listener steps down to the largest size accepted. 10k msg/s passes with 8 MiB |
| Rejected/drop counters | Hourly buckets; "24 h" is the current hour plus the 23 before it. A refused TCP connection counts once |
| Live-tail sampling | Token bucket, 50 lines/s per subscriber; `sampled.rate` is that subscriber's matching rate |
| Measured (M1, a 14-core laptop) | 10k msg/s for 30 s over UDP, TCP-LF and TCP-octet: 300,000 sent, 300,000 on disk, 0 missing each. Zero loss up to 60k msg/s (UDP) and 100k (TCP) |

## 3. Architecture

A single Go binary with the web UI embedded (`embed.FS`). There's no runtime, database server or separate
frontend install.

```
 UDP :514 ─┐
           ├─> parse (PRI, timestamps; raw always kept) ─> per-device router ─> buffered writer ─> logs/<device>/<day>.log
 TCP :514 ─┘                                   │                                   │
                                               ├─> live hub (ring buffer) ─> SSE ─> UI live tail
                                               └─> stats (per-device counters)      └─> index (SQLite: file, time ranges, offsets)
 background: rotator ─> gzip ─> retention (age + disk cap + low-disk guard)
 HTTP :8514 ─> REST API + embedded UI
```

**Proposed libraries** (pure Go, no cgo, so every target cross-compiles from one runner):
- `modernc.org/sqlite`: SQLite with no cgo.
- `github.com/kardianos/service`: one API for Windows services, systemd and launchd.
- The standard library for networking, HTTP, gzip and zip.
- Our own small syslog parser: it's lenient by design, and existing libraries reject too much.
- Frontend: Svelte 5 + Vite + Tailwind, built into `web/dist` and embedded. The bundle stays small and there's
  no virtual-DOM cost for the live tail.

### 3.1 Listeners
- UDP and TCP on 514 by default. Both ports and bind addresses can be changed in config.
- TCP framing: auto-detect octet-counting (RFC 6587 §3.4.1) or newline-delimited (LF, CRLF or NUL), per
  message. A frame counts as octet-counted when it starts with up to 10 digits, a space and `<`. After a
  connection's first octet frame, the `<` check is dropped for that connection. This keeps a newline-framed line
  starting with "123 " from being read as a count.
- **Incomplete frames (2.0, decision 79):** an octet-counted frame that ends before its advertised length is kept as
  far as it arrived and marked incomplete, with both lengths (`\#incomplete=9/50` on its line, §3.3), whoever ended
  the connection: the sender's close, a reset, a TLS close, the frame timeout, an eviction or shutdown. Each TCP and
  TLS listener counts them (`/api/stats` `tcp_frames`). A frame of which only the count arrived has nothing to keep and
  is only counted. A newline-framed message is marked incomplete (with no lengths) only when Woodshed closed the
  connection mid-line; a sender's last line without its LF at close is a complete message, because non-transparent
  framing (RFC 6587 §3.4.2) can't tell it from one that was cut. From 1.0 to 1.3 a frame its sender cut short was
  stored with nothing to say so, and one Woodshed cut was counted as truncated.
- Max message size is 64 KiB. Anything longer is truncated and counted (`truncated` counter), never dropped; from 2.0
  its line is marked `\#truncated` too. `truncated` counts only this: an incomplete frame isn't in it.
- TCP idle timeout: a connection with no complete message for 24 h is closed (`tcp_idle_timeout`, 1 min to 7 days).
  It was 10 min in 1.0.0, but some senders keep one connection without keepalives, notice it was closed only when a
  later write fails, and lose what they send until they reconnect. Eviction doesn't wait for it: when all connection
  slots are taken, the one idle longest (over 30 s) goes; at the per-address (or IPv6 /64) limit, a newcomer evicts
  its own source's connection idle longest (over 30 s, with no message in progress) instead of being refused, so a
  sender that rebooted without closing its connections isn't locked out. TCP keepalives are on (first probe after
  15 s idle, 9 probes 15 s apart), so connections to a vanished sender close within minutes **(decided (coordinator, 2026-11-13, owner-delegated), 1.0.1)**.
- UDP socket receive buffer: ask for 32 MiB. On Linux the kernel caps this at `net.core.rmem_max`, so the deb/rpm
  installs `/etc/sysctl.d/60-woodshed.conf` raising it to 32 MiB, and removes it on uninstall **(decided)**. On
  every OS, log the buffer size we actually got at startup and show it on the About page.
- Bind address: wildcard (`0.0.0.0` and `::`) by default. On macOS a non-root process may bind ports below 1024
  only on the wildcard address, not on a specific IP (tested on macOS 27.2, see §5). So on macOS a specific bind
  address with a port below 1024 is refused with a clear error; use the sender allowlist to restrict senders.
- **Port clash:** if a bind fails, that listener doesn't start. The service keeps running so the UI can show a
  red banner: which port and protocol, the OS error, the process holding it where the OS lets us find out, and
  how to fix it. A "Retry" button rebinds without restarting the service.
- Optional sender allowlist (CIDRs). It's empty by default, meaning everyone is accepted. Rejected senders are
  counted per IP and shown in the UI.

### 3.2 Parsing
- Parsing only adds metadata: facility, severity, device timestamp, hostname, app. **The raw message is always
  stored exactly as received.**
- Supports RFC 5424, RFC 3164 and common non-compliant variants (missing PRI, odd timestamps, BOMs). If parsing
  fails, the message is stored raw with severity "unknown".
- A fuzz test (`go test -fuzz`) runs on the parser in CI.

### 3.3 Storage layout
```
<data>/
  woodshed.toml            config (Linux: /etc/woodshed/woodshed.toml instead)
  index.db                 SQLite: devices, files, time-range checkpoints, stats
  logs/
    10.1.0.1/
      2026-11-10.log       today's file (open)
      2026-11-09.log.gz    rotated and compressed
      2026-11-08.001.log.gz  size-split parts (each closed at 100 MiB)
    fd00_1__5/             IPv6 addresses with ':' replaced by '_' (Windows-safe)
  exports/                 generated zips, deleted after 24 h
```
- Default data dirs: Windows `C:\ProgramData\Woodshed`, macOS `/Library/Application Support/Woodshed`, Linux
  `/var/lib/woodshed`.
- **Line format:** `<received UTC, RFC 3339 with ms> <sender IP> <raw message>`, one line per message. Embedded
  CR/LF in a message is escaped as `\r` / `\n` so one message is always one line. Example:
  `2026-11-10T20:41:07.112Z 10.1.0.1 <134>Nov 10 20:41:07 edge-fw-01 conn opened tcp ...`
- **Marker (2.0, decision 79):** a message that wasn't stored whole ends its line with a blank, `\#` and its flags,
  comma-separated: `truncated` (cut at the max message size), then `incomplete=A/L` (an octet-counted frame that
  ended with A of its advertised L bytes; A counts bytes past the max size too) or `incomplete` (a line Woodshed cut;
  the length isn't known). For example `... <13>short \#incomplete=9/50` or `... \#truncated,incomplete=70000/100000`.
  The escaping writes a backslash after a blank only as `\\`, `\n` or `\r`, so ` \#` can't come from a message; the
  marker isn't part of the raw message, and readers ignore flags they don't know. A reader before 2.0 shows it as
  text at the end of the message. A whole message has no marker, so its line is exactly as in 1.x.
- Files use the received time in UTC, because device clocks are often wrong or in local time. The device's own
  timestamp stays inside the raw message.
- Writes are buffered per device and flushed every 1 s or 1 MiB, whichever comes first; fsync every 5 s. If the
  process crashes we lose at most about 5 s of data, and that is documented.

### 3.4 Rotation, compression, retention
- Each device writes one plain active file. It's closed when it reaches **100 MiB** (configurable) **or** at
  00:00 UTC, whichever comes first. The midnight close keeps each file inside one day, so "logs from Tuesday"
  is a file-name lookup.
- A background worker gzips each closed file at low priority, then verifies the gzip before deleting the
  original. Only the active file per device is uncompressed.
- Retention applies to the compressed files. Defaults: **30 days or 20 GB total on disk, whichever comes first**
  **(decided)**. Age: every compressed file older than 30 days goes. Size: while all logs exceed the cap, delete
  in **fair-share** order.
  1. Devices first seen in the last 24 h, oldest file first: a flood of new senders pays first, however it's spread.
  2. Established devices over their share, the most over first, oldest file first. Shares split the cap by each
     device's average bytes a day over the last 7 days (from the stats, which outlive the files; 1 KiB floor, and no
     share below a tenth of an equal split), so a long-established busy device gets a large share and junk senders
     little.
  3. Everyone, oldest file first.

  Every device established for over 24 h keeps its last min(retention days, 2) calendar days (today included): the
  size cap never takes them, so it can be exceeded by them; the low-disk guard takes them only once every newer
  device's data is gone. Active (and parked) files are never deleted by the size cap. A device that sent more than
  half of the last 24 h's bytes is reported with a warn event, at most once an hour.
- Rotated files use gzip (`.log.gz`) rather than `.zip`. gzip streams, so search reads it without unpacking, and
  it's the standard for rotated logs. Exports are `.zip` (§4.1) because that's what people open by
  double-clicking.
- Low-disk guard: if free space on the data volume falls below the reserve, max(1 GB, min(5% of the volume,
  10 GB)), delete closed files until it's back above, in the same fair-share order. If that isn't enough, close the
  largest active files as parts and delete those too, rather than pausing until midnight (only when that can
  reach the reserve). The 10 GB cap keeps a large disk from reserving tens of
  GB it never needs (on a 460 GB disk, 5% alone paused writes with 24 GB still free). If nothing is left to
  delete, pause writing, count the dropped messages, and show a red banner that states the reserve. Never fill
  the disk.
- Every deletion is recorded in `index.db` (file, reason, time) and shown in Settings → Storage history.

### 3.5 Index
- One row per file: device, path, first and last received time, size, line count, compressed or not.
- Checkpoints every 1 MiB or 1 minute: (time, byte offset, uncompressed). Search and export use them to jump
  to a time range instead of scanning from the start.
- The index can be rebuilt from the files (`woodshed reindex`), so the files are always the source of truth.

### 3.6 Live hub and stats
- An in-memory ring buffer holds the last 5,000 messages. The UI live tail uses SSE with server-side filters
  (device, group, severity, text).
- Above about 50 lines/s the server sends a sample and an "N msg/s, showing a sample" notice, so the browser
  never falls behind. Pause freezes the view; the server keeps receiving.
- Per-device counters (messages, bytes, truncated, last heard) go into `index.db` in 1-minute buckets and are
  kept for 7 days for the sparklines.
- **Drop counting, honestly:**
  - We count every message we drop ourselves (disk guard, write errors).
  - On Linux we also read the kernel's UDP drop counter for our socket (`/proc/net/udp`).
  - On Windows and macOS kernel UDP drops aren't visible to us. The UI says so instead of showing a reassuring 0.

## 4. Web UI

The visual style follows the mockup (`design/mock.html`): soft glass cards, rounded tiles, light and dark
modes. **Log text is never on glass:** the live tail, search results and file viewer use a solid background,
monospace text, high contrast and severity colors.

| Page | Contents |
|---|---|
| Welcome (first run) | "Woodshed is listening": this machine's IPs, ports and protocols, listener status, a test command to send a message from this machine, and a link to the dashboard once the first message arrives |
| Dashboard | Stat cards (msg/s with a 1 h sparkline, devices online/quiet, disk used against the cap with days kept, dropped messages); device tiles (name, IP, a green/amber/red last-heard dot, msg/min); group tabs; the live tail |
| Devices | Table of all senders: rename, set group, show first/last seen and totals, "forget" (hides the device; its logs are kept until retention deletes them) |
| Search | Text (case-insensitive substring; a toggle for regex), devices/groups, time range, severity. Results stream in, capped at 10,000 with "load more". A context view shows ±50 lines around a hit |
| Export | Pick devices and a time range, then build a zip (see 4.1). Lists recent exports for download |
| Settings | Listeners (ports, bind address, allowlist), storage (folder, retention, part size, storage history), UI access (LAN mode, password, certificate), quiet thresholds |
| About | Version, build, OS, data folder, socket buffer achieved, a link to the releases page |

Quiet status defaults: green when heard within 5 min, amber up to 1 h, red after that. All three are
configurable.

### 4.1 Export zip
- Only the raw log lines in the chosen range, one file per device per day. They're decompressed so whoever
  receives them can read them straight away.
- `manifest.json`: Woodshed version, export time, range, devices (IP, name, group), per-file line count and
  SHA-256, and any gaps in range (for example "listener down 14:02–14:09", from the service's own event log).
- `woodshed-events.log`: the service's own events in the range (restarts, rotations, deletions, drops, bind
  errors). This way the recipient can tell "the device sent nothing" apart from "Woodshed wasn't running".

## 5. Security
- The UI is on `127.0.0.1:8514` by default **(decided)**. 8514 is unassigned in the IANA registry (checked
  2026-11-10), isn't on the browsers' blocked-port list (Chrome loaded a page on it), and was free on the test
  Mac. If it's taken at start-up, the service logs the error and `woodshed status` prints it.
- **LAN mode** (off by default):
  - Turning it on requires setting a password first (hashed with Argon2id).
  - The UI moves to HTTPS with a self-signed certificate generated on the machine. A user certificate can be
    loaded instead.
  - Sessions use secure, HttpOnly, SameSite=Strict cookies, with CSRF tokens on every change.
  - Login is rate-limited and locks out for a while after 10 failures.
- The REST API and UI share the same authentication. There are no unauthenticated routes in LAN mode except
  login and a static health check.
- Export and file routes accept only IDs from the index, never paths, so path traversal isn't possible.
- The service runs with the least privilege each OS allows:
  - Linux: a `woodshed` system user with `CAP_NET_BIND_SERVICE` for port 514.
  - Windows: a virtual service account (`NT SERVICE\Woodshed`) with write access only to its data folder.
  - macOS: a launchd daemon running as a dedicated `_woodshed` user. Tested 2026-11-10 on macOS 27.2 as an
    ordinary user: binding 514 on `0.0.0.0` and `::` succeeded over both UDP and TCP; binding 514 on `127.0.0.1`
    or the en0 address failed with "Permission denied". So the dedicated user works with the default wildcard
    bind. Confirmed in CI (2026-11-11, macos-latest): the launchd daemon as `_woodshed` binds UDP and TCP 514 on the
    wildcard. With the application firewall on, it reports the binary as permitted; no prompt appears headless.
    A prompt for a logged-in user on an unsigned binary is still unverified.
- No outbound connections, no telemetry, no update checks. The CI test suite asserts that no code path dials
  out. From 1.1 the one exception is the opt-in update check (§10.2): tests assert that nothing else dials out, and
  that it doesn't either unless it's on.

## 6. Packaging and install

| OS | Package | Service | Notes |
|---|---|---|---|
| Windows | MSI (WiX v5) | Windows service, auto-start, restart on failure | Adds firewall rules for 514 UDP/TCP only; the UI port isn't opened unless LAN mode is turned on. Also published to winget and Scoop |
| macOS | `.pkg` (pkgbuild/productbuild) | launchd daemon | Universal binary (arm64 + x86_64). Also published as a Homebrew tap |
| Linux | `.deb`, `.rpm`, tarball | systemd unit | `amd64` and `arm64` |

- Builds run on GitHub Actions from a tag. GoReleaser OSS handles the binaries, nfpm (deb/rpm), Homebrew,
  Scoop and checksums. The MSI and `.pkg` are built in separate jobs on Windows and macOS runners (GoReleaser's
  MSI support is a paid feature).
- Signing: none at first. Add macOS signing and notarization and Windows signing (a free open-source signing
  program, or a cloud signing service) before promoting it widely. Until then the README documents the
  Gatekeeper and SmartScreen prompts.
- Uninstall stops and removes the service but **keeps the logs** unless the user ticks "also delete logs".
- Upgrade in place: the config and data folder are kept, and the index schema migrates on start.
- CLI on the same binary: `woodshed run|install|uninstall|status|reindex|send|bench|version`.

## 7. Quality bar
- Unit tests for the parser (plus fuzzing), framing, rotation and retention (with a fake clock and fake disk
  space), the index and export.
- Integration test: send 1M messages over UDP and TCP from the built-in `woodshed send` tool and check that the
  counts on disk match exactly, including across a forced rotation and a service restart.
- Benchmark: `woodshed bench` sustains 10k msg/s for 10 minutes with zero drops on the reference spec. It runs
  in CI on every release tag, and the results are recorded in the release notes.
- CI runs on Linux, Windows and macOS runners. The installers are installed, started, sent messages and
  uninstalled on each runner (an install smoke test).
- A 24 h soak test before v1.0: steady load, a forced low disk, a listener port clash, and a reboot.

## 8. Milestones
1. **M0 Skeleton:** repo, CI matrix, the binary serves the embedded "hello" UI, `woodshed run`.
2. **M1 Core server:** listeners, parser, per-device files, rotation, gzip, retention, disk guard, index,
   events log, `send` and `bench`.
3. **M2 UI:** welcome page, dashboard, devices, live tail, settings, light and dark.
4. **M3 Search and export.**
5. **M4 Installers:** MSI, pkg, deb/rpm, service install, upgrade and uninstall, install smoke tests in CI.
6. **v1.0:** soak test, docs (README, install per OS, FAQ), first tagged release.

### 8.1 M4 status (2026-11-11)
Proven in CI on GitHub-hosted runners (`.github/workflows/install-smoke.yml`; on each: least-privilege account,
UDP/TCP 514, the UI, 10,000 messages on disk exactly once, restart, uninstall keeping data, delete-logs removing it):
- deb (Ubuntu, systemd, `CAP_NET_BIND_SERVICE` only), rpm (Fedora 41 container with systemd as PID 1), MSI
  (`NT SERVICE\Woodshed`, protected ACL, 514-only firewall rules, event log, v0.0.1→v0.0.2 major upgrade), pkg
  (launchd as `_woodshed`), and `woodshed install` / `uninstall` on all three OSes, which now matches the packages.
- UI shutdown with an idle connection: 5.0 s → 0.14 s.
- 2 h soak on macOS at 3,000 msg/s: 21.6M sent, every message on disk except the 183,000 counted as dropped during
  a forced low-disk pause (exactly equal), 0 duplicates; RSS 31→37 MiB (peak 45), 19–23 open files.

Still unproven:
- Inbound traffic from another host through the OS firewalls (CI used loopback).
- A real reboot; the 24 h soak (§7); a midnight crossing on the real binary (no fake clock in the binary).
- arm64 packages; the macOS firewall prompt for a logged-in user; `reset-password` restarting a real service.

## 9. Roadmap (after v1)

**Scope rule:** Woodshed is an *evidence collector for troubleshooting*: it collects, keeps, searches and exports what
network devices send, so it can be handed to whoever is helping. It isn't a monitoring system, a flow-analytics
product or a SIEM. Each new data type has to fit that rule (decided 2026-11-11).

### 1.0.1
- **TCP idle timeout from 10 min to 24 h** (to build on main). Today `DefaultIdleTimeout = 10 * time.Minute`
  (`internal/listen/listen.go:31`) closes a TCP connection that hasn't completed a message for 10 min. Some senders
  send no keepalives and notice a closed connection only when a write fails. They lose that message, and some
  firewalls block traffic at that moment, because a failed write to a TCP log host counts as "host down".
  - Raise the default to 24 h, configurable as `listeners.tcp_idle_timeout` (file-only like the other TCP limits;
    1 min to 7 d). The same value applies to the TLS listener (§10.3).
  - Slots are still freed under pressure: when `MaxConns` are open, the existing eviction closes the connection idle
    longest (idle over `EvictIdle`, 30 s).
  - A longer timeout lets stale connections fill a sender's own per-source limit (32) when it reboots without closing
    them. So at that limit, the newcomer evicts that sender's own connection idle longest (over `EvictIdle`) instead
    of being refused. Server-side TCP keepalives (Go's default on accepted connections) stay on, so a half-open
    connection to a rebooted sender still closes within minutes.
  - Tests: a quiet connection survives 23 h on a fake clock; eviction still works when `MaxConns` are full; a source at
    its limit with stale connections is let in.

### 1.1
- Events v2 (field panel, histogram, boolean terms, saved searches), the opt-in update check, and TLS syslog
  (RFC 5425, TCP 6514), designed in §10.

### 1.2
All of it is designed in §11 **(owner, 2026-11-14: all of these in 1.2, with thorough testing)**.
- **Pluggable data types:** generalise the pipeline (listener → per-device store → index → search → export) so
  each data type adds its own listener, record format, UI tab and export section, with syslog as the first.
  Devices stay keyed by source IP across types. Events v2 already takes a `type` (§10.1.6).
- **SNMP trap receiver** (UDP 162; v1, v2c, and v3 with user-configured credentials stored like the UI password).
  Traps are stored decoded as text lines, with varbinds and the raw PDU, in the same per-device, per-day files. No
  MIB compiler in the first version; numeric OIDs, plus an optional folder of MIB files for names. §11 refines two
  points: traps get their own per-device, per-day files in a `traps/` folder inside each device's folder (§11.1), and
  v3 secrets are encrypted rather than hashed, because the receiver has to use them (§11.2.6).
- **Incident bundle** (owner, 2026-11-14): pick a moment, get the evidence around it.
  - Started from Events ("Bundle around this" on a line, or a point on the histogram), from Export ("Around a time")
    and from the CLI: `woodshed bundle --at <time> --before 30m --after 10m [--devices …|--group …] [--out file.zip]`,
    so a remote helper can ask for one command and one zip.
  - Window presets: 15 min before / 5 after, 1 h / 15 min, 4 h / 1 h, 24 h / 1 h, or custom; local or UTC input.
  - Devices: chosen ones, a group, or every device that sent anything in the window.
  - Before building, Events shows the window (histogram, field panel) so it can be narrowed first.
  - The zip: one folder per data type (syslog now; traps in 1.2, poll data and reboot markers in 1.3, flows in 2.0),
    the manifest with SHA-256s, and a `README.txt` summary per device: counts by severity, first and last message,
    gaps when Woodshed wasn't running, reboots detected, and drops or truncations in the window.
  - Later, maybe: an offline `timeline.html` in the zip, and a prompt when a device reboots or goes quiet.
- **Command-line search** (owner, 2026-11-14): `woodshed search "<q>" [--regex|--terms] [--from … --to …|--last 1h]
  [--devices …] [--severities …] [--app …] [--host …] [--context N] [--json]` prints matching lines to stdout using
  the same engine as Events (compressed days included, only the files that cover the range). Native on every OS, for
  headless boxes, scripts and remote sessions; it reads the data folder directly (it needs the same rights as
  `reindex`), so it works with the UI off or in LAN mode.
- **UDP receive off the write path:** today the UDP reader writes each message itself, so a slow disk (fsync,
  rotation) backs up into the OS socket buffer, where loss isn't counted on Windows or macOS. Hand messages to a
  bounded queue and count drops when it's full, so every loss Woodshed causes shows in `dropped_24h`. A 2026-11-12 lab
  soak on Windows lost ~20 per million UDP in bursts near the top of the hour; the cause wasn't found in Woodshed.

### 1.3
Designed in §12.
- **SNMP poller ("OID watcher")**, moved up from 2.0 (owner, 2026-11-13). It collects evidence, so it's small and
  fixed:
  - It polls a small fixed set every 30–60 s: sysUpTime; IF-MIB in/out octets (the HC counters), errors and
    discards; CPU and memory through HOST-RESOURCES-MIB where the device supports it.
  - Each device can add a list of custom OIDs. The presets stay vendor-neutral.
  - Counters are stored as rates in a small per-device time-series store, with the same retention as the logs.
  - They're shown as graphs on the Events timeline, for the same window.
  - A drop in uptime is detected as a reboot, and marked on the timeline and in the export.
  - Poll data is included in the export zip.
- Security:
  - It polls only addresses the user configured.
  - v2c communities and v3 auth/priv keys are encrypted at rest with the OS key store where there is one (DPAPI on
    Windows, the 0600 service-account file on macOS (§11.9)), and otherwise kept in a file only the service account
    can read. 1.2's trap receiver settles how on each OS (§11.2.6): macOS uses the file, because the Keychain needs
    cgo.
  - SECURITY.md's outbound rule gains "SNMP polls to devices you configure".
- Out of scope: discovery, topology, polling hundreds of OIDs, threshold dashboards, a MIB browser.
- It shares the SNMP library and the v3 credential handling with the 1.2 trap receiver, which is why it comes after
  it.

### Later 1.x (not yet ordered)
- Alerts: device quiet, error-rate spike, disk filling, drops (email and webhook). Simple thresholds only.
- Device identity by hostname as an option, for relayed traffic.
- Forwarding to another collector; RELP.
- Signed installers.

### 2.0
Designed in §13.
- **Flow collector (flow v5, v9 and IPFIX)** (UDP 2055/4739, configurable): template handling per exporter and
  observation domain, compact columnar storage per device per hour, retention and the disk guard shared with
  syslog. Search by time, IPs, ports and protocol; simple top-talker and top-port views for a time window;
  windowed export (CSV or IPFIX file). No long-term flow analytics, baselining or anomaly detection.
- **The export zip covers every data type**: syslog, traps, polls and flows for the chosen devices and window, with
  one manifest.
- Device setup helper (generated logging, trap and flow-export config per vendor).

### After 2.0 (candidates)
- **sFlow** as a fifth data type: packet samples and counter samples, which many switches export instead of
  flow v5/v9 or IPFIX (§13.11).

### Out of scope
- SIEM features: correlation rules, threat detection, compliance reporting, case management.
- Full network monitoring: discovery, topology, general-purpose SNMP polling (beyond the 1.3 poller's small set),
  dashboards-as-code.

## 10. 1.1 design (draft, 2026-11-13)

Three features: Events v2 (§10.1), the opt-in update check (§10.2) and the TLS syslog listener (§10.3). Owner decisions are marked **(decided)**; the delegated calls are
listed in §10.4. The API contract is in `docs/api.md` (each feature's own section).

### 10.1 Events v2

Everything here reads the same stored files and the existing index (file rows, checkpoints, minute and hourly
stats). There's no new index type and no query language beyond the boolean terms in §10.1.3 (the §9 scope rule).

**New filters**, on search, the summary, export and saved searches (the live tail is unchanged in 1.1):
- `facilities=0,4,16,unknown`: like `severities` (0–23, `unknown`, `none`), read from the PRI.
- `exclude_devices`, `exclude_app`, `exclude_host`: the opposites of `devices`, `app` and `host`, with the same
  matching rules. When a value is both included and excluded, the exclusion wins.
- Severity and facility are excluded by sending the complement set, so they need no exclude parameter.
- `syntax=text|terms` (§10.1.3) and `type=syslog` (§10.1.6).

#### 10.1.1 Field panel
A panel beside the results lists, for the current query and range, each field's top values and their counts:
device, severity, facility, host (the header hostname) and program/tag. The server lists the fields and how each maps
to a filter (`GET /api/search/schema`); the client has no field list of its own, so a new data type brings its own
fields (§10.1.6).
- Clicking a value adds it as a filter. Values of one field OR together, and different fields AND together.
  Alt/Option-click, or the row's "−" button, excludes the value. Each row also has a "+" button, for touch and
  keyboard. Clicking an active filter's chip removes it. Clicking a value twice doesn't cycle through states: a
  click that does something different each time is easy to get wrong.
- Lines with no hostname or program/tag are counted as "(none)". That row isn't clickable, because no filter can
  express it yet.
- Each field shows up to 10 values (`top`, at most 50), then "N others" and the number of distinct values. Severity
  and facility show every value that has a count.

**Counts are exact over a stated span; they're never sampled and never shown with "≈".** One scan, using the search
engine, reads newest first and counts every matching line. Each response covers `[counted_from, to)` exactly, and the
panel says so ("Counted 14:02–15:00 of 12:00–15:00"). The UI keeps asking with the cursor, as search does, for up to
60 s of scanning per query, then offers **Count the rest**. Why exact:
- The counts are evidence. "web-01 sent 1,204 of these" has to match what Export puts in the zip, and a scaled
  sample can't be checked against it.
- Sampling fails on the query troubleshooting runs most: a rare string in a busy day. A fixed sample finds 0–3 hits
  and scales them into noise. The scan's cost is the bytes it reads, not the number of matches, so a sample saves
  little exactly where it's needed.
- Reading newest first makes a partial answer useful: the last hour of a 24 h range is counted first, and its counts
  are exact.
- The cost is that a busy server takes many budgets over a long range. The panel states its span instead of hiding
  it, the fix is a narrower range or fewer devices, and the histogram is instant for unfiltered queries.

The summary tracks at most 10,000 distinct values per field. After that, new values count under "others"
(`distinct_capped`).

#### 10.1.2 Histogram
A histogram above the results shows the matches per time bucket for the current query. Dragging across it selects a
range, snapped to bucket edges, and runs the search on that range. The range goes into the URL, so Back zooms out.

The bucket size depends on the range (`to − from`), giving at most 120 buckets:

| Range up to | Bucket | | Range up to | Bucket |
|---|---|---|---|---|
| 2 min | 1 s | | 30 h | 15 min |
| 10 min | 5 s | | 5 d | 1 h |
| 30 min | 15 s | | 10 d | 2 h |
| 2 h | 1 min | | 30 d | 6 h |
| 10 h | 5 min | | 120 d | 1 d |
| | | | longer | 7 d |

So the presets get: 15 min → 15 s buckets (60 bars), 1 h → 1 min (60), 24 h → 15 min (96), 7 d → 2 h (84). The
default 1 h view is on whole minutes, so it can use the stats. Buckets start at multiples of their size since the
Unix epoch, in UTC (7 d buckets start on Monday 00:00 UTC). The first and last buckets count only lines inside
`[from, to)`. `bucket=` overrides the size with one from the table, up to 1,000 buckets.

The histogram has two sources:
- **The index** (`source: "index"`), when the query is unfiltered and the bucket is at least 1 min. Unfiltered means
  no `q`, `exclude`, `app`, `host`, their exclude forms, or facility or severity filter. A device selection (devices,
  group, ungrouped, `exclude_devices`) still counts as unfiltered, because the stats are per device. No log file is
  read, so it answers in milliseconds and is complete in the first response.
  - Buckets in the last 24 h come from the per-minute stats. Buckets of 1 h or more in the last 7 d come from the
    hourly stats.
  - Anything older comes from the files' checkpoints (stats are kept for 7 d, logs for 30 d by default), and so does a
    minute-sized bucket older than 24 h. The lines between two checkpoints (and between the last one and the file's
    last received time) are spread evenly over that time. With 1 d buckets this is exact, because files never cross
    midnight UTC and each file's row has its line count; only the first and last buckets, where `from` and `to` cut a
    day, can be approximate. An approximate bucket carries `approx: true`, and the UI shows "≈" in its tooltip.
  - Stats outlive the files that retention deletes. For each device, stats from before its oldest remaining file are
    left out (search would find nothing there), and the bucket that straddles that point is taken from the
    checkpoints.
  - Hidden devices follow search's device selection, and the `_refused` counter is never included.
- **A scan** (`source: "scan"`) otherwise. It's the same scan as the field panel's (one pass feeds both), with the
  same budget, cursor and `counted_from`. Buckets older than `counted_from` are `null` and are drawn hatched, as "not
  counted yet".

#### 10.1.3 Boolean terms
`syntax=terms` turns `q` (and `exclude`) into terms joined by AND, OR and NOT, with parentheses and quoted phrases.
The default stays `syntax=text`, the 1.0 meaning: `q` is one substring, so `deny tcp` still matches only that phrase.
Every existing link, bookmark, export and "Open in Events" keeps its meaning. The UI's Regex toggle becomes a
three-way switch, **Text | Terms | Regex** (`re=1` or `syn=terms` in the page URL).

Why a parameter, rather than switching it on when the query contains operators: syslog text is full of the words and
characters such a rule would key on ("NOT FOUND", `"GET /index.html"`, `(pid 312)`), so a 1.0 link could silently
change meaning. A parameter is explicit, is kept in saved searches, and costs one toggle.

Grammar (whitespace separates tokens):
```
expr   = or
or     = and { "OR" and }
and    = unary { [ "AND" ] unary }        (two terms side by side mean AND)
unary  = "NOT" unary | atom
atom   = word | phrase | "(" expr ")"
phrase = '"' { any character except '"' and '\' | '\"' | '\\' } '"'
word   = a run of characters other than whitespace, '(' and ')', not starting with '"'
```
- Precedence: NOT, then AND, then OR, each left to right. `a OR b c` means `a OR (b AND c)`.
- Only the upper-case words `AND`, `OR` and `NOT` are operators; `and`, `or` and `not` are ordinary terms. To search
  for the word AND, quote it: `"AND"`.
- Each word and phrase is a substring of the raw message, matched exactly as text mode matches `q`:
  case-insensitive unless `case=true` (which applies to every term), with the same Unicode folding. A phrase is one
  substring, spaces included: `"deny tcp"` in terms mode equals `deny tcp` in text mode.
- Outside quotes, `(` and `)` always group. Quote a term that contains them (`"(pid 312)"`). A `"` inside a word is
  an ordinary character, so `user="bob"` is one word.
- `NOT x` on its own is allowed and matches every line without x. An empty `q` matches everything, as now.
- `regex=true` together with `syntax=terms` is a 400. RE2 already has alternation, and a regex inside the term
  grammar would need quoting rules of its own (regex terms like `/…/` aren't in 1.1, §10.4).
- Limits: 32 words and phrases, parentheses nested up to 8 deep, and 4 KiB of `q`.
- Errors are 400s that give a 1-based character position. For `exclude`, the message starts with `exclude: `.
  - `Unclosed quote starting at character 12.`
  - `Unmatched ")" at character 20.` / `Missing ")" for the "(" at character 3.`
  - `"OR" at character 9 needs a term on both sides.` (the same for AND)
  - `"NOT" at character 30 needs a term after it.`
  - `Empty phrase at character 5.` / `Empty parentheses at character 5.`
  - `Too many terms (40); the limit is 32.` / `Parentheses nested deeper than 8.` / `The query is longer than 4 KiB.`
  - `Terms and regex can't be combined: pick one.`
- Highlighting marks the words and phrases that aren't under a NOT.
- Implementation note: the escaped-bytes prefilter uses the longest term that every match must contain (a positive
  term on the top-level AND chain), when there is one.

#### 10.1.4 Saved searches
Saved searches are named and stored on the server, so everyone who can open the UI shares them (there are no
accounts).
- A saved search holds every Events parameter:
  - `type`, `q`, `syntax`, `regex`, `case` and `exclude`;
  - the device selection (`devices`, `group`, `ungrouped`, `exclude_devices`);
  - `severities`, `facilities`, `app`, `exclude_app`, `host`, `exclude_host` and `order`;
  - the range: relative (`{"last": "1h"}`, from 1 min to 400 d) or absolute (`from`, `to`). Saving a preset range
    saves it as relative.

  Display settings (the raw view) aren't saved.
- Limits: 200 saved searches. A name is 1–80 characters after trimming, unique ignoring case. A saved search is
  validated like `/api/search`, so a bad regex can't be saved.
- They're stored in `index.db`, in a new `saved_searches` table (a schema migration on start), not in the TOML.
  - Device names, groups and hidden flags already live in `index.db`, and `reindex` keeps them. Saved searches are the
    same kind of user data. `reindex` rebuilds only the files and checkpoints tables.
  - Each save is one row in one transaction. In the TOML, every save would rewrite the user's config file and change
    the settings ETag, so someone with Settings open would get a 409 because someone else saved a search. On Linux the
    TOML is in `/etc/woodshed`, which config-management tools often overwrite.
  - The cost: deleting `index.db` loses them, as it loses device names. Each saved search has **Copy link**, and the
    API returns plain JSON for a backup.
- **Deleted devices:** a saved search keeps the device IDs it was saved with, and Woodshed never edits it behind the
  user's back. Device IDs are source IPs, so a forgotten device that sends again matches again.
  - Until then, the API lists the IDs it can't find (`missing_devices`), the UI shows them struck through as "no
    longer known", and the search runs with the rest.
  - If every named device is gone, the selection matches nothing, as `/api/search` does today. It never widens to all
    devices. A group with no devices left behaves the same way (`missing_group: true`).
- UI: a **Saved** menu on Events (open, save, save as, rename, delete). Opening a saved search fills the form and the
  URL with its parameters, plus `saved=<id>`. **Save** updates it, and the form shows "changed" once it differs.

#### 10.1.5 Load
- A summary request has its own budget (`budget_ms`, 2 s by default, at most the 10 s search budget), so the panel
  updates every couple of seconds.
- The running counts stay on the server for 10 min after the last request, for at most 8 summaries, least recently
  used out first. A cursor whose counts are gone gets a 400, and the UI starts again.
- At most 2 summary scans run at once. The others wait within their own budget and return what they have. Result
  searches never wait for summaries.
- A summary stops when its HTTP request is cancelled. The UI cancels it on every new query.

#### 10.1.6 Other data types
1.2 adds SNMP traps, and 2.0 adds flows, "under the same hood" (§9). Events v2 is shaped so that they plug in without
breaking the API.
- **Shared:**
  - the time range and the received-time order;
  - device selection by source IP;
  - the budget, cursor and partial rules;
  - the histogram (counts per bucket), with its index and scan sources;
  - the summary response's shape and the field descriptors;
  - saved searches (`type` plus `query`).
- **Per type:**
  - the record format and its parser;
  - what `q` matches (for a trap, its decoded text line; flows may have no free text);
  - its fields and their filter parameters, listed by `GET /api/search/schema` (for example trap OID and SNMP
    version, or protocol and port);
  - its stats, for the index histogram;
  - how its records show in the results.
- Every endpoint takes `type`, defaulting to `syslog`. 1.1 accepts only `syslog`; anything else is
  `400 type: unknown data type "x"`. A saved search's `query` is validated by the rules of its type. The first step
  in 1.2 is a second entry in the schema's list.
- 1.3's poll graphs aren't a searchable type: they sit on the histogram's time axis, for the same window and with
  the same bucket table. (Superseded by §12.3: poll lines are a searchable type; the graphs sit on the axis as described.)

### 10.2 Opt-in update check

**(decided, 2026-11-13: off until the user agrees; it asks once; a plain HTTPS GET of the public releases list; it
never downloads or installs anything.)** When it's on, Woodshed fetches the project's public releases file once a day.
If there's a newer version, it shows a banner that links to that version's release page.

**Asking.** `updates.check` is `"ask"`, `"on"` or `"off"`.
- The default is `"ask"`: for fresh installs, for upgrades from 1.0 (their config has no `[updates]`), and in portable
  mode.
- While it's `"ask"`, nothing is fetched, and `/api/status` carries the info banner `update_prompt`: "Check for new
  Woodshed versions once a day? It fetches one public file from gmccollu.github.io and sends nothing about this
  server." It has two buttons, **Turn on** and **No thanks** (action `update_choice`). Either answer is written to the
  config, and the banner doesn't come back. Settings → Updates has the switch either way.
- Portable mode asks too. A portable copy on a laptop is the one most likely to stay on an old version, and the answer
  is saved in its own folder.
- To decide for many machines, set `[updates] check = "off"` (or `"on"`) in `woodshed.toml` before the first start.
  There's no banner then.
- Silent fleet installs set it at install time with `WOODSHED_UPDATE_CHECK=on|off|ask` (**decided (coordinator, 2026-11-13, owner-delegated)**):
  - MSI: a public property, `msiexec /i woodshed_X.Y.Z_windows_amd64.msi /qn WOODSHED_UPDATE_CHECK=off`.
  - pkg, deb and rpm: an environment variable the install script reads, as in
    `sudo WOODSHED_UPDATE_CHECK=off apt install ./woodshed_X.Y.Z_amd64.deb`.
  - When it's set, the installer runs `woodshed update-check <value> --config <path>` (a new admin command, like
    `lan-mode`, which also serves headless servers), on a fresh install and on an upgrade alike: an explicit choice
    wins. When it isn't set, the config is left alone. An invalid value is ignored with a warning in the install log;
    it never fails the install, because a half-configured deb is worse than a missing setting.
  - The install smoke tests check each one. Whether macOS `installer` passes the variable through to the pkg's
    scripts, and `sudo` and dpkg to the deb's, is an acceptance item for the 1.1 build (§10.4); if `installer`
    doesn't, the pkg documents pre-seeding the TOML instead.
- A build whose version isn't a release (`0.0.0-dev` from `make build`), or that has no `releases_url`, never checks
  and never asks. Settings says "Not available in this build".

**The request.**
- The URL is `https://gmccollu.github.io/woodshed/releases.json`, a constant in `internal/updatecheck` that can't be
  configured. Why this file and not the GitHub API:
  - It already exists. `pages.yml` writes it from the releases API on every release change and daily, for the
    website's download section. `site/tools/releases.mjs` gives it the shape `{generated_at, stable, prerelease}`, each
    a release with `tag_name`, `html_url`, `published_at` and its assets, or `null`. The checker reads only `stable`
    and `prerelease`, and from each only `tag_name` and `html_url`.
  - It's static, about 8 KB, cached by a CDN, and has no API rate limit. The anonymous API allows 60 requests an hour
    per IP, so a shared company egress address with a few installs and browsers would run out, and the check would
    fail. This is the same reason `pages.yml` gives for writing the file at all.
  - Its schema is ours. `releases.mjs`'s output becomes a contract: those keys stay, and a test in `site/test` pins
    them.
  - The trade-off: a Pages outage or a failed deploy makes checks fail or lag by a day. Both are visible in Settings,
    and both are harmless.
- It's a plain `GET`: no query string, no cookies (no cookie jar), no `Authorization`, and no `If-None-Match` or
  `If-Modified-Since` (an ETag can work as an identifier). The only headers are `Host`, `User-Agent: Woodshed`,
  `Accept: application/json` and `Accept-Encoding: gzip`.
- **The User-Agent is `Woodshed`, with no version.** The comparison is local, so the server never needs the version. A
  version in every daily request would let the host count installs per version and see who's behind on fixes; a bare
  name doesn't. Go's default `Go-http-client/1.1` would be just as anonymous, but it hides what's calling; naming it
  is more honest to whoever reads the proxy logs.
- Proxy: it honours `HTTPS_PROXY` / `https_proxy` and `NO_PROXY` (Go's `ProxyFromEnvironment`). The service sees only
  variables set in its own environment (systemd `Environment=`, the launchd plist, the Windows service's environment).
  The OS's system proxy settings aren't read, and the FAQ says so.
- TLS uses the system's roots, version 1.2 or later, and there's no option to skip verification.
- Redirects aren't followed; a redirect is an error. The URL is a contract and must not move: a custom domain for the
  site would have to keep this path answering.
- Limits: a 10 s timeout for the whole request and a 1 MiB response, JSON only.
- It has its own `http.Transport` and `net.Dialer` in `internal/updatecheck`, the only package allowed to connect to a
  host that Woodshed picks itself.

**Schedule.**
- The first check runs 2–10 min (at random) after start-up. If one ran in the last 24 h, the next is due 24 h after
  it instead. The last check's time is kept in `<data>/update-check.json` (mode 0640).
- After that, checks run every 24 h ± 1 h, picked at random each time. After a failure it retries once 1–2 h later,
  then waits for the next daily check.
- Turning it on checks within a minute. **Check now** in Settings runs a check (at most once a minute). Turning it off
  cancels the next check and clears the banner.
- Each check is logged in the service log (time and result), not in the events log.

**The result.**
- Versions are compared as SemVer, without the `v`. An identifier such as `rc10` compares its letters, then its
  number, so `rc10` is newer than `rc9`.
- A release build looks at `stable`. A prerelease build also looks at `prerelease`. If either is newer than the
  running version, the newer of the two counts as available.
- When one is available, an info banner `update_available` appears: "Woodshed 1.2.0 is available (this is 1.1.0)." It
  can be dismissed and has a link (`url`) to the release page.
  - The link must be `releases_url + "/tag/" + tag_name`. If `html_url` says anything else, it's ignored, and the
    banner links to `releases_url`.
  - Woodshed writes the text from the parsed version alone, and nothing else from the file is shown, so a tampered
    file can't put words or links in the UI.
- Dismissing the banner hides it for that version, for everyone (kept in `update-check.json`). A newer version shows
  it again.
- Settings → Updates shows the switch, the URL, the last check (its time and result: "OK, 1.1.0 is the latest", or the
  error), the next check, and **Check now**. A failure shows only there, as in "Last check failed 3 h ago: TLS
  certificate not trusted (a proxy that inspects HTTPS?)". The error kinds are `dns`, `connect`, `proxy`, `tls`,
  `timeout`, `http_status`, `redirect`, `too_large`, `bad_json` and `no_release`.

**Tests.**
- `internal/api`'s `TestNoClientNetworkAPIs` and `TestNoHandlerDialsOut` stay as they are, on the default config
  (now `"ask"`).
- A new module-wide static check: only an allowlist of packages may use the client-side network and process APIs that
  `TestNoClientNetworkAPIs` forbids, namely `internal/updatecheck` plus the packages that use them today
  (`internal/loadgen` for `woodshed send` and `bench`, `internal/peer` for loopback to the local Woodshed, and the OS
  helpers in `internal/listen`, `internal/service`, `internal/fwrule` (the TLS listener's host-firewall rule, §10.3.6;
  added at the TLS merge, TLS decision 11) and `cmd/woodshed`). Adding a package to it is a reviewed change.
  The releases host appears in no other package.
- A new runtime test, `TestOnlyUpdateCheckDials` in `internal/server`. It runs the real server with a fake clock, the
  default transport and resolver hooked as in `TestNoHandlerDialsOut`, and the checker's dialer pointed at a local TLS
  server.
  - With `"ask"` and with `"off"`: 3 simulated days with every route exercised (the new ones too) make 0 dials and 0
    lookups.
  - With `"on"`: exactly one request inside the start-up window, then one every 24 h ± 1 h. Each is
    `GET /woodshed/releases.json` with an empty query and exactly the headers above, and nothing else dials or looks
    anything up.
  - Turning it off while it waits: no further request. A restart within 24 h of a check: no start-up check.
  - With `HTTPS_PROXY` set, the one connection is a `CONNECT gmccollu.github.io:443` to the proxy. With a matching
    `NO_PROXY`, it goes direct.
  - Bad responses (a redirect, 1 MiB + 1 byte, not JSON, an off-site `html_url`, no release) give an error in
    Settings, no banner, and no retry beyond the one.

**Doc wording** (applied in the PR that ships the checker, build 2026-11-13). Apply this in the PR that ships the checker, not before. While 1.0 is the latest release, its docs
have to keep saying that it makes no outbound connections, and SECURITY.md's policy covers the latest release.
Editing them on main now would make them wrong for 1.0 users, so the exact wording is here instead.

- **README.md**, Features, replacing "No outbound connections, no telemetry, no update checks.":
  > No telemetry. The only outbound connection is an optional daily update check, off until you turn it on: it
  > fetches one public file (`https://gmccollu.github.io/woodshed/releases.json`), sends nothing about your
  > installation, and never downloads or installs anything.
- **SECURITY.md**, "What counts", replacing the last item:
  > - Woodshed making any outbound network connection other than the opt-in update check: one HTTPS `GET` of
  >   `https://gmccollu.github.io/woodshed/releases.json` a day, made only after an administrator turns it on. A check
  >   while it's off or still asking, a request that sends more than that (a query string, a cookie, an identifier, the
  >   version), a connection anywhere else, or an update banner that links outside this repository's releases all
  >   count.
- **FAQ.md**, "Does Woodshed connect to the internet?":
  > Only if you turn on the update check. The first time you open the UI, Woodshed asks once whether to check for new
  > versions once a day. Until you say yes, and after **No thanks**, it makes no outbound connections at all. You can
  > change your answer any time in **Settings → Updates**.
  >
  > When it's on, Woodshed fetches one public file once a day, `https://gmccollu.github.io/woodshed/releases.json`,
  > with a plain HTTPS GET: no query string, no cookies, and a User-Agent of just `Woodshed` (no version). Nothing
  > about your installation, devices or logs is sent. As with any web request, your DNS server and the site's host
  > see your public IP address and the time. It uses `HTTPS_PROXY` and `NO_PROXY` if they're set in the service's
  > environment; it doesn't read the system's proxy settings. If a newer version is out, the UI shows a banner with a
  > link to its release page. Woodshed never downloads or installs anything itself. Settings shows when it last
  > checked and whether that worked.
  >
  > There's no telemetry. The version is on the **About** page, with a link to the releases page if you'd rather check
  > yourself. To decide for many machines at once, set `check = "off"` (or `"on"`) under `[updates]` in
  > `woodshed.toml` before the first start. Versions before 1.1 have no update check and make no outbound connections.
- **docs/user-guide.md**, a new section before "Stop or remove it":
  > **Updates.** The first time you open the UI, a banner asks whether Woodshed may check for new versions once a day.
  > **Turn on** lets it fetch one public file a day (nothing about your installation is sent); **No thanks** keeps it
  > off and it won't ask again. You can change this in **Settings → Updates**, which also shows the last check. When a
  > newer version is out, a banner links to its release page. Woodshed never updates itself: to upgrade, download the
  > new installer from the releases page and run it, and your settings and logs are kept.
- **CONTRIBUTING.md**, Rules:
  > **No outbound connections, except the update check.** Woodshed never dials out on its own: no telemetry, fonts or
  > CDNs. The one exception is the opt-in update check in `internal/updatecheck` (SPEC §10.2), the only package allowed
  > to reach the internet. Tests enforce both; don't work around them.
- **CHANGELOG.md** (1.1.0): "Opt-in update check: asks once, off unless you turn it on, one GET of the public releases
  file a day, never installs anything." Earlier entries stay as they are.

### 10.3 TLS syslog listener

**(decided, 2026-11-13: off by default; one switch in Settings; TCP 6514 by default, and the port can be changed.)**
A third listener takes syslog over TLS (RFC 5425) for devices that offer it. Everything after the handshake is the
TCP listener: the same framing, limits, parsing, storage and device identity (the source IP). It's off until someone
turns it on, so a 1.0 upgrade changes nothing and creates no key files.

This design follows a source-level study of one widely deployed firewall family's TLS syslog client (2026-11-13),
written up generically here. Its findings shape the defaults:
- They offer TLS 1.2 and 1.3 by default, but on unlicensed or evaluation systems they can offer only TLS 1.0.
- They send no SNI, no ALPN and no client certificate, and never read anything back from the server.
- They trust only a CA that an administrator imported by hand into the device's own trust store, not a public root
  list.
- They insist on EKU serverAuth in a CA-issued server certificate.
- When a name check is configured, they match the certificate's SAN DNS names (CN only when there are none) and
  never its IP SANs. Without one, they check only the chain.
- Messages are LF-framed with no octet count, at most 4 KiB each, over up to 4 parallel connections per host. Order
  across those connections isn't kept.
- They set no keepalives, reconnect every 10 s while the server is unreachable, and drop (don't queue) messages in
  the meantime.
- A failed TLS handshake (a bad certificate, a version mismatch) counts as "log host down". By default that **blocks
  new connections through the firewall** until it's fixed, unless a "permit when the log host is down" option is set.

That last point is why this listener must be conservative: a certificate that changes or expires without warning
doesn't just lose logs, it can stop a site's traffic.

#### 10.3.1 Settings and config
```toml
[listeners.tls]
enabled = false          # the one switch (Settings → Listeners → "Syslog over TLS")
addr = "0.0.0.0"
port = 6514              # any free port; some device docs use 1470 for TCP syslog
allow_legacy_tls = false # also accept TLS 1.0 and 1.1, for older senders (warn banner while on)
cert_file = ""           # your own certificate chain (PEM) and key; both empty means Woodshed's own CA
key_file = ""
```
- Ports below 1024 need the same privileges as 514; 6514 needs none.
- `cert_file` and `key_file` are both empty or both set, and must be absolute paths to readable files, validated
  like `ui.cert_file`. A mismatched pair is a 400 on both keys.
- The listener appears in `/api/status.listeners` as `proto: "tls"`. A bind failure gets the usual `listener_bind`
  banner and Retry.

#### 10.3.2 TLS parameters
- **Versions:** TLS 1.2 and 1.3. `allow_legacy_tls` adds 1.0 and 1.1, and while it's on there's a warn banner
  `tls_legacy`: "TLS 1.0 and 1.1 are allowed for older senders. Turn this off once they're updated."
- **Ciphers:**
  - TLS 1.2: ECDHE with AES-GCM or ChaCha20-Poly1305 only. With an RSA key that's `ECDHE-RSA-AES128-GCM-SHA256`,
    `ECDHE-RSA-AES256-GCM-SHA384` and `ECDHE-RSA-CHACHA20-POLY1305`, and the ECDSA equivalents with a user's ECDSA key.
  - TLS 1.3: the standard suites (Go's fixed set).
  - With `allow_legacy_tls`, 1.0 and 1.1 can't use AEAD suites, so it adds `ECDHE-*-AES128-CBC-SHA` and
    `ECDHE-*-AES256-CBC-SHA`.
  - Never offered: static RSA key exchange, 3DES or RC4.
  - Curves: X25519, P-256 and P-384, plus Go's default hybrid post-quantum group for 1.3.
- **No SNI, ALPN or client certificate is required.** The certificate is the same whatever SNI says, offered ALPN
  values are ignored, and no client certificate is requested.
- **Session resumption:** off (no tickets). The senders studied never resume, and it keeps no ticket key to rotate.
- **Client certificate verification** (an optional `client_ca`) is a "maybe later" for senders that support mutual
  TLS. It isn't in 1.1.

#### 10.3.3 Certificate: Woodshed's own small CA
When TLS is first turned on and no `cert_file` is set, Woodshed creates a CA and a server ("leaf") certificate signed
by it. Devices import the **CA**, so a renewed leaf needs no change on any device.
- **Files** in the data folder, mode 0600 like the UI certificate:
  - `tls-ca.pem` and `tls-ca-key.pem`;
  - `tls-cert.pem` (the leaf, then the CA: the chain that's sent) and `tls-key.pem`.
- **Key type: RSA-2048 for both, signed with SHA-256** (**decided (coordinator, 2026-11-13, owner-delegated)**). The study couldn't confirm which server key
  types older senders accept, while RSA-2048 with SHA-256 is accepted by every TLS 1.0–1.3 client in use, including
  TLS 1.0-only stacks and those limited to 2048-bit keys. ECDSA P-256 would make handshakes cheaper, but a sender that
  can't use it fails closed, and on some firewalls that blocks traffic.
  - The handshake cost of RSA-2048 is about a millisecond per connection, which is nothing even for a reconnect every
    10 s per sender.
  - The trade-off is margin: guidance retires 2048-bit RSA around 2030, inside the CA's lifetime. Replacing the CA is
    an explicit action (below), and a user's own certificate can be any type.
- **The CA:** subject `CN=Woodshed CA <hostname> <yyyy-mm-dd>`; `basicConstraints CA:TRUE, pathlen:0`; KU
  keyCertSign + cRLSign; valid until **2037-12-31T23:59:59Z** (about 11 years from 1.1).
- **The leaf:**
  - `basicConstraints CA:FALSE`;
  - KU digitalSignature + keyEncipherment, and EKU serverAuth;
  - SAN DNS names from the UI certificate's logic (`identityFrom`): the hostname, `<hostname>.local`, the hostname
    in each DNS search domain, `localhost` and every `ui.extra_hostnames` name;
  - IP SANs for every stable address and each `ui.extra_hostnames` IP. Some senders ignore IP SANs, which is why the
    DNS names matter;
  - CN set to the primary DNS name: the first search-domain name if there is one, otherwise the hostname;
  - valid for **10 years** or until the same 2037-12-31T23:59:59Z cap, whichever is earlier.
- **Why such long lives:** these aren't browser certificates.
  - The 398-day limits apply to publicly trusted certificates. A private CA that devices import by hand is under no
    such rule, and the device stacks studied enforce no maximum.
  - An expired certificate stops TLS logging on every device at once, and on some firewalls it blocks traffic. A
    renewal often needs someone other than the Woodshed admin to touch every device.
  - The risk of a long life is a stolen key. Devices rarely check revocation, so a stolen leaf key stays trusted until
    the CA is replaced. The leaf key and the CA key sit in the same 0600 folder, so whoever can take one can take
    both; the answer to a compromise is **Replace CA**, whatever the lifetimes.
  - **Why the 2037 cap** (**decided (coordinator, 2026-11-13, owner-delegated)**): some old 32-bit device stacks keep
    time as a signed 32-bit count of seconds and can't represent anything after 2038-01-19. Such a stack may refuse a
    later date at import, or wrap it into the past and treat the certificate as already expired. An expiry before 2038
    parses everywhere. Its cost is a renewal inside the working life of old gear, but that renewal is planned: the
    60-day banner announces it, and renewing the leaf needs nothing on the devices. Both certificates therefore end
    on 2037-12-31T23:59:59Z, which makes the CA about 11 years.
- **Never changed silently.** Unlike the UI certificate, which regenerates itself, the TLS certificate changes only
  on an explicit action.
  - **Renew certificate** (Settings, or `woodshed tls renew`) makes a new leaf with a new key and the current host
    names, signed by the same CA. Devices keep working, and new connections get the new leaf; open connections keep
    theirs.
  - **Replace CA** (Settings, behind a confirmation that says every device must import the new CA, or
    `woodshed tls renew --new-ca`) makes a new CA and leaf.
  - Every renewal is recorded in the events log and the export's `woodshed-events.log`, with both fingerprints.
- **Warn banners, with the action `tls_renew` that opens Settings; neither ever renews on its own:**
  - `tls_cert_expiring`: from 60 days before the leaf or the CA expires: "The TLS syslog certificate expires on
    2036-11-13. Renew it, then nothing changes on your devices." For the CA, it says devices must import the new one.
  - `tls_cert_names`: when the host's DNS names (hostname, search domains, `ui.extra_hostnames`) include one the leaf
    doesn't cover, for example after a rename: "The TLS certificate doesn't name edge-logs.example.net. Devices that
    check the server name will refuse it. Renew it to add the name." Address changes don't raise it, because the
    senders that check names check DNS names.
- **A user's own certificate** (`cert_file`, `key_file`): sent as given (the leaf and any chain in the file), and
  re-read on Retry and on every Settings save, so a replaced file takes effect without a restart. Woodshed shows its fingerprint,
  subject, issuer and expiry, raises the same expiry banner, and offers no CA download (`404`: get the CA from
  whoever issued the certificate). It's checked when loaded: it must have EKU serverAuth (or no EKU) and a key the
  allowed suites can use, or Settings gets a 400 saying what's missing.

#### 10.3.4 Downloads, fingerprints and status
- **The CA certificate** is a download in Settings, and `GET /api/tls/ca.pem` and `GET /api/tls/ca.der`. The guide says
  which to use: PEM for devices where you paste the certificate as text into a terminal or a web form, DER (`.cer`)
  for devices that want an uploaded binary file, and for the Windows certificate store.
- **Fingerprints:** the SHA-256 of the CA and of the leaf, plus the CA's SHA-1 for devices that show only that. They're
  shown in Settings, in `GET /api/tls`, and in `woodshed status`. The guide says to compare the device's view of the
  CA with Settings before trusting it.
- **Per-sender TLS stats:** so "my device can't connect" can be diagnosed, the listener counts per sender address:
  - TLS connections, and the version and cipher of the last one;
  - failed handshakes in the last 24 h (hourly buckets, like refusals), with the reason and time of the last one.

  Reasons:

  | Reason | Meaning |
  |---|---|
  | `cert_rejected` | the sender sent an alert about the certificate (`unknown_ca`, `bad_certificate`, `certificate_unknown`, `certificate_expired`; the alert is shown). Usually the CA isn't imported, or a name check failed |
  | `version` | no TLS version in common (often a TLS 1.0-only sender while `allow_legacy_tls` is off) |
  | `cipher` | no cipher suite in common |
  | `not_tls` | the first bytes weren't a TLS handshake, usually plain syslog sent to the TLS port |
  | `timeout` | no complete handshake within 10 s |
  | `closed` | the sender closed the connection during the handshake, without an alert |
  | `other` | anything else (the error text is kept) |

  Devices with logs carry this on `/api/devices` as `tls`. Senders that failed before they ever got a message through
  are listed by `GET /api/tls/failures` (at most 10,000 addresses tracked, least recently seen evicted, like
  `/api/rejected`). A sender that's only failing appears there and nowhere else, so Settings → TLS links to it.

#### 10.3.5 Framing and connections
- **Framing** is exactly the TCP listener's: octet counting or LF per message, auto-detected; CRLF and NUL tolerated,
  and a missing final LF at close kept as a message; `max_message_bytes` and `tcp_frame_timeout` as for TCP. An
  octet-counted frame cut short by a TLS close (with or without `close_notify`) is incomplete, as for TCP (§3.1).
- **Connections** share the TCP listener's pool and limits: `MaxConns`, `tcp_max_conns_per_source` (default 32; at
  least 4 parallel connections per sender are needed) and `tcp_max_conns_per_prefix` count TCP and TLS together, and
  eviction works the same way. Order across a sender's connections isn't assumed.
- **Handshakes don't take slots.** A connection joins the pool only once its handshake completes. Handshakes in
  progress have their own limits: at most 256 at once and 8 per sender address. Past those, a new connection is closed
  at once and counted (reason `busy`). Each handshake has 10 s, then it's closed (`timeout`). A sender that
  reconnects every 10 s while misconfigured therefore costs one short handshake each time and can't crowd out working
  senders.
- After a TLS listener closes a connection, nothing is written back: these senders never read. A close without
  `close_notify`, or a plain FIN or RST, is normal.
- The idle timeout is the TCP listener's: 24 h from 1.0.1 (§9).

#### 10.3.6 Firewalls and installers
The service account can't change the host firewall, and shouldn't be able to. So:
- **Windows:**
  - The MSI ships a rule "Woodshed syslog (TLS 6514)", TCP 6514 for `woodshed.exe` on all profiles, present but
    **disabled**. `woodshed install` creates the same rule, disabled. Upgrades keep its state.
  - `woodshed tls on` (as an administrator) turns the listener on in the config and enables the rule, setting its port
    to `listeners.tls.port`. `woodshed tls off` turns both off.
  - The UI switch turns the listener on without touching the rule. While the rule exists but is disabled, or its port
    differs, there's a warn banner `tls_firewall` with the exact command to run in an administrator prompt
    (`woodshed tls on`). The rule's state is read through the OS without administrator rights (an acceptance item, §10.4). The check
    lives outside `internal/api`, which may not run programs.
  - Portable mode has no rule. Windows' first-run "allow" dialog covers the program on every port, so 6514 works if
    Allow was chosen.
- **macOS:** the application firewall allows or blocks the program, not ports. If Woodshed already receives on 514,
  6514 works too. `tls on` and `off` change only the listener. There's no banner.
- **Linux:** the deb and rpm add nothing, as for 514.
  - `woodshed tls on` (as root) also opens the port where it finds an active, known firewall: `ufw allow 6514/tcp`
    when ufw is active, or `firewall-cmd --permanent --add-port=6514/tcp` and a reload when firewalld is running (the
    default zone). It records what it added in `<data>/tls-firewall.json`.
  - `woodshed tls off` removes only what it added. With neither firewall active (plain nftables or iptables rules,
    say), it changes nothing and prints the commands to run.
  - The service user can't read ufw or firewalld state reliably, so Linux gets no banner. Settings → TLS shows the
    commands under "If devices can't connect".
- `woodshed tls on|off|renew [--new-ca]|status` follow `lan-mode`: they need administrator rights, edit the config,
  and ask a running service to apply it (or say it isn't running). `status` prints the listener, the fingerprints,
  the expiry and the last failures.

#### 10.3.7 API (docs/api.md → "TLS syslog listener")
`GET /api/tls` (state, fingerprints, expiry, the firewall hint), `POST /api/tls/renew` (`{"new_ca": false}`),
`GET /api/tls/ca.pem` and `ca.der`, `GET /api/tls/failures`, a `tls` object on each device in `/api/devices`,
`listeners.tls` in `/api/settings`, the listener in `/api/status`, and the banners `tls_legacy`,
`tls_cert_expiring`, `tls_cert_names` and `tls_firewall`.

#### 10.3.8 Tests
- Handshakes with Go clients over every allowed version and suite. Refused: 1.0/1.1 with the flag off, static-RSA
  suites, a client that offers only CBC with 1.2. With the flag on, 1.0 and 1.1 with the CBC suites.
- A client with no SNI, with a wrong SNI and with ALPN connects. A client that verifies the chain against the
  downloaded CA and checks a DNS name from the SANs connects, and one checking a name that isn't there fails with
  `cert_rejected` counted.
- Certificate profile: CA and leaf fields exactly as in §10.3.3. With a fake clock in 2030, the leaf ends at the
  2037 cap, not 10 years on. A Go `x509.Verify` with the CA as the only root, for
  each SAN name. The chain sent is leaf + CA.
- Never silent: a fake clock past the 60-day mark and a changed hostname raise the banners and leave the files
  byte-identical. Renew keeps `tls-ca.pem` byte-identical.
- Framing parity: the TCP listener's framing table run over TLS.
- Handshake limits: 300 stalled handshakes from many addresses leave established senders working; one address
  can't hold more than 8. A stalled handshake is closed at 10 s and doesn't count against `MaxConns`.
- Failure reasons: plain syslog to the TLS port (`not_tls`), an unknown-CA alert (`cert_rejected`), a version
  mismatch (`version`).
- The install smoke tests: the MSI's rule exists and is disabled after install and after an upgrade, `woodshed tls on`
  enables it and a TLS message arrives from another process, and `off` disables it. On Linux with ufw active, `tls on`
  then `off` leaves the rules as they were.
- The default config: the existing no-dial tests still pass, and no TLS key files exist until TLS is turned on.

#### 10.3.9 Doc wording
Apply this with the implementation, as for §10.2.
- **docs/user-guide.md**, a new section after "Point a device at it":
  > **Sending syslog over TLS.** Use this when a device should encrypt its logs on the way. It's off until you turn
  > it on.
  > 1. In **Settings → Listeners**, turn on **Syslog over TLS** (TCP port 6514). On Windows, also run
  >    `woodshed tls on` once in an administrator prompt, so the firewall lets devices in; Settings shows the command
  >    if it's needed.
  > 2. Download Woodshed's **CA certificate** from the same section: **PEM** if the device wants the certificate as
  >    text to paste, **DER (.cer)** if it wants a file to upload.
  > 3. On the device, import it as a **trusted CA certificate** (often called a trust anchor or a CA
  >    certificate). Compare the fingerprint the device shows with the one in Settings.
  > 4. Point the device's syslog at this computer, **TCP port 6514 with TLS** (the setting may be called secure,
  >    encrypted or TLS syslog).
  > 5. If the device can check the server's name, give it one of the DNS names Settings lists for the certificate,
  >    not an IP address: many devices check names only. Then check on the Dashboard that messages arrive.
  >
  > **Before you turn on TCP or TLS logging on a firewall:** some firewalls block traffic through them when a TCP or
  > TLS syslog server can't be reached, or its certificate fails, unless a "permit traffic when the log host is down"
  > option is set. Check that option first.
  >
  > If a device can't connect, **Settings → TLS** shows each sender's failed handshakes and why: the CA isn't trusted,
  > there's no TLS version in common, or plain syslog was sent to the TLS port.
- **docs/install.md**, a section "TLS syslog: firewall and certificate" with §10.3.6 per OS, `woodshed tls
  on|off|renew|status`, the files in the data folder, renewing (the CA stays, so devices need nothing) and replacing
  the CA (every device must import the new one).
- **FAQ.md**, "Why port 514, and why UDP?" gains: "For encrypted syslog, turn on **Syslog over TLS** (TCP 6514); see
  the user guide."
- **README.md**: the "What it isn't" paragraph drops TLS syslog from "planned after 1.0", and Features gains "Optional
  syslog over TLS (TCP 6514) with its own CA, so devices import one certificate that renewals don't change."
- Device-specific commands stay out of the repo.

### 10.4 Decisions for 1.1

**Owner** **(decided, 2026-11-13)**: the update check is opt-in, asks once, makes a plain HTTPS GET of the public
releases list and never installs anything (§10.2); the TLS listener is off by default, has one Settings switch, and
listens on TCP 6514 by default, with the port configurable (§10.3); the roadmap order in §9.

Everything below is **decided (coordinator, 2026-11-13, owner-delegated)**.

Events v2 and the update check:
1. Field counts are exact over a stated span, newest first, never sampled (§10.1.1).
2. One summary endpoint feeds both the field panel and the histogram; `fields=none` gives the histogram alone
   (§10.1.2).
3. Excluding a value is Alt-click or the "−" button, not a second click (§10.1.1).
4. "(none)" rows can't be clicked (§10.1.1).
5. Boolean terms need `syntax=terms`; they never switch on because operators appear, and only upper-case operators
   count (§10.1.3).
6. `syntax=terms` with `regex=true` is a 400 (§10.1.3).
7. Saved searches live in `index.db`, not the TOML (§10.1.4).
8. A saved search keeps the IDs of missing devices and is never edited automatically (§10.1.4).
9. The update check reads the existing Pages file `releases.json`, not the GitHub API (§10.2).
10. The User-Agent is `Woodshed`, with no version (§10.2).
11. Redirects aren't followed (§10.2).
12. Portable mode asks too (§10.2).
13. Development builds never check or ask (§10.2).
14. No `If-None-Match` or `If-Modified-Since` (§10.2).
15. The public docs change only when the checker ships; the wording waits in §10.2 (§10.2).
16. At most 2 summary scans at once, 2 s per summary request by default, running counts kept 10 min for at most 8
    summaries (§10.1.5).

TLS:
1. RSA-2048 with SHA-256 for the CA and the leaf (§10.3.3).
2. Long lives: the CA until the 2037 cap, the leaf 10 years or the cap, whichever is earlier (§10.3.3; the cap is
   TLS answer 1 below).
3. TCP and TLS share one connection pool and its per-source limits (§10.3.5).
4. Handshakes stay out of the connection slots, with their own limits of 256 at once and 8 per address (§10.3.5).
5. Session tickets are off (§10.3.2).
6. `tls_cert_names` warns about DNS names only, not addresses (§10.3.3).
7. With a user's own certificate, the CA download is a 404 (§10.3.4).
8. `WOODSHED_UPDATE_CHECK` applies on upgrades too, and an invalid value is ignored with a warning (§10.2).
9. The 1.0.1 change: at its per-source limit, a sender's newcomer evicts that sender's own longest-idle connection
   (§9). It's being built in 1.0.1.

Answers to the 1.1 questions:
1. No regex terms inside `syntax=terms` in 1.1; mixing the two stays a 400.
2. The live tail gets neither `syntax=terms` nor the new exclude filters in 1.1.
3. No filter for "(none)" (lines with no hostname or program/tag) yet; the panel row stays unclickable.
4. Silent fleet installs get a switch for the update check: the MSI property and the pkg/deb/rpm environment
   variable `WOODSHED_UPDATE_CHECK=on|off|ask` (§10.2).
5. No redirects: the update check follows none, and the site keeps the URL answering.
6. The field panel's 60 s auto-continue limit stays.
7. The other 1.x roadmap items stay unordered.
8. The 1.3 SNMP poller will be a second package that connects out on its own; §10.2's allowlist test and its "only
   `internal/updatecheck`" wording get amended then.

Answers to the TLS questions:
1. Both certificates end at 2037-12-31T23:59:59Z, for 32-bit device stacks (§10.3.3 says why).
2. No static-RSA suites in 1.1. Add them later only if a real sender needs them.
3. Firewall rule details: an acceptance item, below.
4. On Linux the Settings text is enough; there's no firewall banner.
5. No RSA-3072 or ECDSA CA option in 1.1.
6. Client-certificate verification (`client_ca`) comes later, if asked for.
7. The installers' `WOODSHED_UPDATE_CHECK` pass-through: an acceptance item, below.

Update check, **decided (build, 2026-11-13)** (the smallest choice where §10.2 or docs/api.md left it open):
1. A release build, which may check and ask: a SemVer version that isn't 0.0.0, with no build metadata, and a
   prerelease part, if any, like a real tag's (`rc1`, `rc.1`, `beta2`, `alpha`). A `git describe` version
   (`1.0.0-5-gabc1234-dirty`), a CI snapshot (`1.0.1-snapshot.abc1234`) and `-dev`, `-ci` or `-dirty` builds never
   check or ask.
2. `main.releasesURL` is now `https://github.com/gmccollu/woodshed/releases` (it was empty "until the project has a
   public home"), so release builds have a `releases_url`; the About page links to it too.
3. `html_url`: exactly `releases_url + "/tag/" + tag_name` gives that link; empty or anything else under
   `releases_url` gives `releases_url`; anything outside `releases_url` (another host, or a look-alike such as
   `…/releases.evil.example/…`) is the "off-site `html_url`" of the tests: a `bad_json` error and no banner.
4. A considered entry whose `tag_name` isn't a version, or a `stable` entry with a prerelease version (a
   `prerelease` one without), is `bad_json`. A response whose `Content-Type` isn't `application/json` is `bad_json`.
5. Turning it on checks 5–30 s later. **Check now** while a check is running counts that one.
6. After a restart within 24 h of a check, the next is exactly 24 h after it, even when that check failed (a
   pending retry isn't kept across a restart).
7. `latest` is `null` whenever `check` isn't `"on"` (still asking, too), not only after turning it off.
8. `GET /api/settings` always has `updates`; a `PUT` without it keeps the setting (1.0 clients and scripts).
9. `POST /api/updates/check` answers `202` with no body, and `409` in a build that can't check as well.
   `POST /api/updates/dismiss` with a `version` that isn't one is a `400`.
10. The request is HTTP/1.1 and its connection is closed after each check, without Go's `DisableKeepAlives`,
    which would add a fifth header (`Connection: close`).
11. Error messages are Woodshed's own; an HTTP status shows its number and Go's text, never the server's.
12. `woodshed update-check` accepts any case and surrounding spaces; an invalid value exits 2 and changes nothing.
    With no config yet it writes one with the defaults a server would use there, owned like its folder (the folder
    must exist). `--no-restart` is for the installers, which run it before they start or restart the service.
13. The update banners are in the run-state file too, so `woodshed status` lists them; it also has an `Updates`
    line (the setting and the last check).
14. The MSI runs it through WixQuietExec (its output goes to the install log) with `Return="ignore"`, before
    `StartServices`. The pkg's and the deb/rpm scripts print the warning and carry on.

Events v2, **decided (build, 2026-11-13)**: small calls made while building §10.1, where the contract was silent.
1. Terms grammar: inside a phrase, a backslash before anything other than `"` or `\` is itself (`"C:\temp"` is
   `C:\temp`). A phrase followed directly by a word (`"a"b`) is two terms. Character positions count code points; the
   4 KiB limit counts UTF-8 bytes. The checks run in this order: length, quotes and empty phrases, the 32-term count,
   then structure and nesting; a missing operand names the first operator affected (`a AND OR b` names AND). A terms
   `exclude` with no terms (only spaces) excludes nothing.
2. The field panel groups host and program/tag values the way their filters match: ignoring case, and a leading `%`
   for program/tag. The row shows the first spelling seen, so a value's count is what clicking it returns.
   `filterable` is also false for a value with surrounding blanks and for a program/tag ending in `*` (the filter
   would read it as a prefix).
3. `distinct` counts the values with a count in `[counted_from, to)`.
4. A summary cursor is good for one request: each response issues the next one. Reusing an older cursor, or a request
   that was cancelled mid-scan, gets the "expired" 400, so counts are never added twice.
5. The index histogram uses the per-minute stats for a bucket (clipped to `[from, to)`) that is whole minutes and
   starts in the last 24 h, and the minute and hourly stats together for one that is whole hours, at least 1 h, and
   starts in the last 7 days. Anything else (a bucket cut off a minute boundary by `from` or `to`, or older data) comes
   from the checkpoints and may be `approx`. A device's oldest-file bucket is spread from its checkpoints, which for a
   quiet device (one checkpoint per file) makes that bucket rough.
6. Presets in the UI resolve to `to` = now rounded up to the whole minute, `from` = `to` − preset, on Events and Export,
   so the default 1 h view is on whole minutes (§10.1.2).
7. Summary parameters: `top` above 50 and `budget_ms` above 10,000 are clamped (as search clamps `limit`); `order` and
   `limit` are ignored; `histogram=false` leaves the `histogram` key out; an unknown `fields` key is a 400
   `fields: unknown field "x".`
8. Saved searches: IDs are `ss_` and 8 hex digits; the ETag is `"<id>.<version>"`; `If-Match: *` is treated as no
   `If-Match`. A missing `query.range` is `{"last": "24h"}` (search's default range); `syntax` defaults to `text` and
   `order` to `desc`. `last` is 1–7 digits and `m`, `h` or `d`. Terms with regex is reported on `query.syntax`.
   `missing_group` is true when no non-hidden device is in the group (those are the only ones the group searches).
9. The UI's 60 s auto-continue counts the summed `elapsed_ms` of the summary responses, not wall time. Cancel on the
   results also stops the summary; the panel keeps its counts and offers **Count the rest**.
10. Field panel clicks: including a value takes it out of the matching exclude list and the other way round;
    including a device while a group is picked switches to that device; excluding the last value of a closed field
    sends `none`. A drag on the histogram snaps to bucket edges and stays inside the current range; a click zooms into
    one bucket.
11. A saved relative range that isn't one of the presets (say `30m`) opens as a custom range ending now; saving it
    again makes it absolute.
12. Export's README.txt names the new filters in plain words ("Facilities: …", "Program/tag left out: …",
    "Devices left out: …", "boolean terms").
13. A summary keeps each compressed file's paused pass (its open reader) in its server-side state, at most 8 per
    summary, so a long range over gzipped days decompresses each byte once across requests. They close with the
    state (complete, evicted, expired after 10 min, or cancelled). Up to 4 streams (half the CPUs) decompress in
    parallel within the request's budget.

TLS, **decided (build, 2026-11-13)**: the smallest choices the TLS build had to make where §10.3 and docs/api.md
left room:
1. The MSI creates the TLS rule through a custom action (`woodshed-aclfix --tls-firewall ensure|remove`, the same
   `internal/fwrule` code as `woodshed install`), not `fw:FirewallException`. The WiX extension can create a rule
   disabled, but its uninstall step deletes the rule, and a major upgrade removes the old product before the new one
   installs, so an enabled rule would come back disabled after every upgrade. `ensure` creates the rule disabled
   only when it's missing and otherwise leaves it as it is; `remove` runs only on a real uninstall
   (`NOT UPGRADINGPRODUCTCODE`). This answers the first acceptance item's "upgrade keeps its state" by design; CI
   still has to confirm it.
2. The CLI never writes key files: `woodshed tls on` edits the config and the service makes the CA and certificate
   when it starts, as its own account (so the files have the right owner). `woodshed tls renew [--new-ca]` leaves
   `tls-renew-request.json` in the data folder, and the service carries it out at its start (recording the event)
   and deletes it; the CLI restarts a running service, as `lan-mode` does.
3. `GET /api/tls/failures` lists every sender with failed handshakes in the last 24 h, known devices included
   (`device_id` set), as docs/api.md says; the senders "that failed before they ever got a message through" are the
   ones with `device_id: ""`.
4. The TLS banners show only while the listener is on. `tls_cert_names` (and `cert.missing_names`) apply to
   Woodshed's own certificate only. `tls_firewall` shows only for the installed Windows service: portable mode and
   `woodshed run` have no rule.
5. The Windows rule's state is read with `netsh advfirewall firewall show rule name=… verbose` (English field
   names), at most once a minute. Output it can't read (another display language) is `"unknown"`: no banner. `woodshed
   tls on` points the rule at the running `woodshed.exe` and creates it (enabled) if it's missing.
6. `listeners.tls.port` must differ from the TCP and UDP ports on an overlapping address (the same address, or either
   a wildcard) and from `ui.port`. A user's own key must be RSA of at least 2048 bits or ECDSA P-256, P-384 or P-521
   (Ed25519 is refused).
7. Alerts from a sender: `bad_certificate`, `unsupported_certificate`, `certificate_revoked`,
   `certificate_expired`, `certificate_unknown` and `unknown_ca` are `cert_rejected`; `protocol_version` is
   `version`; `handshake_failure` and `insufficient_security` are `cipher`. (Go's own clients send `bad_certificate`
   for an unknown CA.)
8. `POST /api/tls/renew` before TLS was ever turned on is a `409` ("turn it on first"), like a user certificate.
9. The CA's subject date is the UTC date. TLS listener events have their own source (`listener/tls`), so an export's
   gaps include the TLS listener's.
10. `woodshed send --proto tls` uses port 6514 unless `--port` is given and needs `--ca FILE` (PEM or DER) or
    `--insecure`; `woodshed bench --proto all` includes TLS.
11. `internal/fwrule` joins §10.2's allowlist of packages that may use process APIs (`os/exec`): it runs only the host
    firewall's own programs (netsh, ufw, firewall-cmd) and never opens a network connection.

**Acceptance items for the 1.1 build** (the install smoke tests confirm each, or the design changes before release):
- The WiX firewall extension in use can ship the TLS 6514 rule present but disabled, and an upgrade keeps its state.
- The virtual service account (`NT SERVICE\Woodshed`) can read that rule's state, for the `tls_firewall` banner.
- `WOODSHED_UPDATE_CHECK` reaches the install scripts: the MSI property; macOS `installer` to the pkg's scripts;
  `sudo`, apt/dpkg and dnf/rpm to the deb's and rpm's. Where it doesn't, that installer documents pre-seeding the
  TOML instead.

## 11. 1.2 design (draft, 2026-11-14)

1.2 has five parts, all in scope **(owner, 2026-11-14)**: pluggable data types (§11.1), the SNMP trap receiver
(§11.2), the incident bundle (§11.3), command-line search (§11.4) and UDP receive off the write path (§11.5). The
testing plan (§11.6) and compatibility rules (§11.7) are part of the contract. Owner decisions are marked **(owner)**
or **(decided)**; the calls made here are **decided (coordinator, 2026-11-14, owner-delegated)** and are listed in
§11.8 so the owner can overrule any of them. The API contract is in `docs/api.md`, in the section of each route.

### 11.1 Pluggable data types

§10.1.6 sketched the seams; this section fixes them. A **data type** is a named kind of record (`syslog`, `trap`;
later `poll`, `flow`) that shares the pipeline and brings its own parts.

**Shared by every type:**
- device identity (the source IP, `model.DeviceID`), the devices table, names, groups, hidden and blocked flags;
- the sender admission rules: allowlist, blocklist, `max_devices` and the new-sender buckets (§2), applied per
  device whatever the type;
- the store's per-device writers: buffering, flush and fsync timing, rotation at the part size or midnight UTC,
  gzip, checkpoints, crash repair;
- the line envelope `<received UTC, RFC 3339 ms> <sender IP> <record>`, one record per line, CR, LF and backslash
  escaped (§3.3). Syslog's record is the raw message; other types define theirs;
- the index's files and checkpoints tables, retention and the low-disk guard (below);
- the search engine (merge, budget, cursor, partial), Events v2's summary and histogram, saved searches, context,
  export and the incident bundle;
- the events log and the export's gaps.

**What a type implements** (an interface in a new `internal/datatype` package; syslog becomes its first
implementation, with no change to its behaviour):

| Part | What it does | Syslog | Trap |
|---|---|---|---|
| `Name()`, `Label()` | the `type` value and its UI label | `syslog`, "Syslog" | `trap`, "SNMP traps" |
| `Dir()` | its folder inside the device folder | `""` (the device folder itself) | `"traps"` |
| Listener | produces records for the store | UDP, TCP, TLS 514/6514 | UDP 162 (§11.2) |
| `Fields()` | the schema's field descriptors (§10.1.1) | device, severity, facility, host, app | §11.2.5 |
| `ParseFilter(params)` | its own filter parameters; anything else is a 400 | 1.1's parameters | §11.2.5 |
| `Match(record, filter)` | does a stored record pass the filter | 1.1's `check` | §11.2.5 |
| `FieldValues(record)` | the values the field panel counts | PRI, header | the record's keys |
| `Text(record)` | the part `q` matches | the raw message | the record without `raw=…` |
| `Result(record)` | the API result object | 1.1's shape, unchanged | §11.2.4 |
| `Summary(records)` | the bundle README's lines for a device | counts by severity | counts by trap name, reboots |

**Where traps live: their own files, in a `traps/` folder inside each device's folder:**
```
logs/10.1.0.1/2026-11-14.log            syslog, unchanged
logs/10.1.0.1/traps/2026-11-14.log      traps, same naming, parts and .gz as syslog
logs/10.1.0.1/traps/2026-11-13.log.gz
```
Why not one file per device per day with a type marker on each line:
- **Syslog stays byte-for-byte compatible.** Syslog files hold only syslog lines, exactly as 1.0 and 1.1 wrote
  them, so grep, editors, existing exports and scripts see no change. A marker would change every line or mix trap
  lines into syslog files.
- **Search speed.** A syslog search never reads trap bytes and a trap search never reads syslog bytes; the
  checkpoints of each file cover one type, so time seeks stay exact. Mixed files would make every scan read and skip
  the other type and would break the escaped-bytes prefilter's assumption that every line is one kind of record.
- **Reindex** walks `logs/<dev>/` for syslog and `logs/<dev>/<dir>/` for each registered type, with the same file-name
  parser; the folder says the type, so no line has to be read to know it. A folder no registered type claims is
  ignored (and logged once).
- **Retention** deletes whole files, so a type's files can go without rewriting another type's data.
- **Export and the bundle** map a type's folder straight to the zip's folder for that type.
- Inside the device folder, not a parallel `traps/<dev>/` tree, because the device is the unit: forgetting a device,
  its folder's permissions, and someone browsing "everything from this device" all stay one folder. Device IDs are
  addresses, so no device can be named `traps`.
- 1.1's `logfile.List` already skips subfolders inside a device folder, so a 1.1 `reindex` over a 1.2 data folder
  ignores traps rather than misreading them (§11.7).

**Index changes** (one migration, §11.7):
- `files` gains `type TEXT NOT NULL DEFAULT 'syslog'`; every 1.1 row reads as syslog.
- New tables `type_stats` and `type_stats_hourly` (device, type, minute or hour, msgs, bytes, truncated, dropped) for
  every type except syslog, which keeps its 1.1 `stats` tables untouched. The Events index histogram (§10.1.2) reads
  the table for the query's type.
- Device totals (`total_msgs`, `last_heard`, `first_seen`) and the Dashboard's rates count every type, so a device
  that sends only traps is online, not offline.

**Retention and the disk guard cover every type with the same fair-share rules (§3.4):**
- The size cap, age limit and low-disk reserve apply to all of a device's files together, whatever their type.
- A device's share is its average bytes a day over 7 days summed over its types; "new" means first seen in the last
  24 h, whatever type it sent.
- Within a device, "oldest file first" means by `first_received` across its types, so the oldest evidence goes first
  whatever kind it is.
- The protected last min(retention days, 2) calendar days cover every type's files.
- Storage history records each deletion's type.

**Other parts per type:**
- The live tail and the Dashboard's live view stay syslog-only in 1.2. Device tiles count all types.
- `/api/context` reads the ref's own file, so context stays within one type.
- The export zip gets one folder per type (§11.3).

### 11.2 SNMP trap receiver

**Owner:** UDP 162 (configurable); v1, v2c and v3 with user-configured credentials; stored decoded as text lines
with varbinds and the raw PDU; numeric OIDs plus an optional folder of MIB files for names; no MIB compiler
(§9). **Off by default**, decided (coordinator, 2026-11-14, owner-delegated), as for TLS: a 1.1 upgrade opens no new
port.

#### 11.2.1 Settings and config
```toml
[listeners.snmp]
enabled = false        # Settings → Listeners → "SNMP traps"
addr = "0.0.0.0"
port = 162             # traps and informs; any free port
answer_informs = true  # reply to InformRequests (§11.2.3)
mib_dir = ""           # MIB files for names; "" means <data>/mibs
engine_id = ""         # Woodshed's own v3 engine ID, hex; "" means the generated one (§11.2.3)
v3_strict_time = false # true: RFC 3414's time window for traps as written, no relearning (§11.8 #28)
```
- The listener shows in `/api/status.listeners` as `proto: "snmp"`, with the usual `listener_bind` banner and Retry.
  Port 162 is often held by an OS trap service; the banner names the holder as for 514.
- Port 162 is below 1024: the same privileges and the same macOS rule as 514 (a specific address below 1024 is
  refused on macOS; the wildcard works).
- v3 users aren't in the TOML or in `/api/settings`: they're managed through `/api/snmp/users` and kept in the
  credentials store (§11.2.6), so no secret ever sits in the config file or in a settings response.
- The optional v1/v2c community list (accept only these; empty accepts any) is a set of secrets too: it's edited in
  Settings (`listeners.snmp.communities` in `/api/settings`, shown only as hash prefixes) and kept in the same
  credentials store, not in the TOML.

#### 11.2.2 What it accepts
- **PDUs:** v1 Trap-PDU; v2c and v3 SNMPv2-Trap-PDU and InformRequest-PDU. Any other PDU type (Get, Set, Response,
  Report, GetBulk) is counted (`unexpected_pdu`) and stored as `status=unexpected_pdu`, never answered.
- **Size:** up to 65,507 bytes, any UDP datagram; v3 Reports advertise `msgMaxSize` 65,507. A trap is never truncated.
- **Communities (v1/v2c):** any, unless `communities` is set; then a trap with another community is refused before
  storage, counted in `/api/rejected` with reason `community`, and not stored (an explicit filter, like the
  allowlist).
- **v3 security:** USM (RFC 3414) with
  - auth: HMAC-MD5-96, HMAC-SHA-96, and HMAC-SHA-224, -256, -384 and -512 (RFC 7860);
  - priv: DES-CBC (RFC 3414), AES-128-CFB (RFC 3826), and AES-192-CFB and AES-256-CFB. Two incompatible
    key-extension methods for AES-192/256 are in use (the one in the AES-USM draft, and a different one some
    devices implement); each user picks one (`key_ext`: `"draft"` (default) or `"alt"`);
  - levels noAuthNoPriv, authNoPriv and authPriv; a user accepts its own configured level and above, never below.
  - MD5, SHA-1 and DES are weak but common on older gear. Settings labels them "weak"; they aren't refused.
- **Sender limits:** traps pass the same allowlist, blocklist, `max_devices` and new-sender buckets as syslog, in
  the UDP reader (§11.5). There's no separate trap rate limit: a trap flood is a UDP flood, with the same answer.
- **Malformed packets** (BER that doesn't decode, a wrong version, a truncated header) are counted and **kept**:
  stored as `status=malformed error="…"` with the raw bytes, because a device sending broken traps is evidence.
- **v3 failures are kept too**, with their status: `unknown_user`, `unknown_engine` (an inform to the wrong engine
  ID), `not_in_time` (outside the 150 s window), `auth_failed` (wrong digest), `decrypt_failed` (the decrypted bytes
  don't decode) and `level` (below the user's level). A failure stores only the parts that are readable without the
  keys (user name, engine ID, security level and the raw bytes), never decrypted guesses. The one exception is an
  authenticated trap that fails only the time window: it's stored whole as `not_in_time` (§11.8 #28). Each failure
  is also counted per sender in `GET /api/snmp/failures`, like TLS handshake failures, so "the device sends but
  nothing shows" is diagnosable.

#### 11.2.3 Informs and engine IDs
**Woodshed answers informs (`answer_informs = true`).** An unanswered inform is retransmitted (so it's stored several
times) and the device logs the receiver as failing, sometimes raising an alarm of its own. A Response is what the
protocol requires, and it is the answer to an inbound request on the same socket, not an outbound connection
Woodshed starts (SECURITY.md is unchanged).
- The reply goes only to a sender that passed admission (allowlist, blocklist, device limits), and only after the
  inform is in the store's write buffer: it's sent by the queue's drainer (§11.5), so a full queue drops the inform
  unanswered and the sender's retry is the backpressure. An inform is never acknowledged and then lost by Woodshed.
- Replies are rate-limited (100 a second per source address, 1,000 a second in all; the excess are dropped and
  counted) so a spoofed source can't use Woodshed to reflect traffic at someone. The Response echoes the inform's
  request ID and varbinds byte for byte, so it's the inform's size give or take the re-encoded v3 header (at most 32
  bytes more, or it isn't sent; §11.8, build 7): there's no amplification.
- A retransmitted inform (the same source, engine and request ID within 60 s) is answered again and stored again,
  marked `dup=1`, so nothing is lost and the count is still honest.
- `answer_informs = false` stores informs without answering.

**v3 engine IDs:**
- For traps the sender is authoritative: its engine ID is in each message, and a user's keys are localized to it.
- For informs Woodshed is authoritative. Its engine ID is generated at first start in the RFC 3411 format
  "administratively assigned octets" (`80000000` + `05` + 8 random bytes; the enterprise number 0 is a placeholder
  until the project registers its own, §11.9) and kept in `<data>/snmp-engine.json` with `engineBoots`, which goes up
  by one at every start; `engineTime` counts from the start. `engine_id` overrides it for senders configured with a
  fixed receiver engine ID.
- Discovery (RFC 3414 §4): a request with an empty engine ID gets a Report (`usmStatsUnknownEngineIDs`) with
  Woodshed's engine ID, boots and time; one outside the time window gets `usmStatsNotInTimeWindows`. Reports go only
  to admitted senders and count against the reply rate limits. Settings shows the engine ID so it can be configured on
  devices.
- Key localization costs a 1 MiB hash per user and engine ID. Localized keys are cached (10,000 entries, least
  recently used out), and at most 20 new localizations run a second, so spoofed engine IDs can't burn the CPU. (As
  built, the 1 MiB password hash is done once per user and kept; only the alt AES key extension needs one per engine,
  so only that is limited: §11.8, build 6.)

#### 11.2.4 The stored record
One line per trap, in `logs/<dev>/traps/<day>.log`, inside the usual envelope:
```
2026-11-14T09:30:58.112Z 10.1.0.1 v=2c pdu=trap id=4711 cred=#3f9a1c07 status=ok uptime=8641234 trap=1.3.6.1.6.3.1.1.5.3(linkDown) vb=1.3.6.1.2.1.2.2.1.1.3(ifIndex.3):int:3 vb=1.3.6.1.2.1.2.2.1.7.3(ifAdminStatus.3):int:1(up) vb=1.3.6.1.2.1.2.2.1.8.3(ifOperStatus.3):int:2(down) raw=MIGTAgEBBAZ…
```
- **Keys, in this order** (absent keys are left out): `v` (`1`, `2c`, `3`); `pdu` (`v1trap`, `trap`, `inform`, or
  the unexpected type); `id` (request ID; none for v1); `dup=1` for a retransmitted inform; `cred` (below); for v3
  `level` (`noAuthNoPriv`, `authNoPriv`, `authPriv`), `engine` (hex) and `ctx`/`ctx_engine` when set; `status`;
  `error="…"` when the status isn't ok; for v1 `enterprise`, `agent`, `generic`, `specific`; `uptime` (TimeTicks);
  `trap` (the snmpTrapOID; for v1 the RFC 3584 translation, so v1 and v2c traps of the same kind compare); then one
  `vb=` per varbind, in PDU order, without the two the header already shows (sysUpTime.0 and snmpTrapOID.0); `raw=`
  last.
- **Varbinds:** `vb=<oid>(<name>):<type>:<value>`. Types: `int`, `str` (printable UTF-8, quoted, with `"` and `\`
  escaped), `hex` (any other octets), `oid`, `ip`, `c32`, `g32`, `ticks`, `c64`, `opaque` (hex), `null`,
  `nosuchobject`, `nosuchinstance`, `endofmibview`. An `int` with a named value from a MIB adds it: `int:2(down)`.
- **Names:** OIDs are always stored numerically. When the MIB set loaded at receipt names an OID (or its longest
  named prefix, plus the index: `ifOperStatus.3`), the name is added in parentheses. Names known only to MIBs added
  later aren't written into older lines; the UI names every OID from the current MIB set when it shows a trap.
- **`cred`:** v3 shows the user name (`cred=monitor`). v1 and v2c show `#` and the first 8 hex digits of the
  community's SHA-256, never the community itself: a community is often also the device's read (or write) password,
  and these lines go into exports and bundles that leave the machine. The prefix is enough to tell communities apart
  and to filter on.
- **`raw=`** is the whole datagram, base64 (standard alphabet, no line breaks), for evidence, **except** that for
  v1/v2c the community's octets are replaced by as many `*` bytes before encoding, for the same reason. The
  replacement is the only change, it's documented here and in the export README, and the BER lengths are untouched,
  so the PDU still decodes. A v3 message is kept exactly: its secrets are never in the packet.
- `q` and the field values read the record without `raw=…`, so a search never matches base64.
- A record can be several times its datagram (hex, names); lines up to 1 MiB are accepted, which bounds any 65,507-byte
  datagram.

**The API result** for `type=trap` (syslog results keep their 1.1 shape):
`{"received", "device_id", "type": "trap", "ref", "raw": <the record line>, "fields": {"version", "pdu", "trap_oid",
"trap_name", "enterprise", "generic", "specific", "cred", "status", "uptime", "varbinds": [{"oid", "name", "type",
"value"}]}}`, with names from the current MIB set.

**MIB folder:** `mib_dir` holds MIB files (`*.mib`, `*.my`, `*.txt`), read at start, when `mib_dir` changes and on
**Reload MIBs**.
- Woodshed reads only what naming needs: `OBJECT IDENTIFIER` assignments, `OBJECT-TYPE`, `NOTIFICATION-TYPE`,
  `TRAP-TYPE`, `MODULE-IDENTITY`, `OBJECT-IDENTITY`, `IMPORTS`, and `INTEGER { name(n), … }` enumerations, including
  those of `TEXTUAL-CONVENTION`s in the same set. It isn't a MIB compiler: no type checking, no tables, no syntax
  beyond that.
- A small built-in set needs no files: the standard notifications (coldStart, warmStart, linkDown, linkUp,
  authenticationFailure, egpNeighborLoss), sysUpTime, snmpTrapOID, snmpTrapEnterprise, the system group and the IF-MIB
  interface columns (the modules are listed in §11.8, build 13).
- Limits: 2,000 files, 64 MiB in all, 1,000,000 names. A file that doesn't parse is skipped with its error (file,
  line, message) listed in Settings; the rest still load. A missing import is a warning, not an error.

**Device identity is the source IP.** A v1 trap's `agent-addr` is shown (`agent=`) but never used for identity:
- it's self-reported and often wrong (multi-homed devices, NAT, `0.0.0.0`, a loopback or management address), and
  nothing verifies it;
- using it would let any sender write into another device's folder just by putting that address in the packet;
- the source IP is what syslog uses, so a device's traps and its syslog land in the same device folder.
Relayed traps (from a trap forwarder) are the same open item as relayed syslog: "Device identity by hostname as an
option" (§9, later 1.x).

#### 11.2.5 Events and Settings
- **Events:** a type switch, **Syslog | SNMP traps** (`type=trap` in the URL). It shows when the SNMP listener is
  on or trap files exist. Results show time, device, trap name (or OID), and the varbinds in one line; a click opens
  the decoded trap (every varbind with names) and the context view.
- **Fields** (from `GET /api/search/schema`, so the client hard-codes none of them):

  | Key | Label | Filter (include / exclude) | Domain |
  |---|---|---|---|
  | `device` | Device | `devices` / `exclude_devices` | |
  | `version` | Version | `snmp_versions` | `1`, `2c`, `3` |
  | `pdu` | PDU | `pdus` | `v1trap`, `trap`, `inform`, `unexpected` |
  | `trap_oid` | Trap | `trap_oid` / `exclude_trap_oid` | |
  | `enterprise` | Enterprise (v1) | `enterprise` / `exclude_enterprise` | |
  | `generic` | Generic trap (v1) | `generic` | `0`–`6` (coldStart … enterpriseSpecific) |
  | `specific` | Specific trap (v1) | `specific` / `exclude_specific` | |
  | `cred` | Community or user | `cred` / `exclude_cred` | |
  | `status` | Status | `status` | `ok`, `malformed`, `unexpected_pdu`, `unknown_user`, `unknown_engine`, `not_in_time`, `auth_failed`, `decrypt_failed`, `level` |

  `trap_oid`, `enterprise` and `exclude_*` OID values match exactly, or as a prefix with a trailing `.*`
  (`1.3.6.1.4.1.99999.*`). A MIB name works too (`linkDown`), resolved against the current MIB set; an unknown name
  is a 400.
- Syslog-only filters (`severities`, `min_severity`, `facilities`, `app`, `host` and their excludes) with
  `type=trap` are a 400 (`severities: not a filter for SNMP traps.`), and trap filters with `type=syslog` likewise.
  `q`, `syntax`, `regex`, `case`, `exclude`, the device selection and the range work as for syslog.
- **Settings → SNMP traps:** the switch (and the firewall hint, §11.2.7), port, answer informs, communities, the v3
  users table (add, edit, delete; passphrases are write-only and show only "set"), the engine ID (copyable, with
  boots and time), the MIB folder (path, counts, errors, **Reload MIBs**), and the last 24 h: received, by status,
  informs answered, replies rate-limited, and the senders with failures (a link to the failures list).

#### 11.2.6 Credentials at rest
**Owner:** encrypted with the OS key store where available (DPAPI, Keychain), otherwise a file only the service
account can read.
- **What's stored:** each v3 user's name, auth and priv protocols, `key_ext`, level and secrets. When a user lists the
  sender engine IDs it applies to (`engine_ids`), only the keys localized to those engines are kept and the
  passphrases are discarded, so a leak can't reveal a passphrase reused elsewhere. Without `engine_ids`, the
  passphrases are kept, because every new engine ID needs them. Informs use keys localized to Woodshed's own engine ID.
  The v1/v2c community list (§11.2.1) is kept in the same file.
- **Windows:** the users file `<data>\snmp-users.dat` holds a DPAPI blob (`CryptProtectData`, user scope, of the
  account the server runs as: `NT SERVICE\Woodshed` for the service, the logged-in user in portable mode), through
  `golang.org/x/sys/windows`, so no cgo. The file's ACL is the data folder's (service account and Administrators).
  Moving the data folder to another machine or account makes it unreadable: Settings then says the v3 users need
  their passphrases again, and keeps their names and protocols.
- **macOS: a file, not the Keychain**, decided (coordinator, 2026-11-14, owner-delegated). Woodshed is built without
  cgo, and the Keychain API needs it; the `security` command-line tool would put each secret on a command line,
  visible in the process list; and the daemon's `_woodshed` account has no login keychain to unlock. A separate
  keychain file would need its own password stored next to it, which protects nothing more than the file. So macOS
  uses `<data>/snmp-users.json`, mode 0600, owned by `_woodshed`, in the 0750 data folder.
- **Linux:** there's no OS key store for system services (the Secret Service belongs to desktop sessions; kernel
  keyrings don't survive a restart). `<data>/snmp-users.json`, mode 0600, owned by `woodshed`. `systemd-creds`
  (host- or TPM-bound encryption) needs root to create, so it's a possible later option, not 1.2.
- On every OS the file is written atomically; secrets are never logged, never in the events log, never in an API
  response (`GET /api/snmp/users` says only `auth_set` / `priv_set`), never in exports, and never accepted on a
  command line.
- v3 users are managed in Settings (`/api/snmp/users`), not by a CLI command: an admin CLI can't encrypt for the
  service account's DPAPI scope, and taking passphrases on argv is ruled out.

#### 11.2.7 Firewalls and installers
The same pattern as TLS (§10.3.6, and the 1.1 build's decisions):
- **Windows:** the MSI's custom action creates "Woodshed SNMP traps (UDP 162)" for `woodshed.exe`, **disabled**, when
  it's missing, and leaves its state alone on upgrade; `woodshed install` does the same. `woodshed snmp on` (as an
  administrator) turns the listener on and enables the rule on `listeners.snmp.port`; `woodshed snmp off` turns both
  off. The UI switch works without it and shows the warn banner `snmp_firewall` with the command while the rule is
  disabled, missing or on another port.
- **macOS:** the application firewall is per program; nothing to do.
- **Linux:** the packages add nothing. `woodshed snmp on` (as root) runs `ufw allow 162/udp` when ufw is active, or
  `firewall-cmd --permanent --add-port=162/udp` and a reload when firewalld runs, recording what it added;
  `woodshed snmp off` removes only that. Settings shows the commands otherwise. No banner.
- `woodshed snmp on|off|status` follow `woodshed tls`: administrator rights, config edit, restart of a running
  service. `status` prints the listener, the engine ID, the last 24 h counts and the senders with failures.

### 11.3 Incident bundle

**Owner (§9):** pick a moment and get the evidence around it, from Events, Export or the CLI; window presets; chosen
devices, a group, or every device active in the window; a preview before building; one folder per type, the
manifest, and a README summary per device.

**It's an export, not a new resource**, decided (coordinator, 2026-11-14, owner-delegated): `POST /api/exports` with
`"kind": "bundle"`. An export already has the queue, the size estimate, the download ticket, the 24 h expiry, the
manifest with SHA-256s, the gaps and the events log, and a bundle is a window plus a device selection, which is what
an export takes. One list of zips in the UI, one set of tests for the zip writer. A separate `/api/bundles` would
copy all of it.

**The request:**
- `at` (RFC 3339), `before` and `after` (durations, `0s`–`7d` each, at least one non-zero). The window is
  `[at − before, at + after)`, and must end no later than now (a bundle "around now" is cut at now).
- Presets in the UI: 15 min before / 5 after, 1 h / 15 min, 4 h / 1 h, 24 h / 1 h, or custom; the time entered in
  local time or UTC (a toggle; the request is always UTC).
- Devices: `devices`, `group`, `ungrouped`, or `"active_devices": true`: every non-hidden device with at least one
  stored record of any type in the window (from the stats, then the files; hidden devices only when named).
- `types`: default every type with data in the window; or a list (`["syslog"]`).
- No text or field filters: a bundle is everything around the moment. Filtering is what a plain export is for.

**The zip:**
```
README.txt                     the summary below
manifest.json                  kind "bundle", at/before/after, devices, types, per-file lines and SHA-256, gaps
woodshed-events.log            Woodshed's own events in the window
logs/<device>/<day>.log        syslog (the folder name 1.0 exports use)
traps/<device>/<day>.log       traps, the stored record lines
```
- Syslog stays in `logs/`, as in every 1.0 and 1.1 export, so scripts that read exports keep working; each other
  type has its own folder (`traps/` in 1.2; `poll/` in 1.3 (§12.6), `flows/` in 2.0). The manifest lists each folder's type.
  Plain exports use the same layout from 1.2 (`types` defaults to `["syslog"]` there, §11.7).
- The README's summary, per device (plain text, aligned, times in UTC with the local offset in the header):
  ```
  Incident bundle around 2026-11-14 09:42:00 UTC (30 min before, 10 min after)
  Window: 2026-11-14 09:12:00 to 09:52:00 UTC (local time UTC-05:00)
  Devices: 3, every device that sent anything in the window. Types: syslog, SNMP traps.
  Communities in traps are shown as a hash prefix and masked in raw=, by design.

  edge-fw-01 (10.1.0.1), group HQ
    Syslog       12,408 messages, first 09:12:00.014, last 09:51:59.880
                 crit 2, err 41, warning 310, notice 1,022, info 11,033 (none of emerg, alert, debug, unknown)
    SNMP traps   7: linkDown 3, linkUp 3, coldStart 1; first 09:30:11, last 09:31:02
    Reboots      1: 09:30:58 (coldStart trap)
    Gaps         none of 1 s or more (Woodshed and its listeners were up the whole window)
    Losses       dropped 0, truncated 0 (Woodshed's own counts; kernel UDP drops aren't visible on this OS)
  ```
  "Reboots" in 1.2 come from coldStart and warmStart traps; 1.3 adds uptime drops from polls. Gaps and losses come
  from the events log and the stats, as for exports.
- **The preview** (Events, before **Build the bundle**) calls only existing or listed routes:
  `GET /api/devices?active_from=…&active_to=…` for the active devices, `GET /api/search/summary` per type for the
  histogram and field panel over the window, and `POST /api/exports/estimate` with the bundle body for the size.
  Narrowing the window or the devices there changes the bundle request.
- **Entry points:** "Bundle around this" on an Events line (its received time), a point on the histogram, Export's
  "Around a time" tab, and the CLI below.

**`woodshed bundle`** builds the same zip without the service, reading the data folder directly (the access rules of
`woodshed search`, §11.4):
```
woodshed bundle --at <time> [--before 30m] [--after 10m] [--devices a,b | --group G | --ungrouped] [--types syslog,trap]
                [--out FILE.zip] [--utc] [--config FILE | --data DIR]
```
- `--at`: RFC 3339; `YYYY-MM-DD HH:MM[:SS]` in local time (UTC with `--utc`); `now`; or `-15m` (relative to now).
- Defaults: `--before 30m --after 10m`; every active device; every type; `--out woodshed-bundle-<hostname>-<at,
  UTC, YYYYmmddTHHMMSSZ>.zip` in the current folder. An existing file is never overwritten (exit 2).
- It prints the path, the size, the SHA-256 and the per-device line of the summary, so a remote helper can ask for
  "one command and one zip". Exit codes as for `woodshed search`, except that 1 means the window held nothing.

### 11.4 Command-line search

**Owner (§9):** `woodshed search` prints matching lines with the Events engine, compressed days included, reading the
data folder directly, on every OS, with the UI off or in LAN mode.

```
woodshed search [QUERY] [--terms | --regex] [--case] [--exclude TEXT]
                [--type syslog|trap] [--from T --to T | --last DUR]
                [--devices a,b | --group G | --ungrouped] [--exclude-devices a,b]
                [--severities 0,3,unknown] [--facilities 4,16] [--app LIST] [--exclude-app LIST]
                [--host LIST] [--exclude-host LIST] [--field KEY=V1,V2 ...] [--not-field KEY=V1,V2 ...]
                [--order asc|desc] [--limit N] [--context N] [--count] [--json | --raw]
                [--config FILE | --data DIR]
```
- **Query and filters** mean exactly what the `/api/search` parameters mean (§10.1, §11.2.5). `--field` and
  `--not-field` take any field key from the type's schema (`--field trap_oid=linkDown`, `--not-field cred=#3f9a1c07`),
  so a new type needs no new flags; `--app`, `--host` and their excludes are shortcuts for syslog's.
- **Time:** `--last 24h` by default (the API's default range); `--from`/`--to` as for `--at` in `woodshed bundle`.
- **Order:** `asc` by default, oldest first like a log file (Events defaults to newest first, a screen of recent
  lines; a pipe wants chronological order). `--limit` 0 (the default) means every match.
- **No time budget:** the CLI runs to the end of the range; Ctrl-C stops it (exit 130). It reads the files in the
  merge order, so output starts at once.
- **Output:**
  - default: one stored line per match, `<received> <device> <record>` exactly as in the file (escaped, so one line
    per match, safe to grep);
  - `--raw`: only the record, unescaped (a syslog message with embedded newlines prints them);
  - `--json`: one JSON object per line (NDJSON), the `/api/search` result shape plus `"type"` and `"device_name"`;
  - `--context N`: N stored lines before and after each match, from the same file, like `grep -C`: `--` between
    groups, and matches marked with `>` in the text forms (`"context": true` on context lines in JSON);
  - `--count`: only the number of matches;
  - at the end, on standard error: `N matches, M MiB read from F files in Ts` (with `--json`, the same as one JSON
    object), so standard output holds only matches.
- **Exit codes:** `0` at least one match; `1` no match; `2` a usage or query error (the message names the flag or the
  character position, as the API does); `3` access denied; `4` no data folder or index found; `130` interrupted.
- **Access:** it reads the data folder directly, so it needs the rights `reindex` needs to read: root (or
  Administrator), or the service account (`sudo -u woodshed woodshed search …`; `_woodshed` on macOS). Anyone else
  gets exit 3 and a message naming the folder, its owner and both ways in:
  `Can't read /var/lib/woodshed (owner woodshed, mode 0750). Run it as root (sudo woodshed search …) or as the
  service account (sudo -u woodshed woodshed search …).` On Windows: "Run it in an administrator prompt."
  Unlike `reindex`, it may run as root on a folder the service account owns, because it never writes there.
- **Read-only, safe beside the running service:**
  - `index.db` is opened read-only (`mode=ro`), never `immutable` (the writer keeps changing it); WAL lets it read
    while the service writes;
  - log files are opened with the shared-delete opener, so rotation, compression and retention carry on; a file that
    disappears mid-search is skipped and counted in the summary line;
  - the active file is read up to its last complete line;
  - it creates, changes and re-owns nothing in the data folder (a test checks this as root, §11.6);
  - it never talks to the service, so it works with the UI off, in LAN mode, or with the service stopped.
- `--config`/`--data` find the data folder; by default it's the installed service's, as for `woodshed status`, or
  `woodshed-data` next to the binary for a portable copy.

### 11.5 UDP receive off the write path

**Why:** today each UDP reader calls the store itself, so anything that slows a write (an fsync, a rotation, a gzip
pass competing for the disk, the hourly stats roll-up) stalls the reader, and datagrams pile up in the OS socket
buffer. When that overflows they're lost in the kernel, and on Windows and macOS that loss is invisible to Woodshed.
A 2026-11-12 lab soak on Windows lost about 20 messages per million over UDP, in bursts near the top of the hour, and
no cause was found in Woodshed. With a queue, a stall caused by Woodshed either disappears (the queue absorbs it) or
shows up as a counted drop, and the queue's high-water mark shows whether stalls cluster at the top of the hour. If
loss continues while the queue never fills, it's outside Woodshed, and that's now provable.

**Design:**
- Each UDP socket (syslog's and the trap listener's) gets a bounded FIFO queue and one drainer goroutine. The reader
  only reads a datagram, stamps the received time, applies the allowlist and blocklist, and enqueues; it never waits
  on the store or touches the disk. A lone datagram (the queue empty, the drainer idle, the socket quiet for 100 µs)
  is the exception: the reader delivers it itself, through the store's `TryWrite`, which stores it only when that's
  a buffer append with its stream's lock free and otherwise does nothing, so it goes to the queue (§11.8, 70).
- The queue is bounded by messages and by bytes, whichever fills first: `listeners.udp_queue_messages` (default
  100,000, 1,000–2,000,000) and `listeners.udp_queue_bytes` (default 64 MiB, 1 MiB–1 GiB), file-only settings like
  the other listener tuning. 100,000 is 10 s at the 10,000 msg/s target, longer than any stall measured so far.
- The drainer parses, applies the device limits and calls the store, in arrival order, so each device's lines stay in
  received order. It also sends trap Responses (§11.2.3) after the store accepts the inform.
- **When the queue is full** the datagram is dropped at once, counted as dropped for its sender's device (the stats'
  `dropped` column, so it's in `dropped_24h` and the export's losses) with reason `queue_full`, and recorded in the
  events log at most once a minute with the count.
- **Visible:**
  - `/api/stats` gains `udp_queue`: per listener, capacity (messages and bytes), current depth, the 24 h high-water
    mark, and `dropped_24h`; and `dropped_by_reason` (`paused`, `write_error`, `refused`, `queue_full`) beside the
    existing `dropped_24h`, which still counts them all.
  - Banner `udp_queue_full` (warn) while there were queue drops in the last hour: "123 UDP messages were dropped in the
    last hour because writing to disk fell behind (the queue holds 100,000). Check the disk, or raise
    `listeners.udp_queue_messages`."
  - The About page shows the high-water mark per hour for the last 24 h, so a top-of-the-hour pattern is visible.
- TCP and TLS keep writing directly from their connection goroutines: TCP's flow control already pushes back on the
  sender, and nothing is lost.
- Shutdown drains the queue to the store before the final flush, so a clean stop loses nothing that was read.

### 11.6 Testing plan

Every item lands with these tests; CI runs them on Linux, Windows and macOS unless noted.

**SNMP decoding (unit and fuzz):**
- BER: every universal and SNMP application type, long and indefinite-length forms (indefinite is refused, as BER
  for SNMP requires), lengths past the buffer, nesting limits, integers of every width and sign, OIDs with large
  sub-identifiers.
- PDUs: v1 Trap-PDU (with each generic type), v2c Trap and Inform, v3 with every security level; RFC 3584's v1-to-v2
  trap OID translation.
- USM: the RFC 3414 Appendix A password-to-key and localization vectors (MD5, SHA-1), RFC 7860's SHA-2 vectors,
  HMAC truncation lengths, the time window, discovery Reports, and both AES-192/256 key-extension methods against
  vectors captured from the interop runs.
- The record format: each value type, escaping, names from MIBs, the community hash and its masking in `raw=`, and a
  round trip: format → parse the fields back → the same values.
- The MIB reader: the built-in set, enumerations, imports across files, broken files reported with line numbers.
- **Fuzz targets** (`go test -fuzz`, run in CI for a fixed time like the syslog parser's): `FuzzBER`,
  `FuzzMessage` (any datagram through the full decode, no panic, bounded memory, a malformed result rather than an
  error path that drops it), `FuzzUSM` (v3 with fixed keys through auth and decrypt), `FuzzRecord` (format and
  re-parse), and `FuzzMIB`.

**Interoperability (CI, Linux job only):** the distribution's net-snmp command-line tools, installed in CI only and
never a dependency, send to a real `woodshed run`:
- `snmptrap -v 1` and `-v 2c`, `snmpinform -v 2c` (the reply must arrive: `snmpinform` exits 0);
- `-v 3` traps and informs for every combination: noAuthNoPriv; authNoPriv with each of MD5, SHA, SHA-224, SHA-256,
  SHA-384, SHA-512; authPriv with each auth and each of DES, AES-128, and AES-192 and AES-256 with each
  key-extension method (where the tools offer both). That's 1 + 6 + 36 combinations, each as a trap and as an
  inform.
- Secrets go in a temporary `snmp.conf` (the tools' default-passphrase settings), not on the command line.
- A wrong passphrase, an unknown user and an out-of-window time each give the expected status in the stored record and
  in `/api/snmp/failures`.
- If the distribution's build lacks DES (some disable it), those cases are skipped there and covered by
  `woodshed send --proto trap` below.

**`woodshed send --proto trap`** (the lab generator, so lab hosts need no other software):
- `--snmp-version 1|2c|3`, `--inform` (waits for the Response and reports round-trip times and timeouts),
  `--community-file F`, `--user NAME`, `--auth md5|sha|sha-224|sha-256|sha-384|sha-512`, `--priv
  des|aes-128|aes-192|aes-256`, `--key-ext draft|alt`, `--trap-oid OID`, `--varbinds N`, `--engine-id HEX`, plus the
  usual `--count`, `--rate`, `--duration`, `--host`, `--port` (default 162).
- Passphrases and communities come from files or `WOODSHED_SNMP_COMMUNITY` / `_AUTH_PASS` / `_PRIV_PASS`, never
  from the command line.
- Each trap carries the run ID and sequence number in a varbind, so the lab can count exactly-once delivery as it does
  for syslog. `woodshed bench --proto trap` measures throughput in-process.

**End to end** (the real binary): syslog over UDP, TCP and TLS plus traps v1, v2c, v3 and informs from `woodshed send`,
then: Events search and summary for both types, CLI search for both, a bundle around the coldStart, and the unzipped
bundle checked: every file's SHA-256 matches the manifest, the README counts match what was sent, `traps/` holds the
traps, the reboot line names the coldStart, and a v2c community appears nowhere in the zip.

**Install smoke tests** (each OS, the existing job): the SNMP listener stays off after install and after a 1.1→1.2
upgrade; on Windows the 162 rule exists and is disabled, `woodshed snmp on` enables it and a trap from another process
arrives, `off` disables it, and an upgrade keeps the rule's state; on Linux with ufw active, `snmp on` then `off`
leaves the rules as they were; on macOS a trap arrives on the wildcard as `_woodshed`.

**Load and soak:**
- Targets on the reference spec (4 cores, 8 GB, SSD): **2,000 traps/s** v2c with 10 varbinds, and **1,000/s** v3
  authPriv (SHA-256, AES-128), sustained 10 min with 0 loss, while syslog runs at 5,000 msg/s; informs at 500/s with
  every Response within 50 ms (p99). Recorded in the release notes like the syslog bench.
- The UDP queue: a fake slow disk (writes stalled for 3 s every minute) at 10,000 msg/s loses nothing with the
  default queue, and with a 1,000-message queue loses exactly what `queue_full` counts (sent − stored = counted).
- Soak: 24 h on the lab VMs at 3,000 syslog msg/s plus 200 traps/s (mixed v1, v2c, v3 and informs), crossing midnight
  UTC, with a forced low-disk pause and a service restart. Pass: every message and trap stored exactly once or
  counted as dropped, every inform answered once per transmission, RSS flat, and the queue's high-water mark recorded
  per hour (the Windows top-of-hour check).

**Bundle and CLI search against stored data:** a fixture data folder with plain and `.gz` days, size-split parts,
both types, a hidden and a forgotten device, and a gap in the events log:
- `woodshed search` golden outputs for each format (text, `--raw`, `--json`, `--context`, `--count`), each exit
  code, `--order` both ways, ranges crossing `.gz` days and parts, and identical results to `/api/search` for the same
  query;
- beside a running writer that rotates, compresses and deletes files: no error, no duplicates, every line from
  before the search started found;
- as root on a folder the service account owns: afterwards no new file, no changed mode or owner in the data folder;
  as another user: exit 3 and the message;
- `woodshed bundle` and the API bundle over the fixture produce zips with the same file list and SHA-256s, and the
  README summary matches the fixture's counts, gaps and reboots.

### 11.7 Versioning and compatibility
- **Config:** a 1.1 `woodshed.toml` loads unchanged. New keys take their defaults: `[listeners.snmp]` off, the UDP
  queue limits. Nothing turns on by itself.
- **Data:** syslog files are unchanged in format and place. The index migrates once on start (`files.type`, the
  `type_stats` tables); the migration is append-only like every earlier one. Traps go only into the new `traps/`
  folders.
- **Downgrade** isn't supported: 1.1 refuses an index with a newer schema, as every version does. To go back, stop
  1.2, move `index.db` aside and run 1.1's `woodshed reindex`; it rebuilds the syslog index and ignores the `traps/`
  folders (1.1's file listing skips subfolders), which stay on disk.
- **API:** additive only. Every 1.1 request means what it meant: `type` defaults to `syslog`; syslog results keep
  their shape; a 1.1 export body (no `types`, no `kind`) builds the 1.1 zip, syslog in `logs/`; new fields in
  `/api/stats`, `/api/status` and `/api/devices` are additions; new banner kinds and listener `proto` values are
  additions that 1.1 UIs ignore. Saved searches without `type` are syslog.
- **URLs:** Events links without `type` open syslog; `#/events?type=trap…` is new.
- **CLI:** every 1.1 command and flag keeps its meaning; `woodshed send` still defaults to UDP syslog.

### 11.8 Decisions for 1.2

**Owner (2026-11-14):** everything in §9's 1.2 list, plus UDP receive off the write path, is in 1.2, with thorough
testing; the incident bundle and command-line search as described in §9; traps on UDP 162 with v1, v2c and v3,
stored as decoded text lines with the raw PDU, numeric OIDs and an optional MIB folder, no MIB compiler; credentials
encrypted with the OS key store where available, otherwise a service-account-only file.

Everything below is **decided (coordinator, 2026-11-14, owner-delegated)**:
1. Types are implemented through one interface in `internal/datatype`; syslog is its first implementation, unchanged
   (§11.1).
2. Traps live in their own files in `logs/<device>/traps/`, not in the syslog files with a marker, and not in a
   parallel top-level tree (§11.1).
3. Non-syslog types get new `type_stats` tables; syslog's 1.1 stats tables stay untouched (§11.1).
4. Retention treats all of a device's types as one: shares from the summed bytes, oldest file first across types
   (§11.1).
5. The live tail stays syslog-only in 1.2; device tiles count every type (§11.1).
6. The SNMP listener is off by default (§11.2).
7. Woodshed's own BER, PDU and USM code, not a third-party SNMP library: the receive path needs decoding, USM and
   two reply types; a small codec is lenient where a library rejects, keeps the raw bytes, is fuzzed with the
   rest, and adds no dependency. The 1.3 poller reuses it (§11.2).
8. Informs are answered by default, only to admitted senders, only once stored, rate-limited; retransmits are stored
   and marked `dup=1` (§11.2.3).
9. The engine ID uses the RFC 3411 "administratively assigned" format with enterprise number 0 until the project has
   its own (§11.2.3).
10. v3 failures and malformed packets are stored with a status; community refusals aren't (§11.2.2).
11. AES-192/256 offer both key-extension methods per user, defaulting to the draft's (§11.2.2).
12. MD5, SHA-1 and DES are allowed and labelled weak (§11.2.2).
13. Communities are stored as a SHA-256 prefix, and masked with `*` in `raw=`; v3 messages are kept exactly
    (§11.2.4).
14. OIDs are stored numerically with the names known at receipt; the UI names from the current MIB set (§11.2.4).
15. The MIB reader takes names, notifications and integer enumerations only (§11.2.4).
16. A v1 trap's agent-addr is shown, never used for identity (§11.2.4).
17. Syslog-only filters with `type=trap` (and the reverse) are a 400 (§11.2.5).
18. macOS keeps v3 credentials in a 0600 file, not the Keychain: no cgo, no secrets on a command line, and a daemon
    has no login keychain (§11.2.6).
19. With known engine IDs, only localized keys are kept and passphrases are discarded (§11.2.6).
20. v3 users are managed only in Settings and the API, never by CLI flags (§11.2.6).
21. The bundle is an export (`kind: "bundle"`), not a new `/api/bundles` resource; it takes no text or field
    filters (§11.3).
22. Syslog stays in the zip's `logs/` folder for compatibility; other types get their own folders (§11.3).
23. 1.2's reboot detection in bundles comes from coldStart and warmStart traps (§11.3).
24. CLI search defaults: `--last 24h`, oldest first, no limit, no time budget, grep-style exit codes (§11.4).
25. CLI search may run as root on the service account's folder, because it never writes (§11.4).
26. The UDP queue: per socket, 100,000 messages or 64 MiB by default, dropped and counted when full; TCP and TLS stay
    direct (§11.5).
27. The community allowlist is kept in the credentials store, not the TOML, and shown only as hash prefixes
    (§11.2.1).
28. **Traps outside the time window are relearned, not lost** (2026-11-14, answering the build's flag on devices that
    reboot without raising their boots). An authenticated v3 trap that fails only the timeliness check is still
    decrypted (if priv) and stored with its full contents, with status `not_in_time`, so it's visible and never
    silently trusted. The receiver then adopts that trap's boots and time as the sender engine's clock, so the
    device's following traps are in time again. Only a message whose digest verified moves the clock; noAuthNoPriv
    messages have no timeliness and never do. Each resync is counted per sender, so a replay shows as a burst.
    `listeners.snmp.v3_strict_time = true` keeps RFC 3414's rule (the header only, no relearning). Informs are
    unchanged: the authenticated Report already resyncs their senders.

SNMP codec, **decided (build, 2026-11-14)**: the calls build step (a) (`internal/snmp`, `woodshed send --proto trap`,
the interop job) made where §11.2 and §11.6 left room. Nothing here is user-facing yet.
1. **Leniency and bounds.** Definite lengths only. Accepted: non-minimal lengths and integers, unsigned values sent
   with the sign bit set (read as unsigned), a v1 agent-addr sent as an OCTET STRING and a time-stamp as an INTEGER,
   UInteger32 (read as Gauge32), and bytes after the message (ignored; `raw=` keeps them). An OID has at most 128
   sub-identifiers (RFC 2578 §3.5), each at most 2^32−1. Any value that doesn't decode makes the message `malformed`;
   its record keeps what decoded before the break (`v`, `pdu`, `id`, `cred`) and no `vb=`.
2. **Value types beyond §11.2.4's list:** a tag outside the SMI (BOOLEAN, NsapAddress, a constructed value) and an
   IpAddress that isn't 4 octets are stored as `hex:` of the content (`raw=` keeps the tag). `str` means printable UTF-8
   by Go's `unicode.IsPrint` (space yes; tab, CR, LF and NUL no, so they're `hex`); an empty octet string is `str:""`.
3. **Unexpected PDUs** are named `get`, `getnext`, `response`, `set`, `getbulk`, `report`, or `0xNN` for another PDU
   tag, and keep their decoded varbinds. A v1 Trap-PDU in a v2c/v3 message, and an SNMPv2-Trap in a v1 message, are
   `unexpected_pdu`. A first byte that isn't a SEQUENCE is `malformed` ("not an SNMP message").
4. **Discovery probes** (an empty engine ID, reportable) are answered with the Report and counted, and not stored:
   they carry no notification, and every v3 inform sender sends one.
5. **unknown_engine and Reports.** A reportable message (an inform) naming another engine ID is `unknown_engine` and
   gets a `usmStatsUnknownEngineIDs` Report with Woodshed's ID (RFC 3414 §3.2 step 3), so a sender with a stale ID
   recovers. `unknown_engine` also covers a user with engine-bound keys and an engine not in its list, an
   authenticated trap with an empty engine ID, and a localization refused by the rate limit (the error says which).
   Only discovery, unknown engines and time-window misses get Reports; unknown users, wrong digests, decryption errors
   and level failures don't (the RFC allows them, but they'd let a scanner enumerate user names).
6. **Keys.** Each user's password-to-key results (Ku) are computed once when the users are set (the passphrases aren't
   kept by USM after that); a new engine then costs one small hash, so a reboot storm of many devices with new
   engine IDs isn't throttled. The 20-a-second limit applies only to the 1 MiB hash the alt AES-192/256 key extension
   needs per engine. Passphrases have at least 8 characters (RFC 3414 §11.2), for users and for `woodshed send`.
7. **Replies.** The Response echoes the inform's request-id and varbind-list encodings as received, with error-status
   and error-index 0, at the inform's level, with Woodshed's boots and time; it may be at most 32 bytes larger than the
   inform (`snmp.MaxReplyGrowth`), or it isn't built. The not-in-time Report is authNoPriv with the user's key (RFC 3414
   §3.2 step 7a); the others are noAuthNoPriv. A Report's request ID is the request's when the PDU is plaintext, else 0.
8. **Time window for traps:** RFC 3414 §3.2 step 7b per sender engine (10,000 engines kept, least recently used out),
   updated only by authenticated messages; the first message from an engine is accepted. Outside the window, #28
   applies: the codec sets `Message.TimeResync`, keeps the status `not_in_time` and the full PDU, adopts the trap's
   boots and time, and counts `Counters.TimeResyncs`; the listener (step d) counts them per sender.
   `USM.SetStrictTime(true)` is `v3_strict_time`. A sender at the latched boots (2^31−1) stays out of the window
   either way.
9. **v3 failures show only the header**, even when the PDU is plaintext (noAuthNoPriv below the user's level, or
   authNoPriv with a wrong digest): unauthenticated content in a record would look real. A #28 trap is the
   exception, because its digest verified.
10. **Record details.** v3 `cred` (and `ctx`) is bare when it's letters, digits and `._-@+%:/` and doesn't start with
    `#` or `0x`; quoted when it's other printable text; `0x` and hex otherwise. `ctx_engine` is written only when it
    differs from `engine`. `agent=` is dotted, or `0x` and hex when it isn't 4 octets. `generic=` is the number alone.
11. **Names in the record:** an OID gets the name of the OID itself, or of the object or notification it's an instance
    of plus the index (`ifOperStatus.3`); an OID under a plain `OBJECT IDENTIFIER` node gets none
    (`enterprises.32473.1` would say nothing the number doesn't). A record that would pass 1 MiB (less 256 bytes) with
    names is written without them; without names the largest datagram fits.
12. **Masking in broken datagrams:** the community is found leniently (the second element of the outer SEQUENCE when
    it's an OCTET STRING and the version isn't 3), clipped at the end of a truncated datagram. A datagram too broken to
    show a version and an OCTET STRING there has nothing masked.
13. **The MIB reader** also takes the conformance macros (OBJECT-GROUP, NOTIFICATION-GROUP, MODULE-COMPLIANCE,
    AGENT-CAPABILITIES) and any other macro of the `name MACRO-NAME … ::= { … }` shape, since they assign OIDs the same
    way. Comments end at the next `--` or the end of the line (X.680). Identifiers are at most 128 characters. A file
    holding a built-in module replaces it. A bare name two modules define with different OIDs is ambiguous for filters
    (name the module: `IF-MIB::linkDown`). Imports from the macro-only modules (SNMPv2-CONF, SNMPv2-TC, RFC-1212,
    RFC-1215) aren't warned about; unresolvable parents and cycles are warnings. The built-in set is SNMPv2-SMI,
    RFC1155-SMI, RFC1213-MIB, SNMPv2-MIB, IF-MIB, SNMPv2-TC, SNMP-FRAMEWORK-MIB, SNMP-USER-BASED-SM-MIB and
    SNMP-COMMUNITY-MIB, trimmed to OIDs and enumerations.
14. **The engine file** `snmp-engine.json` is `{"engine_id": "<hex>", "engine_boots": N}`, mode 0600, written
    atomically; an `engine_id` override doesn't replace the stored ID; boots stop at 2^31−1.
15. **`woodshed send --proto trap`:** v2c by default; the community is `public` when no file or variable gives one.
    Passphrases come from `--auth-pass-file`/`--priv-pass-file` (one line; a trailing newline is dropped) or the
    variables. The sequence varbind is `1.3.6.1.4.1.32473.1.1.1.0` = `str:"seq=<run>:<n>"` (plus ` <--message>`),
    and the default trap OID `1.3.6.1.4.1.32473.1.0.1`, under 32473, IANA's enterprise number for documentation
    (RFC 5612). `--varbinds` adds mixed-type fillers under `…32473.1.1.2`. v3 traps use a random engine ID with
    boots 1; informs discover the receiver (or take `--engine-id` and learn boots and time from its first Report) and
    send each inform once more after a Report; there are no other retransmissions, so a missing Response is a timeout
    (exit 1). `--timeout` (default 2 s) is the wait for each Response. verifyseq's counting ends the number at the first
    non-digit, so it reads a trap record's quoted value as it reads syslog.
16. **Interop in CI** requires MD5, SHA-1, SHA-2 and AES-128 from the distribution's tools; DES and AES-192/256 cases
    are skipped, and listed in the job summary, where the build lacks them. net-snmp's `AES-192`/`AES-256` are the
    draft key extension and `AES-192-C`/`AES-256-C` the alt one. Its datagrams for the short-key AES-192/256 cases are
    logged with the fixed test passphrases, as key-extension vectors.

**Decided (build, 2026-11-14), `woodshed search` (§11.4, step (c)):**
1. `index.db` is opened `mode=ro` while its `-wal` and `-shm` exist (a writer has it open), and `immutable=1` when
   they don't. A `mode=ro` open creates both files when they're missing (measured on the pure-Go SQLite build), which
   would break "creates nothing" with the service stopped; without them no writer has the index open, since the last
   connection to close removes them. If a service starts mid-search, that search may miss index rows written after it
   began, so an immutable search compares `index.db`'s size and mtime and whether `-wal` exists before and after,
   and if any changed prints `warning: Woodshed started writing while this search ran; results may be incomplete.
   Run it again.` on standard error, keeping the exit code (coordinator, 2026-11-14). This narrows §11.4's "never
   `immutable`". The schema must match this build's: a read-only open can't migrate
   (exit 4 with the reason).
2. The query and filters go through the API's own parser (`api.ParseSearch`) and the server's query builder
   (`server.SearchQuery`), so they can't drift from `/api/search`. Each flag is first checked on its own, so the
   message names the flag (`--severities: "9" is not a severity …`, `--field severity: …`); query errors are prefixed
   `QUERY:` or `--exclude:` and keep the API's character positions.
3. `--field`/`--not-field` keys come from `search.Schema()` for the `--type`; a field with an exclude parameter
   uses it, a closed field (severity, facility) is excluded by sending the rest of its domain (within any values
   asked for; nothing left is `none`). `--type` accepts exactly the schema's types, so (d) adds `trap` without a new
   flag; anything else is exit 2 naming the known types.
4. `--devices`, `--exclude-devices` and `--field device=` take device IDs or addresses; an address is turned into
   its device ID (`2001:db8::5` → `2001_db8__5`), which is what a person has in hand.
5. Time: `--from` alone ends now, `--to` alone starts 24 h before it (the API's defaults); `--last` can't be combined
   with either. `--utc` reads the local forms as UTC, as for `bundle --at`. The parser is shared with (e).
6. `--context N` (0–500) reads each match's own file only, so a group stops at a part or day boundary. Groups merge
   like `grep -C` when they touch or overlap (no `--`, and a match inside another's context is still marked). Matches
   of different devices interleave in time; each group is printed whole before the next device's, so a line can
   appear in two groups of one file when another device's match fell between them. In the text forms matches start
   with `> ` and context lines with two spaces, so columns line up. With `--order desc` a group reads newest first,
   like the rest of the output. JSON has no `--`; with `--context` every object has `"context"`.
7. `--context` with `--order desc` reads each compressed day once: gzip reads only forwards, so the day is
   decompressed whole and kept in memory, up to 256 MiB of uncompressed days at a time (the 16 most recently used
   files). Past that cap a day falls back to restarting a 4 MiB window back from the match, each restart
   decompressing from the start of the day, which is slow for far-apart matches on huge days. Plain files and the
   default ascending order read each file once either way.
8. `--count` prints the number (`{"count":N}` with `--json`) and can't be combined with `--raw` or `--context`;
   `--json` and `--raw` are alternatives. `--count` with no match prints `0` and exits 1, like `grep -c`.
9. The summary line on standard error is `N matches, M MiB read from F files in Ts`, plus `; K files skipped (deleted
   or unreadable during the search)` and ` (interrupted)` when they apply; with `--json` it's one object:
   `{"matches","scanned_bytes","scanned_files","gone_files","elapsed_ms","interrupted"}`.
10. Exit 2 also covers errors that aren't the user's (a write error, an unreadable index row), as for grep; a
    symlinked or hard-linked `index.db` is refused with exit 3.
11. The data folder is `--data`, else `--config`'s, else `woodshed-data` next to the binary when it holds an
    `index.db` (a portable copy), else the installed config's, else the OS default. The config is read with
    `config.Read`, which never creates one.
12. The access check opens the folder, `logs/` and `index.db`; a refusal names whichever failed, its owner and mode,
    and the command line actually typed (`sudo woodshed search --data /var/lib/woodshed link`) rather than `…`. The
    service account in the hint is the folder's owner when that isn't root, else the default (`woodshed`,
    `_woodshed` on macOS).
13. Output is buffered and flushed every 200 ms while the search runs, so a match shows at once even when the next
    is far away; Ctrl-C flushes what was found and prints the summary.

**Decided (build, 2026-11-14)**, the UDP queue (§11.5), for the owner to overrule:
28. `dropped_by_reason` is counted in memory since the server started, not in the index: no schema migration in
    step (b), so it can't collide with step (d)'s. Within a day of a restart it can sum to less than `dropped_24h`
    (docs/api.md says so). `paused` is the brief's "low_disk": queued messages that reach a paused store count there.
29. A queue drop counts where the message would have been stored: the sender's device, admitted as `Write` would. A
    sender the device limits refuse, or past the drainer's per-sender table (65,536 senders between two reports), is
    counted under the `_refused` stats row, still as `queue_full`, so totals stay exact.
30. The events log gets one `queue_full` event a minute for all devices together (warn, naming the device when there's
    one), not one per device as for paused and write-error drops: a stall can touch thousands of devices.
31. `udp_queue_bytes` counts message bytes, not Go's per-entry overhead (about 80 bytes, so at most 8 MB more at the
    default 100,000). The reader truncates at `max_message_bytes` before queueing, so the count is what's stored.
32. Shutdown drains for at most a third of the shutdown timeout (5 s for the service, about 1.3 s portable); what's
    left then counts as `queue_full`. Close still waits for the message in the sink, so no write happens after it.
33. `high_water_by_hour` runs from the later of the start and 24 hours ago (so fewer than 24 entries in the first
    day); the current hour includes the depth now. A rebind keeps the history; `udp_queue` lists an enabled listener
    while it's down, with `port` 0.
34. The `udp_queue_full` banner names the limit that refused the latest drop (`udp_queue_bytes` with a size, or
    `udp_queue_messages` with a count); several UDP listeners share one banner with the counts summed.
35. `woodshed bench` gains `--stall-every`, `--stall-for` and `--udp-queue-messages`, so §11.6's fake-slow-disk run
    needs no test build. Measured on the 14-core build laptop (macOS, loopback), 10,000 msg/s for 130 s with a
    3 s stall every minute: the default queue lost 0 of 1,300,000 (high-water 30,000); a 1,000-message queue lost
    57,998, all counted as `queue_full` by the listener and the store alike (sent = stored + counted).

**Decided (build, 2026-11-14), the data-type framework and the trap receiver (step d)**, for the owner to overrule:
36. Syslog's filter parameters keep 1.1's parser (`api.ParseSearch` into `SearchRequest`'s fields), and the
    framework's syslog filter (`datatype.SyslogFilter`) is built from those fields, so a syslog request means exactly
    what it meant; the trap type parses its own (`datatype.ParseTrapFilter`). A type's filter has a cheap `Pre` and a
    costly `Post`, so syslog keeps 1.1's check order (the PRI, then `q` and `exclude`, then the header parse).
    `FieldValues`, `Text`, `ValueLabel` and `Summary` are the type's; the API result for traps is `datatype.Result`.
37. The store keeps one write stream per device and type. The device cap and the new-sender buckets count
    addresses, and an eviction at the cap takes every stream of the device.
38. Totals, rates, drops, the flood check and the fair-share weights read `stats` and `type_stats` together; the index
    histogram reads only the query type's table. Migration 5 → 6 also adds `deletions.type`, so the storage history
    shows each deletion's type.
39. A non-syslog cursor binds the type and its filter; a syslog cursor binds exactly what 1.1's did.
40. MIB names: one current set for the process, set by the server at start and by Reload MIBs. Filters resolve names
    against it when the request is parsed. `woodshed search` loads the data folder's MIB folder read-only (the
    config's `mib_dir`, else `<data>/mibs`).
41. The default MIB folder `<data>/mibs` is created at start; a `mib_dir` the user names that's missing is listed as
    an error and never created.
42. The credentials file has a public part (names, protocols, key extension, engine IDs, how keys are stored) and one
    protected blob with every secret (passphrases, localized keys, communities), so the names and protocols survive a
    blob that won't decrypt. Off Windows the blob sits inside the 0600 file as it is; on Windows it's DPAPI with an
    application entropy and no UI.
43. An engine-bound user also keeps keys localized to Woodshed's own engine ID, for informs. After an `engine_id`
    override, informs from that user need its passphrases again.
44. A v3 user can't be renamed: delete it and add the new name (a PUT with another `name` is a `400` on `name`).
45. The community list is compared by SHA-256 in constant time. A refused trap is counted in `/api/rejected` (reason
    `community`) and not stored.
46. A discovery probe is admitted as a write would be (the device limits, `store.AdmitType`) before its Report; a
    refusal isn't a drop.
47. A retransmitted inform is the same source address, version, context engine ID and request ID within 60 s. At
    most 200,000 are remembered; past that they're forgotten all at once, so the table never grows.
48. `discovery_reports` counts every Report sent: a discovery probe, an unknown engine ID, a time-window miss.
49. A trap the store refuses (writes paused, the device limits) isn't answered: the sender retries.
50. A runtime `engine_id` change makes a new USM with the same boots and start; the senders' clocks are relearned.
51. The failing-sender list and the reply limiter each track at most 10,000 addresses (least recently seen out;
    past that, a new source gets no reply).
52. The SNMP listener's datagrams count in the listeners' received total, and its events have the source
    `listener/snmp`, so an export's gaps include SNMP listener downtime (proto `"snmp"`).
53. The store logs once per start each folder inside a device folder that no data type claims.
54. Exports take `types` (none is the 1.1 zip, syslog in `logs/`); filters apply only with one type; `kind: "bundle"`
    is a `400` until step (e). The trap filters in an export body or a saved search are JSON lists of strings (numbers
    too, for `generic` and `specific`).
55. `woodshed bench --proto trap` gives its own in-process receiver reply limits of twice the bench rate: §11.6's 500
    informs a second from one sender would otherwise hit §11.2.3's 100 a second per source. The load and soak targets
    for informs need several senders (or this bench); the limits have their own tests. Measured on the 14-core build
    laptop (macOS, loopback, 30 s each, every trap read back): 2,000 v2c traps/s with 10 varbinds, 60,000 of
    60,000 stored once (queue high-water 6); 1,000 v3 authPriv (SHA-256, AES-128) traps/s, 30,000 of 30,000;
    500 v3 authPriv informs/s, 15,000 of 15,000 stored and answered, Response p50 0.31 ms, p99 1.06 ms; and
    10,000 v2c traps/s for 10 s, 100,000 of 100,000 (high-water 13). The 10-minute runs beside 5,000 syslog
    messages/s are the lab's (§11.6).
56. `counts_24h.received` counts every datagram the SNMP listener read, refused communities and discovery probes
    included; `by_status` counts the stored ones.

**Decided (build, 2026-11-15), the incident bundle (§11.3, step e)**, for the owner to overrule:
57. **The window.** `at` later than now is a `400`; the end is cut at now; a window left empty by the cut (`at` now,
    `before` 0s) is a `400`. Left out, `before` and `after` are the CLI's 30m and 10m. Spans take `ms`, `s`, `m`, `h`
    and `d` (combined, decimals allowed, rounded to the millisecond) and are echoed in the shortest form (`1h30m`,
    `7d`, `0s`). Times are milliseconds, as stored: the window's edges are rounded up to the millisecond, like a
    search's.
58. **The devices.** `active_devices`, `devices`, `group` and `ungrouped` are alternatives (exactly one). `all_devices`
    and `exclude_devices` are a `400` naming them, as is each filter sent with a non-default value (`"syntax":
    "text"` or `"regex": false` are accepted, being no filter). Named devices are bundled even when silent (their
    README lines say "none") and when hidden; a group or the ungrouped are their non-hidden devices, as for exports.
    `type` (1.1) is a one-entry `types`.
59. **Active devices are exact, from the files, not the stats** (search.Active): a file whose first or last received
    time is in the window, or a checkpoint received in it, proves a stored record; otherwise one read of the window,
    stopping at the first record. Minute buckets match the window's edges only roughly, and the stats outlive the
    files retention deletes. With `types` given, "active" means a record of those types. `GET
    /api/devices?active_from&active_to` is the same test over every type, combined with the other parameters
    (hidden devices too unless `hidden=exclude`), on both of its paths (by live rate and in SQL).
60. **Types are resolved when the bundle is created**: with none named, the types (registry order) with a record from
    the bundle's devices in the window; the entry keeps them, so the build and the echo agree. Nothing stored leaves
    `types` empty.
61. **Nothing in the window.** With `active_devices` and no active device, the API answers `400` "No device stored
    anything between … and …." (naming the types when given) and the CLI exits 1. Named devices that sent nothing
    still get a zip from the API (the README says so, with the gaps: evidence too); the CLI exits 1 and writes no zip
    (the estimate is 0, or the build wrote no record and the file is removed), per §11.3's "1 means the window held
    nothing".
62. **The summary.** Counted while the records stream into the zip (each type's `datatype.Summary`, replacing step
    (d)'s in-memory `Type.Summary`). Syslog's `by_severity` always has all nine values (emerg … debug, unknown);
    `by_trap` names traps from the current MIB set (else the OID), most first, ties in order of arrival, and counts a
    record without a trap OID by its status (`(auth_failed)`, `(malformed)`). README lists 10 trap names, then "and N
    more (M)"; manifest.json has them all. A summary entry also has `ip`, beyond §11.3's list.
63. **Reboots** are coldStart and warmStart traps and informs whatever their status (a `not_in_time` trap's digest
    verified, #28, and a reboot is exactly when boots and time jump); a retransmitted inform (`dup=1`) isn't a second
    reboot. README lists 5, then "and N more". Without traps in the bundle the line says "not known (no SNMP traps in
    this bundle)".
64. **Gaps and losses per device.** Each device's gaps are the bundle's (the same list for all: the events log has
    no per-device listener, and a device can send over several). Drops and truncations are the device's stats (every
    type) for the buckets that start in the window, per minute (per hour past 24 h), as `/api/stats` counts them, so
    a bucket straddling an edge counts whole; `summary_note` says so. The losses line names the kernel's drops as
    not visible (Windows, macOS) or not per device (Linux).
65. **README times** are UTC: records' first, last and reboots always with milliseconds, other times with them when
    they have any, and with the date when the window spans more than one UTC day. The header's local offset is the
    building machine's at `at` (the service's for the API). The README has no export ID, so the CLI's and the API's
    are the same bytes; their zips differ only in manifest.json's `id` and `exported_at` and the entries' times.
66. **The download** of a bundle is named `woodshed-bundle-<host>-<at>.zip`, like the CLI's default `--out`; the
    host name keeps `A–Z a–z 0–9 . -` and turns anything else into `_`.
67. **`woodshed bundle`:** `--active` is the default made explicit, alternative to `--devices`, `--group` and
    `--ungrouped` (two of them: exit 2). An `--out` inside the data folder is exit 2 (the data folder is never
    written to). The zip is created exclusively with mode 0644 less the umask (it's meant to be handed on); an
    interrupted or failed build removes it. It prints the absolute path, the size and SHA-256, the window with the
    record count, a line per device (`syslog N, SNMP traps N, reboots N, dropped N, truncated N`) and the gaps'
    count. It loads the data folder's MIBs as `woodshed search --type trap` does, and warns, as search does, when a
    service started writing during an immutable read.
68. The events log says "Incident bundle exp_… queued" for a bundle, "Export …" for an export.

69. **The UI** (web/, step e): **Bundle around this** is a button in a line's context view and an item in its
    right-click menu, for syslog and trap lines; the moment is the line's received time to the millisecond, the
    search's devices carry over ("all devices" becomes `active_devices`), and the text and field filters are dropped
    (a bundle has none). "A point on the histogram" is a **Bundle around a moment** mode on the histogram: the next
    click picks the time under the pointer (rounded down to the minute, to the second for buckets under a minute),
    Enter picks a bar's start, Esc cancels; dragging to zoom is unchanged outside the mode. The presets add the API's
    default, 30 min / 10 min, as a fifth, and a new bundle starts on it. The preview is Events in a bundle mode: a
    card with the window, types, estimate and **Build the bundle**, the active devices with per-type counts (from the
    summary's device field), the histogram (a drag narrows the window, a line marks the moment) and the fields panel;
    unticking a device turns `active_devices` into an explicit `devices` list, and filters typed there change only
    what's shown. Export's **Around a time** starts at now (so its window shows "cut at now") and offers **Preview in
    Events**. Local or UTC input reuses the app-wide preference; requests are always UTC. Export's types are Syslog,
    SNMP traps or Both; Both hides the filters, as the API refuses them with two types.

**Decided (build, 2026-11-15), the Windows CPU fix after the 1.2.0-rc1 lab**, for the owner to overrule:
70. **A lone UDP datagram skips the drainer.** rc1's lab (Windows Server 2022, 4 vCPU) measured about a core at 500
    msg/s, half of it kernel time, for syslog and traps alike, and less per message as the rate rose. At low rates the
    reader readied the drainer for every datagram and blocked again at once; the Go scheduler then wakes a second OS
    thread to steal the readied goroutine, which on Windows spins with SwitchToThread (runtime `runqgrab`,
    `osHasLowResTimer`): two thread wake-ups a message where 1.0 had one. Now, when the queue is empty, the drainer has
    nothing in hand and the socket was quiet for 100 µs, the reader delivers the datagram itself through a call that
    can't block: `store.TryWrite` (an append to an open stream's buffer under `TryLock`, with no new day, part or
    flush; otherwise it does nothing). A delivery that would block, a burst and a backlog go through the queue as
    before. A trap the reader decoded but couldn't store goes in as a finish step, so it's decoded and counted once.
    FIFO, the counted drops and the shutdown drain are unchanged. Rejected: waking the drainer per batch with a timer
    (still a wake per lone message, plus latency and a timer); spinning before parking (CPU at idle).
71. **Proof:** `TestCPUPerMessage` (internal/loadgen, `WOODSHED_CPU=1`) measures process CPU per message (getrusage,
    `GetProcessTimes` on Windows) with the sender in a child process, for this build and for rc1's path
    (`BenchOptions.NoFastPath`) side by side; CI prints it on Linux, macOS and Windows.

### 11.9 Questions settled (1.2), decided (coordinator, 2026-11-14, owner-delegated)
1. No IANA Private Enterprise Number for now; the engine ID keeps the placeholder (§11.2). Revisit if the project
   ever publishes a MIB.
2. macOS keeps the 0600 service-account file (§11.2.6), no cgo build. The 1.3 roadmap line is amended to match.
3. The live tail stays syslog-only in 1.2; a type switch on the Dashboard is a later item.
4. A trap-only sender counts against `max_devices` like any sender: a device is a device. No separate SNMP cap.
5. The load targets stand as starting points and are adjusted after the first bench, with the measured numbers
   recorded here.
6. Build order (to keep merges small): (a) `internal/snmp` codec, USM, fuzzing and `woodshed send --proto trap`;
   (b) the UDP queue; (c) `woodshed search`. Then (d) the data-type framework plus trap integration, on top of
   (a) and (b). Then (e) the incident bundle, on top of (d).

## 12. 1.3 design (draft, 2026-11-15)

The SNMP poller ("OID watcher") from §9's 1.3 entry **(owner, 2026-11-13)**: a small fixed set of OIDs polled every
30–60 s from devices the user configures, kept as evidence beside their syslog and traps, graphed on the Events
timeline, with reboots marked. It reuses 1.2's data-type framework (§11.1), its SNMP code (`internal/snmp`) and its
credentials store (§11.2.6). Owner decisions are marked **(owner)**; the calls made here are **decided (coordinator,
2026-11-15, owner-delegated)** and listed in §12.10. The API contract is in `docs/api.md` → "SNMP poller" (and the poll parts of Search, Exports and Settings).

**Scope (owner, §9):** sysUpTime; IF-MIB HC in/out octets, errors and discards, plus ifOperStatus; HOST-RESOURCES
CPU and memory where the device supports it; per-device custom OIDs; vendor-neutral presets; poll data in the export.
**Out of scope:** discovery, topology, polling hundreds of OIDs, thresholds and dashboards, a MIB browser. A "test
poll" asks a device only for what its configured poll would.

### 12.1 What is polled

**Presets** (only IETF MIBs, so they're vendor-neutral):

| Preset | OIDs | Every |
|---|---|---|
| `system` | `sysUpTime.0`; `hrSystemUptime.0` where supported; `hrProcessorLoad` (every processor row, averaged); `hrStorageTable` rows of type `hrStorageRam` (used and size × allocation units) | interval |
| `interfaces` | per interface: `ifHCInOctets`, `ifHCOutOctets`, `ifInErrors`, `ifOutErrors`, `ifInDiscards`, `ifOutDiscards`, `ifOperStatus`, `ifCounterDiscontinuityTime` | interval |
| | `ifNumber.0` and `ifTableLastChange.0` (in the same `Get` as `sysUpTime`), where supported | interval |
| | `ifName`, `ifDescr`, `ifAlias`, `ifHighSpeed` (names and speed) | hourly, after a discontinuity or a restart, and when the table changes (below) |
| `system-info` | `sysName.0`, `sysDescr.0`, `sysObjectID.0` (shown on the device page) | hourly |

- An agent without `ifXTable` (no HC counters, or SNMP v1, which has no Counter64) gets the 32-bit `ifInOctets` and
  `ifOutOctets` instead, and the device page says so ("32-bit counters: rates above about 115 Mb/s at a 5-minute
  interval can be wrong").
- An OID the agent doesn't have (`noSuchObject`, `noSuchName` in v1) turns that part off for the device until the
  next hourly refresh; the device page says "CPU and memory: not available on this device".
- **Interface table refresh** (1.3 lab: an interface that appeared 20 s after a reboot went unpolled for an hour).
  The table (names, speeds, states; which interfaces are polled) is walked again:
  - hourly, and at the cycle after an `ifCounterDiscontinuityTime` change;
  - on a restart's cycle (§12.2.2), and again at the **1st, 2nd and 5th answered cycle after it** (at a 60 s interval
    about 1, 2 and 5 minutes later). Interfaces often appear after the agent starts (bridges, virtual and tunnel
    interfaces, line cards), and which are up, and their speeds, settle as links come up, which changes the pick over
    `max_interfaces`. A follow-up runs only in a cycle the device answers; one that fails is retried at the next;
  - when `ifNumber.0` or `ifTableLastChange.0` (IF-MIB: `sysUpTime` at the last row added or removed) differs from
    the last cycle's, at that cycle. Walks made only for such a change are at least 5 minutes apart, so a device whose
    interfaces come and go every cycle (dial-up or tunnel interfaces) isn't walked every cycle; the first change after
    a quiet spell is walked at once. They cost no request: about 30 bytes more each way in the `sysUpTime` `Get`. One
    the agent lacks is left out, without a status line, until the next hourly try (v1, whose `noSuchName` makes the
    request go again without it, pays one extra `Get` an hour).
  An interface found this way starts without a rate (its first sample) and without `disc=1`; the others keep their
  rates. One that's gone stops being polled at the walk. A walk that changes how many interfaces there are or are
  polled writes the system-info line again (`ifs_total`, `ifs_polled`).
- **Interfaces:** every interface by default, up to `max_interfaces` (64 by default, at most 1,024), in `ifIndex`
  order; or a list of `ifName`s or indexes. More than the cap: the first 64 are polled and the device page says how
  many were left out.
- **Custom OIDs** (per device, at most 32 entries): a **scalar** (one `Get`) or a **walk** (a table column or a small
  subtree with `GetBulk`/`GetNext`, at most `max_rows` rows, 128 by default, at most 1,024; a longer walk stops at the
  cap and says so). Each has an optional label. Counters become rates; gauges and integers are kept as values;
  strings are kept but not graphed.

**Defaults:** a 60 s interval (30 s to 10 min), a 2 s timeout, 1 retry, presets `system`, `system-info` and
`interfaces`. Settings → Polling holds these defaults; each device can override the interval, presets, interfaces and
custom OIDs.

### 12.2 Protocol

`internal/snmp` gains the requester side; the poller itself is a new package, `internal/poller`.
- **PDUs:** `GetRequest`, `GetNextRequest` and `GetBulkRequest` out; `Response` and `Report` in. v1 uses `Get` and
  `GetNext` only (it has no `GetBulk`). **The poller never sends `SetRequest`**, or any PDU other than those three, and
  a test checks that `internal/poller` can't build one.
- **v1 and v2c** with a per-device community; **v3 USM as the non-authoritative side**, with every auth and priv
  protocol 1.2 supports (§11.2.2):
  - Engine discovery (RFC 3414 §4): the first request goes with an empty engine ID; the agent's Report gives its
    engine ID, boots and time; the next request is authenticated and synchronizes the time window. The engine ID,
    boots and time offset are cached per target (and kept in the index), so a normal cycle needs no discovery.
  - A `usmStatsUnknownEngineIDs` or `usmStatsNotInTimeWindows` Report later starts discovery again once, then retries
    the request. A higher `engineBoots` than cached marks an agent restart (§12.2.2).
  - Keys are localized to the agent's engine ID, from the user's passphrases or from keys stored for that engine
    (§12.4).
- **Requests:** at most 32 varbinds per `Get`; `GetBulk` with max-repetitions 25 for walks and interface columns. A
  `tooBig` error halves the request and tries again. Request IDs (and v3 msgIDs) are random 31-bit values; a
  response must come from the address and port polled and match an outstanding request ID, or it's dropped and
  counted (`unmatched`). Agents that reply from another address need fixing on the agent side; the test poll says
  so when it sees one.
- **One UDP socket** (an ephemeral port on the wildcard address) for every poll, so polling opens no listening port
  of its own and no firewall rule is needed: outbound UDP and its replies pass stateful host firewalls by default.
- **Timeouts and retries:** each request waits `timeout` (2 s), then retries `retries` times (1). A cycle that gets no
  answer is a failed cycle.
- **Concurrency:** at most 32 devices are polled at once (`poll.concurrency`, 1–256), one request in flight per
  device. Each device's cycle starts at its own offset within the interval (a hash of its ID), so cycles don't
  bunch. A cycle that hasn't finished when the next is due skips that next one, counted as an `overrun`.
- **Unreachable devices back off:** after 3 failed cycles in a row the interval doubles, up to 10 min, and returns to
  normal on the first answer. Each failed cycle is recorded (§12.3), so "unreachable 10:02–10:09" is evidence too.
- **Pauses:** when the disk guard pauses writing, the poller stops polling (nothing could be stored) and resumes with
  it.

#### 12.2.1 Rates
- Rates are computed **when the sample is written**, from the previous sample of the same series, and the raw
  counter is stored beside them. Why write time: the owner's §9 entry says "stored as rates", graphs and the bundle
  read rates without recomputing, and the delta needs the previous sample, which the poller holds in memory. Why keep
  the raw counter too: it's the evidence; any reader can recompute or check a rate from it.
- The time base is the interval between the two responses' received times (monotonic clock), not the agent's uptime
  ticks, which some agents update coarsely.
- Octets become bits per second; errors and discards become a delta per cycle and per second.
- **Counter32 wrap:** a lower value is a wrap (adding 2³²) only when sysUpTime moved forward, there's no
  discontinuity, and the resulting rate is plausible: at most 1.1 × `ifHighSpeed` when it's known, otherwise at most
  2³² per interval. Otherwise it's a discontinuity.
- **Counter64:** a lower value is always a discontinuity (a real wrap would take years).
- **Discontinuities** give no rate for that series in that cycle (`disc=1`; a gap in the graph, not a spike):
  `ifCounterDiscontinuityTime` changed, the interface's `ifIndex` now has another name, or the agent restarted.

#### 12.2.2 Restarts and reboots
- `sysUpTime` is the **agent's** uptime. A lower `sysUpTime` than the last sample (other than its 497-day wrap: from
  within an hour of 2³² ticks to a small value, about an interval after the last one) is an **agent restart**. So is
  one that went up by clearly less than the time since the last sample (more than 5 s or 2 % short): a restart soon
  after the previous start reads higher than before, but lower than it should (§12.10, build 18). An uptime that
  doesn't move at all is a stuck counter, not a restart. A higher v3 `engineBoots` is a restart too.
- It's a **reboot** when `hrSystemUptime` (where supported) also went down. Without HOST-RESOURCES, the marker says
  "restart (the device may have rebooted)": it can't tell an agent restart from a reboot.
- The reason, in the same words on the charts, in the README and in the CSV: "sysUpTime reset" (lower than the last
  sample), "sysUpTime rose less than the time since the last poll" (up, but by too little; never called a reset),
  "engineBoots went up"; `hrSystemUptime` the same way (1.3 lab).
- Either one writes a marker (`kind=restart` with `reboot=1|0|?`, §12.3), shows on the Events timeline and the device
  page, and goes into the bundle's README. A coldStart or warmStart trap within 2 min of a poll restart is the same
  event: the README shows one line naming both sources. With `hrSystemUptime`, the bundle reads the trap against the
  poll that closes its interval instead (§12.6).

### 12.3 Storage

**`poll` is a third data type** in the 1.2 framework (§11.1): its files are `logs/<device>/poll/<day>.log`, with the
same naming, parts, gzip, checkpoints and line envelope as syslog and traps. Why text lines rather than a compact
binary series format:
- Every part of 1.2 works on them unchanged: rotation, compression, crash repair, the index, `reindex`, retention and
  the disk guard, export, the bundle, context, and `woodshed search`.
- gzip shrinks them well, because each line repeats its keys: a device with 24 interfaces at 60 s writes about
  17 MB a day uncompressed and about 1.4 MB a day compressed (measured, §12.11 #4; the first estimate was 7 MB and
  0.7 MB, before the packet counters).
- A columnar store would be smaller, but it would be a second storage engine, with its own crash safety, retention and
  rebuild, for data that's tiny next to syslog. The 2.0 flow store may still need one; polls don't.

**One line per cycle per part:**
```
2026-11-15T10:00:00.120Z 10.1.0.1 kind=sys cycle=1042 uptime=104512345 hr_uptime=104513000 cpu=12 mem_used=3221225472 mem_total=8589934592 rtt_ms=4
2026-11-15T10:00:00.131Z 10.1.0.1 kind=if cycle=1042 if=3 name="eth3" oper=up speed_mbps=1000 in_octets=987654321012 out_octets=123456789012 in_bps=81234567 out_bps=3456789 in_err=12 out_err=0 in_err_d=0 out_err_d=0 in_disc=340 out_disc=0 in_disc_d=0 out_disc_d=0
2026-11-15T10:00:00.140Z 10.1.0.1 kind=oid cycle=1042 oid=1.3.6.1.4.1.32473.1.2.0 label="queue depth" type=g32 value=17
2026-11-15T10:01:00.118Z 10.1.0.1 kind=status cycle=1043 status=timeout detail="no answer after 1 retry"
2026-11-15T10:04:00.410Z 10.1.0.1 kind=restart cycle=1046 reboot=1 uptime=1532 prev_uptime=104518345 source=sysUpTime,hrSystemUptime
```
- **Keys:** `kind` (`sys`, `if`, `oid`, `status`, `restart`, `info` for the hourly names and `sysDescr`), `cycle` (a
  per-device counter, so a cycle's lines group), then the kind's keys, in a fixed order. Raw counters (`in_octets`,
  `in_err`, …) are always written; rate keys (`in_bps`, `in_err_d`, …) only when there's a valid previous sample;
  `disc=1` marks a discontinuity. Strings are quoted and escaped as in trap records; the line envelope escapes CR and
  LF.
- `kind=status` records every failed cycle: `timeout`, `unreachable` (an ICMP error), `auth_failed`, `unknown_user`,
  `unknown_engine`, `not_in_time`, `decrypt_failed`, `error` (an SNMP error status in the response, named), and
  `overrun`. While backing off, there's one line per attempt, not per missed interval.
- **Device identity:** a poll target has an `address` (where requests go) and a `device_id` (which device folder its
  data goes into), defaulting to the address. That's the one place a device isn't its packet's source IP: the
  administrator configured the target, so it's trusted, and a device that sends syslog from one address and is polled
  on its management address keeps one folder. The device page shows the polled address.

**Index:**
- `files.type = 'poll'`; `type_stats` counts poll lines per device like any type.
- New table `poll_targets` (the target's settings and its cached engine ID, boots and time offset, but never a
  secret). It's user data like device names and saved searches, so `reindex` keeps it.
- New table `poll_hourly` (device, series, hour, min, max, sum, count) for a few **headline series** per device:
  total in and out bits/s over its interfaces, the highest single-interface in and out, error and discard deltas
  summed over interfaces, CPU and memory used. It's written as samples arrive, serves graphs with buckets of an hour
  or more without opening files, and is derived data: `reindex` rebuilds it from the poll files.
- Restart markers are found by reading the poll files' `kind=restart` lines in the range (they're rare, and the
  checkpoints find the range fast).

**Retention and fair share:** poll files count toward each device's bytes and its share exactly as syslog and traps
do (§11.1): the same cap, age limit, low-disk guard and oldest-first order across a device's types.

**Searchable as lines:** `type=poll` works in `/api/search`, the summary and `woodshed search`, because it's a data
type: `woodshed search --type poll --field kind=restart --last 7d` lists restarts, and `q` matches the line
(`oper=down`). Events doesn't offer a Polls tab; polls are shown as graphs (§12.5) and in the device page. This
supersedes §10.1.6's note that poll graphs "aren't a searchable type": the graphs aren't, the lines are.
- Fields (schema): device, `kind`, `if` (interface name), `oper`, `status`, `reboot`. Filters: `kinds`, `ifs` /
  `exclude_ifs`, `oper`, `poll_status`, `reboot`. Syslog's and trap's filters with `type=poll` are a 400.

### 12.4 Credentials
- The same store as 1.2's v3 users (§11.2.6: DPAPI on Windows, a 0600 service-account file on macOS and Linux).
  Each target has either a **v1/v2c community** (kept in the store's protected blob, keyed by the target, shown only
  as `#<hash8>`) or a **v3 user** chosen from the same users table the trap receiver uses.
- A v3 user whose keys are stored only localized (`engine_ids` set, §11.2.6) can poll only agents with those engine
  IDs; the test poll says so and names the agent's engine ID to add.
- Communities and keys are never in a log line, the events log, an API response, an export or a bundle, and never
  on a command line. A poll line names the target's credential only as `cred=#<hash8>` or the user name, and only on
  `kind=status` lines (to diagnose a wrong one).

**SECURITY.md**, "What counts", the outbound item becomes (applied in the PR that ships the poller):
> - Woodshed making any outbound network connection other than:
>   - the opt-in update check: one HTTPS `GET` of `https://gmccollu.github.io/woodshed/releases.json` a day, made
>     only after an administrator turns it on. A check while it's off or still asking, a request that sends more than
>     that (a query string, a cookie, an identifier, the version), a connection anywhere else, or an update banner
>     that links outside this repository's releases all count;
>   - SNMP polls to devices you configure: SNMP `Get`, `GetNext` and `GetBulk` requests (and SNMPv3 engine
>     discovery) sent only to the addresses and ports an administrator added under polling, for the OIDs configured
>     there, at the configured interval, plus test polls an administrator starts. A request to any other address, a
>     `Set` or any other PDU, a request before a target was configured, or a community or key sent to a device other
>     than the one it was configured for all count.
- **FAQ.md**, "Does Woodshed connect to the internet?" gains: "From 1.3, if you add devices under **Polling**,
  Woodshed also sends SNMP requests to those devices, and only to them. With no polled devices, it sends none."
- **README.md**, Features: "Optional SNMP polling of the devices you choose (uptime, interface traffic and errors, CPU
  and memory), graphed beside their logs, with reboots marked."
- **CONTRIBUTING.md**, the rule becomes "No outbound connections, except the update check and SNMP polls", naming
  `internal/poller` beside `internal/updatecheck`.
- **The client-network allowlist test** (`internal/updatecheck/allowlist_test.go`) gains `"internal/poller": "SNMP
  polls to the devices the user configured"`, and §10.2's runtime test `TestOnlyUpdateCheckDials` is amended: with
  no poll targets nothing else dials; with targets, the only other packets go to the targets' address and port.

### 12.5 UI
Simple and fast: every view reads the headline rollups or one device's poll files for the window.
- **Devices page → Polling:** a "Polled" column and filter. **Add polling** on an existing device (its address
  prefilled) or **Add by address** for one Woodshed hasn't heard from (it becomes a device on its first answer).
  The form: address and port (161), device (for a different polled address), version, community or v3 user,
  interval, presets, interfaces (all, up to the cap, or a list), custom OIDs. **Test poll** runs the configured poll
  once, without saving, and shows each step (§12.7). Saving starts polling within one interval.
- **Device page panel** (a new "Polling" panel on a device's page), for the selected range:
  - uptime (with the last restart), sysName and sysDescr, the polled address and the last cycle's time and round
    trip;
  - **5 small charts, 13 lines by default:** CPU (1), memory (1), total in/out bits/s (2), the 4 busiest interfaces
    by peak traffic in the range, in and out (8), and errors plus discards summed (1);
  - the **interface table:** every polled interface with name, alias, oper status, speed, current and peak in/out
    rates, and error and discard deltas in the range; sortable; clicking a row adds it to the charts (at most 8
    interfaces charted at once);
  - restart and oper-status-change markers on every chart.
- **Events timeline:** under the histogram, poll strips on the same time axis and bucket edges. With one device
  selected: total in/out bits/s, CPU, and errors (3 strips). With several: one strip of total in/out bits/s per
  device, at most 4 (the busiest), with "and N more" linking to the Devices page. Restart markers for every selected
  device are vertical lines across the histogram and the strips; hovering names the device and the source. Strips
  show only when a selected device is polled.
- **Settings → Polling:** the defaults (interval, timeout, retries, presets, max interfaces), concurrency, and the
  last hour's totals (cycles, failures by status, overruns).
- **Banners:** `poll_unreachable` (warn) while a polled device hasn't answered for 10 min ("2 polled devices aren't
  answering: …"); `poll_overrun` (warn) when cycles were skipped in the last hour because polling couldn't keep up.

### 12.6 Bundle and export
- A `poll/` folder per device in the zip (the type's folder, as `traps/` is for traps), three CSV files with a
  header row, UTF-8, comma-separated, RFC 4180 quoting, times in RFC 3339 UTC:
  - `poll/<device>/system.csv`: `time,cycle,uptime_s,hr_uptime_s,cpu_pct,mem_used_bytes,mem_total_bytes,rtt_ms,status,detail`
  - `poll/<device>/interfaces.csv`: `time,cycle,if_index,if_name,if_alias,oper,speed_mbps,in_octets,out_octets,in_bps,out_bps,in_errors,out_errors,in_errors_delta,out_errors_delta,in_discards,out_discards,in_discards_delta,out_discards_delta,discontinuity`
  - `poll/<device>/oids.csv`: `time,cycle,oid,label,row,type,value,rate`
  - Restart markers are rows in `system.csv` with `status=restart` and `detail` naming the sources.
  - Empty cells mean "not measured" (no previous sample, a discontinuity, not supported), never zero.
- Every CSV is in the manifest with its SHA-256, and the README says what each column means.
- **README summary per device** gains a Polls line and merges reboots:
  ```
      Polls        40 of 40 cycles answered (60 s); uptime 12 d 3 h at the end of the window
                   peak in 812 Mb/s (eth1, 09:31), peak out 95 Mb/s (eth1, 09:31); CPU peak 91 % (09:30), memory peak 72 %
                   errors +12 in (eth3), +0 out; discards +340 in (eth3); eth3 down 09:30:58 to 09:31:40
      Reboots      1: 09:30:58 (poll: sysUpTime and hrSystemUptime reset; coldStart trap)
  ```
  Only restarts that may have been the device's count as reboots: `reboot=1`, `reboot=?` and the traps. With any
  `reboot=0` (the agent's alone) the line is `Restarts     3 (0 reboots): …`, still listing every restart (§12.10
  #14), and the device's one-line summary says `restarts 3, reboots 0`; with none it's `Reboots      none (…)`. (1.3
  lab: three agent restarts read "Reboots 3".)
- **A coldStart or warmStart trap is read against the polls** (§12.10 build #19) when the device is polled with
  `hrSystemUptime`. The poll that closes the trap's interval (the first answered poll at or after it) decides:
  - it wrote a restart with `reboot=1` or `0`: the trap is that restart. The interval's earliest trap joins it (one
    entry, `poll, coldStart trap`); a later trap in the same interval is a restart of its own, the agent's alone
    after a `reboot=0` (`coldStart trap; the polls show the device kept running`), a reboot after a `reboot=1`;
  - no restart, and `hrSystemUptime` rose normally since the poll before (§12.2.2's rule): the device kept running,
    so the trap is the agent's alone, with the same words. One received just after a poll restart that has no trap
    yet (within 2 min) joins it instead;
  - anything else (not polled, no HOST-RESOURCES, `reboot=?`, `hrSystemUptime` stuck, no answered poll after the
    trap in the window): the 2 min rule above, and a trap left alone counts as a reboot. One after the device's last
    answered poll says `no poll after it in the window to tell`.

  The trap's entry carries `reboot=0` and that `detail` in the manifest, so the title, the count and the one-line
  summary follow from it. `system.csv` holds only the poll's own restart rows. (1.3 lab: two agent restarts 15 s
  apart in one 60 s interval, one poll restart with `reboot=0` and `engineBoots` +2, and two coldStart traps read
  `Restarts 3 (1 reboot)`, the first trap left alone as a reboot. It now reads
  `Restarts     2 (0 reboots): 04:11:26.211 (poll: …; coldStart trap), 04:11:41.207 (coldStart trap; the polls show
  the device kept running)`: two traps are two restarts, and the poll's restart is the first one seen, not a third.)
- Plain exports take `types: ["poll"]` the same way, with the `poll` filters.

### 12.7 CLI
- **`woodshed poll test <address>`** `[--port 161] [--version 1|2c|3] [--community-file F] [--v3-user NAME --auth …
  --auth-pass-file F --priv … --priv-pass-file F --key-ext draft|alt] [--preset system,interfaces] [--oid OID]…
  [--walk OID]… [--timeout 2s] [--retries 1] [--json]`
  - A standalone diagnostic like `woodshed send`: it doesn't read the credentials store (which on Windows only the
    service account can decrypt) or talk to the service. Secrets come from files or `WOODSHED_SNMP_COMMUNITY` /
    `_AUTH_PASS` / `_PRIV_PASS`, never the command line.
  - It prints each step: v3 discovery (engine ID, boots, time), `sysName`, `sysDescr`, `sysUpTime`, whether HC
    counters and HOST-RESOURCES answer, how many interfaces it would poll, each custom OID's value, and round-trip
    times; then what's missing and why.
  - Exit codes: `0` everything answered; `1` no answer; `2` usage; `3` authentication or privacy error; `4` answered
    but some OIDs aren't supported.
  - The UI's **Test poll** runs the same steps in the service, with the stored credentials.
- **`woodshed search --type poll`** works (§12.3), with `--field kind=…` and the rest.
- **`woodshed status`** gains a Polling row: `Polling   12 devices: 11 answering, 1 not answering since 09:02
  (10.1.0.9); last cycle 4 s ago`.
- No `woodshed poll add`: targets are managed in the UI and API, like v3 users, because their credentials go into
  the service's store.

### 12.8 Testing plan
- **Unit and fuzz:** encoding of `GetRequest`, `GetNextRequest` and `GetBulkRequest` (v1, v2c, v3) checked byte for
  byte against captured packets; decoding of `Response` and `Report` with every value type and error status; the
  requester side of USM (discovery, time sync, re-discovery, localization per engine); request-ID matching.
  New fuzz targets: `FuzzResponse` (any datagram as a response to an outstanding request: no panic, bounded memory,
  never a match it shouldn't be), `FuzzPollRecord` (format and re-parse a poll line), `FuzzRates` (any sequence of
  counter values and uptimes: rates never negative, never above the plausibility bound, every drop explained by a
  wrap or a discontinuity).
- **An in-repo test agent**, `internal/snmp/agenttest`: a tiny responder for tests, with a programmable view (scalars,
  `ifTable`/`ifXTable`, HOST-RESOURCES rows), counters that advance at a set rate, and hooks to inject a Counter32
  wrap, a Counter64 drop, a discontinuity time change, an agent restart, a reboot, a sysUpTime wrap, `tooBig`,
  `noSuchObject`, wrong-source replies, slowness and silence. It's authoritative for v3 with every auth and priv
  protocol. Tests start it on loopback; it never ships in the product binary.
- **End to end** (the real binary): the test agent plus syslog and traps from `woodshed send`; a poll target added
  through the API; poll lines on disk; the device page's data, the timeline strips' series and restart markers from
  the API; `woodshed search --type poll`; a bundle with `poll/` CSVs whose rows match the lines and whose README
  merges a poll restart with a coldStart trap.
- **Counter and reboot cases** (the test agent, a fake clock): Counter32 wrap with a plausible rate (counted as a
  wrap), with an implausible one (a discontinuity), Counter64 drop, `ifCounterDiscontinuityTime` change, an
  interface renamed under the same index, agent restart (restart marker, `reboot=?`), reboot with HOST-RESOURCES
  (`reboot=1`), the 497-day sysUpTime wrap (no marker), and engineBoots going up.
- **Interop (CI, Linux job only):** the distribution's net-snmp `snmpd` as the polled agent, on a high port on
  loopback, with a temporary config; v1, v2c, and v3 for noAuthNoPriv, each auth with noPriv, each priv with
  SHA-256, and MD5 with DES (DES skipped if that build lacks it, as in §11.6); discovery, an `snmpd` restart (restart
  marker, `engineBoots` up), real interface counters with traffic on loopback, and HOST-RESOURCES CPU and memory.
  Secrets in the temporary config, never on a command line.
- **Lab:** `snmpd` on our Linux lab VMs, polled from another of our VMs (Ubuntu with the deb, AlmaLinux with the rpm),
  for v2c and v3 authPriv, through a real network and the hosts' firewalls, during the 24 h soak, with one VM rebooted
  mid-run (a `reboot=1` marker, and the coldStart trap merged in the README). Windows has no SNMP agent by default
  (its own SNMP service is an optional, deprecated feature), so on Windows the lab tests the **poller**: a Windows
  Woodshed polling the Linux VMs' `snmpd`, and the test agent on loopback. Windows as a polled agent isn't tested.
  macOS likewise polls the Linux agents and the test agent.
- **Install smoke tests:** no new port or firewall rule; with no targets, the no-dial runtime test passes on every OS;
  with a target pointing at the test agent, the only packets go to it.
- **Load:** 500 devices × 64 interfaces (8 interface columns each, plus `system`) at a 60 s interval, and 100 devices
  at 30 s, from many test agents on loopback addresses, with v2c and v3 authPriv: every cycle completes on time, the
  poller's CPU stays under half a core on the reference spec (4 cores), memory under 200 MiB, and syslog's 10,000
  msg/s bench beside it still loses nothing. The numbers go into the release notes like the syslog and trap benches.
  **First measurement (build, 2026-11-15**, `TestPollLoad`, agents in a child process, a 14-core laptop, not
  the reference spec): 500 × 64 at 60 s v2c, 0.071 cores and 129 MiB RSS for the whole server over 3 min, 1,500 of
  1,500 cycles, no failure or overrun; with 10,000 msg/s of syslog beside it for 1 min, 0.26 cores, 156 MiB, 600,000
  of 600,000 stored. 100 × 64 at 30 s v3 authPriv (SHA-256, AES-128): 0.031 cores, 56 MiB; 0.24 cores and 74 MiB with
  the syslog run, nothing lost.

### 12.9 Compatibility
- **Config:** a 1.2 `woodshed.toml` loads unchanged. A new `[poll]` section takes its defaults (interval 60 s,
  timeout 2 s, retries 1, concurrency 32, `max_interfaces` 64, presets `system`, `system-info`, `interfaces`). With
  no targets configured, nothing is polled and nothing is sent.
- **Data:** syslog and trap files are unchanged. The index migrates once (`poll_targets`, `poll_hourly`). Poll files
  appear only under `logs/<device>/poll/`. The credentials file gains poll communities in its protected blob; a 1.2
  file loads unchanged.
- **API:** additive: `type=poll` is a new value, new routes, new banner kinds and new fields on devices. Every 1.2
  request means what it meant.
- **Downgrade** as before (§11.7): not supported; a 1.2 `reindex` ignores the `poll/` folders, and 1.2 never sends a
  poll.

### 12.10 Decisions for 1.3
**Owner (2026-11-13, §9):** the poller's scope and out-of-scope list, "stored as rates", graphs on the Events
timeline, reboot detection from uptime drops, poll data in the export, polls only to configured addresses, the
credentials handling of 1.2, and SECURITY.md's "SNMP polls to devices you configure".

Everything below is **decided (coordinator, 2026-11-15, owner-delegated)**:
1. `poll` is a third data type with text lines in `logs/<device>/poll/`, not a compact binary store (§12.3).
2. Rates are computed at write time, and the raw counters are stored beside them (§12.2.1).
3. The time base is the responses' received times, not the agent's uptime (§12.2.1).
4. Counter32 wraps are accepted only when the rate is plausible; Counter64 drops are always discontinuities
   (§12.2.1).
5. A sysUpTime drop is an agent restart; it's a reboot only when `hrSystemUptime` dropped too, otherwise "may have
   rebooted" (§12.2.2).
6. A poll target has an address and a device ID, so a device polled on another address keeps one folder (§12.3).
7. Headline rollups (`poll_hourly`) for long-range graphs; per-interface long ranges read the files (§12.3).
8. Poll lines are searchable through the API and CLI, but Events has no Polls tab (§12.3).
9. Defaults: a 60 s interval (30 s–10 min), 2 s timeout, 1 retry, 32 devices at once, 64 interfaces per device, 32
   custom OIDs, 128 rows per walk, at most 500 targets, addresses only (no name lookups) (§12.1, §12.2).
10. Back off after 3 failed cycles, doubling up to 10 min (§12.2).
11. Responses only from the polled address and port; replies from another address are dropped (§12.2).
12. The device page charts 13 lines in 5 charts by default, at most 8 interfaces at once; the timeline shows at most
    4 devices' strips (§12.5).
13. The bundle's `poll/` holds three CSVs per device, with empty cells for "not measured" (§12.6).
14. `woodshed poll test` is standalone with secrets from files or the environment; there's no `woodshed poll add`
    (§12.7).
15. Windows is tested as a poller, not as a polled agent (§12.8).

**Decided (build, 2026-11-15)**, where the contract was silent; each can be overruled:
1. **Requests.** `internal/snmp`'s requester has one request type with three values (Get, GetNext, GetBulk); a test
   tries every value and finds only those three PDUs, and an AST test in `internal/poller` checks the package
   reaches no encoder but the session's. The per-cycle interface counters are `Get`s of the exact instances polled
   (32 varbinds each); `GetBulk` (max-repetitions 25) is for walks: custom walks, HOST-RESOURCES and the hourly
   interface columns. Hourly walks stop at 4,096 rows per interface column and 256 for HOST-RESOURCES.
2. **`unreachable`** is a send the OS refuses as host or network unreachable. An ICMP error on the shared
   unconnected socket can't be tied to one target, so a closed port shows as `timeout`.
3. **Record keys** beyond §12.3's example, all in `internal/pollrec`'s fixed order: `if` lines carry `oper_was` when
   the state changed since the last sample (what oper markers are read from, with a cheap byte filter), `bits=32` for
   the 32-bit fallback, the packet counters `in_ucast` … `out_bcast` and their `*_pps` rates (§12.11 #1), and
   `wraps=` naming the counters that wrapped; `sys` and `status` lines carry `interval_s`; a capped walk's last row has
   `capped=1`; `info` lines are either the system form (`sys_name`, `sys_descr`, `sys_oid`, `hc`, `hr`, `ifs_total`,
   `ifs_polled`) or one per polled interface (`if`, `name`, `descr`, `alias`, `speed_mbps`), at each interface table
   refresh (§12.1). Errors and discards are stored as per-cycle deltas only (`_d`); per second is the delta over
   `interval_s`.
4. **Custom OIDs** are asked every cycle even when missing (stored as `type=nosuchobject`, an empty walk as one such
   line); only the presets' parts turn off until the hourly refresh.
5. **Defaults are copied.** Fields a body leaves out take Settings → Polling's values at the time of the request and
   are stored with the target; changing the defaults later affects new targets. Of the defaults, only `concurrency`
   changes running polls.
6. **`pinned`** (a list of `ifName`s or indexes, default `[]`) is the target field behind §12.11 #3's pinning.
7. **One target per device.** A second target with the same `device_id` is a `400` on `device_id`, so a device's poll
   files hold one target's cycles. `device_id` is a device ID, so an IP address (IPv6 with `_`, as everywhere).
   A target over `poll.max_targets` or for an address and port already polled is a `409`.
8. **Device identity in the store.** Poll lines pass the store's device admission (`max_devices`, the new-sender
   buckets) like any type. A failed cycle's `status` line is a stored line of that device, so it counts as heard
   (its `last_heard` moves) even while it doesn't answer; `poll_status`, the `poll_unreachable` banner and the device
   page are what say a polled device isn't answering.
9. **State kept in memory.** Previous samples (rates, uptimes, oper states) live in the poller only: the first cycle
   after Woodshed starts has no rates and can't see a restart that happened while Woodshed was stopped. The v3 engine
   (ID, boots, time and when it was seen) is written to `poll_targets` when it changes, so a restart needs no
   discovery. Rollups are merged into `poll_hourly` once a minute and at stop; a crash can lose the last minute's
   rollups until `reindex`.
10. **A partly answered cycle** (an early request answered, a later one failed) keeps the lines written, adds a
   `status` line, counts as a failure in the hour's totals, and doesn't count towards backoff (the device answered).
   An `overrun` takes its own cycle number.
11. **Graph reads.** `from` defaults to a day before `to`; file reads use the summary's 2 s budget, and a `partial`
   response's `next_cursor` resumes from the time reached. Markers are capped at 100 per device. The timeline's
   "busiest" is the highest hourly in or out rollup in the range.
12. **Test polls** are limited to 10 a minute in all and one at a time per target (by ID, or address and port for an
   unsaved body); `{"id"}` with other fields tests the stored target with those fields changed. The CLI's `--walk`
   reads at most 128 rows.
13. **The allowlist test** also flags datagram sends on an unconnected socket (`WriteToUDP`, `WriteToUDPAddrPort`,
   `WriteMsgUDP`, `WriteMsgUDPAddrPort`), which need no `Dial`; `internal/poller` and the test agent
   `internal/snmp/agenttest` (test support, imported only by tests, checked) join the list, and `internal/listen`'s
   entry names its inform replies.
14. **Exports** (fork of this build): the zip's `poll/` holds only the three CSVs, not the lines; a CSV's `lines` in
   the manifest count its rows; CSVs use CRLF line ends (RFC 4180), times RFC 3339 UTC with milliseconds, `uptime_s`
   as ticks/100. The packet counters stay in the lines only (§12.6 lists no CSV columns for them). A merged reboot's
   `source` is one string, `"poll, coldStart trap"`, with the earlier time and the poll's `detail`; restarts with
   `reboot=0` or `?` are listed too. The README lists at most 3 oper changes per device, then "and N more".
15. **Search fields:** `status` is `ok` on every line but `status` lines; `if` is the name (or the index without
   one) on `if` and interface `info` lines; `ifs` matches names ignoring case, or indexes exactly. A result's
   `values` holds every key but `kind`, `cycle` and the promoted `oper`, `status` and `reboot`.
16. **UI:** the device page is a route of its own, `#/device?id=…`, reached from Devices (not in the nav); "Polled" is
   a view of the poll-target list; pinning is a `PUT` with `pinned`; delta series are drawn as avg × count per
   bucket; at most 40 markers per chart or strip, the rest counted; chart colours are new `--chart-1…8` and
   `--chart-mark` tokens, in the contrast check.
17. **Shared request fixtures.** `web/src/lib/fixtures/ui-requests.json` holds the UI's exact request bodies,
   written from the forms' own body builders (the web tests fail on drift; the mock replays it) and posted to a real
   in-process server by `internal/server`'s `TestUIRequestBodiesAgainstServer`, so the mock and the server can't
   drift (coordinator, 2026-11-15, after the 1.2 `key_ext` bug).
18. **Restarts that don't lower the uptime** (build, 2026-11-16, from the first snmp-poll-interop run): an agent up
   6.4 s, restarted, and polled 7.5 s later read 6.5 s, so "lower than the last sample" saw nothing, and that snmpd
   didn't raise `engineBoots` either. A real device that reboots twice within a few intervals would have been missed
   the same way. `sysUpTime` (and `hrSystemUptime` for the reboot test) now also counts as restarted when it went up
   by less than the time between the samples (measured on the monotonic clock) minus the larger of 5 s and 2 % of
   that time (agents update it coarsely; the receive times stand for the agent's reading times only to within a
   round trip). A value that didn't move (macOS's snmpd keeps `hrSystemUptime` at 0) is neither a restart nor, for
   `hrSystemUptime`, evidence either way (`reboot=?`).
19. **Restart traps read against the polls** (build, 2026-11-16, from the 1.3 lab): the bundle paired a poll
   restart with the nearest trap within 2 min and counted every other trap as a reboot, so two agent restarts in
   one poll interval read `Restarts 3 (1 reboot)` although the polls showed the device never stopped. A trap is now
   classified by the poll that closes its interval when that poll knows `hrSystemUptime` (§12.6): its restart takes
   the interval's earliest trap, and a trap with no poll restart but `hrSystemUptime` rising normally is the agent's
   alone. Without that evidence the 2 min rule stands, so an unpolled device's trap is still a reboot. Two traps in
   one interval stay two entries: each is a restart the agent announced, and `engineBoots` agrees in the lab.

### 12.11 Questions settled (1.3), decided (coordinator, 2026-11-15, owner-delegated)
1. The `interfaces` preset also polls the HC packet counters in and out: unicast, multicast and broadcast
   (`ifHCIn/OutUcastPkts`, `…MulticastPkts`, `…BroadcastPkts`, 32-bit fallbacks as for octets). Packet and broadcast
   rates are what show a broadcast storm or a small-packet flood, a common outage cause; six OIDs per interface is still
   a small fixed set.
2. An `oper` change (an interface going down or up) is a timeline marker on the Events histogram as well as on the
   device page, like restarts; markers are capped per strip as restarts are.
3. `max_interfaces` (default 64) picks, in order: interfaces the user pinned, then interfaces that are up, by
   `ifHighSpeed` descending, then by index. The device page says when interfaces were left out and offers pinning.
4. The storage estimate is measured by the first bench and recorded here before it's published in the docs.
   **Measured (build, 2026-11-15):** one device with 24 interfaces at 60 s with the default presets (system with
   HOST-RESOURCES, system-info, interfaces with the packet counters of #1) writes 36,600 lines a day (1,440 `sys`
   lines, 34,560 `if` lines, 600 hourly `info` lines): **16.8 MB a day uncompressed and 1.38 MB gzipped** (12.2×), as
   the store compresses a closed day (`TestPollStoragePerDay` in `internal/poller`, `WOODSHED_POLL_STORAGE=1`). It's
   about twice §12.3's estimate because of the six packet counters and their rates added here; the current day stays
   uncompressed until midnight UTC.

## 13. 2.0 design (draft, 2026-11-16)

§9's 2.0 entry **(owner)**: a flow collector (flow v5, flow v9 (RFC 3954) and IPFIX (RFC 7011)), the export covering every data type, and the device
setup helper. The framing is the scope rule's: an evidence collector for troubleshooting, so "the flows around the
outage window", not long-term flow analytics, baselining or anomaly detection. Owner decisions are marked
**(owner)**; the calls made here are **decided (coordinator, 2026-11-16, owner-delegated)** and listed in §13.10. The
API contract is in `docs/api.md` → "2.0 (planned)".

### 13.1 Collector

**Owner (§9):** UDP 2055 and 4739, configurable; templates per exporter and observation domain; compact columnar
storage per device per hour; retention and the disk guard shared; search by time, IPs, ports and protocol; top
talkers and top ports for a window; windowed export as CSV or IPFIX file.

```toml
[listeners.flow]
enabled = false            # Settings → Flows; off by default
addr = "0.0.0.0"
flow_port = 2055           # flow v5 and v9 (any version is accepted on either port)
ipfix_port = 4739          # IPFIX; 0 turns one port off
template_timeout = "30m"   # a template not refreshed for this long expires
pending_bytes = 33554432   # the buffer for data that arrived before its template (§13.1.3)
queue_messages = 50000     # this listener's UDP queue (§11.5): packets
queue_bytes = 134217728    #   and bytes, whichever fills first
```
- **Off by default**, decided (coordinator, 2026-11-16, owner-delegated), like TLS, traps and polling: a 1.3 upgrade
  opens no port.
- Both ports read every version (the header's version field says which), so an exporter pointed at the "wrong" port
  still works. Each port shows in `/api/status.listeners` as `proto: "flow"` and `proto: "ipfix"`, with the usual
  `listener_bind` banner and Retry.
- **Transport:** IPFIX over UDP only in 2.0. IPFIX over TCP (and over TLS, reusing §10.3) is a later 2.x item if a
  user asks for it; SCTP isn't planned (Windows has no native SCTP, and exporters rarely use it).
- It goes through the 1.2 UDP queue (§11.5) with its own size (flow packets are larger and come in bursts) and through
  the sender limits: allowlist, blocklist, `max_devices` and the new-sender buckets.
- **Device identity is the exporter's source IP.** The exporter's own address fields (v9 and IPFIX
  `exporterIPv4Address`, the v5 header's engine fields) are kept and shown, never used for identity, for the reasons
  §11.2.4 gives for a trap's agent-addr.
- Firewall and installers follow traps (§11.2.7): the MSI ships "Woodshed flows (UDP 2055)" and "(UDP 4739)" disabled,
  `woodshed flow on|off|status` flips the listener and the rules, ufw/firewalld on Linux.

#### 13.1.1 Versions
- **Flow v5:** the fixed 48-byte record; the header's `sampling_interval` (mode and 14-bit rate) is the records'
  sampling and the domain's (v5 is always domain 0); `unix_secs`, `unix_nsecs` and `sys_uptime` turn the records'
  uptime-relative times into UTC.
- **Flow v9** (RFC 3954): template, options template and data FlowSets, per (exporter address, source ID).
- **IPFIX** (RFC 7011): template, options template and data sets, per (exporter address, observation domain ID),
  with variable-length fields, enterprise-specific IEs, and the RFC 7011 time IEs (seconds, milliseconds,
  microseconds, nanoseconds, deltas, and `systemInitTimeMilliseconds` from options data). Uptime-relative times
  (v9's and IPFIX's `flowStartSysUpTime`/`flowEndSysUpTime`, unsigned 32-bit milliseconds) are resolved modulo 2^32
  to the time nearest the export time, so a 49.7-day wrap, or a flow older than the exporter's init time (a clock
  stepped back, a capture file replayed), lands at its real time.
- The template key includes the exporter's source port as well, because exporters that restart pick a new port and
  may reuse template IDs with new definitions.

#### 13.1.2 Templates
- **Cache:** per (exporter, port, domain), at most 256 templates; at most 10,000 in all (oldest refresh out first).
  A template with an ID already cached replaces the old one from that packet on; records decoded before keep their
  old definition (each segment stores the template definitions its records used, §13.2).
- **Timeout:** a template not refreshed within `template_timeout` (30 min; exporters typically resend every few
  minutes or packets) expires. Its later data waits for a refresh like unknown-template data (§13.1.3).
- **Withdrawal:** an IPFIX template withdrawal (a template record with field count 0, or the all-templates form)
  removes the template at once. Exporters aren't supposed to send withdrawals over UDP, but honouring one that comes
  costs nothing and is safer than keeping a definition the exporter says is gone.
- **Options templates** are decoded and their data kept as **exporter metadata**:
  - sampling: v9 `SAMPLING_INTERVAL` (34) and `SAMPLING_ALGORITHM` (35), the sampler table (`FLOW_SAMPLER_ID`,
    `FLOW_SAMPLER_RANDOM_INTERVAL`), and IPFIX `samplingInterval`, `samplingPacketInterval` and
    `samplingPacketSpace`, `samplingProbability`, `selectorAlgorithm`;
  - interface names: `ifName` (82) and `ifDescription` (83) scoped by interface index;
  - `systemInitTimeMilliseconds`, exporter addresses, and anything else, as raw.
  The metadata is versioned by time, so a record uses the sampling and interface names in force when it arrived.
- **Sampling is kept and shown.** Every stored record has `sampling`: `1` (unsampled), `N` (1 in N), or `0`
  (unknown: the exporter said nothing). It comes from the record's own sampling IEs, else its sampler ID's options
  data, else the domain's, else the v5 header. Queries show counts as exported and, where the rate is known, scaled
  (§13.3).

#### 13.1.3 Unknown, malformed and enterprise-specific data
- **Enterprise-specific IEs** (the IPFIX enterprise bit) and IEs Woodshed doesn't know (in v9, any type it has no
  column for) are kept raw, per record: enterprise number, element ID and bytes. They're shown as `pen:id=hex` and
  exported as they came (§13.4). A v9 vendor-range field type (32768–65535; v9 has no enterprise numbers) is
  enterprise number 0 with the whole type as its ID, `0:40003` (decision 74).
- **Data before its template:** a data set whose template isn't cached waits in a bounded buffer: `pending_bytes`
  (32 MiB) in all, at most 1 MiB per exporter, for at most `template_timeout`. When the template arrives the data is
  decoded with each record's original received time and marked `late=1`.
- **When the buffer is full or the wait is over,** the set is stored undecoded (received time, exporter, domain,
  template ID, the raw bytes) in the segment's raw section and counted (`no_template`). A template that turns up later
  doesn't re-decode it automatically, but `woodshed reindex --flows-redecode` and the query engine's decode-on-read
  for raw sets (when the segment's own template history has that template) do.
- **Malformed packets** (a length past the end, a set shorter than its header, an impossible field length, a wrong
  version) are counted and stored raw too (`malformed`), with what decoded before the break, never dropped silently.
- Counts per exporter: decoded records, late-decoded, `no_template`, `malformed`, sequence gaps (v9 and IPFIX carry
  a sequence number; a gap is loss before Woodshed, between the exporter and here, and is shown as such), and
  duplicates (the same sequence number twice within a minute, usually an exporter sending to two collectors through a
  mirroring device).

### 13.2 Storage

**`flow` is a fourth data type** in the 1.2 framework (§11.1), but with its own storage engine. The framework gains a
second storage kind beside "lines": **segments**. The shared parts stay shared: device identity, admission, the
files table, retention and the disk guard, the index histogram, saved searches, export and the bundle. The flow type
brings its own writer, reader, query engine and export writers.

**Why columnar segments and not the line envelope:** volume. A small site's firewall exports about 1,000 flow records
a second, 86 million a day.
- As text lines (about 250 bytes each), that's about 21 GB a day uncompressed and 3–4 GB gzipped, more than a
  default 20 GiB cap holds for a week.
- Columnar blocks, each column encoded for its type and then compressed, land around 12–20 bytes a record (estimated;
  the first bench replaces this), about 1–1.7 GB a day.
- Top talkers over an hour read only the address and byte columns; a filter on a port or protocol skips whole blocks
  by their index without decompressing them. A gzipped line file must be decompressed whole.
- The cost is a second on-disk format with its own crash safety and recovery, specified below. Polls (§12.3) didn't
  justify one; flows do.

**Files:** `logs/<device>/flows/<YYYY-MM-DD>T<HH>.wsf`, one segment per device per received hour (UTC), so the day
folder logic, `ls` order and "logs from Tuesday" still work. A segment past 256 MiB or 8,192 blocks starts a numbered
part (`…T09.001.wsf`), like log parts (§13.10 decision 57).

**Segment format (version 1):** little-endian, every section with a CRC-32C.
1. **Header** (32 bytes): magic `WSFLOW01`, format version, device ID length and bytes, the hour, the writer's
   Woodshed version.
2. **Blocks**, appended as records arrive. A block holds up to 65,536 records or 1 s of arrivals, whichever comes
   first. Its header has the row count, the min and max received time, the min and max flow start and end, and the
   column directory. Each **column** is encoded for its type, then compressed with DEFLATE (the standard library's;
   no new dependency):
   - times: delta from the block's minimum, then zigzag varints;
   - addresses: a per-block dictionary (16-byte form, IPv4 mapped) plus varint indexes;
   - ports, protocol, TCP flags, ToS, interfaces, AS numbers, VLANs, direction, end reason: varints (protocol and flags
     as bytes);
   - packets and bytes: varints;
   - `sampling`, `template` (an index into the segment's template table), `exporter_domain`, `late`: run-length;
   - **firewall-event, NAT and bidirectional columns** (§13.2.1): addresses like the other addresses, ports and
     event codes as varints, counters as varints, times like the other times;
   - **extras:** a length-prefixed TLV list per record for every IE without a column, enterprise-specific ones
     included.
   - **Mostly empty columns cost about nothing:** each column has a presence bitmap, run-length encoded, and stores
     values only for the records that have one. A column that's empty for the whole block isn't written at all (the
     block's column directory leaves it out), so a plain-flow exporter pays nothing for the event and NAT columns,
     and an event-only exporter pays a few bytes per block for the counters it never sends.
3. **Block index** (in each block header, and repeated in the footer): a 256-bit protocol bitmap, the distinct input
   and output interfaces (a list up to 64, else a Bloom filter), and a Bloom filter (about 1 % false positives) over
   the record's source and destination addresses, their /24 and /48 prefixes, and its ports. A query skips a block
   when its time range or index rules it out.
4. **Raw section:** undecodable sets and malformed packets (§13.1.3), each with its received time.
5. **Template table:** every template definition the segment's records used, and the exporter metadata (sampling,
   interface names) in force, so a segment decodes and exports on its own.
6. **Footer:** the block directory and the segment's totals (records, bytes, packets, time ranges), then the footer's
   length and CRC. Written when the segment closes (the hour ends, the part limit, a clean stop).

#### 13.2.1 Firewall events, NAT and bidirectional flows
A troubleshooting collector's main flow sources include firewalls exporting **event-style** flow v9 and IPFIX:
one record when a connection is created, one when it's torn down, and one for each denied connection, with the NAT
translation. Their fields get **first-class columns and filters**, not extras, decided (coordinator, 2026-11-16,
owner-delegated), using the standard IANA IEs (checked against the IANA IPFIX registry, 2026-11-16). Flow v9
templates that use the same field type numbers are read the same way.

| Column | IANA IE | Notes |
|---|---|---|
| `fw_event` | `firewallEvent` (233) | 1 created, 2 deleted, 3 denied, 4 alert, 5 update; 0 is invalid and stored as given |
| `nat_event` | `natEvent` (230) | the registry's values (NAT44 and NAT64 session create and delete, addresses exhausted, …), shown by name |
| `post_nat_src`, `post_nat_dst` | `postNATSourceIPv4Address` (225), `postNATDestinationIPv4Address` (226), `postNATSourceIPv6Address` (281), `postNATDestinationIPv6Address` (282) | one column each for IPv4 and IPv6 |
| `post_nat_src_port`, `post_nat_dst_port` | `postNAPTSourceTransportPort` (227), `postNAPTDestinationTransportPort` (228) | |
| `start`, `end` | `flowStartMilliseconds` (152), `flowEndMilliseconds` (153) | also the other start and end IEs (§13.1.1) |
| `event_time` | `observationTimeMilliseconds` (323) | the time an event was observed |
| `in_if`, `out_if` | `ingressInterface` (10), `egressInterface` (14) | as for every flow |
| `initiator_bytes`, `responder_bytes`, `initiator_packets`, `responder_packets` | `initiatorOctets` (231), `responderOctets` (232), `initiatorPackets` (298), `responderPackets` (299) | what event-style exporters often send instead of one-direction deltas |
| `rev_bytes`, `rev_packets` | RFC 5103's reverse IEs (enterprise number 29305 with the forward IE's ID: reverse `octetDeltaCount`, `packetDeltaCount`, and their total-count forms) | the reverse direction of a biflow |
| `rule_id` | none standard (below) | from an IE the user names |

- **No standard IE carries an ACL or rule identifier.** The IANA registry has none (checked 2026-11-16); exporters
  that send one use enterprise-specific IEs. So `rule_id` is filled from IEs listed in
  `listeners.flow.rule_id_ies` (`["<enterprise number>:<element ID>", …]`, the first present wins; empty by default;
  a flow v9 field type as `"0:<type>"`, e.g. `"0:40003"`, decision 76), and stays in extras otherwise. The setup
  helper and the docs say how to find the IE in an exporter's template (the Flows tab lists each exporter's template
  fields).
- **Event records work with flow time.** A record with only an event time (`observationTimeMilliseconds`, or a v9
  event timestamp field) gets `start = end = event_time`, so it matches every window containing that moment, sorts
  by it, and falls in that minute of `flow_minute`. A record with no time at all uses its received time
  (`time_source=received`).
- **Counting bytes without double counting.** Delta counters (`octetDeltaCount`, `packetDeltaCount`) add up as
  usual. A record carrying only totals (`octetTotalCount`, or the initiator and responder counts) adds them only on
  its final record: a `deleted` event (2), or a non-event record. `created` (1), `update` (5) and `denied` (3) records
  keep their counts in their columns but add nothing to sums, since a teardown repeats them. The `flows` metric
  counts records; `connections` (Top and the README) counts `deleted` plus `denied` events for event-style
  exporters, and records for the others.
- **Deny events are filterable and in Top:** `fw_event=denied` (and the other names), `nat_event`, `post_nat_*` and
  `rule_id` are filters (§13.3), Top can rank denied events (`by=src` with `fw_event=denied` is "top denied sources";
  `by=rule_id` and `by=fw_event` too), and the Events Top panel has a **Denied** view: top denied sources,
  destinations, destination ports and rules.
- Biflow counters add to the conversation view: `conversation` sums `bytes` plus `rev_bytes` (or initiator plus
  responder) for both directions.

**Durability and recovery:**
- Blocks are flushed every 1 s (or at 65,536 records) and fsynced on the store's 5 s schedule, so a crash loses at
  most about 5 s, as for the other types.
- The open segment has no footer. Recovery reads the blocks in order, keeps every block whose CRC checks, cuts the
  file after the last good one (the cut is recorded in the events log with the bytes removed), and writes the footer.
- Closed segments are immutable and already compressed: no gzip pass. Retention deletes whole segments.

**Flow time and received time:**
- Each record keeps the exporter's flow start and end, converted to UTC, plus its received time. Queries use **flow
  time**: a record matches a window when `[start, end]` overlaps it, because "the flows around the outage" means when
  the traffic happened. Files are found by received hour, widened by the longest flow lag seen for the exporter (its
  active timeout plus its clock skew, measured; 35 min by default), then narrowed by each block's flow time range.
- If an exporter's clock differs from the received time by more than an hour, its records use the received time
  instead and say so (`time_source=received`; the exporter's own times stay in extras), and the device page warns
  about the clock.
- A record whose own end is more than 1 h after its datagram arrived, or more than 24 h before, from an exporter
  whose header clock is fine, is kept exactly as decoded and counted per exporter ("times off arrival", §13.10
  decision 70): the `flow_time` banner, the device page and the bundle README say so. It's found by a window around
  its own times, not around its arrival.

**Index:**
- `files.type = 'flow'` rows, one per segment, with first and last received and the record count.
- A new `flow_segments` table: per segment, its flow-time range, totals, sampling rates seen and exporter domains, so
  totals and file selection need no file reads.
- A new `flow_minute` table (device, minute, records, bytes, packets, and scaled bytes and packets where sampling is
  known): each record's bytes and packets spread evenly over the minutes its `[start, end]` covers. It serves the
  unfiltered flow histogram and the timeline strip without reading segments, and lives as long as its segments.
- `type_stats` counts flow records by received minute like any type (rates, totals, fair-share weights).
- **Reindex** reads each segment's footer (or recovers it, as above) and rebuilds `files`, `flow_segments` and
  `flow_minute` from it. `--flows-redecode` also re-reads raw sections with the segment's templates.

**Retention, fair share and a flow budget:**
- Flows count toward the cap, the age limit and the low-disk guard like every type (§11.1).
- Fair share is between devices, so on its own it can't stop a firewall's flows from squeezing **its own** syslog
  out: both are the same device's bytes. So flows get a **per-type budget**, decided (coordinator, 2026-11-16,
  owner-delegated): `storage.flow_budget_bytes`, by default 40 % of `retention_bytes` (8 GiB of the default 20 GiB),
  at most 90 %.
  - While flows exceed their budget, the oldest flow segments go first (fair-shared between flow exporters by their
    7-day average, as §3.4 shares devices), before any other type is touched.
  - The rest of the cap holds every other type under the 1.2 rules, and flows never count against it.
  - The low-disk guard deletes flow segments first (oldest first, all but each exporter's current hour) before any
    other type.
  - Flows have no "last 2 days" protection: the budget is their guarantee. The current and previous hour are
    protected, as active files are.
- Why a per-type budget is justified here and wasn't for traps or polls: flows are 100 to 1,000 times their volume,
  and a cap shared without one would let a busy exporter turn a 30-day log store into a 3-day one. Settings shows the
  budget, what it currently holds ("about 5 days of flows at the current rate"), and the same estimate as
  `/api/storage/estimate`.

### 13.3 Query

**Filters** (`type=flow` on `/api/search`, the summary, saved searches, export and `woodshed search`; syslog's, the
trap type's and the poll type's filters are a 400 with it, and the reverse):
- the time window `from`/`to` (flow time, overlap), the device selection (exporters);
- `src`, `dst`, `ip` (either side), each a comma list of addresses or prefixes (`10.20.0.0/16`, `2001:db8::/32`), and
  `exclude_src`, `exclude_dst`, `exclude_ip`;
- `src_port`, `dst_port`, `port` (either), comma lists of ports and ranges (`443`, `8000-8100`), with excludes;
- `proto`: names or numbers (`tcp`, `udp`, `icmp`, `47`), with `exclude_proto`;
- `in_if`, `out_if`: interface indexes or names from the options data, with excludes;
- `domain`: exporter observation domain or source ID; `tcp_flags` (any of `syn,fin,rst,…`); `sampled` (`yes`,
  `no`, `unknown`); `status` (`ok`, `late`, `no_template`, `malformed`).
- Firewall-event and NAT filters (§13.2.1): `fw_event` (`created`, `deleted`, `denied`, `alert`, `update`, or
  numbers), `nat_event` (names or numbers), `post_nat_src`, `post_nat_dst`, `post_nat_ip` (addresses or prefixes,
  with excludes), `post_nat_src_port`, `post_nat_dst_port`, and `rule_id` (with `exclude_rule_id`). `src` and `dst`
  match the pre-NAT addresses; `ip_any` matches pre- or post-NAT on either side.
- `q` is a 400 for flows (`q: flows have no text; use src, dst, ip, port or proto.`): they have no free text to match.

**Results:** flow records, newest first by flow end (or `order=asc`), with the same budget, cursor and partial rules
as `/api/search`: `{"received", "device_id", "type": "flow", "ref", "fields": {start, end, src, dst, src_port,
dst_port, proto, tcp_flags, packets, bytes, packets_scaled, bytes_scaled, sampling, in_if, out_if, in_if_name,
out_if_name, domain, fw_event, nat_event, event_time, post_nat_src, post_nat_dst, post_nat_src_port,
post_nat_dst_port, initiator_bytes, responder_bytes, initiator_packets, responder_packets, rev_bytes, rev_packets,
rule_id, time_source, status, extras}}`. There's no `raw`: a record isn't a line.

**Top-N:** `GET /api/flows/top` for a window and filter:
- `by`: `src` (top talkers), `dst`, `conversation` (the unordered address pair, both directions summed),
  `dst_port` (with protocol: `tcp/443`), `src_port`, `proto`, `in_if`, `out_if`, `post_nat_src`, `post_nat_dst`,
  `fw_event`, `rule_id`;
- `metric`: `bytes` (default), `packets`, `flows` or `connections` (§13.2.1); `top` 10 by default, at most 100. With
  `fw_event=denied` the default metric is `flows` (denied events carry no bytes);
- each row has the exported count, the scaled count (when every record behind it has a known sampling rate; with
  some unknown, the scaled value is a lower bound marked `≥`), its share of the window's total, and `first`/`last`
  flow times.
- **Exact vs sampled:** exported counts are exact (what the exporter reported); scaled counts multiply each record by
  its own sampling rate. Both are shown whenever any record was sampled: "312 MB exported (≈ 312 GB at 1:1000)".
  Nothing is scaled silently, and `sampling: 0` records are never scaled.
- Aggregation is exact up to 1,000,000 distinct keys per request (across its workers), within the server's shared
  query budget; past that, the keys already counted stay exact, and new ones go to a fixed-size space-saving table
  with a count-min check. The response says `approx: true`, each estimated row carries `approx` and `max_error`, and
  `error_bound` caps any key not counted (§13.10 decision 51; docs/api.md).

**Budget and partial semantics, like Events v2:** a search, a summary or a top-N request has the summary's 2 s
default budget (at most 10 s) and continues with a cursor, keeping running totals on the server (§10.1.5's rules: 10
min, at most 8, least recently used out). Segments are read newest first by flow end, and blocks within them likewise,
so a partial answer covers the most recent part of the window first. Instead of `counted_from` (flows overlap in time,
so no clean frontier exists), a flow response reports **progress**: blocks and records read of those the window can
touch, and the flow-time span fully read (`complete_from`: every block ending after it has been read). The UI says
"Counted 62 % of the window's flow records, newest first" and keeps going like the field panel.

**Events:**
- A **Flows** tab (`type=flow`), shown when the flow listener is on or flow segments exist: the results table (time,
  exporter, src → dst, ports, protocol, packets, bytes, both counts when sampled), the field panel (from the schema:
  `proto`, `dst_port`, `src_port`, `src`, `dst`, `in_if`, `out_if`, `fw_event`, `nat_event`, `rule_id`, `domain`,
  `sampled`, `status`; values count flows, with bytes beside them), the histogram (flows or bytes per bucket, from
  `flow_minute` when unfiltered), and a **Top** panel (talkers, destination ports, conversations, and **Denied**: top
  denied sources, destinations, ports and rules), each value clickable into a filter.
- On the other tabs, a **flow strip** under the histogram for the selected devices that export flows: bytes per
  second exported (and scaled), from `flow_minute`, on the same bucket edges as the poll strips (§12.5); at most 4
  devices.

### 13.4 Export and the incident bundle
**The export covers every data type (owner, §9).** From 2.0 the UI's Export defaults to all types for the chosen
devices and window, and the bundle includes every type with data in the window, flows included; the API's default
for a plain export stays `["syslog"]` (§13.9). One zip, one manifest, one folder per type: `logs/` (syslog),
`traps/`, `poll/`, `flows/`.

**Flows in the zip,** for each device, decided (coordinator, 2026-11-16, owner-delegated):
- `flows/<device>/flows.csv`: one row per record in the window, columns
  `start,end,event_time,src,src_port,dst,dst_port,proto,tcp_flags,packets,bytes,sampling,packets_scaled,bytes_scaled,in_if,in_if_name,out_if,out_if_name,domain,fw_event,nat_event,post_nat_src,post_nat_src_port,post_nat_dst,post_nat_dst_port,initiator_bytes,responder_bytes,initiator_packets,responder_packets,rev_bytes,rev_packets,rule_id,tos,src_as,dst_as,next_hop,time_source,status,received`
  (`fw_event` and `nat_event` by name),
  RFC 4180 with CRLF, times RFC 3339 UTC with milliseconds, `proto` as a number, `tcp_flags` as letters (`SAF`), empty
  cells for "not reported". Extras (enterprise IEs) aren't in the CSV.
- `flows/<device>/flows.ipfix`: an IPFIX file (RFC 5655): the same records re-encoded as IPFIX messages, one
  observation domain per original domain, with templates that carry every field the records had, extras and
  enterprise-specific IEs included; v5 and v9 records are mapped to their IPFIX IEs, and a v9 vendor-range field type
  is written with the enterprise bit and enterprise number 0 (decision 75). The file says it was written by Woodshed
  from stored records, not captured off the wire.
- **Both by default**, because they serve different readers: the CSV is what a person opens first (a spreadsheet,
  `grep`), and the IPFIX file is the lossless form flow tools read, with the enterprise fields a CSV can't hold.
  `flow_formats` (`["csv"]`, `["ipfix"]` or both) picks one; the CSV compresses well inside the zip.
- `flows/<device>/raw.txt`: the window's raw sets and malformed packets (§13.1.3), base64, one per line, when there
  are any.
- The size estimate (`/api/exports/estimate`) gives the flow records and bytes separately, and the UI always offers
  **Leave flows out** before building, pre-selected for a window over 4 h whose flows are estimated above 1 GB
  (§13.11). A zip holds at most 20 million flow records per device; past
  that the export fails with a message to narrow the window or filter (`400` at estimate time).

**README per device** gains a Flows block:
```
    Flows        1,204,332 records from 2 observation domains; sampled 1 in 1,000 on domain 1, unsampled on domain 2
                 bytes 18.2 GB exported (≈ 1.9 TB scaled), packets 21.4 M (≈ 2.1 G scaled)
                 top talkers by bytes: 10.20.0.5 31 %, 10.20.0.9 12 %, 192.0.2.44 7 %
                 top destination ports: tcp/443 54 %, udp/53 9 %, tcp/22 4 %
                 top conversations: 10.20.0.5 ↔ 198.51.100.7 22 %
                 firewall events: 48,210 created, 47,902 deleted, 3,114 denied
                 top denied sources: 203.0.113.50 1,920, 198.51.100.23 411; top denied ports: tcp/23 1,204, tcp/445 870
                 NAT: 41,377 translated connections; top post-NAT sources: 192.0.2.10 88 %
                 sequence gaps 3 (≈ 90 records lost before Woodshed); waiting for a template 0; malformed 0
```
and the manifest's summary gains the same numbers as JSON. When any record is far from its arrival time (decision
70), a line before the sequence gaps says so: `times off arrival: 1 ahead (up to 1.2 h) in this window; 3,600 ahead
(up to 49.7 days) in the last 24 h; kept at their own times, so a window around their arrival misses them (the
exporter's clock or uptime is probably wrong)`.

### 13.5 Device setup helper
**Owner (§9):** generated logging, trap and flow-export configuration per device. A **Setup → Send to Woodshed** page
fills in this Woodshed's addresses, ports, CA certificate and the user's choices:
- **What:** syslog (UDP, TCP or TLS), SNMP traps (v2c or v3), flows (flow v9 or IPFIX), and the SNMP agent settings a
  device needs so Woodshed can poll it (§12).
- **Syntax family**, named by syntax, never by vendor or product, decided (coordinator, 2026-11-16, owner-delegated):
  - "Line-oriented CLI (global configuration mode)": `logging host …`, `snmp-server host …`, `flow exporter …`-style
    commands;
  - "Hierarchical set-style CLI": `set system syslog host …`-style;
  - "Linux: rsyslog", "Linux: net-snmp `snmpd` and `snmptrap`", "Linux: softflowd" (open-source tools, named as such);
  - "Web UI checklist": for appliances configured through a web page, the fields and values to enter, in order.
- **Output:** a snippet with Woodshed's values filled in and every secret as a placeholder (`<COMMUNITY>`,
  `<AUTH-PASSPHRASE>`): the page never puts a stored secret into a snippet, and generating one changes nothing on the
  server. A note per snippet: what it does, how to check that it worked (the Dashboard, `woodshed status`), and, for
  TCP and TLS syslog, the 1.1 warning about firewalls that block traffic when the log host is down (§10.3.9).
- **Keeping it vendor-neutral and accurate:**
  - Templates live in `internal/setuphelper/templates/`, one file per family and data type, with a header naming the
    syntax family, the public reference it follows (a manual page, an RFC, a project's documentation), and its
    verification level.
  - **Verification levels,** shown on the page: **Tested** (CI applies it to the real open-source tool against a real
    Woodshed and checks the data arrives: rsyslog, `snmpd`/`snmptrap`, softflowd); **Lab-checked** (applied by hand on
    lab gear, with the date, recorded in the template header); **Reference only** ("check your device's
    documentation": the command names follow common syntax but nothing in CI runs them).
  - A test fails if a template, a family label or a snippet contains a vendor or product name from a deny list kept
    in the test, so the page stays generic.
  - Device-specific commands stay out of the repo, as for TLS; the owner can share those separately.
- `GET /api/setup/families` and `POST /api/setup/snippet` (docs/api.md) serve the page; `woodshed setup snippet
  --family … --what …` prints the same for headless boxes.

### 13.6 Performance targets
On the reference box (4 vCPU, 8 GB, SSD), decided (coordinator, 2026-11-16, owner-delegated) as starting points for
the first bench, which records the measured numbers here:
- **Ingest:** 50,000 flow records/s sustained for 10 min (IPFIX, about 30 records a packet), 0 loss, while syslog runs
  at 5,000 msg/s; bursts of 150,000 records/s for 10 s absorbed by the queue. Under 2 cores at 50,000/s.
- **Memory:** at most 16 MiB of templates and exporter metadata; `pending_bytes` 32 MiB; open blocks at most 64 MiB
  across exporters (a block is flushed early to stay under it); the writers' directories at most 32 MiB across
  exporters (a segment is closed early to stay under it, decision 58); the queue's bytes (128 MiB); query state at most
  256 MiB, whatever the window's size or key count (decision 51). 512 MiB for flows in all at the targets.
- **Disk:** 12–20 bytes per stored record (to be measured).
- **First bench (build, 2026-11-16,** `woodshed bench --proto ipfix`, the sender in a child process, a 14-core laptop
  under other load; the reference box and the lab runs replace these):
  - 50,000 records/s for 10 min (30 a packet, 2 domains) with UDP syslog at 5,000 msg/s: all 30,000,000 records and
    3,000,186 messages stored, 0.43 of a core, peak RSS 153 MiB (Go heap 90 MiB), 20.4 bytes per stored record (19.2
    in blocks, 20.0 for a closed segment in the format bench).
  - Queries over 18,000,000 records (the 1 h at 5,000/s case): top talkers (`woodshed flows top --by src`, bytes)
    0.34–0.72 s, complete; a search for one source address, first 500, 0.10 s.
  - Over 180,000,000 records (the 1 h at 50,000/s case; 3.4 GiB of segments, 20.2 bytes a record): top talkers 2.9–3.8 s
    and top destination ports 2.4 s, complete in one response (inside the 10 s budget); top conversations, past the
    1,000,000-key exact limit and so approximate, 28 s (inside the 60 s target); a search for one source address,
    newest 500, 0.16 s. Memory: the `flows top` process peaks at about 480 MiB RSS for top talkers (mostly the 14
    workers' block buffers) and 1.8 GiB for conversations past the exact limit, over the 256 MiB query-state target.
    The reference box's 4 workers would need less; a hard cap is open.
  - **Bounded (build, 2026-11-16, third round;** decision 51; the same data regenerated, the same laptop under load
    average 5–6): every query now uses at most 4 workers and a 128 MiB shared table budget. Peak RSS of the whole
    `flows top` process, 3 runs each: top talkers 7.5–8.5 s, 99–102 MiB; top destination ports 6.4–7.0 s, 89–91 MiB;
    top conversations (approximate past 1,000,000 keys) 14.4–15.1 s, 216–219 MiB, with the heaviest conversations
    still counted exactly and `error_bound` 64.5 GB beside a top row of 287 GB. Top talkers are slower than with 14
    workers (2.75–3.8 s) but stay inside the 10 s budget; the memory target comes first.
  - Test ceilings (`internal/flowquery/mem_test.go`): a conversation top over 1.6 and 4.5 million distinct keys peaks
    at 154 and 158 MiB of heap (ceiling 192 MiB, and the peak may not grow by more than 24 MiB with the key count).
    Exact keys cost 131 bytes for a conversation, 115 for an address and 99 for a port, checked against the heap up to
    1,000,000 keys.
  - **Plans and the writer (build, 2026-11-16, fourth and fifth rounds;** decisions 56 and 57; peak heap measured by
    the tests on the build machine):
    - A week over 50 exporters (8,400 segments of 60 blocks, 504,000 blocks): a top-N 23 MiB, a search page 16 MiB,
      against 20 and 16 MiB over its last day, 7 times fewer blocks (`TestWeekPlanBounded`, ceiling 192 MiB, and the
      week may not add 16 MiB; batches are the same shape either way, so it holds beside CPU burners too). A minute's
      window over 300 exporters' 3,600-block segments: 579 MiB → 19 MiB over closed segments, 730 → 21 MiB over open
      ones (`TestNarrowWindowPlanBounded`, ceiling 64 MiB).
    - The writer over an hour of ingest (`internal/flowseg/hourmem_test.go`: a simulated store, real headers of
      loadgen's size, blocks as long as 20 bytes a record, so a busy exporter's hour is 14 or 53 parts of 256 MiB),
      before → after, heap above the hour's start at GOGC 10 (at the default GOGC 100 in brackets, where the
      collector's headroom over the open blocks adds to it):

      | Case | Peak over the hour | At the hour mark (every segment closing) | Kept a block | Allocated an hour |
      |---|---|---|---|---|
      | 50,000/s, 1 exporter | 27.9 → 1.1 MiB (58.1 → 4.3) | 9.2 → 0.3 MiB | — | 1,246 → 5 MiB |
      | 150,000/s, 1 exporter | 23.0 → 1.5 MiB (38.6 → 13.8) | 9.6 → 0.3 MiB | — | 3,802 → 16 MiB |
      | 150,000/s, 50 exporters | 135 → 49 MiB (343 → 106) | 114 → 1.0 MiB (263 → 0.9) | 587 → 218 B | 147 GB → 221 MiB |

      Closing one dense segment (1,000 blocks of 34 KB headers, a 34 MB footer): 166 → 0.7 MiB. Ceilings, on what
      doesn't depend on how far the collector lags a starved CPU (the sampled peak over 50 exporters was 121 MiB on
      one core against 49 on many, the same 37.5 MiB live): the live heap within the directories' 216 bytes a block
      (×1.25) plus 8 MiB, allocation within 2 KiB a block plus 320 KiB a part, at most 300 bytes kept a block, and
      under 8 MiB at the hour mark (`TestWriterHourHeapBounded`); 8 MiB of heap and of allocation for a 136 MB
      footer's close (`TestCloseHeapBounded`).
      Each exporter's open block (a record's 466 bytes in memory, under FlowOpenBytesCap) is outside these: 1.4 MiB
      at 3,000 records a second, 23–29 MiB for a full 50,000–65,536-record block.
  - A 150,000 records/s burst for 10 s: all 1,500,000 stored, nothing dropped by the queue, 0.33 of a core.
  - At 5,000 records/s a segment takes 21.9 bytes a record (the per-block index and the Bloom filter over random
    source ports weigh more in smaller blocks).
  - The format alone: encoding about 440 ns a record (2.2 % of a core at 50,000/s); decoding the source and bytes
    columns 38–40 M records/s on one core, every column about 5.4 M/s.
- **Queries:** top talkers (`by=src`, bytes) over 1 h at 5,000 records/s (18 million records) in under 3 s,
  complete in one response; at 50,000/s (180 million) partial within the 10 s budget and complete within 60 s.
  A filtered search for one address over 1 h at 5,000/s returns its first page in under 1 s.

### 13.7 CLI
- `woodshed search --type flow --src 10.20.0.0/16 --dst-port 443 --last 1h` (the flow filters as flags, or
  `--field`), printing one CSV-like line per record by default, `--json` as NDJSON, `--count`.
- `woodshed flows top --by src|dst|conversation|dst-port|src-port|proto --metric bytes|packets|flows --last 1h
  [filters] [--json]`: the top-N table, exported and scaled columns.
- `woodshed flow on|off|status`: the listener and firewall rules (§13.1); `status` shows each exporter's rate,
  templates, sampling, sequence gaps and pending data.
- `woodshed bundle` includes flows (`--types`, `--flow-formats csv,ipfix`).
- `woodshed status` gains a Flows row: exporters, records a second, budget used.

### 13.8 Testing plan
- **Unit and fuzz:** the v5, v9 and IPFIX decoders against hand-built and captured packets (every IE type and length,
  variable-length fields, enterprise IEs, padding, options records, template replacement, withdrawal and timeout,
  sequence gaps and duplicates, time conversion from uptime-relative, absolute and delta forms). Fuzz targets:
  `FuzzFlowV5`, `FuzzFlowV9`, `FuzzIPFIX` (no panic, bounded memory, malformed counted not lost), `FuzzTemplates`
  (random sequences of templates, withdrawals and data against one cache: no stale decode after a replacement),
  `FuzzSegment` (any bytes as a segment file: recovery never panics and never keeps a block whose CRC fails) and
  `FuzzIPFIXFile` (re-read what the IPFIX file writer wrote).
- **The segment format:** write → read round trips for every column type; crash cuts at every byte offset of a test
  segment, then recovery keeps exactly the complete blocks; the block index never skips a block that holds a match
  (property test against a full scan).
- **Interop (CI, Linux job only):** softflowd (installed in CI only) replays fixed pcap files (`-r`) to a real
  `woodshed run` as v5, v9 and IPFIX, and the stored records are compared with the pcap's flows computed independently.
  pmacct's `nfprobe` as a second exporter for IPFIX with options data (sampling and interface names). The IPFIX file
  Woodshed exports is read back by our decoder and by an independent IPFIX file reader in CI (tshark), and both must
  agree with the CSV; so is a bundle's file from a v9 `--events` run with vendor-range fields (decision 77).
- **`woodshed send --proto flow-v5|flow-v9|ipfix`:** generators for the lab with exactly-once-checkable records.
  Each record carries the run ID and a sequence number: in v9 and IPFIX as an enterprise-specific IE under 32473
  (IANA's documentation enterprise number, as 1.2's trap generator uses), in v5 split across `src_as` and `dst_as`
  (16 bits each). Flags: `--rate` (records/s), `--records-per-packet`, `--domains`, `--sampling N`,
  `--template-every N`, `--template-first-delay` (to test pending data), `--enterprise-ies`. `woodshed bench --proto
  ipfix` measures ingest in-process.
- **`--events`** (v9 and IPFIX): an event-style generator, because no open-source exporter emits firewall events.
  It sends, per simulated connection, a `created` record, an optional `update`, and a `deleted` record with
  initiator and responder totals, plus a share of `denied` records (`--deny-ratio`, default 0.1) with only an event
  time; every record carries the `firewallEvent`, `natEvent`, post-NAT address and port, ingress and egress interface,
  `observationTimeMilliseconds` and `flowStart`/`flowEndMilliseconds` IEs as a firewall would, a rule ID in an
  enterprise IE (for `rule_id_ies`), and the sequence IE. `--biflow` sends RFC 5103 reverse counters instead. CI checks
  every column, the deny filters, "top denied sources", the no-double-count rule and the CSV; the lab runs it from
  the namespace senders at the rates below.
- **End to end:** syslog, traps, a polled test agent and IPFIX from `woodshed send` into the real binary; a flow
  search, top-N, the Flows tab's summary, CLI search and top, and a bundle around a chosen time: its `flows/` CSV and
  IPFIX file hold exactly the generator's records in the window (by sequence number), the README's top talkers match
  a count from the generator's own log, and the sampling note appears when `--sampling` was set.
- **Load:** the targets in §13.6, recorded in the release notes like the other benches; the budget and the low-disk
  guard under a flow flood (flows deleted first, syslog untouched); the queue's `queue_full` counts exactly what's
  lost when it's overrun.
- **Soak:** 24 h on the lab VMs at 10,000 flow records/s plus 3,000 syslog msg/s, crossing midnight, with a restart, a
  forced low-disk pause and an exporter that restarts with new template definitions. Pass: every record stored once or
  counted, no stale-template decode, RSS flat, the flow budget holding.
- **Lab:** the lab's traffic-generator VM sends from its network-namespace senders: `woodshed send --proto ipfix` in 8
  namespaces at 5,000, 20,000 and 50,000 records/s in all (one exporter per namespace, 2 domains each, one sampled 1 in
  100), and softflowd on a namespace interface carrying real generated traffic. Checked by sequence numbers end to end,
  and on Windows, macOS and both Linux packages.
- **Setup helper:** the "Tested" templates applied in CI (rsyslog, `snmpd`, softflowd) deliver data; the deny-list test
  over every template; snippets never contain a stored secret.

### 13.9 Compatibility and the major version
- **Config:** a 1.3 `woodshed.toml` loads unchanged; `[listeners.flow]` is off and `storage.flow_budget_bytes`
  defaults to 40 % of the cap, which changes nothing while there are no flows.
- **Data:** syslog, trap and poll files are unchanged, except that a syslog message that wasn't stored whole ends its
  line with a marker (§3.3, decision 79); a 1.x reader shows it as text. The index migrates once (`flow_segments`, `flow_minute`).
  Segments appear only under `logs/<device>/flows/`. A 1.x `reindex` ignores them (its listing skips subfolders), so
  the path back is the usual one (§11.7).
- **API:** additive. `type=flow`, the flow routes and filters, `flow_formats` and the new banner kinds are new; every
  1.3 request means what it meant, and a plain export without `types` is still syslog-only.
- **Why 2.0, when nothing in the API breaks:** it's the roadmap's milestone, and it changes two things an operator
  relies on. Woodshed gains a second, binary on-disk format next to the plain text files (§1's "plain text files any
  tool can read" now has an exception, documented, with CSV and IPFIX exports as the readable form), and with flows
  on, what retention deletes first changes (the flow budget). Downgrading to 1.x loses access to flows. Nothing a 1.x
  client or script does stops working. That's why it's 2.0 (§13.11).

### 13.10 Decisions for 2.0
**Owner (§9):** the 2.0 scope: the collector on UDP 2055 and 4739, templates per exporter and domain, compact
columnar storage per device per hour, shared retention and disk guard, search and top views for a window, CSV or
IPFIX export, the export covering every type, the setup helper; no long-term analytics.

**Owner (2026-11-16):** the flow protocols' trademarked name is used nowhere in the project: not in code
identifiers, file names, fuzz targets, CLI flags or values, config or API values, UI text, docs, the CHANGELOG or
tests. The protocols are "flow v5", "flow v9 (RFC 3954)" and "IPFIX (RFC 7011)", and the general noun is "flows" or
"flow export". Config and API values are `v5`, `v9` and `ipfix`; the 2055 socket is the flow port (`flow_port`,
`proto: "flow"`); `woodshed send` and `bench` take `--proto flow-v5|flow-v9|ipfix`. Third-party tools we invoke keep
their own names (softflowd, pmacct's nfprobe, tshark's `cflow.*` fields). `internal/repocheck` fails `go test` on the
word in any tracked file or file name.

Everything below is **decided (coordinator, 2026-11-16, owner-delegated)**:
1. The flow listener is off by default; both ports accept every version (§13.1).
2. IPFIX over UDP only; TCP (and TLS) later if asked; no SCTP (§13.1).
3. Template keys include the exporter's source port; at most 256 templates per exporter and 10,000 in all; withdrawals
   are honoured even over UDP (§13.1.2).
4. Every record keeps its sampling rate (`0` when unknown); counts are shown exported and scaled, never scaled
   silently (§13.1.2, §13.3).
5. Data before its template waits in a 32 MiB buffer (1 MiB per exporter) for up to the template timeout, then is
   kept raw; malformed packets are kept raw (§13.1.3).
6. Columnar segments (`.wsf`) per device per received hour, DEFLATE per column, block indexes with Bloom filters; the
   original datagrams aren't kept (§13.2).
7. Queries use flow time (overlap), files are found by received time widened by the measured lag; exporters with
   clocks more than an hour off use received time (§13.2).
8. A per-type flow budget, 40 % of the cap by default; flows go first under the budget and the low-disk guard; no
   2-day protection for flows (§13.2).
9. `q` is a 400 for flows; flows have their own address, port and protocol filters (§13.3).
10. Top-N is exact up to 1,000,000 keys, then approximate and flagged (§13.3; bounded memory, decision 51).
11. Partial flow answers report progress and `complete_from`, not `counted_from` (§13.3).
12. Events gets a Flows tab and a flow strip on the other tabs (§13.3).
13. Flows in the zip: CSV and an IPFIX file, both by default; at most 20 million records per device per zip (§13.4).
14. The UI's Export defaults to all types; the API's default stays syslog-only (§13.4).
15. Setup helper families are named by syntax, never by vendor or product; three verification levels; a deny-list
    test (§13.5).
16. The performance targets in §13.6.
17. The major version is a milestone and an operator-visible change (the binary format, the flow budget), not an API
    break (§13.9).

Made while building it, each **decided (build, 2026-11-16)**:

*Collector (§13.1):*

18. Both flow ports feed one receive queue (shown as `flow` in `udp_queues`) and one drainer, so the collector's
    template state stays single-threaded; there's no inline fast path for flows (exporters send steadily, and a
    packet carries ~30 records).
19. A v5 header sampling interval of 0 or 1 is unsampled, for the records and domain 0. An exporter's scopes with
    one domain ID (other ports or versions) show the highest rate among them in `/api/flows`. Domain-level sampling
    comes from options data without a sampler ID (v9 scope System, IPFIX scope observationDomainId); sampler tables
    from 48/302 with 34, 50, 305/306, 309/310 or 311.
20. `rule_id`: a fixed-length field of 1–8 bytes is a big-endian unsigned integer in decimal; a variable-length or
    longer one is printable ASCII as text (trailing NULs trimmed), else hex. The IE also stays in extras.
21. An exporter clock more than 1 h off: end = received, start = received − duration, event time = received,
    `time_source=received`; the exporter's own times are kept as extras 152, 153 and 323.
22. Totals (85/86, initiator and responder) fill bytes and packets (with the totals mark) only when the record has no
    delta counter; otherwise they go to extras. With several forms of one time, the most precise absolute form wins.
23. Duplicates are counted and still stored. Sequence numbers: v9 counts packets (records lost ≈ gap × the average
    records per packet), v5 and IPFIX records; undecodable sets make the next number unknown (resync, no gap); a jump
    back of more than 100,000 is an exporter restart.
24. A break in the header or set structure stores the whole packet raw; a break inside a data set stores the rest of
    that set raw, after the records decoded before it.
25. Interface names are resolved per record at decode (the domain's names, else any of the exporter's domains; ifName
    wins over ifDescription; at most 256 bytes) and stored with the record, so a record keeps the names in force when
    it arrived.
26. Bounds: 1,024 fields per template, 12 MiB of templates and decode plans, 4 MiB of metadata, 20,000 exporters
    (least recently heard out first).

*Storage (§13.2):*

27. The segment header is 32 fixed bytes, then the device ID and the writer version, with a header length (a long
    IPv6 device ID doesn't fit in 32). Raw sets and templates are written as chunks with each flush, templates before
    the block that uses them, so a crashed segment still decodes on its own; at close come the whole template table,
    the footer and a 16-byte trailer. One address dictionary per block serves every address column; DEFLATE level 6,
    and a column that doesn't shrink is stored raw.
28. Post-NAT addresses and ports are in each block's Bloom filter, so `post_nat_*` and `ip_any` can skip blocks.
29. Effective flow time: end is the flow end, else the event time, else the received time; start is the flow start,
    else the end (never after it). The `flow_minute` rule: a record counts once, in its end's minute; its bytes and
    packets spread evenly over at most 120 minutes (a longer flow's start is clamped). `flow_minute` rows are kept per
    segment, so deleting a segment removes its minutes.
30. Scaled sums leave out records of unknown sampling (they're then a lower bound, marked), everywhere: segments,
    `flow_minute`, Top and the summary.
31. A segment's hour is the received hour of the datagram that opens it; late-decoded records go into the open
    segment. Queries pick segments by their flow-time range (`flow_segments`), so no received-hour widening is needed.
    After a restart within the hour, recovery closes the segment and the exporter's next records start a new part: a
    closed segment is never reopened.
32. The other types' cap is the storage cap less what flows hold (at most their budget). The fair-share weight is each
    exporter's flow datagram bytes over 7 days (`type_stats`); `type_stats` counts flow records as messages and their
    datagrams' bytes as bytes. The low-disk guard deletes every closed flow segment, oldest first, before any other
    data.
33. Readers outside the writer's process (`woodshed search`, `flows top`, `bundle`) read a segment still being written
    up to its last complete block, read-only (`flowseg.OpenLive`).
34. `woodshed reindex --flows-redecode` rewrites a segment with its raw sets decoded by the segment's own template of
    that exporter port, domain and ID (the first received after the set, else the latest), the records marked late.
    Queries decode the same sets on read, with the same choice, placed in the plan by the segment's received range
    (records may start up to an hour before it).

*Query and API (§13.3):*

35. Top-N and summaries read in waves of blocks; a wave once started finishes, and every request reads at least one,
    so a continuation always progresses and its counts cover whole blocks. A search page that runs out of budget
    returns only the records no unread block can beat, and a cursor past every block read. A continued query whose
    range was the default keeps its first request's range.
36. A flow summary gives `progress` and sets `counted_from` to `complete_from`; bucket counts hold the `metric`
    (flows by default) with `bytes` and `bytes_scaled` beside; field values are filter values (protocols by name,
    ports as numbers labelled `tcp/443`).
37. `GET /api/flows/templates?device=` lists an exporter's cached templates with IE names, for Settings → Flows.
    `/api/context` refuses a flow ref. Bundles' active devices are exact for flows: each candidate segment's blocks
    prove or rule out the window by their received bounds, and only a block straddling an edge has its received
    column decoded (then the raw sets), so the cost is a footer read per segment and usually one or two block decodes (late-decoded records can make
    more blocks straddle an edge).
38. In JSON bodies (saved searches, exports) the flow filters are top-level lists; `status` is shared with the trap
    lists' key. A parameter two types share is each one's own (`CheckParams`); messages say "flows".
39. `woodshed search --type flow` prints the bundle CSV's columns after a device column, oldest flow end first; the
    flow filters are flags named like their parameters (`--dst-port`).

*Export (§13.4):*

40. `raw.txt` lines: `<received, RFC 3339 UTC ms> <status> v<version> domain=<id> template=<id> <base64 of the set>`.
41. The estimate's bytes are 225 B a record for the CSV and 95 B for the IPFIX file, uncompressed (measured 205–242
    and 92–95 on the fixtures). The 20,000,000 cap is checked at create, when a bundle resolves, and while writing.
42. The bundle README's sequence gaps are the collector's last-24-hour counts and say so (only the running collector
    keeps them; `woodshed bundle` says they aren't known). The firewall-event, denied and NAT lines appear only with
    something to count; scaled figures only when a rate above 1 is known, with "≥" when some sampling is unknown;
    top lists hold 3 entries; "translated connections" count NAT create events.
43. `flows.ipfix` writes columns as their IANA IEs at fixed lengths (the received time as
    collectionTimeMilliseconds, 258), extras as they came, interface names as options data before the records that
    use them, and opens each domain with an options record whose observationDomainName says "Written by Woodshed
    <version> from stored flow records; not captured off the wire." It doesn't carry the late status, the exporter
    port or the original version and template IDs; a record too big for one message has its trailing extras cut
    (counted).

*Generators and tests (§13.8):*

44. Generator IDs: IPFIX PEN 32473 IE 1 is the run, 2 the sequence, 3 the rule, 10 and up the fillers; v9 (no
    enterprise numbers) uses field types 40001–40003 and 40010 up; v5 puts the sequence in `src_as` (high 16 bits) and
    `dst_as` (low 16), and the run's last 4 hex digits in engine type and ID. `--sampled-domains` sets how many domains
    are sampled; `--biflow` is IPFIX only.
45. `woodshed bench --proto ipfix` runs the sender in a child process (`woodshed send`), so the CPU it reports is the
    pipeline's.

*Second round (build, 2026-11-16):*

46. Options records are kept raw (§13.1.2) when any non-scope field is one the collector doesn't interpret (sampling,
    sampler and selector, interface index and name, systemInitTime are interpreted): keyed by template ID and scope
    values per exporter port, domain and version, up to 4 versions per key (identical values only refresh), at most
    1,024 keys per scope and 2 MiB of the 4 MiB metadata cap.
47. The exporter's metadata (sampling, samplers, system init time, interface names, the raw options records) is one
    JSON blob in each segment's template table, given to the store when its version changes; the store keeps a stream
    (and its blob) for an hour after its last batch, so every later segment carries it.
48. `flow_templates` also fires when an exporter's oldest pending data has waited over 10 minutes
    (`ExporterStats.PendingOldest`).
49. A settings save applies `rule_id_ies` to the collector and to raw sets decoded on read at once, no restart.
50. The segment writer's cut-back after a failed write is tested by fault injection (every section kind, whole and
    short writes, a failing truncate, at Close); no writer bug was found.

*Third round, query memory (build, 2026-11-16; the coordinator asked for a hard bound under §13.6's 256 MiB):*

51. **Every flow query's memory is bounded, whatever the window's size or key count** (`internal/flowquery/agg.go`):
    - One top-N table per request, shared by its workers and split in 64 shards by key hash. Each worker combines
      repeated keys in a 1,024-entry cache and hands them to a shard 32 at a time.
    - Exact up to 1,000,000 keys in all, not per worker, and within the engine's pool: 128 MiB shared by every running
      query, saved continuation and summary. When a request needs room, the least recently used saved continuation
      is dropped (its cursor expires).
    - The exact table is a pointer-free slab with an extendible hash index that splits in place, so it leaves no
      growth garbage. A key costs 131 bytes for a conversation, 115 for an address and 99 for a port; the pool charges
      that, and a test checks it against the heap. 1,000,000 conversations fit in 128 MiB.
    - A shard that can't take a new key keeps its exact keys and counts new ones in a fixed-size space-saving table
      (256 entries a shard, 16,384 in all) with a count-min sketch (4 × 1,024 a shard), about 5 MiB in all, outside
      the pool. A newcomer to a full table replaces the lightest entry only if the smaller of the lightest count and
      its sketch count, plus its own, beats it. That estimate is the row's `max_error`.
    - Rows admitted to a full table are always marked `approx`; their other counts cover only the records since they
      entered. A key in neither table has at most `error_bound`. The totals stay exact.
52. **The engine's workers are shared by every query** (the default is GOMAXPROCS, at most 4, the reference box's
    vCPU), with their decode buffers reused, about 8 MiB each. Big queries queue for workers rather than add buffers.
    While the pool holds 32 MiB or more, a collection runs after any wave that follows 16 MiB of allocation; without
    it, Go's pacer let garbage grow to the live table's size beside a 130 MiB table.
53. **A closed segment's footer is read streamed** (CRC checked as it goes). Only each block's directory entry is kept
    (472 bytes), with where its header copy sits; a block's Bloom filter loads from there when a filtered scan needs
    it and isn't kept. Before, every query held every one of its segments' whole footers, a few bytes a record. A
    query closes a segment once its last block is read, and decoding reuses each column's inflate buffer and the
    address dictionary.
54. **Summary values come from the same pool.** Per-worker counts flush into the shared ones at 1,024 values a field,
    and a field that once turns a value away takes no new ones, so a value can't miss its earlier counts. A bundle's
    README top-N tables share one 64 MiB pool, with small approximate tables (1,024 entries).
55. **Still proportional to the window, and left as is (flagged; since bounded by decisions 56 and 57):**
    - the plan: 64 bytes for each block the window touches, one block a second per exporter at most, about 5.5 MiB
      per exporter-day;
    - the open segments' directories: 472 bytes a block, about 1.7 MiB per open exporter-hour.

    A week over 50 exporters would plan about 1.9 GiB. The writer still built a closing segment's whole footer in
    memory (ingest side, at hour close).

*Fourth round, plans (build, 2026-11-16):*

56. **A query's plan streams the window** (`internal/flowquery/plan.go`):
    - Segments come from the index a page at a time (256 rows, `FlowSegmentsPage`: newest end first, or lowest start
      first ascending, each a range on an `(end, path)` or `(start, path)` index) and load a batch at a time, sorted
      within the batch. A batch stops at **16,384 directory
      entries loaded or 256 segments**, always a whole segment: every block and raw chunk of a loaded segment counts,
      in the window or not, since its footer (or snapshot) holds them all, and a segment counts one more for itself.
      Counting only the window's blocks let a minute over 300 exporters' hour segments load 273 of them a batch
      (579 MiB closed, 730 MiB open; 19 and 21 MiB now), and raw-only segments without limit. A closed segment with
      nothing in the window closes its file as soon as it's planned; the others hold one until their blocks are read.
    - A batch's bytes (472 a directory entry, 64 a planned block) are charged to decision 51's 128 MiB pool until the
      next batch, or until the query or its saved state ends, so saved continuations' plans count with the tables. A
      segment the pool can't fit (after dropping saved states) ends the batch, charged anyway: one segment over at most.
    - **Open segments are listed once, when the plan starts, and never come from the pages**: the store moves an open
      segment's row on every flush, so a row could jump past the page cursor and be missed, or land during the plan
      and be read twice. Descending they load first (any end); ascending at their indexed start less an hour (read by
      path; unindexed: first). The pages skip their rows.
    - `complete_from` and a search page's certainty are the bound of everything unread: the batch's next block and
      the next segment, an unread open one included. A search page past its budget reads on until that bound passes
      its cursor, so pages always progress; segments behind a cursor are skipped in a loop.
    - Progress counts the index's records until a segment loads, then its exact rows.
    - Open segments are listed without their snapshots (`store.OpenFlowList`); a plan takes each when its batch
      reaches it (472 bytes a block, at most 3.9 MiB at the part limit), and one closed since is read from its file.
      `OpenSnapshot` doesn't copy the snapshot's block list.
    - `Each` (exports) goes a device at a time with its own plan; Count streams batches. `Raw` (a bundle's raw.txt)
      pages the window's raw-holding segments, 256 rows at a time.

*Fifth round, writer memory (build, 2026-11-16):*

57. **The segment writer's memory is bounded, at hour close too** (`internal/flowseg/state.go`,
    `internal/store/flow.go`):
    - Close writes the footer streamed: the template table, then the footer body through a 256 KiB buffer (pooled),
      each block's header copied from the block itself with the CRC computed as it goes, then the section prefix, an
      fsync, and the trailer. The format is unchanged (a test compares the bytes with the old in-memory encoder at
      five buffer sizes). The fsync keeps a crash from leaving a trailer over a torn body, which Open would call
      corrupt rather than unfinished, so the store's recovery would skip it. Before, Close held about five times the
      footer (166 MiB for a 34 MB one); now 0.7 MiB, most of it the directory Close returns.
    - The store closes with `CloseSummary`, which returns Summary's fields and builds no directory, so 50 exporters
      closing at the hour mark add 1 MiB of heap, not 114 MiB (§13.6).
    - The store's index rows come from `Writer.Summary` (the footer-level fields), not a snapshot that copied the
      block directory on every flush: 147 GB of garbage an hour over 50 exporters at one block a second, 221 MiB now.
    - The writer keeps 216 bytes a block (587 before, a 472-byte BlockInfo and a header span), sampling and domain
      lists shared with the previous block's.
    - A segment starts a new part at **8,192 blocks**, as at 256 MiB (`store.Options.FlowPartBlocks`). One block a
      second is 3,600 an hour, and early flushes add up to about one more a second, so an hour stays one part; a busy
      exporter reaches 256 MiB first (about 270 blocks of 50,000 records at 20 bytes a record). At the limit a writer
      keeps at most 1.7 MiB, a snapshot copies 3.9 MiB, and the footer holds 8,192 headers. Queries, a reindex and a
      bundle see every part (tests at a 10-block limit).
    - Fault injection (decision 50) covers every write of the streamed tail and a failed header read.

58. **The writers' directories have one budget across exporters, decided (coordinator, 2026-11-16):** 32 MiB by
    default (`store.Options.FlowDirBudget`). Uncapped, 216 bytes a block is about 0.8 MiB per exporter-hour at one
    block a second (the 1 s flush makes one even for a quiet exporter): about 37 MiB by the hour's end over 50
    exporters and 220 MiB over 300, which with the 128 MiB query pool breaks the process's 256 MiB.
    - Each writer's `DirBytes` (its blocks' and raw chunks' entries) is added to one total as it writes. After every
      maintenance pass's flush (each second), while the total is over the budget, the segments whose writers keep the
      most are closed, largest first, until it's back under. Their exporters' next records start the hour's next part
      (`…T09.001.wsf`): a part roll, nothing dropped. The total can pass the budget by one second's blocks.
    - `/api/stats` `flow_parts_early` counts these closes since the server started; the log says so at most once an
      hour.
    - Measured at 150,000 records a second (each exporter writes one block a second at both rates: the open-block
      cap's early flushes don't trigger), a simulated second hour after the first filled the budget: 50 exporters at
      3,000 a second make 1.16 parts an exporter-hour (8 early parts an hour in all), 300 at 500 a second make 4.15
      (945 early parts an hour). An hour stays one part up to about 43 exporters at one block a second.
    - Tested (`TestFlowDirBudget`): 300 exporters for 10 simulated minutes under a third of their uncapped
      directories. The total never passes the budget by more than a block an exporter, live heap grows 20–28 MiB
      (ceiling: the budget, 24 KiB an exporter and 16 MiB; uncapped would be about 45), and every record is read
      exactly once from the parts' files, the index, a query and a reindex; a bundle over budget-rolled parts is
      checked in `internal/export`.
59. **Left open (flagged):** an open segment's snapshot still copies 472 bytes a block per query that reaches it
    (bounded by the part limit and the plan's batch). Sharing the writer's append-only entries without a copy is the
    follow-up if it shows up.

**Setup helper build decisions** (the setup-helper build agent, 2026-11-16, for the owner's review; branch
`feat-setup-helper`):
60. **Routes:** `POST /api/setup/snippet` as the contract says, plus `GET /api/setup/snippet?…` with the same fields
    as query parameters (`type` accepted for `what`) for scripts. The CLI is `woodshed setup snippet --family …
    --what …` with `--type` as an alias, and `woodshed setup families`; the snippet goes to stdout, its notes to
    stderr.
61. **Additive response fields:** a snippet also has `family`, `what`, `transport`, `address`, `reference`, `does`
    (the "what this does" line), `check`, `parts` (each a `file`, `command`, `cli` or `steps` with its own Copy) and
    `addresses` (the list the page offers). A family also has `transports`, `choices` and `notes`, with every data
    type as a key (`[]` where the family has no template), so the shape is fixed.
62. **Template format:** `text/template` files in `internal/setuphelper/templates/`, one per family and data type,
    each with a header (family, what, transports, reference, verification, `checked_on` for lab_checked) and
    `does`, `parts`, `notes` and `check` blocks; parts are split on `@@part` marker lines. Golden files pin every
    family, type and transport.
63. **Coverage:** the web UI checklist covers all four types; the line-oriented and set-style CLIs cover syslog,
    traps and polling, with no flow template, because flow export commands differ too much between devices of either
    style to give one that's useful (a family note points to the checklist's values). rsyslog covers syslog; net-snmp
    traps and polling; softflowd flows. The line-oriented CLI gives as text only lines most such devices share
    (`logging host`, `logging trap`, a v2c community or host line); keywords that differ are placeholders
    (`<TCP-OPTION>`, `<SHA-256-KEYWORD>`) with notes. (Review, 2026-11-16: the first version had a flow template with
    an invented keyword in one maker's structure, and mixed makers' keywords in the syslog and SNMPv3 lines.)
64. **Verification:** rsyslog and net-snmp are Tested by the CI job `setup-snippets` (TestSetupSnippets in
    internal/server, against a real running server, each record exactly once). softflowd is Tested too since the
    flow listener merged: the runner replays the flow interop test's synthetic pcap with `-r` in place of the
    snippet's `-i <INTERFACE>` (a CI runner has no traffic to watch), every other option as generated, and each flow
    must be stored once with the pcap's packet and byte counts, for v9 and IPFIX. TestSetupTestedTemplatesHaveCI and
    the deny-list test both fail a Tested template no unskipped case applies. Beside the defaults, CI runs one case per
    family over IPv6 loopback, one with non-default choices (severity and facility; SHA-1 and another user), the
    net-snmp poll snippet applied to a distribution-style snmpd.conf, and rsyslog TCP and TLS with Woodshed down until
    the queue overflows. A tested template's `ci:` header says what CI applies, served as `verification_detail`.
65. **Choices:** source interface (line-oriented CLI), the interface softflowd watches, severity (RFC 5424 keywords,
    default `info`), facility (`local0`–`local7` or the device's default), SNMPv3 user, SHA-256 (default) or SHA-1,
    AES-128 (the protocols most devices and net-snmp share; the notes say to match both sides), and the polled
    agent's port. Values are checked against strict patterns, so nothing a user types can add a line to a snippet;
    names from the certificate and the config go through the same host-name pattern (wildcards are dropped). A typed
    agent port of 0 is an error, not the default.
66. **Filled from live state:** the listener's own address when it's bound to one, else the host's addresses, then the
    TLS certificate's DNS names and `ui.extra_hostnames`; each listener's port and whether it's on (a note says how to
    turn it on, first); for TLS, the name a client should check (the address when it's a name on the certificate,
    else its first DNS name that isn't `localhost`; rsyslog and many devices check names, not IP addresses) and the
    CA's fingerprint.
67. **rsyslog:** one omfwd action in `/etc/rsyslog.d/60-woodshed.conf`, RFC 5424 format, octet-counted framing for
    TCP and TLS, an in-memory queue that retries while Woodshed is down, and for TLS the gtls driver with
    `x509/name` and the action-level `StreamDriver.CAFile` (rsyslog 8.2108 or later), so it never touches the main
    config's `global()`. The queue has `queue.timeoutEnqueue="0"`: once it's full, new messages for Woodshed are
    dropped at once, because by default each enqueue to a full queue waits 2 s and holds up all of rsyslog's logging.
    Retries start every 10 s and back off to once a minute at most (`action.resumeInterval="10"`,
    `action.resumeIntervalMax="60"`): rsyslog's default backs off to 30 minutes, and until a retry drains the full
    queue, new messages are dropped even with Woodshed back.
    No disk-assisted queue, to keep the snippet one file with nothing to clean up. **net-snmp:**
    `trap2sink`/`trapsess` in snmpd.conf (snmpd sends coldStart at start); for v3 a `createUser` line beside
    `trapsess -u … -l authPriv`, because snmpd sends traps as its own engine and, from 5.7, doesn't create that
    user from the `trapsess` passphrases ("USM unknown security name"); the test trap's secrets in
    `~/.snmp/snmp.conf` (mode 600) rather than the command line, and `rocommunity` (`rocommunity6` for IPv6) limited
    to Woodshed's address for polling. The poll snippet replaces the distribution's `agentaddress` line rather than
    adding one: snmpd joins every `agentaddress` line it reads.
68. **The page:** "Set up a device" at `#/device-setup`, **Connect** in the navigation (the existing **Setup** label
    stays the Welcome page, which now links to it). The mock answers from `web/src/lib/mock/setup-fixture.json`,
    which a Go test generates from the real templates, so it can't drift.
69. **Vendor-neutral:** the deny list (network, security and log-product vendors, their OS and product names, and
    desktop and server OS names) is in `internal/setuphelper/denylist_test.go` only. It runs over the templates, the
    families, every rendered snippet, the page and the docs' setup sections. **(owner, 2026-11-16)** no trademarked
    flow-protocol name anywhere in the setup helper: it says "flow v9 (RFC 3954)" and "IPFIX (RFC 7011)", the flow
    transports are `v9` and `ipfix`, and the deny list matches the name anywhere in a word, so an enum value built
    from it fails too. softflowd's own `-v 9|10` flags are unchanged.

**Flow times far from their arrival, decided (build, 2026-11-17)** (CI found IPFIX uptime times not wrapped, so
softflowd's records were stored 49.7 days in the future, where no search looked and nothing warned; the decoder is
fixed, §13.1.1, and this catches the class: a broken exporter clock or uptime, or a decoder bug of ours. **(owner)**
count and flag these records, never drop them):
70. **The check** (`internal/flow/timeoff.go`), at decode, on every record the collector emits (live and late-decoded;
    not the IPFIX file reader, decode-on-read or `reindex --flows-redecode`, which have no collector state):
    - **Ahead:** the record's end is more than **1 h** after its datagram arrived (a late-decoded record: its own
      datagram's arrival). A flow can't end after it was exported, so only a clock explains it, and 1 h is the header
      clock rule's limit (decision 21): a header up to an hour off is accepted, so records within it are left to that
      rule. The end is checked because it's never before the start.
    - **Behind:** the end is more than **24 h** before arrival. An exporter sends a flow within its inactive or active
      timeout of the last packet (seconds to an hour), so a day can't be a normal export whatever the timeouts, and
      the uptime faults this is for (a 32-bit wrap, a reset counter) are days off. The start isn't checked behind: a
      long-lived connection may start days earlier.
    - Records on received time (`time_source=received`, the header clock rule) are never counted: their end is their
      arrival.
    - **The record isn't changed:** stored, indexed and exported with its own times, `status` and `time_source` as
      decoded. Nothing is dropped.
71. **Counts per exporter:** ahead and behind, and the largest offset each way, by hour for 24 hours and by 5 minutes
    for the last hour (the banner's window; "the last hour" is the last 12 five-minute slots, 55 to 60 minutes). The
    rings are allocated on an exporter's first such record (about 1.4 KiB), so a normal exporter pays a pointer.
    Exposed as `/api/flows` `exporters[].time_offsets_24h` and `time_offsets_1h` (`ahead`, `behind`, `max_ahead_ms`,
    `max_behind_ms`), the pattern of `clock_skew_ms` there (syslog has no clock-skew count to follow), and in
    `woodshed flow status`.
72. **Surfacing:**
    - The **`flow_time`** banner (warn) for an exporter with at least **10** ahead or 10 behind in the last hour: "Flow
      records from 10.1.0.1 have times up to 49.7 days ahead of when they arrived: the exporter's clock or uptime is
      probably wrong. They're kept as sent, at their own times." Ten keeps one stray record (a cache entry left from a
      clock step) quiet, while a broken clock or uptime affects every record, so an exporter sending a record a minute
      still passes it within the hour. Offsets read as hours under two days, else days (`49.7 days` is the uptime
      wrap's signature). Several exporters share one banner, five named.
    - The device page's Flows card: a warning while the last hour passes the banner's count, and a "Times off arrival"
      row for the last 24 h. **Settings → Flows** shows the 24-hour count in the Clock column.
    - The bundle: the manifest summary's flow entry gains `time_offsets` (the window's own records) and
      `time_offsets_24h` (the collector's; `null` from `woodshed bundle`), and the README's Flows block a "times off
      arrival" line when either is non-zero (§13.4). The bundle preview shows the 24-hour part.
73. **Findability, flagged (not built):** these records are found by a flow-time window around their own times (the
    plan picks segments by `flow_segments`' flow-time range and blocks by theirs, decision 31; tested 49.7 days ahead
    and 30 h behind). They **can't** turn up in a search or a bundle for the time they arrived: flow queries and the
    bundle's flow files match on flow time only (decision 7), and there is no received-time match for flows (only
    `raw.txt` and a bundle's active devices use received bounds). The README line and the banner say so instead.
    - The smallest change that would fix it: a `time=received` choice for flow search, summary, top and export, which
      windows on the received column. The parts exist: segments by their `files` row's first and last received, blocks
      by their header's min and max received (§13.2), records by `received`, ordered by it; no format or index change.
      A bundle would then add, in a second pass, the window's records that arrived in it with flow times outside it.
      The cost is in the plan (decision 56): a second ordering and its own `complete_from` and cursor bound. Left for
      the owner to call.
    - A side cost, also left as is: a segment holding normal and far-off records has a flow-time range spanning the
      offset, so queries anywhere in that span plan it (a footer read; a mixed block is decoded). Bounded by the plan's
      batches (decision 56); it only happens while an exporter is broken.

**Flow v9 vendor-range field types, decided (build, 2026-11-17)** (the lab-prep agent's `woodshed run` found two bugs:
the IPFIX file wrote v9 types 32768–65535 with the enterprise bit but no enterprise number, `9c43 ffff 9c41 ffff …`,
so tshark decoded 190 garbage records of 2,000 and an independent reader stopped at the template; and `rule_id_ies`
couldn't name one, so v9 event runs never filled `rule_id`):
74. **The key:** a v9 vendor-range type is `{enterprise number 0, ID = the type}`, all 16 bits, everywhere: records,
    extras (`0:40003=…`), `rule_id_ies`, `/api/flows/templates`. An IANA IE never has the high bit, so `0:` with an
    ID above 32767 can only be a v9 type. This was already the decoder's and the generator's key (`loadgen.RuleIE`).
75. **In IPFIX (the export file and the generator's builder):** RFC 7011 §3.2 requires an enterprise number after the
    enterprise bit, so such a field is written as the enterprise bit, the type's low 15 bits and **enterprise number
    0**, at its own length like an enterprise IE (`9c43 0004 00000000` for type 40003, 4 bytes). The decoder reads
    enterprise bit + number 0 back as the v9 type (`flow.VendorRangePEN`), live and in the file reader, so the file
    round-trips every record and field. Options weighed:
    - IANA's documentation number (32473, RFC 5612), as the type's low 15 bits: valid, but a reader can't tell these
      fields from real 32473 IEs (`woodshed send`'s IPFIX run uses 32473:1–3), so the file wouldn't round-trip without
      a side table. Any registered number has the same problem and claims a field for an enterprise that didn't
      define it.
    - No enterprise bit (the low 15 bits as an IANA ID): no number needed, but it collides with the IANA registry.
    - Number 0: the registry's own reserved entry, never an exporter's, so it can't clash with a real enterprise IE;
      an RFC 7011 reader skips it by its length like any enterprise field it doesn't know (CI's tshark check, decision
      77, is the proof). Chosen.
    - A v9 run and an IPFIX run of the same flows (the generator's same seed) store and export the same columns and
      rule IDs, with run, sequence and rule fields at the same lengths (4, 8, 4), under `0:40001–40003` and
      `32473:1–3`.
76. **`rule_id_ies` syntax:** `"<enterprise number>:<element ID>"` as before (element ID 0–32767 with a non-zero
    number), and with number 0 an ID of 0–65535: `"0:40003"` names v9 type 40003. No separate `v9:` prefix: the
    templates list already shows the field as `0:40003`, and Settings → Flows offers **Use as rule ID** for it. The
    server, the form and the mock check the same.
77. **Tests and checks:** a strict RFC 7011 walker (independent of our decoder) reads every record of a v9 export with
    vendor fields; `ReadFile` gives back every record and field, `rule_id` included; in-process end to end, a v9
    `--events` run with `rule_id_ies = ["0:40003", "32473:3"]` fills `rule_id`, which filters, ranks in Top and fills
    the bundle's `flows.csv`; the CI job `flow-interop` runs it with tshark required (`TestFlowV9VendorRuleIDEndToEnd`:
    every record's 5-tuple equals the CSV, no malformed frames). Alongside: `woodshed flow status` validates the config
    as `run` and `reindex` do (exit 1 with the same message), and `woodshed search --help` lists `flow` under `-type`.

**IPFIX sequence conventions, decided (build, 2026-11-17)** (the 2.0.0-rc1 lab: an open-source exporter numbers each
message after counting its own data records, where RFC 7011 §3.1 counts the records sent before it. Its capture: 21
data + 1 options records carried 21, then 22, 21 and 20 data records carried 43, 64 and 84. Nothing was lost, but the
RFC check saw 64 as reordered and 84 as a gap of 19, so every export of more than one message added a false gap to
`flow status`, `/api/flows` and the bundle README):
78. **Learned per scope:** each IPFIX (exporter, port, observation domain) learns its convention from its own stream.
    Timing is `rfc` (`seq[n+1] = seq[n] + records[n]`) or `after` (`seq[n+1] = seq[n] + records[n+1]`), and,
    separately, whether options data records count (the capture's first message says they don't there: 21 data + 1
    options gave 21). A message whose counts and predecessor's are known is a vote for a side when only that side
    explains its number; 3 votes in a row decide it (messages of equal size tell timing nothing, so it may take a
    while). The same 3 in a row for the other side change a decided one (another exporter on that address).
    - **Gaps:** while a side is undecided, a jump is a gap only when neither side explains it (the smaller jump is
      the estimate); once decided, only the decided side explains, so a real loss always counts. A loss that happens
      to equal the difference between the two sides, before they're decided, is the one case missed.
    - **Behind the expected number:** a late (reordered) message is ignored, as before (the jump it left counts as a
      gap). Three messages behind in a row, each following the one before, are an exporter restart, so a restart to
      low numbers resyncs too (before, only a jump back of over 100,000 did); this applies to v5 and v9 as well.
    - A message with no records (templates only) shares its number with the next one and isn't a duplicate.
    - v5 and v9 don't learn: v5 counts records and v9 packets, as decision 23 says.
    - `/api/flows` shows the decided timing per domain as `seq_mode` (`"rfc"` or `"after"`, absent while undecided);
      `woodshed flow status` notes an `after` domain.

**Incomplete TCP frames, decided (build, 2026-11-17)** (a public report: "`50 <13>short` followed by EOF returned the
same nine-byte payload and truncated=false as `9 <13>short`". The reader returned what arrived of an octet-counted
frame as if it were complete, and the listener marked the last message truncated only when Woodshed itself had closed
the connection; present since 1.0):
79. **Keep the bytes, flag the frame.** An octet-counted frame that ends before its count is stored as far as it
    arrived and flagged incomplete with its arrived and advertised lengths, whatever ended it (§3.1). Options weighed:
    - Reuse `truncated`: it already means "cut at the max message size" in the counters, the stats buckets, the
      dashboard and the bundle's losses, so a sender's early close would read as our size limit, and a frame can be
      both (cut at 64 KiB of an advertised 100 KiB, 70 KiB arrived). Rejected: a distinct `incomplete` flag, and our own
      cuts (frame timeout, eviction, shutdown), which 1.0–1.3 counted as truncated, move to it.
    - Drop the partial frame: loses evidence, and the project never drops what arrived. Rejected.
    - **Where a reader sees it.** Before 2.0, `truncated` was only a counter: no stored line said a message was cut.
      Lines now end with a marker (§3.3). Options weighed: a prefix before the message (a 1.x reader would then parse
      no PRI, so severity and the fields break on downgrade), a sidecar or index column (the files are the source of
      truth and `reindex` rebuilds the index from them), and a suffix. The suffix keeps a 1.x reader's PRI, header and
      search working and only shows the marker as trailing text; ` \#` can't come from the escaping, so 2.0 readers
      find it exactly. Chosen. Search, context, the live tail, `woodshed search --json` and the UI show the flags
      (`truncated`, `incomplete`, `frame_arrived`, `frame_length`, absent when unset); text matching never sees the
      marker; exports and bundles copy lines as stored, so the marker travels with them.
    - **Counting.** Per stream listener since start (`/api/stats` `tcp_frames`: `incomplete`, `frame_timeouts`, also on
      About), not merged with the frame-timeout counter: a timeout is one of several causes. Incomplete messages aren't
      added to the per-device stats buckets (that would mean an index migration); the marked lines are the per-device
      record.
    - **Newline framing** can't tell a sender's last line without its LF from a cut one, so that line stays complete;
      only a line Woodshed cut is incomplete (no lengths).

### 13.11 Questions settled (2.0), decided (coordinator, 2026-11-16, owner-delegated)
1. **It's 2.0.** The owner's roadmap names it, and the new binary on-disk format and the retention-priority change
   justify a major version even with an additive API (§13.9).
2. **sFlow isn't in 2.0.** It's on the after-2.0 list as a candidate fifth type (§9).
3. **Firewall-event, NAT and bidirectional fields are first-class columns and filters** (§13.2.1), with the standard
   IANA IEs, event records on flow time, deny events in filters and Top, the CSV and README columns, and an
   event-style generator for CI and the lab (§13.8). There's no standard rule-ID IE; `rule_id` comes from an IE the
   user names.
4. **The flow budget** stays at 40 % of the cap by default, configurable (`storage.flow_budget_bytes`).
5. **The six setup families are enough for 2.0.** The CLI families stay **Reference only** until they're verified on
   gear the project is allowed to use, and the page says so next to each one: "Reference only: not tested on a
   device; check your device's documentation." Nothing is labelled **Tested** without a CI test that applies it, and
   the deny-list test also fails a template marked Tested that no CI test names.
6. **Flows are in bundles by default.** Before building, the bundle shows the per-type estimate and a **Leave flows
   out** option; the 20 million records per device cap applies. For a window over 4 h whose flows are estimated above
   1 GB, the UI pre-selects **Leave flows out** (the user can clear it).

## 14. Open questions
1. Where the repo lives. The answer given was the internal GHE, which conflicts with "open source on
   github.com" in §2 (see the reply of 2026-11-10).
2. Retention fairness: decided 2026-11-11 (fair shares, §3.4). An optional per-device cap or minimum
   days is still open.
3. macOS launchd daemon as `_woodshed` and the application-firewall prompt: test in M0 (see §5).
