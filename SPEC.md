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
| Measured (M1, Apple M4 Pro) | 10k msg/s for 30 s over UDP, TCP-LF and TCP-octet: 300,000 sent, 300,000 on disk, 0 missing each. Zero loss up to 60k msg/s (UDP) and 100k (TCP) |

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
- Max message size is 64 KiB. Anything longer is truncated and counted (`truncated` counter), never dropped.
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
- Signing: none at first. Add an Apple Developer ID (notarization) and Windows signing (SignPath's free OSS
  program, or Azure Trusted Signing) before promoting it widely. Until then the README documents the
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
    Windows, the the 0600 service-account file on macOS (§11.9)), and otherwise kept in a file only the service account can read. 1.2's trap
    receiver settles how on each OS (§11.2.6): macOS uses the file, because the Keychain needs cgo.
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
- **NetFlow v5/v9 and IPFIX collector** (UDP 2055/4739, configurable): template handling per exporter and
  observation domain, compact columnar storage per device per hour, retention and the disk guard shared with
  syslog. Search by time, IPs, ports and protocol; simple top-talker and top-port views for a time window;
  windowed export (CSV or IPFIX file). No long-term flow analytics, baselining or anomaly detection.
- **The export zip covers every data type**: syslog, traps, polls and flows for the chosen devices and window, with
  one manifest.
- Device setup helper (generated logging, trap and flow-export config per vendor).

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
  the same bucket table.

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
  and a missing final LF at close kept as a message; `max_message_bytes` and `tcp_frame_timeout` as for TCP.
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
§11.8 so the owner can overrule any of them. The API contract is in `docs/api.md` → "1.2 (planned)".

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
  keys (user name, engine ID, security level and the raw bytes), never decrypted guesses. Each failure is also
  counted per sender in `GET /api/snmp/failures`, like TLS handshake failures, so "the device sends but nothing
  shows" is diagnosable.

#### 11.2.3 Informs and engine IDs
**Woodshed answers informs (`answer_informs = true`).** An unanswered inform is retransmitted (so it's stored several
times) and the device logs the receiver as failing, sometimes raising an alarm of its own. A Response is what the
protocol requires, and it is the answer to an inbound request on the same socket, not an outbound connection
Woodshed starts (SECURITY.md is unchanged).
- The reply goes only to a sender that passed admission (allowlist, blocklist, device limits), and only after the
  inform is in the store's write buffer: it's sent by the queue's drainer (§11.5), so a full queue drops the inform
  unanswered and the sender's retry is the backpressure. An inform is never acknowledged and then lost by Woodshed.
- Replies are rate-limited (100 a second per source address, 1,000 a second in all; the excess are dropped and
  counted) so a spoofed source can't use Woodshed to reflect traffic at someone. The Response is no larger than the
  inform, so there's no amplification.
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
  recently used out), and at most 20 new localizations run a second, so spoofed engine IDs can't burn the CPU.

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

**MIB folder:** `mib_dir` holds MIB files (`*.mib`, `*.my`, `*.txt`), read at start and on **Reload MIBs**.
- Woodshed reads only what naming needs: `OBJECT IDENTIFIER` assignments, `OBJECT-TYPE`, `NOTIFICATION-TYPE`,
  `TRAP-TYPE`, `MODULE-IDENTITY`, `OBJECT-IDENTITY`, `IMPORTS`, and `INTEGER { name(n), … }` enumerations, including
  those of `TEXTUAL-CONVENTION`s in the same set. It isn't a MIB compiler: no type checking, no tables, no syntax
  beyond that.
- A small built-in set needs no files: the standard notifications (coldStart, warmStart, linkDown, linkUp,
  authenticationFailure), sysUpTime, snmpTrapOID, snmpTrapEnterprise and the IF-MIB interface columns.
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
  type has its own folder (`traps/` in 1.2; `polls/` in 1.3, `flows/` in 2.0). The manifest lists each folder's type.
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
    Gaps         none (Woodshed and its listeners were up the whole window)
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
  only reads a datagram, stamps the received time, applies the allowlist and blocklist, and enqueues; it never calls
  the store, parses, or touches the disk.
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

## 12. Open questions
1. Where the repo lives. The answer given was the internal GHE, which conflicts with "open source on
   github.com" in §2 (see the reply of 2026-11-10).
2. Retention fairness: decided 2026-11-11 (fair shares, §3.4). An optional per-device cap or minimum
   days is still open.
3. macOS launchd daemon as `_woodshed` and the application-firewall prompt: test in M0 (see §5).
