# Changelog

All notable changes to Woodshed. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/). Release notes on GitHub are taken from this file
(`scripts/release-notes.sh`), so set a section's date before tagging it.

## [1.2.0] - unreleased

### Added
- `woodshed search` searches the stored logs from the command line with the Events engine: the same text, Terms and
  Regex modes and every filter (devices, groups, severities, facilities, programs/tags, hosts, their exclusions, and
  `--field KEY=V` / `--not-field KEY=V` for any field), compressed days included. Output is the stored lines, the
  messages alone (`--raw`), NDJSON (`--json`), lines around each match (`--context N`) or a count, with a summary on
  standard error and grep-style exit codes. It reads the data folder directly and never writes to it, so it works
  beside the running service, with the UI off, or with the service stopped. See
  [docs/user-guide.md](docs/user-guide.md#searching-from-the-command-line).

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
