# Woodshed

A syslog server for Windows, macOS and Linux. Install it, point your devices at it, and it keeps every message as
plain text files (one folder per device, one file per day) within a disk budget. There's a web UI to watch the live
tail, search, and export a zip for whoever needs the logs.

![demo](docs/demo.gif)

## Why

I work escalations for network gear. A lot of the cases that drag on are the ones where nobody has the logs. The
outage happened, the device rebooted or its buffer rolled over, and there was no syslog server, or there was one
that quietly dropped messages and nobody knew. Without logs from the window that matters, you're left asking the
customer to wait for it to happen again.

Setting up a syslog server properly is easy if you live in Linux. It isn't if you're a small shop with one Windows
box, or someone on site with a laptop who needs logs off a device in the next 10 minutes. Woodshed is what I wanted to
hand those people: download it, run it, point the device at it. It doesn't fill the disk, it counts and shows what it
drops instead of hiding it, and the export zip carries checksums and the times Woodshed wasn't running, so whoever
reads it knows what they're looking at.

What it isn't: a SIEM. No correlation, alerting or forwarding (alerts and forwarding are planned after 1.0). If you already run a log platform you're happy with, you probably don't need this. How it compares:
[Why not tcpdump, rsyslog, syslog-ng or Graylog?](FAQ.md#why-not-tcpdump-rsyslog-syslog-ng-or-graylog)

## Download

[Releases page](https://github.com/gmccollu/woodshed/releases): MSI for Windows (x64, ARM64), a universal pkg
for macOS, deb and rpm for Linux (amd64, arm64), or a portable zip/tarball that runs with nothing installed.

[`releases/latest`](https://github.com/gmccollu/woodshed/releases/latest) is always the newest stable release. File
names carry the version, so a direct link looks like
`https://github.com/gmccollu/woodshed/releases/download/v1.0.0/woodshed_1.0.0_amd64.deb`.

The installers and binaries aren't code-signed yet, so Windows SmartScreen and macOS Gatekeeper will ask once
before running them ("Windows protected your PC" → More info → Run anyway; on macOS, System Settings → Privacy &
Security → Open Anyway). Every release has `checksums.txt`, and from 1.0.0 you can check a file's build provenance
with `gh attestation verify FILE --repo gmccollu/woodshed`. More in the
[FAQ](FAQ.md#windows-or-macos-warns-me-about-the-download).

## Quick start

1. Install it (or unpack the portable download and run `woodshed`). On Linux, portable mode needs `sudo` for port 514.
2. Open <http://localhost:8514/>. The Setup page lists this machine's addresses and whether it's listening.
3. On the device, set the syslog server to one of those addresses, port 514, UDP or TCP. The Setup page tells you
   when the first message arrives.

If nothing shows up, see [Devices can't reach Woodshed](FAQ.md#devices-cant-reach-woodshed). The Linux packages don't
open the firewall for you.

The [user guide](docs/user-guide.md) goes from install to a support zip. Also: [FAQ](FAQ.md),
[docs/install.md](docs/install.md) (every installer in detail), [CHANGELOG.md](CHANGELOG.md), [SPEC.md](SPEC.md) (the
design), [docs/api.md](docs/api.md) (the UI's API), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md).

## How it's tested

- Every release runs `woodshed bench` for 10 minutes at 10,000 msg/s over UDP on a GitHub-hosted runner (4 vCPU,
  15 GiB) and puts the result in the release notes. Every release so far: 6,000,000 sent, 6,000,000 stored, 0 missing,
  0 duplicates.
- On Linux lab VMs (Ubuntu 24.04 with the deb, AlmaLinux 9 with the rpm, 4 vCPU / 8 GB) over a real network, from 8
  senders: 0 loss over TCP at every step up to 40,000 msg/s, at about a third of one core and under 50 MiB of memory.
  UDP was 0 loss up to 40,000 msg/s on Ubuntu and 20,000 on Alma. Where UDP did lose messages (40k on Alma, 80k on
  Ubuntu), diagnostic runs with the VM's interface counters showed the loss was before the VM's NIC: every datagram
  that reached the VM was stored.
- A reboot mid-stream: the service came back on its own, 2 UDP messages were lost around the shutdown, and the export
  showed the 17-19 second gap as "Woodshed wasn't running".
- 24 h soaks at 3,000 msg/s on both lab VMs: [soak results].
- CI runs the tests on Windows, macOS and Linux, plus arm64 Linux and Windows on Arm. Install tests build the MSI,
  pkg, deb and rpm and install, upgrade and uninstall them on each OS (arm64 included), and run portable mode too.
- Before the first release candidate the code had a separate security review: no critical findings, one high (memory
  exhaustion from spoofed source addresses) and seven medium. All were fixed and re-tested twice. What's still open is
  below.

## Known issues

As of 1.1.0 (details in the [CHANGELOG](CHANGELOG.md)):

- The installers aren't code-signed yet, so Windows SmartScreen and macOS Gatekeeper ask once.
- On Windows and macOS the OS doesn't expose kernel UDP drops, so the UI says that instead of showing 0.
- On non-English Windows the "TLS firewall rule is off" banner doesn't appear; `woodshed tls on` still turns the rule on.

## Features

- Listens on UDP and TCP port 514 straight away, no setup. TCP framing (octet counting or newline) is detected per
  message. RFC 5424, RFC 3164 and the usual non-compliant variants are parsed leniently, and the raw message is always
  stored exactly as received.
- Optional syslog over TLS (TCP 6514) with its own CA, so devices import one certificate that renewals don't change.
- Plain files: one folder per device and one file per day (`logs/<ip>/<day>.log`), gzipped once closed. Read them
  with grep, an editor or any log tool.
- Doesn't fill the disk: retention by age and total size (30 days / 20 GiB by default), plus a low-disk guard. Every
  deletion is recorded and shown in Settings.
- Dropped, truncated and refused messages are counted and shown. Where the OS hides kernel UDP drops (Windows,
  macOS), the UI says so instead of showing 0.
- Web UI: a dashboard with the message rate, device tiles and a live tail with server-side filters; an Events page to
  browse and filter all stored history (text or regex, program/tag, host, exclude, devices, time, severity); a
  devices page to rename, group or hide senders; settings that apply without a restart; light and dark modes.
- `woodshed search` searches the stored logs from a terminal with the same filters as Events, compressed days
  included, on every OS (natively on Windows, no WSL). It only reads, so it's safe beside the running service.
- The UI listens on `127.0.0.1:8514` only by default. LAN mode serves HTTPS with a password.
- No telemetry. The only outbound connection is an optional daily update check, off until you turn it on: it
  fetches one public file (`https://gmccollu.github.io/woodshed/releases.json`), sends nothing about your
  installation, and never downloads or installs anything.
- If port 514 is taken, the UI still starts and shows which program holds the port, with a Retry button.
- One binary, one service, with the UI embedded. The installers set it up as a system service.

## Running portable or as a service

Portable, nothing installed: download the archive for your system, unpack it and double-click `woodshed` (or run
`./woodshed`). It listens on UDP and TCP 514, keeps its logs in `woodshed-data/` next to it, and opens the UI. On Linux,
port 514 needs `sudo ./woodshed` (or `sudo setcap cap_net_bind_service=+ep ./woodshed` once). See
[Portable mode](docs/install.md#portable-mode-no-install).

As a service: use the installer for your system ([docs/install.md](docs/install.md)).

## Building from source

You need Go (see `go.mod`) and Node.js with npm for the UI.

```sh
# Build the UI and the binary (into dist/woodshed)
make build
```

Run it in the foreground with its own folder. Port 514 needs administrator rights on Linux and is often taken by
the OS's own syslog daemon, so this example uses a high port; the default config listens on 514.

```sh
mkdir -p ./mysyslog
cat > ./mysyslog/woodshed.toml <<'EOF'
[listeners.udp]
enabled = true
addr = "127.0.0.1"
port = 15514

[listeners.tcp]
enabled = true
addr = "127.0.0.1"
port = 15514
EOF
./dist/woodshed run --config ./mysyslog/woodshed.toml
```

In another terminal, send a test message and check the listeners:

```sh
./dist/woodshed send --port 15514 --message "hello from woodshed"
./dist/woodshed status --config ./mysyslog/woodshed.toml
```

Then open <http://localhost:8514/>. The message is also on disk, in
`./mysyslog/woodshed-data/logs/127.0.0.1/<date>.log` (files are named by the UTC date).

Settings missing from the file take their defaults, and a config file that doesn't exist yet is created with
them; either way the data folder is `woodshed-data` next to the config. Stop the server with Ctrl-C: it writes
everything to disk first.

## Commands

| Command | What it does |
|---|---|
| `woodshed` / `woodshed portable [--dir DIR]` | Portable mode: run here with nothing installed, data in `woodshed-data/` |
| `woodshed run [--config FILE]` | Run the server in the foreground |
| `woodshed install` / `uninstall` | Install or remove the system service where no installer package was used (needs administrator rights) |
| `woodshed status` | The service's state, the listeners and the UI address |
| `woodshed reindex` | Rebuild the index from the log files (with the server stopped) |
| `woodshed set-password [--stdin]` | Set the UI password from the shell, for servers without a browser (run as administrator) |
| `woodshed lan-mode on\|off [--port N]` | Turn LAN mode on or off from the shell; prints the addresses and the certificate's SHA-256 (run as administrator) |
| `woodshed reset-password` | Forgot the UI password: remove it and turn LAN mode off (run as administrator) |
| `woodshed send` | Send numbered test messages to any syslog server |
| `woodshed bench` | Measure sustained throughput on a temporary in-process server |
| `woodshed version` | Print the version |

`woodshed <command> --help` shows each command's flags.

## Development

```sh
make test              # go vet + go test -race, including the end-to-end test of the real binary
go test -short ./...   # everything except the end-to-end test
cd web && npm run dev:mock   # the UI against mock data
```

## License

MIT. See [LICENSE](LICENSE).
