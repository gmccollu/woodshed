# Lab tests on real VMs (release candidates)

CI proves the packages on GitHub-hosted runners over loopback (`scripts/smoke/`). This lab covers what CI can't
(SPEC §8.1, "still unproven"): traffic from other hosts through each OS's own firewall, many devices at once, a
real reboot, the 24 h soak, and rate steps on a 4-core / 8 GB VM.

Everything is driven by `scripts/lab/wl`. It knows no hostnames or addresses: they come from `scripts/lab/lab.env`
(gitignored; start from `lab.env.example`), and every host is an ssh alias in `LAB_SSH_CONFIG`.

## The setup

- **Targets:** one VM per package, each 4 vCPU / 8 GB / 60 GB or more: Ubuntu (deb), a RHEL-family Linux
  (rpm) and Windows Server (MSI). Each target's login is an administrator: on Linux, passwordless sudo; on
  Windows, OpenSSH Server with an administrator key.
- **Sender host:** a Linux machine on the targets' subnet. `wl setup-sender` gives it at least 8 network
  namespaces, each holding one ipvlan leg with its own address (`LAB_SENDER_IPS`). The targets therefore see
  8 devices on a real network, and every message crosses the target's NIC and host firewall. The legs share the
  host's MAC, which virtual switches that reject forged MACs accept. A namespace has no default route. All of
  this lives under `/opt/woodpile-lab` plus one unit (`woodpile-lab-senders.service`) and one sudoers drop-in.
  Nothing existing on the host changes.
- **Driver:** any machine that can ssh to the aliases. Results land in `LAB_RESULTS/<target>/`.

## Steps

```sh
# 0. Once: copy lab.env.example to lab.env and fill it in. Build the helper binaries
#    (verifyseq for linux and windows, and the linux sender):
scripts/lab/wl tools
# 1. On a machine with GitHub access: download the release candidate and check it against checksums.txt.
#    (Copy LAB_ASSETS to the driver if that's another machine.)
scripts/lab/wl fetch v0.1.0-rc.1
# 2. The sender namespaces. If the sender login can't sudo yet, wl prints the one root command to run there.
scripts/lab/wl setup-sender
scripts/lab/wl senders ubuntu          # each namespace has its address and pings the target
# 3. Per target (ubuntu, rhel, win): everything except the soak, about 30-40 min:
scripts/lab/wl all ubuntu
# 4. The soak, on every target at once. It runs on the sender and the VM, so the driver can sleep:
scripts/lab/wl soak ubuntu start       # then: soak ubuntu status, and after 24 h: soak ubuntu verify
```

## What each step checks

| Step | Checks |
|---|---|
| `install` | the package installs; the service runs as its unprivileged account (`woodshed`, or `NT SERVICE\Woodshed`) and holds UDP and TCP 514; `/healthz` answers. Linux also: only `CAP_NET_BIND_SERVICE`, and `rmem_max` raised to 32 MiB |
| `check` | the host firewall is on (wl turns it on if it's off, with SSH kept open; `LAB_FW_ENABLE=0` to skip). **Negative control:** with 514 closed, UDP and TCP from a sender don't arrive. Then wl opens it exactly as `docs/install.md` says (`ufw allow 514`, or the `firewall-cmd` line; on Windows the MSI's own rules) and checks that each of the 8 sender IPs reaches UDP and TCP 514 and gets its own device folder |
| `correctness` | `LAB_CORRECT_N` (100,000) messages, half UDP (4 senders), a quarter TCP-LF and a quarter TCP-octet (2 senders each), are on disk exactly once (`scripts/verifyseq`) |
| `stress` | UDP, then TCP, at each rate in `LAB_STRESS_UDP`/`_TCP` for `LAB_STRESS_SECS`, doubling past the list up to `LAB_STRESS_MAX` until the **knee**: the first step with any loss or duplicate, or where the senders fall more than 5% short. Each step records the sent and on-disk counts, loss %, the service's CPU (% of one core), peak RSS, and the kernel UDP drops (Linux) in `stress.jsonl`. Pass: 10,000 msg/s over UDP and TCP with no loss (SPEC §2) |
| `reboot` | a UDP stream runs across a reboot; the service comes back by itself as its account on 514; the run sent before the reboot (and the correctness run) are still complete; a new run after it is complete; the stream has no duplicates (its gap is the reboot window) |
| `portable` | (deb and MSI targets) the tarball or zip binary, run by hand from a folder on port `LAB_PORTABLE_PORT` with its own config and data, receives 10,000 messages from the 8 senders exactly once. On Windows it first records what happens with no firewall rule for that exe (expected: blocked), then adds a temporary allow rule. On Linux it runs unprivileged on the high port, with a temporary firewall opening |
| `soak` | `LAB_SOAK_RATE` (3,000) msg/s for `LAB_SOAK_HOURS` (24): senders 0-5 over UDP and 6-7 over TCP, as transient systemd units on the sender. On the VM, a systemd unit (Linux) or a SYSTEM scheduled task (Windows) samples RSS or working set, open fds or handles, and CPU every 60 s. `verify` (run after the senders finish) checks every message is on disk exactly once, that memory stays flat (median of the last tenth ≤ 1.5 × the second tenth + 20 MiB), and that fds or handles stay bounded |
| `collect` | the journal or Application event log, unit or service config, firewall rules, config, `woodshed status`, the data listing and the samples, pulled back as a tgz or zip |

Every check writes a `PASS`/`FAIL` line to `LAB_RESULTS/<target>/results.log`; each step's directory has its log,
the verifyseq JSON lines and the samples.

## Notes

- A run's messages are numbered (`woodshed send --run ID --first-seq S`). `wl-send` splits a run's count and rate
  evenly over the chosen namespaces, giving each a contiguous block of sequence numbers, so one `verifyseq -n N`
  checks the whole run whichever senders carried it.
- TCP sends to a closed port can wait minutes for a connect timeout, so the negative control bounds each sender
  (`--timeout`).
- The stress CPU figure is the service's CPU time over the step's sampling window, in % of one core (400% = all 4).
- On Windows, the hand-run exe is started as a scheduled task, because OpenSSH ends a session's child processes
  when it closes.
- `wl-send --proto tls --ca FILE` sends over TLS checking the server against a downloaded CA; `--proto trap` sends SNMP
  traps or informs (`--snmp-version`, `--inform`, `--user`, `--auth`, `--priv`, `--key-ext`). Communities and
  passphrases are only ever read by `woodshed send` from files (`--community-file`, `--auth-pass-file`,
  `--priv-pass-file`), which must be regular files under `/opt/woodpile-lab/stage/`. For informs the WLSEND line adds the
  answered and timed-out counts and the worst sender's round trips. Woodshed answers at most 100 informs a second per
  source address, so an inform step above 100/s per sender times out by design.
- `remote/labcheck.py` (Linux VMs, read-only): `secret-scan` (needles on stdin), `window` (an export or bundle zip
  against its window and the data dir) and `missing` (a run's missing numbers, mapped to send times).
  For the SNMP poller (1.3): `netdev` samples `/proc/net/dev` for one interface, `poll-rates` compares a poller's
  per-cycle bit and packet rates with those samples, `poll-cycles` reports cycle spacing, failures, restarts and rate
  continuity, `poll-size` the poll bytes per day (raw and gzipped), and `poll-csv` checks a bundle's `poll/` CSVs
  row by row against the poll lines (a data dir, or `woodshed search --type poll --json` output from any OS).
  `secret-scan` also reads inside zips. The polled agent is the distribution's net-snmp `snmpd`, configured by the
  lab's own tooling with that run's test secrets (never in this repo).
- `remote/linux-lab.sh` and `remote/win-lab.ps1` are the VM-side halves; `wl stage` copies them with verifyseq,
  the package and the portable binary.
