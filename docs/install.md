# Installing Woodshed

Woodshed is one program that runs as a background service. Every installer sets up the service, starts it, and
leaves it listening for syslog on **UDP and TCP port 514**. The web UI is at **http://127.0.0.1:8514/** on the same
machine (localhost only until you turn on LAN mode in Settings).

> **Before you send a firewall's logs over TCP or TLS:** some firewalls block traffic through themselves while their
> TCP or TLS syslog server is unreachable (Woodshed stopped, its computer restarting, the path to it down), or its
> certificate fails, unless an option such as "permit traffic when the log host is down" is set. Check that option on
> the firewall before you choose TCP or TLS. UDP has no such risk: the firewall keeps passing traffic whether or not
> anything receives its logs.

## Portable mode: no install

To spin up a syslog server on the spot (for a case, a lab, a laptop), download the program for your system (the
`.zip`/`.tar.gz` archive), unpack it and **double-click `woodshed`** (`woodshed.exe` on Windows), or run `./woodshed`
in a terminal. Nothing is installed. A window shows:

```
Woodshed 1.0.0, portable mode
  Data folder:  /home/me/Downloads/woodshed/woodshed-data
  Listening on UDP 514 and TCP 514
  Send logs to: 192.0.2.10, 2001:db8::10
  Web UI:       http://localhost:8514/

Press Ctrl-C or close this window to stop. Your logs stay in /home/me/Downloads/woodshed/woodshed-data
```

and the UI opens in your browser. Point devices at one of the addresses shown; each new device gets a line in the
window. Ctrl-C, closing the window, logging off or shutting down all save everything first.

- **Data:** `woodshed-data/` next to the program. If that folder can't be written (read-only media, Program Files,
  macOS running a downloaded copy from a temporary location), it uses `~/Woodshed` (`%USERPROFILE%\Woodshed`) and
  says so. Move or zip the folder to hand the logs to someone; it works wherever it ends up.
- **Port 514 on Linux** needs rights: run `sudo ./woodshed`, or once `sudo setcap cap_net_bind_service=+ep ./woodshed`
  and then `./woodshed` as yourself. macOS and Windows need nothing. If another syslog server already has the port,
  the window and the UI say which program; stop it and press **Retry** in the UI. The syslog port never moves on its
  own.
- **The UI port:** if 8514 is taken (for example by an installed Woodshed), it uses the next free one up to 8530 and
  prints it.
- **Windows firewall:** the first time, Windows asks whether to allow Woodshed; choose **Allow** so devices can reach
  it (it may need an administrator). The window prints the `netsh` command for an administrator if no rule allows it.
- **Options:** `woodshed portable --dir FOLDER` keeps the data elsewhere; `--port`, `--listen`, `--ui-port` and
  `--no-browser` are there too (`woodshed portable --help`). Running a second copy on the same folder is refused,
  with the address of the one already running.
- **For always-on use, install the service** (below).

## Installers

Download the installer for your system from the project's releases page. Replace `X.Y.Z` below with the version.

**Download links before 1.0:** every release so far is a prerelease, and GitHub's "latest" URLs
(`/releases/latest`, `/releases/latest/download/<file>` and the API's `/releases/latest`) skip prereleases, so they
return 404. Use the [releases page](https://github.com/gmccollu/woodshed/releases), or a tagged URL in scripts:

```sh
curl -fLO https://github.com/gmccollu/woodshed/releases/download/v1.0.0/woodshed_1.0.0_amd64.deb
# pattern: https://github.com/gmccollu/woodshed/releases/download/v<version>/<file>
```

From 1.0.0, `https://github.com/gmccollu/woodshed/releases/latest` works as usual.

| System | File |
|---|---|
| Windows 10/11, Server 2016+ (x64, ARM64) | `woodshed_X.Y.Z_windows_amd64.msi` / `..._arm64.msi` |
| macOS 13 or later (Apple silicon and Intel) | `woodshed_X.Y.Z_macos_universal.pkg` |
| Debian, Ubuntu | `woodshed_X.Y.Z_amd64.deb` / `..._arm64.deb` |
| Fedora, RHEL, Rocky, Alma, openSUSE | `woodshed-X.Y.Z-1.x86_64.rpm` / `...aarch64.rpm` |
| Any Linux, or no service | `woodshed_X.Y.Z_linux_amd64.tar.gz` (and `_arm64`, `_darwin_universal`, `_windows_*.zip`) |

To check a download, compare it with `checksums.txt` from the same release:
`sha256sum -c --ignore-missing checksums.txt` (Linux), `shasum -a 256 -c --ignore-missing checksums.txt` (macOS), or
`Get-FileHash woodshed_X.Y.Z_windows_amd64.msi` (PowerShell).

## Where things live

| | Windows | macOS | Linux |
|---|---|---|---|
| Program | `C:\Program Files\Woodshed\woodshed.exe` (added to `PATH`) | `/usr/local/bin/woodshed` | `/usr/bin/woodshed` |
| Config | `C:\ProgramData\Woodshed\woodshed.toml` | `/Library/Application Support/Woodshed/woodshed.toml` | `/etc/woodshed/woodshed.toml` |
| Logs received | `C:\ProgramData\Woodshed\logs\` | `/Library/Application Support/Woodshed/logs/` | `/var/lib/woodshed/logs/` |
| Woodshed's own log | Event Viewer → Windows Logs → Application | `/Library/Logs/Woodshed/woodshed.log` | `journalctl -u woodshed` |
| Service | `Woodshed` (runs as `NT SERVICE\Woodshed`) | launchd `com.woodshed.daemon` (runs as `_woodshed`) | systemd `woodshed.service` (runs as `woodshed`) |

The config file is created with defaults the first time the service starts. Received logs are plain text, one
folder per device and one file per day (older days are gzipped). The data folder is readable only by the service
account and administrators, so open it as an administrator (Windows) or with `sudo` (macOS, Linux).

Upgrades keep the config and data. Uninstalling keeps them too unless you ask for them to be deleted (below).

## Moving from Woodpile

The release candidates were called Woodpile. Install Woodshed the usual way and it replaces them: the MSI upgrades
over the Woodpile MSI, the deb and rpm remove the `woodpile` package (and print "stopped and disabled the old
Woodpile service" when it was running), and the pkg stops the Woodpile daemon and removes its program and app.
`woodshed install` (no package) instead refuses while a Woodpile service is still there, and prints the command that
removes it.

The Woodpile data isn't moved: Woodshed starts with an empty data folder and default settings. The installer and
`woodshed status` say where the old folder is. Keep it as long as you need the logs, then delete it, and the old
service account with it:

| | Delete the Woodpile data |
|---|---|
| Linux | `sudo rm -rf /var/lib/woodpile /etc/woodpile && sudo userdel woodpile` |
| macOS | `sudo rm -rf "/Library/Application Support/Woodpile" /Library/Logs/Woodpile && sudo dscl . -delete /Users/_woodpile && sudo dscl . -delete /Groups/_woodpile` |
| Windows | delete `C:\ProgramData\Woodpile` from an administrator prompt: `Remove-Item -Recurse -Force C:\ProgramData\Woodpile` |

## Windows

**Install:** double-click the MSI and approve the administrator prompt. Or, silently from an elevated prompt:

```powershell
msiexec /i woodshed_X.Y.Z_windows_amd64.msi /qn
msiexec /i woodshed_X.Y.Z_windows_amd64.msi /qn WOODSHED_UPDATE_CHECK=off   # decide the update check too
```

The installer:
- installs the `Woodshed` service (automatic start, restarted if it fails) running as the virtual account
  `NT SERVICE\Woodshed`, which can write only to `C:\ProgramData\Woodshed`;
- adds Windows Firewall rules for woodshed.exe on UDP 514 and TCP 514 only. The UI port isn't opened. It also adds
  **Woodshed syslog (TLS 6514)** for syslog over TLS, turned off until `woodshed tls on` (see
  [TLS syslog](#tls-syslog-firewall-and-certificate)), and **Woodshed flows (UDP 2055)** and **Woodshed flows
  (UDP 4739)** for flows (v5, v9) and IPFIX, turned off until `woodshed flow on` (see [Flows](#flows-firewall));
- resets the ACL of `C:\ProgramData\Woodshed` and everything already in it (owner Administrators; links inside are
  removed), and keeps only `SeChangeNotifyPrivilege` in the service's token;
- adds a Start menu shortcut, **Woodshed**, that opens the UI.

**Firewall profiles:** the two rules (**Woodshed syslog (UDP 514)** and **Woodshed syslog (TCP 514)**) apply to all
network profiles, **Public included**, because devices often sit on a network Windows calls Public only because
nobody told it otherwise, and they'd be silently blocked. To allow syslog only on Domain and Private networks
(administrator PowerShell; repeat after an upgrade or repair, which re-creates the UDP and TCP rules; the TLS rule
keeps its settings):

```powershell
Get-NetFirewallRule -DisplayName "Woodshed syslog (*)" | Set-NetFirewallRule -Profile Domain,Private
```

**Upgrade:** run the newer MSI. It replaces the old version and restarts the service; the config and logs stay.

**Uninstall:** Settings → Apps → Woodshed → Uninstall. This removes the program, service and firewall rules and
**keeps** `C:\ProgramData\Woodshed`. To delete the logs and config as well:

```powershell
msiexec /x woodshed_X.Y.Z_windows_amd64.msi DELETE_LOGS=1
```

or delete `C:\ProgramData\Woodshed` yourself after uninstalling.

**SmartScreen (while installers are unsigned):** the browser may say the file "isn't commonly downloaded"; choose
**Keep**. When you open it, Windows may show "Windows protected your PC"; choose **More info → Run anyway**. Signed
installers will remove both prompts.

**Scoop** (not published yet; program only, no service): `scoop bucket add woodshed https://github.com/gmccollu/scoop-bucket`, then
`scoop install woodshed`, and run `woodshed run` in a terminal.

## macOS

**Install:** double-click the `.pkg` and follow the installer (it needs an administrator password). When it
finishes, the welcome page opens in your browser. From a terminal instead:

```sh
sudo installer -pkg woodshed_X.Y.Z_macos_universal.pkg -target /
```

To decide the update check for a silent install, see [The update check on many machines](#the-update-check-on-many-machines).

The installer:
- creates a hidden system user and group, `_woodshed`, that the service runs as;
- installs `/usr/local/bin/woodshed` (one binary for Apple silicon and Intel) and the launchd daemon
  `/Library/LaunchDaemons/com.woodshed.daemon.plist`, which starts at boot and is restarted if it stops;
- creates `/Library/Application Support/Woodshed` and `/Library/Logs/Woodshed`, owned by `_woodshed`.

**Upgrade:** install the newer `.pkg`. The daemon is stopped, replaced and started again; the config and logs stay.

**Uninstall:**

```sh
sudo /usr/local/share/woodshed/uninstall.sh                # keeps the logs and config
sudo /usr/local/share/woodshed/uninstall.sh --delete-logs  # also deletes them and the _woodshed user
```

**Gatekeeper (while the installer is unsigned and not notarized):** macOS says the package "can't be opened"
because Apple can't check it. Click **Done**, open **System Settings → Privacy & Security**, scroll to the message
about the Woodshed package and click **Open Anyway**, then confirm. (On current macOS, Control-click → Open no longer
skips this.) The `sudo installer` command above doesn't show the prompt.

**macOS firewall:** if the application firewall is on (System Settings → Network → Firewall), allow incoming
connections for `/usr/local/bin/woodshed` there (Options… → +) if devices can't reach port 514.

**Homebrew** (not published yet; program only, no service): `brew install --cask gmccollu/tap/woodshed`, then `woodshed run`.

## Linux (deb and rpm)

**Install:**

```sh
sudo apt install ./woodshed_X.Y.Z_amd64.deb        # Debian, Ubuntu
sudo dnf install ./woodshed-X.Y.Z-1.x86_64.rpm     # Fedora, RHEL and derivatives
sudo zypper install ./woodshed-X.Y.Z-1.x86_64.rpm  # openSUSE
sudo WOODSHED_UPDATE_CHECK=off apt install ./woodshed_X.Y.Z_amd64.deb   # and decide the update check
```

The package:
- creates the `woodshed` system user and group (no login, no home);
- installs `woodshed.service`, which runs as `woodshed` with only `CAP_NET_BIND_SERVICE` (for port 514), a
  read-only view of the system, and write access to `/var/lib/woodshed` and `/etc/woodshed` only;
- installs `/etc/sysctl.d/60-woodshed.conf`, raising `net.core.rmem_max` to 32 MiB so Woodshed can get the UDP
  receive buffer it asks for, and applies it straight away;
- enables and starts the service, and prints the UI address.

The package doesn't change the host firewall. If one is on, open port 514:

```sh
sudo ufw allow 514                                                  # Ubuntu (ufw)
sudo firewall-cmd --permanent --add-port=514/udp --add-port=514/tcp && sudo firewall-cmd --reload  # firewalld
```

**Upgrade:** install the newer package the same way. The service is restarted (if it was running) and the
config and logs stay.

**Uninstall:**

```sh
sudo apt remove woodshed    # keeps /var/lib/woodshed and /etc/woodshed
sudo apt purge woodshed     # also deletes them
sudo dnf remove woodshed    # keeps them; delete the two folders by hand if you want them gone
```

Removing the package stops and disables the service and deletes the sysctl drop-in. The raised `rmem_max` stays
in effect until the next reboot. The `woodshed` user is left in place, as distribution policy recommends; remove
it with `sudo userdel woodshed` if you want.

**Tarball (no package manager):** unpack it and either run `./woodshed run` in a terminal, or install it as a
service with `sudo ./woodshed install` (see [Without a package](#without-a-package-woodshed-install)).

**Known-good platforms** (reported by users, beyond what CI tests): Debian 13 unprivileged LXC on Proxmox VE 9.2:
works with the deb.

## Containers (LXC, Docker, Kubernetes)

**LXC (Proxmox and others):** the deb and rpm work in an unprivileged system container. The service runs under the
container's systemd as `woodshed` with only `CAP_NET_BIND_SERVICE`, and binding port 514 works. On a headless
container, set the UI password and turn on LAN mode from the shell: see
[Headless setup](#headless-setup-no-browser-on-the-machine) (`woodshed set-password`, `woodshed lan-mode on`).

**The UDP receive buffer is the host's setting.** `net.core.rmem_max` isn't per-container: from inside an
unprivileged container it can't be raised, so the package's `/etc/sysctl.d/60-woodshed.conf` has no effect there
(the install prints a one-line note saying so). Woodshed then gets a smaller UDP buffer than it asks for (32 MiB),
logs a warning at start, and the UI shows a warning banner with both sizes and this fix: bursts of messages may be
dropped by the kernel before Woodshed sees them. Fix it **on the host** (the Proxmox node, the Docker host, the
Kubernetes node), as root:

```sh
sysctl -w net.core.rmem_max=33554432
echo 'net.core.rmem_max = 33554432' > /etc/sysctl.d/60-woodshed.conf   # keeps it across reboots
```

Then restart Woodshed in the container (`systemctl restart woodshed`) so it asks again; the banner goes away.

**Docker:** there's no official image yet. If you build one, mind three things:
- the device's address is its identity, so senders must reach Woodshed with their own source IP: publish 514
  with Docker's default NAT (`-p 514:514/udp -p 514:514/tcp`, which keeps it) or use `--network host`, not a
  proxy that rewrites the source;
- the UI listens on `127.0.0.1` inside the container until LAN mode is on, so a published 8514 can't reach it: use
  `--network host`, or turn on LAN mode (HTTPS with a password) and publish 8514;
- keep the data folder on a volume, and run one container per data folder (a second Woodshed on the same folder
  refuses to start). Without systemd, run `woodshed run --config /etc/woodshed/woodshed.toml` as the command.

**Kubernetes:** the same, plus: a `LoadBalancer` or `NodePort` Service for UDP 514 needs
`externalTrafficPolicy: Local`, or every device shows up under the node's address (the default policy rewrites the
source IP); `hostNetwork: true` avoids that too. One replica per volume, and `rmem_max` set on the nodes.

## TLS syslog: firewall and certificate

Syslog over TLS (TCP 6514) is off until you turn it on in **Settings → Listeners → Syslog over TLS**, or with
`woodshed tls on` as an administrator. How to point a device at it is in the
[user guide](user-guide.md#sending-syslog-over-tls). The commands, all as an administrator (`sudo` on Linux and
macOS); like `lan-mode`, they edit the config and restart a running service:

```sh
woodshed tls on [--port 6514]   # turn the listener on (and open the firewall, below)
woodshed tls off                # turn it off and undo the firewall change; the certificate is kept
woodshed tls renew              # a new certificate, signed by the same CA: devices need nothing
woodshed tls renew --new-ca     # a new CA too: every device must import it again
woodshed tls status             # the listener, the fingerprints, the expiry and the last failures
```

**The firewall, per OS** (the service's own account can't change the firewall, and shouldn't be able to):
- **Windows:** the MSI and `woodshed install` add the rule **Woodshed syslog (TLS 6514)** (TCP 6514 for
  woodshed.exe, every profile), turned off. `woodshed tls on` turns it on (on `listeners.tls.port`), and `woodshed tls
  off` turns it off. Upgrades and repairs keep its state, and uninstalling removes it. Turning TLS on in Settings
  doesn't touch the rule: while it's off, missing or on another port, a banner gives the command to run in an
  administrator prompt. A portable copy has no rule: if you chose Allow at Windows' first-run prompt, it covers every
  port.
- **macOS:** the application firewall allows or blocks the program, not ports, so if Woodshed already receives on
  514, 6514 works too. `tls on` and `off` change only the listener.
- **Linux:** the packages add nothing, as for 514. `woodshed tls on` opens the port where it finds an active
  firewall it knows: `ufw allow 6514/tcp` when ufw is active, or `firewall-cmd --permanent --add-port=6514/tcp` and a
  reload when firewalld is running (the default zone). It records what it added in `tls-firewall.json` in the data
  folder, and `woodshed tls off` removes only that. With neither active (your own nftables or iptables rules, say),
  it changes nothing and prints the commands; allow inbound TCP 6514 yourself. Settings shows the same commands under
  "If devices can't connect".

**The certificate:** the first time TLS is turned on, Woodshed makes its own small CA and a server certificate signed
by it, in the data folder (mode 0600). Devices import the **CA**, so a renewed server certificate needs no change on
any device. Both are RSA-2048 and end no later than 2037-12-31 (the server certificate lasts 10 years, or until then),
because some older devices can't handle dates after early 2038. Nothing renews on its own: Woodshed warns 60 days
before the certificate or the CA expires, and when the computer has a DNS name the certificate doesn't cover (after
a rename, say); then use **Renew** (or `woodshed tls renew`). **Replace CA** (`woodshed tls renew --new-ca`) is for
when the CA must change, for example if the data folder was copied somewhere it shouldn't be: every device must
import the new CA certificate before it can connect again. Each renewal is in the event log (and an export's
`woodshed-events.log`) with the old and new fingerprints.

To use your own certificate instead, set `cert_file` and `key_file` under `[listeners.tls]` (absolute paths to PEM
files: the certificate, then any chain, and its key). It must allow server authentication (EKU serverAuth) and use an
RSA (2048 bits or more) or ECDSA key. Woodshed re-reads the files on every Settings save and on **Retry**, shows their
fingerprint and expiry, and warns before they expire; there's no CA download (get the CA from whoever issued the
certificate).

## SNMP traps: firewall

The SNMP trap receiver (UDP 162) is off until you turn it on in **Settings → SNMP traps**, or with `woodshed snmp on`
as an administrator. A 1.1 upgrade leaves it off. How to point devices at it, and the v3 users and communities, are in
the [user guide](user-guide.md#receiving-snmp-traps). The commands, all as an administrator (`sudo` on Linux and
macOS); like `woodshed tls`, they edit the config and restart a running service:

```sh
woodshed snmp on [--port 162]   # turn the receiver on (and open the firewall, below)
woodshed snmp off               # turn it off and undo the firewall change; users and stored traps are kept
woodshed snmp status            # the listener, the engine ID, the last 24 h counts and the senders with failures
```

v3 users and the v1/v2c community list are set only in Settings (or the API), never on a command line, where a
passphrase would show in the process list.

Port 162 needs the same privileges as 514, which the service has. On macOS, a specific address below 1024 is refused;
the wildcard (`0.0.0.0` or `::`) works. If another trap service already holds 162 (`snmptrapd` on Linux, the
**SNMP Trap** service on Windows), the listener banner names it: stop that service or pick another port.

**The firewall, per OS** (as for TLS):
- **Windows:** the MSI and `woodshed install` add the rule **Woodshed SNMP traps (UDP 162)** (inbound UDP for
  woodshed.exe, every profile), turned off. `woodshed snmp on` turns it on (on `listeners.snmp.port`), and
  `woodshed snmp off` turns it off. Upgrades and repairs keep its state, and uninstalling removes it. Turning the
  receiver on in Settings doesn't touch the rule: while it's off, missing or on another port, a banner gives the
  command to run in an administrator prompt.
- **macOS:** the application firewall allows or blocks the program, not ports: nothing to do.
- **Linux:** the packages add nothing. `woodshed snmp on` runs `ufw allow 162/udp` when ufw is active, or
  `firewall-cmd --permanent --add-port=162/udp` and a reload when firewalld is running, and records what it added in
  `snmp-firewall.json` in the data folder; `woodshed snmp off` removes only that. With neither active it changes
  nothing and prints the commands; allow inbound UDP 162 yourself.

**Files:** Woodshed's own v3 engine ID and boot counter are in `snmp-engine.json`, and the v3 users and communities
in `snmp-users.json` (mode 0600, the service's account) or, on Windows, `snmp-users.dat` (encrypted for the
service's account with DPAPI), both in the data folder. MIB files go in the `mibs` folder there.

## Flows: firewall

The flow listener (flow v5 and v9 on UDP 2055, IPFIX on UDP 4739; each port reads every version) is off until you turn it on
in **Settings → Flows**, or with `woodshed flow on` as an administrator. A 1.3 upgrade leaves it off. Pointing
exporters at it is in the [user guide](user-guide.md#collecting-flows). The commands, all as an
administrator; like `woodshed snmp`, they edit the config and restart a running service:

```sh
woodshed flow on [--flow-port 2055] [--ipfix-port 4739]   # 0 closes a port
woodshed flow off                                            # turn it off and undo the firewall change; stored flows are kept
woodshed flow status                                         # each exporter: records a second, templates, sampling, gaps
```

Both ports are above 1024, so no privilege is needed for them.

**The firewall, per OS** (as for traps):
- **Windows:** the MSI and `woodshed install` add the rules **Woodshed flows (UDP 2055)** and **Woodshed flows
  (UDP 4739)** (inbound UDP for woodshed.exe, every profile), turned off. `woodshed flow on` turns each on, on its
  port (`listeners.flow.flow_port` and `ipfix_port`; a port of 0 keeps its rule off), and `woodshed flow off` turns
  both off. Upgrades and repairs keep their state, and uninstalling removes them. While the listener is on and a rule
  is off, missing or on another port, a banner gives the command.
- **macOS:** the application firewall allows or blocks the program, not ports: nothing to do.
- **Linux:** the packages add nothing. `woodshed flow on` runs `ufw allow 2055/udp` and `ufw allow 4739/udp` when
  ufw is active, or `firewall-cmd --permanent --add-port=…/udp` and a reload when firewalld is running, and records
  each in `flow-firewall.json` and `flow-ipfix-firewall.json` in the data folder; `woodshed flow off` removes
  only those. With neither active it changes nothing and prints the commands.

Flow exporters often send in bursts. The listener has its own receive queue (50,000 packets or 128 MiB by default,
`queue_messages` and `queue_bytes` under `[listeners.flow]`), and a full queue's drops are counted per exporter.

## Headless setup (no browser on the machine)

On a server or container you reach only over SSH, the UI's first-run steps (a password, then LAN mode) are also
commands. Run them as root (`sudo`; an administrator prompt on Windows): they write the password hash into the data
folder and change the config, as an administrator editing those files would. A running service is restarted to
pick up the change (a second or two without listeners); a foreground `woodshed run` is told to restart itself.

```sh
sudo woodshed set-password            # asks twice; nothing is shown as you type
sudo woodshed lan-mode on             # HTTPS on every interface, with a login
sudo woodshed status                  # listeners, warnings, UI addresses, certificate SHA-256
sudo woodshed update-check off        # or on: the daily update check, without the UI's question
```

- **`woodshed set-password`** sets or changes the UI password (at least 8 characters). In a script, pass it on
  stdin instead of the prompt: `printf '%s\n' "$PASSWORD" | sudo woodshed set-password --stdin`. The hash is
  stored like the UI stores it (`ui-password.hash`, Argon2id, mode 0600, owned by the data folder's owner). The
  first password also turns on `ui.require_login_local`, as setting it in the UI does, so the UI asks for it on
  localhost too; the command says so. To turn that off, set `require_login_local = false` under `[ui]` in the config
  (or untick it in Settings) and restart.
- **`woodshed lan-mode on|off [--port N]`** turns LAN mode on or off, and `--port` moves the UI. `on` refuses until
  a password is set, and refuses a port that a syslog listener uses. It prints the addresses to open,
  `https://<address>:<port>/` for each of the machine's stable addresses, and the certificate's SHA-256: check it
  against what the browser shows the first time you connect (the certificate is self-signed). `off` puts the UI
  back on `http://localhost:<port>/`.
- **`woodshed status`** run as root reads the running server's state from the data folder, so it shows the
  listeners, any warnings (for example a UDP receive buffer smaller than asked for, see above), the UI addresses and
  the certificate's SHA-256 even when the UI needs a login. Run without root, it can't read the config or the data
  folder: it says so, assumes the default UI port, and shows the service's state and what the server answers there
  (only that the UI needs a login, in LAN mode).
- **`woodshed update-check on|off|ask`** sets `updates.check` (see below) and restarts a running service. `ask` puts
  the UI's one-time question back.
- **Forgot the password?** `sudo woodshed reset-password` removes it and turns LAN mode off.

## The update check on many machines

From 1.1, Woodshed can check for new versions once a day: one HTTPS GET of
`https://gmccollu.github.io/woodshed/releases.json`, nothing about the machine sent, nothing ever downloaded or
installed. It's off until someone agrees: the first time the UI opens, a banner asks (**Turn on** or **No thanks**).
The setting is `check` under `[updates]` in `woodshed.toml`: `"ask"` (the default), `"on"` or `"off"`. Settings →
Updates shows it with the last check; `woodshed status` shows it too.

To decide it for a fleet, so nobody is asked:

| Installer | How |
|---|---|
| MSI | the property `WOODSHED_UPDATE_CHECK`: `msiexec /i woodshed_X.Y.Z_windows_amd64.msi /qn WOODSHED_UPDATE_CHECK=off` |
| deb | the environment variable: `sudo WOODSHED_UPDATE_CHECK=off apt install ./woodshed_X.Y.Z_amd64.deb` |
| rpm | the environment variable: `sudo WOODSHED_UPDATE_CHECK=off dnf install ./woodshed-X.Y.Z-1.x86_64.rpm` |
| pkg | the environment variable, `sudo WOODSHED_UPDATE_CHECK=off installer -pkg woodshed_X.Y.Z_macos_universal.pkg -target /`, if macOS `installer` passes it to the package's scripts (see below) |
| any | after installing: `sudo woodshed update-check off` (an administrator prompt on Windows) |

`on`, `off` and `ask` work, in any case. The value applies on a first install and on an upgrade alike (an explicit
choice wins); without it the config is left alone. An invalid value is ignored with a warning in the install output
(the MSI's log with `msiexec /l*v`, `/var/log/install.log` for the pkg) and never fails the install. The installers
apply it by running `woodshed update-check <value>` before the service starts.

**Pre-seeding the config** is the way for the pkg when `installer` doesn't pass the variable through (then
`/var/log/install.log` has no `WOODSHED_UPDATE_CHECK` line): write the file before the first install,

```sh
sudo mkdir -p "/Library/Application Support/Woodshed"
printf '[updates]\ncheck = "off"\n' | sudo tee "/Library/Application Support/Woodshed/woodshed.toml" >/dev/null
```

and Woodshed uses the defaults for everything else (Settings writes them out at the first save). On Linux the config is
`/etc/woodshed/woodshed.toml`; there, use the variable or `woodshed update-check` instead, because a
`/etc/woodshed` you create before the package keeps your ownership and the service then can't save its settings.

## Behind a reverse proxy (nginx, Caddy)

You can put Woodshed's UI behind a reverse proxy (for your own certificate and name, or single sign-on in front).
Syslog (514) doesn't go through it. Two ways:

**1. Proxy on the same machine, to the localhost UI** (LAN mode off). First set a password
(`woodshed set-password`): with a password, the UI asks for it on localhost too (`ui.require_login_local`), so the
proxy isn't an open door. Then add the proxy's public name to `ui.trusted_hosts`: in localhost mode Woodshed refuses
any `Host` header but `localhost`, `127.0.0.1` and `[::1]` (a `403` that names the rejected host), as a defence
against DNS rebinding.

```toml
# /etc/woodshed/woodshed.toml, then: sudo systemctl restart woodshed
[ui]
trusted_hosts = ["logs.example.com"]
```

nginx (pass the `Host` header through, and don't buffer the live tail, which streams):

```nginx
server {
    listen 443 ssl;
    server_name logs.example.com;
    ssl_certificate     /etc/ssl/logs.example.com.crt;
    ssl_certificate_key /etc/ssl/logs.example.com.key;
    location / {
        proxy_pass http://127.0.0.1:8514;
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_read_timeout 1h;
    }
}
```

Caddy (passes `Host` through by default):

```
logs.example.com {
    reverse_proxy 127.0.0.1:8514 {
        flush_interval -1
    }
}
```

**2. Proxy on another machine, to LAN mode.** Turn on LAN mode (`woodshed lan-mode on`) and proxy to
`https://<woodshed host>:8514`. Woodshed's certificate is self-signed: have the proxy trust that certificate
(its SHA-256 fingerprint is in `woodshed status`) rather than turning verification off, and pass `Host` through as
above. To give the certificate your own names instead, list them in `ui.extra_hostnames`; it's regenerated with
them (and with the machine's DNS search domain) when they change.

Either way, keep 8514 closed to everything but the proxy.

## Without a package: `woodshed install`

For machines where you don't use the installer package (a tarball, a build from source), `woodshed install` sets up
the service the way the package does, and `woodshed uninstall` removes it again. Both need administrator rights
(`sudo`, or an administrator prompt on Windows).

```sh
sudo ./woodshed install              # Linux, macOS
sudo woodshed uninstall              # keeps the logs and config
sudo woodshed uninstall --delete-logs
```

```powershell
.\woodshed.exe install              # elevated PowerShell
woodshed uninstall [--delete-logs]
```

| | Linux | macOS | Windows |
|---|---|---|---|
| Program | copied to `/usr/local/bin/woodshed` | copied to `/usr/local/bin/woodshed` | copied to `C:\Program Files\Woodshed\woodshed.exe` |
| Service | the package's unit, as `/etc/systemd/system/woodshed.service` | the package's plist, `/Library/LaunchDaemons/com.woodshed.daemon.plist` | `Woodshed`, automatic start, restarted on failure |
| Account | `woodshed` system user (created if missing) with only `CAP_NET_BIND_SERVICE` | `_woodshed` user and group, created by the package's own script | `NT SERVICE\Woodshed` |
| Data folder | `/var/lib/woodshed`, owned by `woodshed`, mode 0750 | `/Library/Application Support/Woodshed`, owned by `_woodshed`, mode 0750 | `C:\ProgramData\Woodshed` with the MSI's ACL (below) |
| Also | `/etc/sysctl.d/60-woodshed.conf` (32 MiB UDP buffer) | `/etc/newsyslog.d/com.woodshed.daemon.conf` | the `Woodshed` event source; firewall rules for UDP and TCP 514 |

`--config FILE` points the service at another config, and `--data-dir FOLDER` picks the data folder (default: the
one in the table). The data folder never comes from the config, which the service account can write: an existing
config must already name the same folder, and a new one is written with it. The installer refuses system and home
folders (`/`, `/etc`, `/var`, `/Library`, `C:\Windows`, Program Files, `C:\Users\<name>`...), a folder that isn't empty
and isn't a Woodshed data folder, a config that is a link, and (on Windows) a data folder not owned by SYSTEM or
Administrators. It gives the folder to the service account without following symlinks or hard links. `uninstall`
reads the folders back from the unit, the plist or the service's registry key, not the config, and
`--delete-logs` applies the same checks before deleting anything.

`install` refuses when the package already installed the service (the unit in `/usr/lib/systemd/system`, the pkg
receipt, or the MSI's `HKLM\Software\Woodshed` key), and `uninstall` refuses to remove a package's service: use the
package to remove it. So a machine never has two Woodshed services. Remove a `woodshed install` service before
installing the package.

`uninstall --delete-logs` deletes the data folder and the config; on macOS it also deletes the `_woodshed` account,
like the pkg's `uninstall.sh --delete-logs`. On Linux the `woodshed` user is kept, as with the package.

**The Windows data-folder ACL** (the same as the MSI's): owner Administrators, inheritance from ProgramData turned
off, full control for SYSTEM and Administrators, and modify (read, write, delete; no permission changes) for
`NT SERVICE\Woodshed`. Ordinary users get no access. As SDDL:

```
O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;S-1-5-80-246480601-2135328064-241538422-929878615-662582935)
```

`woodshed install` sets it with `SetNamedSecurityInfo`. To set it by hand (an elevated prompt):

```powershell
$acl = Get-Acl C:\ProgramData\Woodshed
$acl.SetSecurityDescriptorSddlForm("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;S-1-5-80-246480601-2135328064-241538422-929878615-662582935)")
Set-Acl C:\ProgramData\Woodshed $acl
```

Or with icacls, which gives the same DACL (`M` is 0x1301bf) but leaves the owner as it is:
`icacls C:\ProgramData\Woodshed /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "NT SERVICE\Woodshed:(OI)(CI)M"`.

## Files in the data folder

| File | What it is |
|---|---|
| `logs/<device>/<day>.log`, `.log.gz` | the received messages; plain text, one line each |
| `logs/<device>/traps/<day>.log`, `.log.gz` | the received SNMP traps, one decoded trap a line (since 1.2). A 1.1 `woodshed reindex` ignores these folders |
| `index.db` (+ `-wal`, `-shm`) | the SQLite index; `woodshed reindex` rebuilds it from the logs. Stop the service and run it as the service's user: `sudo -u woodshed woodshed reindex` (Linux), `sudo -u _woodshed woodshed reindex` (macOS), an administrator prompt on Windows. As root it refuses, so a link planted in the folder can't steer root |
| `woodshed.toml` | the config (Linux: `/etc/woodshed/woodshed.toml` instead) |
| `woodshed.lock` | locked while a Woodshed process uses the folder, so two servers (or a server and `reindex`) never share it. The lock is the OS's and goes away with the process, even after a crash; the file itself stays and holds the last PID |
| `update-check.json` | the update check's last check, its result and the dismissed version (mode 0640); only written while the check is on or a banner is dismissed |
| `woodshed.state.json` | written by the running server (PID, version, UI address and any UI error) for `woodshed status`; deleted at a clean stop |
| `ui-password.hash`, `ui-cert.pem`, `ui-key.pem` | LAN mode's password hash and self-signed certificate (mode 0600) |
| `tls-ca.pem`, `tls-ca-key.pem`, `tls-cert.pem`, `tls-key.pem` | syslog over TLS: Woodshed's CA, and the server certificate (then the CA: the chain it sends) with their keys (mode 0600). Made the first time TLS is turned on, and only changed by Renew or Replace CA |
| `tls-firewall.json` | Linux: what `woodshed tls on` added to ufw or firewalld, so `tls off` removes only that |
| `tls-renew-request.json` | left by `woodshed tls renew` until the service carries it out at its next start |
| `snmp-engine.json` | Woodshed's own SNMP v3 engine ID and boot counter (mode 0600), made at the first start |
| `snmp-users.json` (`snmp-users.dat` on Windows) | the SNMP v3 users and the v1/v2c communities: the names and protocols, and every secret in one protected part (mode 0600; DPAPI on Windows) |
| `snmp-firewall.json` | Linux: what `woodshed snmp on` added to ufw or firewalld, so `snmp off` removes only that |
| `flow-firewall.json`, `flow-ipfix-firewall.json` | Linux: what `woodshed flow on` added to ufw or firewalld, per port, so `flow off` removes only those |
| `mibs/` | MIB files for trap names (created at start; Reload MIBs in Settings reads them again) |
| `exports/` | export zips, deleted after 24 hours |

## Checking that it works

1. Open http://127.0.0.1:8514/ on the machine. The welcome page shows the addresses and ports Woodshed is
   listening on, and a test command.
2. Send a test message with `woodshed send --message "hello"` (see `woodshed send --help`), or point a device at the
   machine's address, port 514.
3. `woodshed status` shows the service's state, the listeners and the UI address (as an administrator, also the TLS
   certificate's fingerprints when TLS is on).

## Troubleshooting

**Port 514 is in use.** Another syslog server (often the OS's own: rsyslog, syslog-ng) is listening. The UI still
starts and shows a red banner naming the port, the error and, where the OS says, the program holding it; `woodshed
status` shows the same. Find it yourself with `sudo ss -lunp 'sport = :514'` and `sudo ss -ltnp 'sport = :514'`
(Linux), `sudo lsof -nP -i :514` (macOS) or `Get-NetUDPEndpoint -LocalPort 514; Get-NetTCPConnection -LocalPort 514`
(PowerShell). Stop that program, or move Woodshed to another port in Settings, then press **Retry** in the banner.
No restart is needed.

**Port 8514 (the UI) is in use.** The service keeps running and retries; `woodshed status` says the UI isn't
answering and why. Change `ui.port` in the config and restart the service.

**Devices can't reach it.** Check the host firewall: the MSI and `woodshed install` on Windows open UDP and TCP 514
only; the Linux packages change no firewall (`sudo ufw allow 514`, or the firewalld command above); on macOS allow
`/usr/local/bin/woodshed` in the application firewall if it's on. The UI port is never opened: it's localhost-only
unless you turn on LAN mode (on Windows the UI then shows the admin command that opens it).

**"another Woodshed process is using this data folder".** A server already runs on that folder (`woodshed status`
says which); stop it first. `woodshed reindex` refuses for the same reason while the service runs.

**Gatekeeper or SmartScreen blocks the installer.** The installers aren't signed yet: see the macOS and Windows
sections above for the one-time prompts.

**Forgot the UI password.** `sudo woodshed reset-password` (an administrator prompt on Windows) removes it and turns
LAN mode off; the UI is back on http://localhost:8514/.

**Where's Woodshed's own log?** Windows: Event Viewer → Windows Logs → Application, source `Woodshed`. macOS:
`/Library/Logs/Woodshed/woodshed.log`. Linux: `journalctl -u woodshed`.

## How the installers are tested

`.github/workflows/install-smoke.yml` installs every package for real on fresh GitHub-hosted machines
(scripts in `scripts/smoke/`): the deb on Ubuntu, the rpm in a Fedora container running systemd, the MSI on Windows
Server and the pkg on macOS, then `woodshed install` on each. Every run checks that the service runs as its
unprivileged account and holds UDP and TCP 514 (on macOS as `_woodshed`, on Linux with only `CAP_NET_BIND_SERVICE`),
that the UI answers on 8514, that 10,000 messages sent with `woodshed send` are all on disk exactly once, that
`woodshed status` works, and that a restart, an upgrade (Windows, 0.0.1 → 0.0.2) and an uninstall keep the data
while the delete-logs paths (`apt purge`, `DELETE_LOGS=1`, `uninstall.sh --delete-logs`, `woodshed uninstall
--delete-logs`) remove it. On Windows it also checks the data-folder ACL, the firewall rules and the event log.
For the update check, it checks that `WOODSHED_UPDATE_CHECK` reaches each installer's scripts (the MSI property on
an upgrade and a fresh install, the deb's and rpm's variable through sudo and the package manager) and that an
invalid value is ignored, and for the pkg it reports whether `installer` passes the variable through and checks
the pre-seeded config.
