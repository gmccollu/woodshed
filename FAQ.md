# Woodshed FAQ

New to Woodshed? Start with the [user guide](docs/user-guide.md). Installer details are in
[docs/install.md](docs/install.md).

- [Why not tcpdump, rsyslog, syslog-ng or Graylog?](#why-not-tcpdump-rsyslog-syslog-ng-or-graylog)
- [Why port 514, and why UDP?](#why-port-514-and-why-udp)
- [Devices can't reach Woodshed](#devices-cant-reach-woodshed)
- [What does the installer change in the firewall?](#what-does-the-installer-change-in-the-firewall)
- [Windows or macOS warns me about the download](#windows-or-macos-warns-me-about-the-download)
- [Where are the logs?](#where-are-the-logs)
- [Can I search the logs without the UI?](#can-i-search-the-logs-without-the-ui)
- [How much disk does it use, and how long does it keep logs?](#how-much-disk-does-it-use-and-how-long-does-it-keep-logs)
- [Can I open the UI from another computer?](#can-i-open-the-ui-from-another-computer)
- [I forgot the UI password](#i-forgot-the-ui-password)
- [How do I uninstall it?](#how-do-i-uninstall-it)
- [Does Woodshed connect to the internet?](#does-woodshed-connect-to-the-internet)
- [The "latest release" link gives a 404](#the-latest-release-link-gives-a-404)
- [Can I run it in a container (LXC, Docker, Kubernetes)?](#can-i-run-it-in-a-container-lxc-docker-kubernetes)
- [Can I put the UI behind a reverse proxy?](#can-i-put-the-ui-behind-a-reverse-proxy)

## Why not tcpdump, rsyslog, syslog-ng or Graylog?

They're all good tools, for different jobs:

- **tcpdump** captures only while someone is running it and watching. Installed, Woodshed is a service: it survives
  reboots, rotates its files, keeps to its disk cap, lets you search what it kept, and exports a zip that marks the
  times it wasn't running.
- **rsyslog and syslog-ng** are great if you're comfortable configuring them. Woodshed is for the one Windows box or
  the laptop on site: no config file to write, a web UI, a disk cap that's on by default, counters for anything it
  drops, and an export zip for whoever needs the logs.
- **Graylog, ELK and Loki** are log platforms, with more moving parts to run. If you already have one, use it.

## Why port 514, and why UDP?

514 is the standard syslog port, and it's what almost every device sends to by default, so Woodshed works without
changing anything on the device. Most devices send syslog over UDP: it's simple and doesn't slow the device down,
but a message lost on the network isn't resent. Woodshed also listens on TCP 514 for devices that offer it
(more reliable, in order). Both are on by default; you can change the ports in **Settings → Listeners**.

For encrypted syslog, turn on **Syslog over TLS** (TCP 6514); see the
[user guide](docs/user-guide.md#sending-syslog-over-tls).

If something else already uses port 514 (often the computer's own syslog service), Woodshed still starts and the UI
shows a red banner saying which program has the port. Stop that program, or move Woodshed to another port, then press
**Retry**.

## Devices can't reach Woodshed

1. Send a test from the Woodshed computer itself: `woodshed send --message "hello"`. If that shows up, Woodshed works
   and the problem is between the device and this computer.
2. Check the address: the device must use one of the addresses on the **Setup** page, port 514, UDP or TCP as set on
   the device.
3. Check the firewall (next question). On Linux the packages don't open any port: run `sudo ufw allow 514` (Ubuntu)
   or `sudo firewall-cmd --permanent --add-port=514/udp --add-port=514/tcp && sudo firewall-cmd --reload`.
4. Check **Settings → Listeners → Sender allowlist**: if it lists addresses, other senders are refused (and counted
   under "Refused senders").

## What does the installer change in the firewall?

- **Windows:** the MSI (and `woodshed install`) adds two inbound rules for `woodshed.exe`, **Woodshed syslog (UDP
  514)** and **Woodshed syslog (TCP 514)**, and nothing else. The UI port (8514) is never opened.
  The rules apply to all network profiles, including Public: Windows often calls a network "Public" just because
  it hasn't been told otherwise, and devices on such a network would otherwise be silently blocked. To allow syslog
  only on Domain and Private networks, run this in an administrator PowerShell:

  ```powershell
  Get-NetFirewallRule -DisplayName "Woodshed syslog (*)" | Set-NetFirewallRule -Profile Domain,Private
  ```

  An upgrade or repair of the MSI re-creates the rules for all profiles, so run it again after one.
- **macOS:** nothing. If the macOS firewall is on, allow `/usr/local/bin/woodshed` in **System Settings → Network →
  Firewall → Options**.
- **Linux:** nothing (see the commands above).
- **Portable mode:** nothing is installed. On Windows, the first run asks whether to allow Woodshed through the
  firewall; choose **Allow**.

## Windows or macOS warns me about the download

Woodshed's downloads aren't code-signed yet, so the first time you open one:

- **Windows (SmartScreen):** your browser may say the file "isn't commonly downloaded"; choose **Keep**. When you open
  it, "Windows protected your PC" appears: click **More info**, then **Run anyway**.
- **macOS (Gatekeeper):** it says the file "can't be opened" because Apple can't check it. Click **Done**, open
  **System Settings → Privacy & Security**, scroll down to the message about Woodshed and click **Open Anyway**, then
  confirm. (Control-click → Open no longer skips this on current macOS.)

You only need to do this once per download. To check a download hasn't been changed, compare it with `checksums.txt`
on the same release page: `shasum -a 256 FILE` (macOS), `sha256sum FILE` (Linux) or `Get-FileHash FILE` (Windows).

## Where are the logs?

As plain text files, one folder per device and one file per day (dates in UTC), with older days compressed:

| | Installed | Portable |
|---|---|---|
| Windows | `C:\ProgramData\Woodshed\logs\` | `woodshed-data\logs\` next to `woodshed.exe` |
| macOS | `/Library/Application Support/Woodshed/logs/` | `woodshed-data/logs/` next to `woodshed` |
| Linux | `/var/lib/woodshed/logs/` | `woodshed-data/logs/` next to `woodshed` |

The installed folders are readable only by the service and administrators: open them as an administrator, or with
`sudo`. Each line is the time Woodshed received the message, the sender's address and the message exactly as it
arrived. Any text tool can read them; `.log.gz` files open with any unzip tool. To hand logs to someone, use
**Export** in the UI rather than copying files: the zip also says when Woodshed wasn't running.

Woodshed's own log (start-up errors and the like): Windows Event Viewer → Windows Logs → Application, source
`Woodshed`; macOS `/Library/Logs/Woodshed/woodshed.log`; Linux `journalctl -u woodshed`; portable mode prints to its
window.

## Can I search the logs without the UI?

Yes: `woodshed search` searches them from a terminal, with the same filters as Events, on Windows, macOS and Linux.
It runs natively on each (on Windows in an ordinary administrator prompt, no WSL or Unix tools needed), reads the
compressed days without unpacking them, and streams its matches, so a multi-gigabyte day is no harder than a small
one: there's no huge text file to open in an editor that can't cope with it. It never writes to the data folder, so
you can run it while the service is running.

```
woodshed search --last 1h "link down"
woodshed search --devices 192.0.2.10 --context 5 --regex "deny (tcp|udp)" > around-the-denies.txt
```

Run it as an administrator (or with `sudo` on macOS and Linux), like opening the log folder. See
[Searching from the command line](docs/user-guide.md#searching-from-the-command-line).

## How much disk does it use, and how long does it keep logs?

By default it keeps 30 days or 20 GB of logs, whichever comes first, deleting the oldest days first. Change both
in **Settings → Storage**. It also never fills the disk: it keeps 5% of the disk free (at least 1 GB, at most 10 GB),
deleting the oldest logs if it has to, and if there's nothing left to delete it pauses writing and shows a red
banner, counting what it couldn't store. Every deletion is listed in **Settings → Storage history**. The dashboard
shows how much disk the logs use and how many days that covers.

## Can I open the UI from another computer?

Not by default: the UI answers only on the computer Woodshed runs on (`http://localhost:8514/`). To open it from
other computers, turn on **LAN mode** in **Settings → UI access**:

1. Set a password first (in the same section).
2. Turn on **LAN mode** and save. The UI moves to HTTPS at `https://<this computer's address>:8514/`, and every
   visitor has to log in.
3. Your browser warns about the certificate the first time, because Woodshed makes its own; you can load your own
   certificate under **Advanced** instead.
4. On Windows, the UI port also needs a firewall rule; Settings shows the exact command to run as an administrator.

Anyone who can reach that address sees the login page, and with the password, all of your logs, so use a strong one.
After 10 wrong passwords, logins are refused for a while.

## I forgot the UI password

On the Woodshed computer, as an administrator, run:

```sh
sudo woodshed reset-password            # macOS, Linux
woodshed reset-password                 # Windows, in an administrator prompt
```

It removes the password, turns LAN mode off and restarts the service, so the UI is back on
`http://localhost:8514/` on that computer. Set a new password in Settings to turn LAN mode on again. There's no way to
do this over the network, on purpose.

## How do I uninstall it?

Uninstalling removes the program and the service but keeps your logs and settings, unless you ask for them to be
deleted.

- **Windows:** Settings → Apps → Woodshed → Uninstall (keeps the logs). To delete them too:
  `msiexec /x woodshed_X.Y.Z_windows_amd64.msi DELETE_LOGS=1`, or delete `C:\ProgramData\Woodshed` afterwards.
- **macOS:** `sudo /usr/local/share/woodshed/uninstall.sh` (keeps the logs) or add `--delete-logs`.
- **Linux:** `sudo apt remove woodshed` (keeps the logs) or `sudo apt purge woodshed` (deletes them);
  `sudo dnf remove woodshed` keeps them (delete `/var/lib/woodshed` and `/etc/woodshed` yourself).
- **Installed with `woodshed install`:** `woodshed uninstall`, or `woodshed uninstall --delete-logs`, as an
  administrator.
- **Portable:** close it and delete its folder (the logs are in `woodshed-data`).

## Does Woodshed connect to the internet?

Only if you turn on the update check. The first time you open the UI, Woodshed asks once whether to check for new
versions once a day. Until you say yes, and after **No thanks**, it makes no outbound connections at all. You can
change your answer any time in **Settings → Updates**.

When it's on, Woodshed fetches one public file once a day, `https://gmccollu.github.io/woodshed/releases.json`,
with a plain HTTPS GET: no query string, no cookies, and a User-Agent of just `Woodshed` (no version). Nothing
about your installation, devices or logs is sent. As with any web request, your DNS server and the site's host
see your public IP address and the time. It uses `HTTPS_PROXY` and `NO_PROXY` if they're set in the service's
environment; it doesn't read the system's proxy settings. If a newer version is out, the UI shows a banner with a
link to its release page. Woodshed never downloads or installs anything itself. Settings shows when it last
checked and whether that worked.

There's no telemetry. The version is on the **About** page, with a link to the releases page if you'd rather check
yourself. To decide for many machines at once, set `check = "off"` (or `"on"`) under `[updates]` in
`woodshed.toml` before the first start. Versions before 1.1 have no update check and make no outbound connections.

## The "latest release" link gives a 404

It works from 1.0.0 on. Before that every release was a prerelease, and GitHub's `releases/latest` (the page,
`releases/latest/download/...` and the API) skips prereleases, so old links or scripts written then may still point
at a release candidate. Prereleases such as `v1.1.0-rc1` never count as latest. File names carry the version, so a
direct link looks like `https://github.com/gmccollu/woodshed/releases/download/v1.0.0/woodshed_1.0.0_amd64.deb`.

## Can I run it in a container (LXC, Docker, Kubernetes)?

Yes. The deb and rpm work in an unprivileged LXC system container (users report Debian 13 on Proxmox VE 9.2
working), and binding port 514 there works. One thing to do **on the host**: raise `net.core.rmem_max`, which a
container can't change for itself:

```sh
sysctl -w net.core.rmem_max=33554432
echo 'net.core.rmem_max = 33554432' > /etc/sysctl.d/60-woodshed.conf
```

Until then the UI shows a warning that the UDP receive buffer is small, and bursts of messages can be dropped. For
Docker and Kubernetes, keep the senders' source addresses intact (they're how Woodshed tells devices apart) and mind
that the UI is localhost-only until LAN mode is on. Details: [Containers](docs/install.md#containers-lxc-docker-kubernetes).
On a machine without a browser, set the password and turn on LAN mode from the shell:
[Headless setup](docs/install.md#headless-setup-no-browser-on-the-machine).

## Can I put the UI behind a reverse proxy?

Yes, nginx or Caddy in front of the UI (not of port 514). Set a password first, so the UI asks for it even on
localhost, and add the proxy's public name to `ui.trusted_hosts`: otherwise Woodshed refuses the request with a
`403` naming the unexpected host. Or proxy to LAN mode from another machine. Examples:
[Behind a reverse proxy](docs/install.md#behind-a-reverse-proxy-nginx-caddy).

