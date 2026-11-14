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
Older days are compressed (`.log.gz`).

| | Installer | Portable |
|---|---|---|
| Windows | `C:\ProgramData\Woodshed\logs\` (open it as an administrator) | `woodshed-data\logs\` next to `woodshed.exe` |
| macOS | `/Library/Application Support/Woodshed/logs/` (needs `sudo`) | `woodshed-data/logs/` next to `woodshed` |
| Linux | `/var/lib/woodshed/logs/` (needs `sudo`) | `woodshed-data/logs/` next to `woodshed` |

By default Woodshed keeps 30 days or 20 GB, whichever comes first, and never fills the disk. Change it in
**Settings → Storage**.

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
