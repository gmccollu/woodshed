# Woodshed HTTP API (v1 contract)

The UI talks only to these routes. All responses are JSON unless noted. Times are RFC 3339 UTC strings.
Byte counts are integers. The frontend builds against this contract with mock data; the backend implements it.
Change this file first if the contract changes.

## Status and stats

`GET /api/status`
```json
{
  "version": "0.1.0", "build": "abc1234", "os": "darwin/arm64",
  "data_dir": "/Library/Application Support/Woodshed",
  "started_at": "2026-11-10T20:00:00Z",
  "first_message_at": null,                   // null until the first message is received (drives the Welcome page)
  "udp_rcvbuf_bytes": 33554432,               // what the OS actually granted
  "udp_rcvbuf_requested_bytes": 33554432,
  "releases_url": "",                         // build-time constant; empty until the project has a public home
  "kernel_drops_visible": false,
  "listeners": [
    {"proto": "udp", "addr": "0.0.0.0", "port": 514, "ok": true,  "error": ""},
    {"proto": "tcp", "addr": "0.0.0.0", "port": 514, "ok": false, "error": "bind: address already in use", "holder": "syslogd (pid 312)"},
    {"proto": "tls", "addr": "0.0.0.0", "port": 6514, "ok": true, "error": ""},   // only while listeners.tls.enabled
    {"proto": "snmp", "addr": "0.0.0.0", "port": 162, "ok": true, "error": ""}    // only while listeners.snmp.enabled
  ],
  "host_ips": ["10.1.0.50", "fd00::50"],
  "ui_cert_fingerprint": "",                  // LAN mode: SHA-256 of the UI's certificate, "AB:CD:…" (64 hex pairs); "" on localhost
  "banners": [{"kind": "listener_bind", "level": "error", "text": "TCP 514 is in use by syslogd (pid 312).",
               "action": "retry_listeners"}]   // action: "" | "retry_listeners" | "update_choice" | "update_dismiss" | "tls_renew";
                                               // kinds: listener_bind, writes_paused, low_disk, ui_port_busy, udp_buffer_small,
                                               // update_prompt, update_available (see "Update check"), tls_legacy, tls_cert_expiring,
                                               // tls_cert_names, tls_firewall (see "TLS syslog listener"), udp_queue_full
                                               // (see "UDP receive queue"), snmp_firewall, snmp_credentials, snmp_mibs
                                               // (see "SNMP trap receiver"), poll_unreachable, poll_overrun
                                               // (see "SNMP poller"); an optional "url" on any banner
}
```
A listener that failed to bind may also carry, when known, `holder_kind` (`"woodshed_service"`: the installed Woodshed
service; `"woodshed"`: another running copy of Woodshed; omitted otherwise), `holder_pid` (integer) and `holder_ui_url`
(that Woodshed's UI address). Another user's process (the service runs as its own account) is invisible to `lsof` and
`/proc` for an ordinary user, so when the holder can't be seen and an installed Woodshed service is running (or the
default data folder's run-state file names another live Woodshed), that one is reported as the likely holder.
Banner kind `ui_port_busy` (warn): another Woodshed (usually the installed service) is running but can't open its UI
because this copy holds the UI port.

`POST /api/listeners/retry` → `204`, then re-read `/api/status`.

`GET /api/stats`
```json
{
  "msgs_per_sec": 1284.2,
  "sparkline": [1100, 1180, 1250],            // msgs/sec averaged per minute, oldest first, last 60 minutes
  "devices": {"total": 14, "online": 12, "quiet": 1, "offline": 1},
  "disk": {"used_bytes": 3435973836, "cap_bytes": 21474836480, "free_bytes": 400000000000, "days_kept": 30,
           "bytes_per_day": 2361393152, "compression_ratio": 9.2, "estimated_days": 9.1, "limited_by": "cap"},
  "dropped_24h": 0,                           // drops Woodshed itself saw (disk guard, write errors, refused new senders, UDP queue full)
  "dropped_by_reason": {"paused": 0, "write_error": 0, "refused": 0, "queue_full": 0},
  "kernel_dropped_24h": null,                 // integer on Linux, null where the OS doesn't expose it
  "truncated_24h": 0,
  "rejected_24h": 0,                          // refused messages and TCP connections (allowlist, per-source limit)
  "udp_queue": [{"listener": "udp", "port": 514, "capacity_messages": 100000, "capacity_bytes": 67108864,
                 "depth": 12, "high_water_24h": 3210, "dropped_24h": 0,
                 "high_water_by_hour": [120, 3210, 88]},   // oldest first, the last 24 hours
                {"listener": "snmp", "port": 162, "capacity_messages": 100000, "capacity_bytes": 67108864,
                 "depth": 0, "high_water_24h": 40, "dropped_24h": 0, "high_water_by_hour": [12, 40]}]   // while listeners.snmp.enabled
}
```
**Drops by reason** (since 1.2): `dropped_by_reason` splits `dropped_24h`: `paused` (the low-disk guard had paused
writing, UDP messages still in the queue included), `write_error` (a log file write failed), `refused` (new senders
over the device limits, see `device_limit`) and `queue_full` (a UDP listener's queue was full, below). `dropped_24h`
still counts every drop, `queue_full` included. The reasons are counted since the server started, so for a day after a
restart they can sum to less than `dropped_24h`, which comes from the index.

**UDP receive queue** (since 1.2, SPEC §11.5): each UDP socket's reader only reads, stamps, applies the blocklist and
allowlist and queues; one drainer parses and stores in arrival order, so a slow disk fills the queue instead of the OS
socket buffer. `udp_queue` has one entry per enabled UDP listener (syslog's `"udp"`, and `"snmp"` while the trap
listener is on), with `port` 0 while it isn't bound:
- `capacity_messages` and `capacity_bytes`: the limits, whichever fills first. `capacity_bytes` counts message bytes.
- `depth`: messages waiting now. `high_water_24h`: the most waiting at once in the last 24 hours.
- `high_water_by_hour`: the most waiting at once in each hour, oldest first, the current hour last: 24 entries, or
  fewer within a day of the start (the About page draws it, to show stalls that cluster at the top of the hour).
- `dropped_24h`: messages dropped because this queue was full. A queue drop counts for the sender's device (the
  trap listener's for its traps), so it's in the device's `dropped` stats, the top-level `dropped_24h` and an export's losses, and the events log gets one
  `drop` event a minute with the count.
- If messages are lost while the queue never fills, the loss happened before Woodshed read them (the OS socket buffer
  or the network).
- File-only settings (not in `/api/settings`): `listeners.udp_queue_messages` (default 100,000, 1,000–2,000,000) and
  `listeners.udp_queue_bytes` (default 67,108,864, 1 MiB–1 GiB), for every UDP listener.
- At shutdown the queue drains into the store first, for at most a third of the shutdown timeout; anything still
  queued then counts as `queue_full`.

Banner `udp_queue_full` (warn, action `""`, since 1.2): UDP messages were dropped in the last hour because a queue was
full: "123 UDP messages were dropped in the last hour because writing to disk fell behind (the queue holds 100,000).
Check the disk, or raise `listeners.udp_queue_messages`." When the byte limit refused the latest drop, it gives the
byte size and names `listeners.udp_queue_bytes` instead.
Banner `udp_buffer_small` (warn, Linux): the OS granted a UDP receive buffer below 8 MiB (`udp_rcvbuf_bytes` <
`udp_rcvbuf_requested_bytes`). Text names both sizes, says bursts may be dropped before Woodshed sees them, and gives
the fix (`net.core.rmem_max` on the host for containers; the package's sysctl file otherwise). Logged at WARN at start.

`days_kept` is the number of distinct UTC days that still have data on disk (today counts).
`bytes_per_day` is the on-disk (compressed-equivalent) bytes written over the last 24 h: raw bytes divided by
`compression_ratio`, the ratio measured on files this server has closed and gzipped (a default of 8 until it has
closed a file; `null` until it has 1 h of data). `estimated_days` = `cap_bytes` / `bytes_per_day`, or `null`.
`limited_by` is `"cap"` when `estimated_days` < `retention_days` (the size cap, not the age limit, decides how long
logs are kept), `"age"` otherwise, or `null` when unknown. While it's `"cap"`, `/api/status` carries a warn banner
of kind `retention_cap` ("At the current rate the 20 GiB cap keeps about 9 days, less than the 30-day setting").

`GET /api/storage/estimate?retention_bytes=N` → `{"estimated_days": 4.5, "bytes_per_day": …, "compression_ratio": …}`:
the same estimate for a cap the user is typing in Settings, before saving.
`devices` counts exclude hidden devices.

`GET /api/rejected` → `[{"ip": "198.51.100.7", "count_24h": 120, "last_seen": "...", "reason": "allowlist"}]` (refused
senders). `reason` is the latest refusal's reason: `allowlist`, `blocked` (on the blocklist), `per_source` (over the TCP
connections-per-source limit) or `community` (a v1/v2c trap whose community isn't in `listeners.snmp.communities`;
it isn't stored).
Sorted by `count_24h` descending, at most 200 entries. The server tracks at most 10,000 refused IPs and evicts the
least recently seen.
Banner kind `device_limit` (warn): new senders are being refused because the active-device cap
(`listeners.max_devices`, default 10,000 devices that sent in the last 10 minutes) or the new-device rate
(`listeners.new_device_burst` 5,000, then `listeners.new_devices_per_minute` 200) was reached; their messages count
as dropped. Senders that already have logs on disk are exempt from the rate. All three are editable in Settings.
`banners` in `/api/status` are sent in priority order: errors first, then warnings.

## Devices

`GET /api/devices?limit=200&offset=0&sort=rate|name|last_heard|first_seen&q=text&group=HQ&ungrouped=true&hidden=include|only|exclude&blocked=include|only|exclude`
→ `{"devices": [...], "total": 1234}`. Default `limit` 200, max 1,000; default `sort=rate`. Directions are fixed:
`rate` busiest first, `name` A–Z (devices without a name sort by IP), `last_heard` and `first_seen` newest first. `q` matches
id, IP or name (case-insensitive substring); `hidden` and `blocked` default to `include`. Each device:
```json
[{"id": "10.1.0.1", "ip": "10.1.0.1", "name": "edge-fw-01", "group": "HQ", "hidden": false,
  "first_seen": "...", "last_heard": "...", "status": "online", "blocked": false,   // status: online | quiet | offline | blocked
  "msgs_per_min": 36720, "total_msgs": 9123456, "bytes_on_disk": 123456789,
  "tls": null,                                 // null until the device has tried TLS since the server started; see below
  "types": ["syslog", "trap"], "lines_by_type": {"syslog": 9120000, "trap": 3456},
  "polled": false}]                            // since 1.3; a polled device also has "poll_status": "ok"
```
`total_msgs` counts every data type (syslog and SNMP traps, SPEC §11.1), so a device that sends only traps is online.
`types` lists the data types the device has files of on disk now (`[]` when none), and `lines_by_type` their stored
lines (records), from the index.
`polled` says an SNMP poll target writes into this device (SPEC §12.3), and `poll_status` (only then) is that
target's `state.status` (see "SNMP poller").
`tls`, once the device has tried syslog over TLS (counts since the server started, kept 24 h):
```json
{"connections_24h": 288, "version": "TLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256", "last_connected": "2026-11-13T15:09:51Z",
 "failures_24h": 2, "last_failure": {"time": "2026-11-13T09:00:12Z", "reason": "timeout", "detail": ""}}
```
`version` and `cipher` are the last successful connection's (`last_connected` is `null` if none succeeded);
`last_failure` is `null` when there was none. Reasons are those of `/api/tls/failures`.

Hidden devices are included, with `"hidden": true`.

**Active devices** (since 1.2, the incident bundle's preview): `active_from` and `active_to` (RFC 3339, both or
neither, `active_from` before `active_to`) keep only the devices with a stored record of any type received in
`[active_from, active_to)`; they combine with the other parameters (`hidden=exclude` gives the devices a bundle with
`active_devices` picks), and `total` counts the active devices that match. It's exact: a device counts when a record
in the range is on disk now (from the index's file rows and checkpoints, then reading the range where those can't
tell), not from the per-minute stats. A missing partner, a bad time or an empty range is a `400`.

`GET /api/groups` → `[{"name": "HQ", "devices": 12}]`, sorted by name, with the number of non-hidden devices in each
(ungrouped devices aren't listed).

`PATCH /api/devices/{id}` body `{"name": "...", "group": "...", "hidden": true, "blocked": true}` (any subset) → the
updated device. `blocked: true` adds the device's exact address (`/32` or `/128`) to `listeners.blocklist`;
`blocked: false` removes that exact entry (a broader CIDR that also covers it stays, and the device stays blocked:
the response says so with `"blocked_by": "198.51.100.0/24"`).

**Blocklist** (`listeners.blocklist`, IPs or CIDRs, editable in Settings): messages and TCP connections from a
matching sender are refused at the listener, before parsing or storage, and counted as refusals with reason
`blocked`. The blocklist is checked before the allowlist and wins over it. A blocked device's existing logs, search
and export are unaffected; its `status` is `blocked`, and it isn't counted as online, quiet or offline in
`/api/stats`. Validation errors use `listeners.blocklist[i]` like the allowlist.

## Live tail

`GET /api/live?devices=10.1.0.1,10.1.0.2&group=HQ&ungrouped=true&severities=3,4,unknown&q=text` → `text/event-stream`.
- `event: message` `data: {"received": "...", "device_id": "10.1.0.1", "severity": 6, "raw": "<134>..."}`
- `event: sampled` `data: {"rate": 1284.2, "shown": 50}`: sent once a second while the server is sampling.
- `group` and `ungrouped=true` are alternatives; `ungrouped=true` matches devices with no group.
- Hidden devices are left out of the live tail unless they're named in `devices`, the same rule as search.
- `severity` is an integer 0–7, or `null` when the message had no parseable PRI.
- `min_severity` is the numeric syslog severity ceiling (0 emerg … 7 debug); messages with an unknown severity
  are always included.
- On connect, the server first sends up to the last 200 matching messages from the ring buffer.
- A heartbeat comment (`: ping`) is sent every 15 s, so a client can treat 45 s of silence as a dead stream.

## Severity filters (live tail and search)

Both `/api/live` and `/api/search` take either:
- `severities=0,3,7,unknown`: any set of syslog severities (0 emerg … 7 debug) plus `unknown` (no parseable PRI).
  Only those are returned. An empty or missing value means all; `severities=none` means nothing (the live tail
  sends no messages, search returns no results). `none` can't be combined with other values.
- `min_severity=N`: the older ceiling form (0…N, plus unknown). If both are given, `severities` wins.

An invalid value (not 0–7 or `unknown`) is a `400 {"error": ...}`.

## Search

`GET /api/search?q=text&regex=false&case=false&devices=a,b&group=HQ&ungrouped=true&from=...&to=...&severities=...&app=sshd,%25FW-6-*&host=web-01&exclude=text&order=desc&limit=500&cursor=...&type=syslog&syntax=text&facilities=...&exclude_devices=...&exclude_app=...&exclude_host=...`
```json
{"results": [{"received": "...", "device_id": "10.1.0.1", "severity": 6, "raw": "...", "ref": "opaque",
              "app": "sshd", "host": "web-01"}],
 "next_cursor": "opaque-or-empty", "scanned_bytes": 123456, "scanned_files": 12, "elapsed_ms": 840,
 "partial": false}
```
- `q`: substring by default (case-insensitive unless `case=true`). With `regex=true` it's an RE2 regular expression;
  an invalid one is a `400` with the parse error. With `syntax=terms` it's boolean terms (below). `case` applies to
  all of them. Empty `q` matches every line, so it's a filtered browse.
- `type`: the data type: `syslog` (the default), `trap` (SNMP traps, below), since 1.3 `poll` (SNMP poll
  records, below) or, since 2.0, `flow` (flow records: see "Flows"). Any other value is a
  `400 {"error": "type: unknown data type \"x\"."}`. Without `type`, everything means what it meant in 1.1.
- `syntax`: `text` (the default: `q` and `exclude` mean exactly what they meant in 1.0) or `terms` (below). Anything
  else is a `400`.
- `q` is matched against the raw message as received (unescaped), not the stored line prefix.
- `exclude`: lines whose raw message matches it are left out. It's matched like `q`: a substring by default, an RE2
  regular expression with `regex=true`, and `case` applies. An invalid one is a `400` (the message starts
  `exclude: `). Empty means nothing is excluded.
- `app`: comma-separated programs/tags. Only lines whose header has one of them are returned, ignoring case. A value
  ending in `*` is a prefix (`ssh*`, `%FW-6-*`). A leading `%` is ignored on both sides, so `FW-6-302013` and
  `%FW-6-302013` both match the tag `%FW-6-302013` (in a URL, `%` is written `%25`). `*` alone matches any
  line that has a program/tag.
- `host`: comma-separated hostnames from the message header (not the sender's IP; use `devices` for that), exact
  match ignoring case.
- `app` and `host` read the header the same way the server parses messages (RFC 5424, RFC 3164 and common variants).
  A line whose header has no program/tag or hostname has `""` there and never matches an `app` or `host` filter. The
  header is parsed only for lines that passed the other filters.
- Each result's `app` and `host` are the parsed program/tag (with a `%` tag's `%`) and header hostname, or `""` when
  the header has none. Context lines carry them too.
- `exclude_app`, `exclude_host`: comma-separated, each matched exactly like `app` and `host`. A line whose
  program/tag (or hostname) matches any of them is left out. A line without a program/tag (or hostname) is never
  left out by them. When a value is both included and excluded, the exclusion wins.
- `facilities=0,4,16,unknown`: syslog facilities 0–23 (from the PRI) plus `unknown` (no parseable PRI). It works like
  `severities`: empty or missing means all, and `none` means nothing. An invalid value is a `400`.
- `from` / `to`: RFC 3339, on the received time: `from` ≤ received < `to`. Default `to` = now and `from` = to − 24 h.
  `from` must be before `to`.
- `devices`, `group` / `ungrouped`: as for `/api/live`. Hidden devices are searched only when named in `devices`.
- `exclude_devices=a,b`: leave these devices out, after `devices`, `group` and `ungrouped` have picked theirs. A
  device that's both named and excluded is excluded.
- `order`: `desc` (newest first, the default) or `asc`.
- `limit`: default 500, max 5,000.
- `cursor`: from the previous page's `next_cursor`; the other parameters (every filter above included) must be the
  same as on the first page, or the server returns `400`. The order of the values in the list parameters doesn't
  matter. `limit` is the exception: it may change from page to page.
- Each request has a time budget of 10 s. If the budget runs out before `limit` results (or the page reaches 8 MiB of
  messages), the response has what it found, `partial: true` and a `next_cursor` that resumes where the scan stopped. The UI keeps asking while
  `partial` is true and the user hasn't cancelled.
- `next_cursor` is empty when the range is exhausted.
- `scanned_bytes`, `scanned_files` and `elapsed_ms` are for this request only; the UI adds them up across pages.
- `ref` identifies one line for `/api/context`. It stays valid until the file is deleted by retention.
- The filters below `exclude` (`app`, `host`, their excludes, `severities`, `min_severity`, `facilities`) are syslog's;
  with `type=trap` or `type=poll` each is a `400` (`{"error": "severities: not a filter for SNMP traps."}`, `… for
  SNMP polls.`). A parameter sent with an empty value doesn't count as present.

**`type=trap`** (SPEC §11.2.5): `q`, `syntax`, `regex`, `case` and `exclude` match the record text without its `raw=`
part (so a search never matches base64), and the device selection and the range work as for syslog. The trap
filters, only with `type=trap` (with syslog each is a `400` "`<name>: not a filter for syslog.`"):
- `snmp_versions=1,2c,3`, `pdus=v1trap,trap,inform,unexpected`, `generic=0,6` (v1's generic trap, 0–6),
  `status=ok,auth_failed`: sets, like `severities` (empty means all, `none` alone means nothing). `unexpected` is any
  PDU but a trap or inform. Statuses: `ok`, `malformed`, `unexpected_pdu`, `unknown_user`, `unknown_engine`,
  `not_in_time`, `auth_failed`, `decrypt_failed`, `level`.
- `trap_oid`, `enterprise` and their `exclude_` forms: comma-separated OIDs, each exact or a prefix written with a
  trailing `.*` (`1.3.6.1.4.1.32473.*`, which matches that OID and everything under it), or a MIB name (`linkDown`,
  `IF-MIB::linkDown`, also with `.*`) resolved with the current MIB set when the request is parsed. An unknown name is
  a `400` (`trap_oid: "noSuchTrap" is not a name in the loaded MIBs.`); a name two modules define differently is a
  `400` asking for the module.
- `specific`, `exclude_specific`: comma-separated integers (v1's specific trap).
- `cred`, `exclude_cred`: comma-separated community hashes (`#3f9a1c07`) or v3 user names, exact, ignoring case.
- An `exclude_` filter never drops a record without that value (a v2c trap has no `enterprise`).

A trap result (syslog results keep the shape above):
```json
{"received": "2026-11-14T09:30:58.112Z", "device_id": "10.1.0.1", "type": "trap", "ref": "opaque",
 "raw": "v=2c pdu=trap id=4711 cred=#3f9a1c07 status=ok uptime=8641234 trap=1.3.6.1.6.3.1.1.5.3(linkDown) vb=… raw=MIGTAgEB…",
 "fields": {"version": "2c", "pdu": "trap", "trap_oid": "1.3.6.1.6.3.1.1.5.3", "trap_name": "linkDown",
            "enterprise": "", "generic": null, "specific": null, "cred": "#3f9a1c07", "status": "ok", "error": "",
            "uptime": 8641234, "dup": false,
            "varbinds": [{"oid": "1.3.6.1.2.1.2.2.1.8.3", "name": "ifOperStatus.3", "type": "int", "value": "2", "value_name": "down"}]}}
```
- `raw` is the stored record (SPEC §11.2.4), unescaped. `fields` is decoded from it, with names from the current MIB
  set (so a name can appear here that the stored line lacks).
- `generic` and `specific` are integers for v1 traps, `null` otherwise; `uptime` is `null` when the record has none.
  `value` is always a string. A record that doesn't parse has `status` `"malformed"` and the fields it has.

**`type=poll`** (since 1.3, SPEC §12.3): the poller's record lines, one per cycle per part, searchable like any type
(`/api/search`, `/api/search/summary`, saved searches, exports and `woodshed search`); Events shows them as graphs,
not as a tab. `q`, `syntax`, `regex`, `case` and `exclude` match the whole record (`oper=down`), and the device
selection and the range work as for syslog.
- Schema fields: `device`, `kind` (domain `sys`, `if`, `oid`, `status`, `restart`, `info`), `if` (the interface's
  name, or its index when it has none; on `if` lines and interface `info` lines), `oper` (domain `up`, `down`,
  `testing`, `unknown`, `dormant`, `notPresent`, `lowerLayerDown`; `if` lines), `status` (domain `ok`, `timeout`,
  `unreachable`, `auth_failed`, `unknown_user`, `unknown_engine`, `not_in_time`, `decrypt_failed`, `error`,
  `overrun`; a `status` line's own, `ok` for every other kind), `reboot` (domain `1`, `0`, `?`; `restart` lines).
- Filters, only with `type=poll` (with another type each is a `400` "`<name>: not a filter for syslog.`" or
  "`… for SNMP traps.`"): `kinds`, `oper`, `poll_status` and `reboot` are sets like `severities` (empty means all,
  `none` alone means nothing); `ifs` / `exclude_ifs` are comma-separated interface names (ignoring case) or indexes.
  `oper` passes only `if` lines and `reboot` only `restart` lines; `exclude_ifs` never drops a line without an
  interface. Syslog's and the trap type's filters with `type=poll` are a `400`
  (`{"error": "status: not a filter for SNMP polls."}`: the poll status filter is `poll_status`).

A poll result:
```js
{"received": "2026-11-15T10:00:00.131Z", "device_id": "10.1.0.1", "type": "poll", "ref": "opaque",
 "raw": "kind=if cycle=1042 if=3 name=\"eth3\" oper=up speed_mbps=1000 in_octets=987654321012 … in_bps=81234567 …",
 "fields": {"kind": "if", "cycle": 1042, "if": "eth3", "oper": "up", "status": "ok", "reboot": "",
            "values": {"if": "3", "name": "eth3", "speed_mbps": "1000", "in_octets": "987654321012", "in_bps": "81234567"}}}
```
- `raw` is the stored record (SPEC §12.3), unescaped. `values` holds every other key of the record as text (`if`
  there is the index); `oper`, `status` and `reboot` are `""` on the kinds that don't have them. A record that
  doesn't parse has an empty `kind` and `values.error`.

**`syntax=terms`** (grammar in SPEC §10.1.3): words and `"quoted phrases"` are substrings of the raw message, matched
as `q` is (`case` applies to all of them). They're joined by `AND` (or just a space), `OR` and `NOT`, upper case only,
with `( )` for grouping. NOT binds tightest, then AND, then OR. Inside a phrase, `\"` is a quote and `\\` a
backslash; any other backslash is itself. At most 32 words and phrases, 8 levels of parentheses and 4 KiB of `q`.
`exclude` takes the same grammar.
- `regex=true` with `syntax=terms` is a `400 {"error": "Terms and regex can't be combined: pick one."}`.
- A parse error is a `400` naming a 1-based character position, for example
  `{"error": "Unclosed quote starting at character 12."}`. For `exclude`, the message starts with `exclude: `. The
  full list is in SPEC §10.1.3.

`GET /api/context?ref=opaque&before=50&after=50` → `{"lines": [...same shape as results...], "hit_index": 50,
"at_start": false, "at_end": false}`
- Context isn't filtered: it's every stored line around the hit, so it takes no filter parameters.
- `at_start` / `at_end` are true when there are no older / newer stored lines for that device.
- Lines come from the same device and the same data type as the ref, in file order, and can cross into the
  neighbouring part or day file. A trap `ref` returns trap lines, in the trap result shape, and a poll `ref` poll
  lines, in the poll result shape.
- `before` / `after` max 500 each. A `ref` whose file is gone is a `404`.

## Exports

`POST /api/exports` body `{"devices": ["10.1.0.1"], "group": "", "ungrouped": false, "from": "...", "to": "...",
"severities": [0, 1, "unknown"], "q": "", "regex": false, "case": false, "app": ["sshd", "%FW-6-*"], "host": ["web-01"],
"exclude": "", "type": "syslog", "syntax": "text", "facilities": [4, "unknown"], "exclude_devices": ["10.1.0.9"],
"exclude_app": ["kernel"], "exclude_host": ["lab-01"]}` → `202 {"id": "exp_..."}`
- `from` and `to` are required. Pick devices with `devices`, `group`, `ungrouped`, or `"all_devices": true` (every non-hidden device); at least one must select a device, and `exclude_devices` then leaves some out. `severities`, `q`, `regex`,
  `case`, `app`, `host`, `exclude`, `type`, `syntax`, `facilities`, `exclude_app` and `exclude_host` are optional filters
  with exactly the same meaning as search, so "Export these results" exports what the search showed. The list
  parameters are JSON lists here (search takes them comma-separated); blank items are dropped. Without filters every
  line in range is exported.
- `types` (since 1.2): the data types in the zip, `["syslog"]` by default, so a 1.1 body builds exactly the 1.1 zip.
  Filters (`q`, `exclude`, syslog's or the trap filters) apply only to an export of one type; with more than one it's
  a `400` on `types`: "Filters apply to one data type; pick one, or leave the filters out." `type` (1.1) is the same
  as a one-entry `types`; both together must agree.
- The trap filters (with `"types": ["trap"]`) are JSON lists of strings (numbers too, for `generic` and
  `specific`), with the names and meaning of search's: `"snmp_versions": ["2c"]`, `"pdus": ["inform"]`,
  `"trap_oid": ["linkDown"]`, `"generic": [0, 6]`,
  `"specific": ["17"]`, `"cred": ["#3f9a1c07"]`, `"status": ["ok"]` and the `exclude_` forms.
- The poll filters (since 1.3, with `"types": ["poll"]`) are JSON lists the same way: `"kinds": ["if"]`,
  `"ifs": ["eth1", 7]`, `"exclude_ifs"`, `"oper": ["down"]`, `"poll_status": ["timeout"]`, `"reboot": ["1"]`.
- `kind` (since 1.2): `"export"` (the default) or `"bundle"`, the incident bundle (below). `at`, `before`, `after`
  and `active_devices` on a plain export are a `400`.
- One export builds at a time; a second `POST` while one is building is queued.

### The incident bundle

<!-- The examples here are fenced as js, not json: routes_test.go pairs each json block with the GET route above it. -->

Since 1.2 (SPEC §11.3): every record around a moment, from the devices that sent anything then, with a summary per
device. It's an export (`kind: "bundle"`): the queue, the estimate, the download ticket, the 24 h expiry, the
manifest, the gaps and the events log are the export's.
```js
{"kind": "bundle", "at": "2026-11-14T09:42:00Z", "before": "30m", "after": "10m",
 "active_devices": true, "devices": [], "group": "", "ungrouped": false, "types": []}
```
- `at` (RFC 3339) is required and can't be in the future. `before` and `after` are durations (`ms`, `s`, `m`, `h`
  and `d` units, combined as in `1h30m`; `0s` to `7d` each, at least one non-zero; `30m` and `10m` when left out).
  The window is `[at − before, at + after)`, cut at now: a bundle "around now" ends when it's requested.
- Devices, exactly one of: `"active_devices": true` (every non-hidden device with a stored record of any of the
  bundle's types in the window, as `GET /api/devices?active_from&active_to` finds them), `devices` (those devices,
  hidden or silent ones too), `group` or `ungrouped` (their non-hidden devices).
- `types`: `[]` (or left out) means every type with data in the window from those devices; or a list (`["syslog"]`,
  `["trap"]`). `type` (1.1) is the same as a one-entry `types`.
- No filters: a bundle is everything around the moment. `from`, `to`, `all_devices`, `exclude_devices`, and any
  filter (`q`, `exclude`, `regex`, `case`, `syntax` other than `"text"`, `severities`, `facilities`, `app`, `host`,
  their `exclude_` forms, the trap filters, the poll filters) are a `400` naming the field.
- No device stored anything in the window (with `active_devices`): a `400` "No device stored anything between
  <from> and <to>." (naming the types when `types` was given). Named devices that sent nothing still get a bundle,
  with "none" in their summary.
- Response: `202 {"id": "exp_..."}`. `POST /api/exports/estimate` takes the same body.
- In `GET /api/exports`, a bundle's `from` and `to` are its window and its `filters` add `"at"`, `"before"`,
  `"after"` (written as `"30m"`, `"1h15m"`, `"7d"`, `"0s"`) and `"active_devices"`; `kind` is `"bundle"` and
  `types` the types it was built with (`[]` when nothing was stored). A plain export's entry has none of the four.
- The download is named `woodshed-bundle-<host>-<at, UTC as YYYYmmddTHHMMSSZ>.zip`, as `woodshed bundle` names it.

The zip is an export's (below), with each type in its folder, and:
- `README.txt` leads with the summary (SPEC §11.3): the moment and the window in UTC with the local offset, how the
  devices were picked, then per device its counts by type (syslog by severity, traps by name), first and last
  received, reboots (coldStart and warmStart traps), the gaps, and Woodshed's own drop and truncation counts in the
  window. Times carry the date when the window spans more than one UTC day. Since 1.3 a device's polls have a Polls
  line (cycles answered and the interval, uptime at the end, peak traffic, CPU and memory peaks, error and discard
  deltas, oper changes; SPEC §12.6), and reboots also come from poll restarts: a coldStart or warmStart trap within
  2 min of a poll restart is one line naming both sources (`09:30:58.112 (poll: sysUpTime and hrSystemUptime reset;
  coldStart trap)`).
- `manifest.json` has `"kind": "bundle"`, `"at"`, `"before"`, `"after"`, `"summary"` and `"summary_note"`, and
  `request.filters.active_devices` when that picked the devices. `summary` is the README's numbers per device:
  ```js
  [{"device_id": "10.1.0.1", "ip": "10.1.0.1", "name": "edge-fw-01", "group": "HQ",
    "types": {"syslog": {"lines": 12408, "first": "2026-11-14T09:12:00.014Z", "last": "2026-11-14T09:51:59.88Z",
                         "by_severity": {"emerg": 0, "alert": 0, "crit": 2, "err": 41, "warning": 310, "notice": 1022,
                                         "info": 11033, "debug": 0, "unknown": 0}},
              "trap": {"lines": 7, "first": "2026-11-14T09:30:11Z", "last": "2026-11-14T09:31:02Z",
                       "by_trap": {"linkDown": 3, "linkUp": 3, "coldStart": 1}}},
    "reboots": [{"time": "2026-11-14T09:30:58Z", "source": "coldStart trap"}],
    "gaps": [], "dropped": 0, "truncated": 0}]
  ```
  `first` and `last` are `null` for a type the device sent none of. `by_severity` always has all nine; `by_trap` is
  the trap names (from the MIB set, else the OID; `(malformed)` and the like for a record without one), most first.
  Since 1.3, `types.poll` counts the CSV rows (`by_kind`: `sys`, `if`, `oid`, `status`, `restart`, `info`), and an
  entry of a bundle with polls has `"poll"`:
  ```js
  {"cycles": 40, "answered": 40, "interval_s": 60, "uptime_end_s": 1048512,
   "peak_in_bps": 812345678, "peak_in_if": "eth1", "peak_out_bps": 95123456, "peak_out_if": "eth1",
   "cpu_peak": 91, "mem_peak_pct": 72, "errors_in_d": 12, "errors_out_d": 0, "discards_in_d": 340, "discards_out_d": 0,
   "oper_changes": [{"if": "eth3", "down": "2026-11-15T09:30:58Z", "up": "2026-11-15T09:31:40Z"}]}
  ```
  A value that wasn't measured is `null` (never 0); `up` is `null` for an interface still down at the end.
  `reboots[].source` is `"coldStart trap"` (or `"warmStart trap"`, `"… inform"`), `"poll"` with a `"detail"`
  (`"sysUpTime and hrSystemUptime reset"`; `"…; the device may have rebooted"` without HOST-RESOURCES), or both in
  one string, `"poll, coldStart trap"`, when a poll restart and a trap are within 2 min (at the earlier time, with the
  poll's `detail`).
  `gaps` are the bundle's (the same for every device). `dropped` and `truncated` sum the stats buckets that start in
  the window (per minute, per hour past 24 h), so a bucket that straddles an edge counts whole.

**CLI** (not HTTP): `woodshed bundle --at <time>` builds the same zip from the data folder, without the service
(SPEC §11.3, the user guide's "Incident bundles").

`POST /api/exports/estimate` (same body) → `{"lines": 123456, "bytes": 45678901, "files": 12}`: an upper bound
from the index, without scanning, so the UI can show the size before building.

`GET /api/exports` → `[{"id", "created", "devices", "from", "to", "state": "queued|building|ready|failed|expired",
"progress": 0.42, "lines": 0, "size_bytes": 0, "error": "", "ready_at": null, "expires_at": null,
"filters": {"group": "", "ungrouped": false, "severities": [], "q": "", "regex": false, "case": false, "app": [], "host": [],
"exclude": "", "type": "syslog", "syntax": "text", "facilities": [], "exclude_devices": [], "exclude_app": [],
"exclude_host": [], "kind": "export", "types": ["syslog"]}}]`, newest
first. `ready_at` / `expires_at` are set once the export is ready; `filters` echoes the request. For an export of
traps with trap filters, `filters` also has `"trap"`, an object of the trap lists given (`{"trap_oid": ["1.3.6.1.6.3.1.1.5.3"]}`,
MIB names resolved, prefixes kept with `.*`), and `type` is `"trap"`; `trap` is omitted when there are none. An export
of polls with poll filters likewise has `"poll"` (`{"kinds": ["if"], "oper": ["down"]}`) and `type` `"poll"`.

`GET /api/exports/{id}` → one entry, same shape.

`GET /api/exports/{id}/download` → the zip (`Content-Disposition: attachment; filename="woodshed-<from>-<to>.zip"`).
When login is required, a browser download can't send the `X-Woodshed-Session` header, so the UI first calls
`POST /api/exports/{id}/ticket` (normal auth) → `{"url": "/api/exports/{id}/download?ticket=<opaque>"}` and navigates
to that URL. A ticket is single-use, valid for 60 s, bound to the session that asked for it and to that export, and
stored only hashed; the download route accepts it in place of the header (the cookie is still required). Without
login required, the ticket step is optional.
`409` if it isn't ready, `404` if unknown or expired.

`DELETE /api/exports/{id}` → `204`. It cancels a building export or deletes a ready one.

Exports are deleted 24 h after they're ready. Their size counts against free disk (the low-disk guard can delete
them first), but not against the log retention cap.

**Zip contents** (SPEC §4.1):
- `logs/<device-id>/<YYYY-MM-DD>.log`: the matching lines as stored, one message per line, in received order: each
  line is `<received> <sender> <message>`, with CR, LF and backslash in the message escaped as `\r`, `\n` and `\\`
  (`README.txt` shows how to unescape). Search and context results still return the raw message unescaped. Syslog
  stays in `logs/`, exactly as in 1.0 and 1.1.
- `traps/<device-id>/<YYYY-MM-DD>.log` (an export with `trap` in `types`): the trap record lines as stored, in the
  same envelope and escaping.
- `poll/<device-id>/system.csv`, `interfaces.csv` and `oids.csv` (since 1.3, an export with `poll` in `types`): not
  the stored lines but CSV files with a header row, UTF-8, comma-separated, RFC 4180 quoting (CRLF line ends), times
  in RFC 3339 UTC, with the columns of SPEC §12.6: `system.csv` `time,cycle,uptime_s,hr_uptime_s,cpu_pct,
  mem_used_bytes,mem_total_bytes,rtt_ms,status,detail` (failed cycles and restart markers are rows with their
  status, `restart` with `detail` naming the sources); `interfaces.csv` `time,cycle,if_index,if_name,if_alias,oper,
  speed_mbps,in_octets,out_octets,in_bps,out_bps,in_errors,out_errors,in_errors_delta,out_errors_delta,in_discards,
  out_discards,in_discards_delta,out_discards_delta,discontinuity` (`if_alias` from the interface's latest names
  line); `oids.csv` `time,cycle,oid,label,row,type,value,rate`. An empty cell is "not measured" (no previous sample,
  a discontinuity, not supported), never zero. A file is in the zip only when it has rows. Each is in the
  manifest's `files` with its rows as `lines`, its SHA-256 and an empty `day`; an export's `lines` counts CSV rows
  for polls.
- `manifest.json`: Woodshed version, export time, the request (devices with names and groups, range, filters:
  `severities`, `q`, `regex`, `case`, `app`, `host`, `exclude`, `type`, `syntax`, `facilities`, `exclude_devices`,
  `exclude_app` and `exclude_host`), and per-file line count and SHA-256. Also `gaps`: periods inside the range when Woodshed wasn't running or a listener
  was down, from the event log (the SNMP listener's as `proto` `"snmp"`). Since 1.2 also `"kind": "export"`,
  `"types"` (the data types exported) and `"folders"` (each zip folder's type: `{"logs": "syslog", "traps": "trap"}`
  for the types exported; since 1.3 also `"poll": "poll"`); `request.filters.type` is `"trap"` for an export of traps
  alone, `"poll"` for one of polls alone.
- `woodshed-events.log`: the service's own events in the range (start, stop, bind errors, rotations, deletions,
  drops, pauses).
- `README.txt`: a short note on what each file is, with the range and the filters in plain words ("Filters: none"
  when there are none). A zip with traps also explains the record, and that a community is shown only as a hash
  prefix in `cred=` and masked with `*` in `raw=`. A zip with polls explains each CSV column. No community or key is
  ever in a zip (poll lines name a credential only as `cred=#<hash8>` or the user name).

## Search summary and schema (Events)

`GET /api/search/schema`: the data types Events can show, and the fields of each one's field panel. The client builds the panel from this list;
it has no field list of its own.
```json
{"types": [
  {"type": "syslog", "label": "Syslog", "default": true,
   "fields": [
     {"key": "device",   "label": "Device",      "param": "devices",    "exclude_param": "exclude_devices", "domain": null},
     {"key": "severity", "label": "Severity",    "param": "severities", "exclude_param": "",
      "domain": [{"value": "0", "label": "emerg"}, {"value": "1", "label": "alert"}, {"value": "2", "label": "crit"},
                 {"value": "3", "label": "err"}, {"value": "4", "label": "warning"}, {"value": "5", "label": "notice"},
                 {"value": "6", "label": "info"}, {"value": "7", "label": "debug"}, {"value": "unknown", "label": "unknown"}]},
     {"key": "facility", "label": "Facility",    "param": "facilities", "exclude_param": "",
      "domain": [{"value": "0", "label": "kern"}, {"value": "1", "label": "user"}, {"value": "4", "label": "auth"},
                 {"value": "16", "label": "local0"}, {"value": "unknown", "label": "unknown"}]},   // all 24 and unknown; see below
     {"key": "host",     "label": "Host",        "param": "host",       "exclude_param": "exclude_host", "domain": null},
     {"key": "app",      "label": "Program/tag", "param": "app",        "exclude_param": "exclude_app",  "domain": null}
   ]},
  {"type": "trap", "label": "SNMP traps", "default": false,
   "fields": [
     {"key": "device",     "label": "Device",             "param": "devices",       "exclude_param": "exclude_devices",    "domain": null},
     {"key": "version",    "label": "Version",            "param": "snmp_versions", "exclude_param": "",
      "domain": [{"value": "1", "label": "v1"}, {"value": "2c", "label": "v2c"}, {"value": "3", "label": "v3"}]},
     {"key": "pdu",        "label": "PDU",                "param": "pdus",          "exclude_param": "",
      "domain": [{"value": "v1trap", "label": "v1 trap"}, {"value": "trap", "label": "trap"}, {"value": "inform", "label": "inform"},
                 {"value": "unexpected", "label": "other PDU"}]},
     {"key": "trap_oid",   "label": "Trap",               "param": "trap_oid",      "exclude_param": "exclude_trap_oid",   "domain": null},
     {"key": "enterprise", "label": "Enterprise (v1)",    "param": "enterprise",    "exclude_param": "exclude_enterprise", "domain": null},
     {"key": "generic",    "label": "Generic trap (v1)",  "param": "generic",       "exclude_param": "",
      "domain": [{"value": "0", "label": "coldStart"}, {"value": "6", "label": "enterpriseSpecific"}]},   // all of 0-6; see below
     {"key": "specific",   "label": "Specific trap (v1)", "param": "specific",      "exclude_param": "exclude_specific",   "domain": null},
     {"key": "cred",       "label": "Community or user",  "param": "cred",          "exclude_param": "exclude_cred",       "domain": null},
     {"key": "status",     "label": "Status",             "param": "status",        "exclude_param": "",
      "domain": [{"value": "ok", "label": "ok"}, {"value": "auth_failed", "label": "wrong auth"}]}   // every status; see below
   ]}
]}
```
- `param` is the filter parameter a value is added to; a value goes in exactly as its `value`.
- `exclude_param` is the parameter that excludes a value. It's `""` for a field with a `domain`: to exclude a value
  there, send every other value of the domain in `param`.
- `domain` is the complete value set of a closed field (severity, facility), or `null`. The facility labels are kern,
  user, mail, daemon, auth, syslog, lpr, news, uucp, cron, authpriv, ftp, ntp, audit, alert, clock and local0–local7
  (0–23), then unknown.
- The panel shows the fields in this order. Since 1.2 there are two types, syslog and SNMP traps (`trap`); a later type
  is another entry in `types`.
- The trap type's `generic` domain is 0–6: coldStart, warmStart, linkDown, linkUp, authenticationFailure,
  egpNeighborLoss, enterpriseSpecific. Its `status` domain is `ok`, `malformed`, `unexpected_pdu` ("unexpected PDU"),
  `unknown_user` ("unknown user"), `unknown_engine` ("unknown engine"), `not_in_time` ("not in time"),
  `auth_failed` ("wrong auth"), `decrypt_failed` ("can't decrypt") and `level` ("below the user's level").

`GET /api/search/summary?q=...&fields=...&top=10&histogram=true&bucket=60&budget_ms=2000&cursor=...`: the field panel and the histogram
for a query, from one scan (SPEC §10.1.1–10.1.2). Parameters: every `/api/search` filter parameter (not `order` or `limit`), plus:
- `fields`: comma-separated field keys from the schema; all of them by default, or `none` for the histogram alone.
- `top`: values per field, 10 by default, at most 50. Fields with a `domain` return every value that has a count.
- `histogram`: `false` to leave it out.
- `bucket`: the bucket size in seconds, one of 1, 5, 15, 60, 300, 900, 3600, 7200, 21600, 86400 and 604800, giving
  at most 1,000 buckets. By default it's picked from the range (SPEC §10.1.2). Any other value is a `400`.
- `budget_ms`: this request's time budget, 2,000 by default, at most 10,000.
- `cursor`: from the previous response's `next_cursor`. The other parameters must be the same, or it's a `400`.

```json
{"type": "syslog", "from": "2026-11-13T14:00:00Z", "to": "2026-11-13T15:00:00Z",
 "matched": 48210,                           // matching lines counted so far, in [counted_from, to)
 "counted_from": "2026-11-13T14:00:00Z",     // equals from once the count is complete
 "histogram": {"bucket_seconds": 60, "source": "index",          // "index" | "scan"
               "buckets": [{"start": "2026-11-13T14:00:00Z", "count": 812, "approx": false}]},   // count: null = not counted yet
 "fields": [{"key": "host", "label": "Host",
             "values": [{"value": "web-01", "label": "web-01", "count": 20311, "filterable": true}],
             "other": 1204, "none": 37, "distinct": 14, "distinct_capped": false}],
 "next_cursor": "", "partial": false, "scanned_bytes": 0, "scanned_files": 0, "elapsed_ms": 4}
```
- **Counts are exact** for the matching lines in `[counted_from, to)`. The scan reads newest first, so a partial
  response has counted the newest part of the range. Each response carries the running totals, not a delta, so the
  client just replaces what it shows. `partial` and `next_cursor` work as in search; `next_cursor` is `""` once the
  count is complete.
- `histogram.source`:
  - `"index"` when the query has no `q`, `exclude`, `app`, `host`, `exclude_app`, `exclude_host`, facility or severity
    filter, and the bucket is at least 60 s. Devices, group, ungrouped and `exclude_devices` are allowed. It's read
    from the stats and checkpoints without opening a log file, and it's complete in the first response whatever
    `counted_from` says. `approx: true` marks a bucket spread from checkpoints (SPEC §10.1.2).
  - `"scan"` otherwise. The buckets come from the same scan as `fields`: those wholly before `counted_from` are
    `null`, and the one that straddles it has the count so far.
- Buckets start at multiples of `bucket_seconds` since the Unix epoch, in UTC (7-day buckets on Mondays, 00:00 UTC).
  The first bucket may start before `from` and the last end after `to`; both count only lines in `[from, to)`.
- `fields[].values` are sorted by count, highest first, ties by `value`. `label` is what to show: a device's name, or
  its IP if it has none, and the domain label for severity and facility.
  - `other` counts the lines with a value that isn't listed.
  - `none` counts the lines without a value (no hostname or no program/tag; always 0 for device, severity and
    facility).
  - `distinct` is the number of different values seen. At most 10,000 per field are tracked, and past that
    `distinct_capped` is true and new values count under `other`.
  - `filterable` is false for a value that `param` can't express, such as one containing a comma.
- `matched` is the sum of the histogram when only the index histogram was asked for (`fields=none`).
- With `type=trap` the fields are the trap type's and the index histogram reads the traps' own stats; the response
  has `"type": "trap"` and the same shape. A `trap_oid` or `enterprise` value's `label` is its name in the current MIB
  set (the OID when it has none), and a closed field's is its domain label. `fields` naming another type's key is a
  `400`.
- The running counts are kept on the server for 10 minutes after the last request, for at most 8 summaries (least
  recently used out first). A cursor whose counts are gone is a
  `400 {"error": "This summary expired; start it again."}`.
- At most 2 summary scans run at once; a third waits within its own budget and returns what it has. Searches never
  wait for summaries. A cancelled request stops its scan.

## Saved searches

Saved searches (SPEC §10.1.4) are named and stored on the server, shared by everyone who can open the UI.

`GET /api/saved-searches?type=syslog` → every saved search of that type (default `syslog`), sorted by name ignoring
case:
```json
[{"id": "ss_8f2c1a9d", "name": "Edge denies", "type": "syslog",
  "created": "2026-11-13T14:02:11Z", "updated": "2026-11-13T14:02:11Z",
  "query": {"q": "deny NOT 10.0.0.1", "syntax": "terms", "regex": false, "case": false, "exclude": "",
            "devices": ["10.1.0.1"], "group": "", "ungrouped": false, "exclude_devices": [],
            "severities": [], "facilities": [], "app": ["%FW-6-*"], "exclude_app": [], "host": [], "exclude_host": [],
            "order": "desc", "range": {"last": "1h"}},
  "missing_devices": [], "missing_group": false}]
```
- `query` takes every Events parameter, with the same meaning and validation as `/api/search` (lists as JSON lists,
  severities and facilities as in the export body). Missing keys take their defaults.
- `range` is either `{"last": "15m"}`, a whole number of `m`, `h` or `d` from 1 minute to 400 days, resolved against
  now each time it runs, or `{"from": "…", "to": "…"}` in RFC 3339.
- `missing_devices` lists the IDs in `devices` that the server doesn't know (any more), and `missing_group` is true
  when `group` has no devices. Both are worked out on every read and never stored. A saved search is never changed
  because a device went away: device IDs are addresses, so a device that sends again matches again. If every named
  device is missing, the search matches nothing; it never widens to all devices.

`GET /api/saved-searches/{id}` → one saved search, with an `ETag`. `404` if it's unknown.

`POST /api/saved-searches` body `{"name": "Edge denies", "type": "syslog", "query": {...}}` (`type` optional) →
`201` with the saved search.

`PUT /api/saved-searches/{id}` (the same body) → `200` with the saved search. Send `If-Match` with its `ETag`, as for
settings. A stale one gets `409 {"error": "This saved search changed since you loaded it."}`. A PUT without `If-Match`
is accepted.

`DELETE /api/saved-searches/{id}` → `204`, or `404` if it's unknown.

Limits and errors:
- At most 200 saved searches: one more is a `409 {"error": "There are already 200 saved searches; delete one first."}`.
- `name` is 1–80 characters after trimming, unique ignoring case. A clash is a
  `409 {"error": "A saved search named \"Edge denies\" already exists."}`.
- Each list in `query` holds at most 1,000 items, and the body is at most 64 KiB.
- Validation errors are a `400` with dotted keys, as for settings:
  `{"errors": {"name": "…", "query.q": "Unclosed quote starting at character 12.", "query.range.last": "…"}}`.
- They're stored in `index.db` (SPEC §10.1.4), which `woodshed reindex` keeps.
- **Type `trap`** (since 1.2): `type` may be `trap` (`GET /api/saved-searches?type=trap` lists those). Its `query`
  takes the trap filters as top-level JSON lists of strings (`"snmp_versions": ["3"]`, `"trap_oid": ["linkDown"]`,
  `"status": ["auth_failed"]`, …, as in the export body) and refuses syslog's with a dotted key
  (`{"errors": {"query.severities": "severities: not a filter for SNMP traps."}}`), and a syslog search refuses the
  trap lists the same way. A trap filter that doesn't parse is a `400` on its key (`query.trap_oid`). The response's
  `query` has every 1.1 key at its default as well, and the trap lists that are set. Saved searches without `type` are
  syslog.
- `query.range` defaults to `{"last": "24h"}` (search's default range), `query.syntax` to `text` and `query.order`
  to `desc`.

## Settings

`GET /api/settings` returns an `ETag`. `PUT /api/settings` should send it as `If-Match`; a stale one gets `409
{"error": "settings changed since you loaded them"}` (a PUT without `If-Match` is accepted, for scripts).
`GET /api/settings` / `PUT /api/settings` (whole object; the server validates and returns the saved object, or `400` with
`{"errors": {"listeners.udp.port": "message", "listeners.allowlist[2]": "message"}}`). Error keys are dotted JSON paths,
with `[i]` for list items. `[i]` indexes the list exactly as the client sent it: the server validates before any
normalising (dedupe, sort). `listeners.allowlist` entries may be a bare IP or a CIDR. `storage.data_dir` is read-only in v1: a PUT that changes it gets a `400` on that key.
```json
{
  "listeners": {"udp": {"enabled": true, "addr": "0.0.0.0", "port": 514},
                "tcp": {"enabled": true, "addr": "0.0.0.0", "port": 514},
                "tls": {"enabled": false, "addr": "0.0.0.0", "port": 6514, "allow_legacy_tls": false, "cert_file": "", "key_file": ""},
                "snmp": {"enabled": false, "addr": "0.0.0.0", "port": 162, "answer_informs": true, "communities": [],
                         "mib_dir": "", "engine_id": ""},
                "allowlist": [], "blocklist": [],
                "max_devices": 10000, "new_device_burst": 5000, "new_devices_per_minute": 200},
  "storage": {"data_dir": "...", "retention_days": 30, "retention_bytes": 21474836480, "part_bytes": 104857600},
  "ui": {"lan_mode": false, "port": 8514, "cert_file": "", "key_file": "", "require_login_local": false,
         "extra_hostnames": [], "trusted_hosts": []},
  "quiet": {"quiet_after_seconds": 300, "offline_after_seconds": 3600},
  "updates": {"check": "ask"},
  "poll": {"interval_s": 60, "timeout_ms": 2000, "retries": 1, "concurrency": 32, "max_interfaces": 64,
           "max_targets": 500, "presets": ["system", "system-info", "interfaces"]}
}
```
`updates.check` must be `"ask"`, `"on"` or `"off"` (a `400` on `updates.check` otherwise); see "Update check". A PUT
without `updates` (a 1.0 client or script) leaves it as it is.

`poll` (since 1.3) is the SNMP poller's defaults (SPEC §12.1): a new target takes them for the fields its body leaves
out. Ranges: `interval_s` 30–600, `timeout_ms` 200–10,000, `retries` 0–5, `concurrency` 1–256, `max_interfaces`
1–1,024, `max_targets` 1–5,000; `presets` any of `system`, `system-info`, `interfaces`. Errors are keyed `poll.<field>`.
A PUT without `poll` (a 1.2 client) leaves it as it is.

`listeners.tls` is the TLS syslog listener (SPEC §10.3), off by default:
- `port` is 1–65535, and differs from the UDP and TCP ports when they share an address (and from `ui.port`). Ports
  below 1024 need the same privileges as 514.
- `cert_file` / `key_file`: both empty (Woodshed's own CA and certificate) or both set, absolute paths to readable
  files. A pair that doesn't match, a certificate without EKU serverAuth (when it has an EKU), or a key the allowed
  suites can't use (anything but RSA of at least 2048 bits or ECDSA P-256/P-384/P-521) is a `400` on
  `listeners.tls.cert_file` and/or `listeners.tls.key_file`, saying what's wrong. The files are re-read on every save
  and on Retry, so a replaced file takes effect without a restart.
- Turning `enabled` on for the first time without `cert_file` creates the CA and the certificate before the PUT
  returns. Turning it off keeps them.

`listeners.snmp` is the SNMP trap receiver (SPEC §11.2), off by default; see "SNMP trap receiver". A PUT without it
(a 1.1 client or script) leaves it as it is.
- `port` is 1–65535 and differs from the UDP syslog port when they share an address. Ports below 1024 need the same
  privileges as 514 (on macOS a specific address below 1024 is refused; the wildcard works).
- `answer_informs`: reply to InformRequests (the default). Off, informs are stored without an answer.
- `communities`: the v1/v2c accept list (empty accepts any community), at most 100 strings of 1–255 bytes. They're
  secrets, so they're kept in the SNMP credentials file (SPEC §11.2.6), never in the TOML. `GET` returns each as
  `"#<hash8>"` (`#` and the first 8 hex digits of its SHA-256); a `PUT` that sends a `"#…"` value back keeps the
  community it stands for, and a plain string adds a new one, so the settings round trip never carries a stored
  secret. A `"#…"` value that matches no stored community is a `400` on `listeners.snmp.communities[i]`.
- `mib_dir`: an absolute path, or `""` for `<data>/mibs` (created at start). A folder you name that's missing is
  listed as an error under `/api/snmp` `mibs`; it isn't created.
- `engine_id`: `""` (the generated one) or 5–32 bytes as hex (10–64 hex digits), not all zeros or all `ff`. A change
  applies at once; the stored ID is kept for when the override is removed.
- The file-only `listeners.snmp.v3_strict_time` (default `false`) isn't in `/api/settings` (SPEC §11.8 #28).

`GET /api/storage/history` → `[{"time", "file", "device_id", "bytes", "reason": "age|cap|low_disk", "type": "syslog|trap"}]`

## TLS syslog listener

SPEC §10.3. The listener is off until `listeners.tls.enabled` is set.

`GET /api/tls`
```json
{"enabled": true, "port": 6514, "source": "woodshed",           // "woodshed": its own CA | "file": cert_file/key_file
 "allow_legacy_tls": false,
 "ca": {"subject": "CN=Woodshed CA logs-01 2026-11-13", "not_before": "2026-11-13T15:00:00Z", "not_after": "2037-12-31T23:59:59Z",
        "sha256": "AB:CD:…", "sha1": "AB:CD:…"},                // null when source is "file", or before TLS was first turned on
 "cert": {"subject": "CN=logs-01.example.net", "issuer": "CN=Woodshed CA logs-01 2026-11-13",
          "not_before": "2026-11-13T15:00:00Z", "not_after": "2036-11-13T15:00:00Z", "sha256": "AB:CD:…",
          "dns_names": ["localhost", "logs-01", "logs-01.example.net", "logs-01.local"], "ip_addresses": ["10.1.0.50", "127.0.0.1", "::1"],
          "missing_names": []},                                // null before TLS was first turned on
 "firewall": {"state": "disabled", "command": "woodshed tls on"}}   // state: "ok" | "missing" | "disabled" | "wrong_port" | "unknown"
```
- `sha256` and `sha1` are the fingerprints of the DER certificate, as upper-case hex pairs separated by colons (like
  `ui_cert_fingerprint`). `sha1` is given for the CA only, for devices that show nothing else.
- `missing_names` are the host's DNS names (hostname, search-domain names, `ui.extra_hostnames`) that the certificate
  doesn't cover; they drive `tls_cert_names`. Always `[]` with `source: "file"`.
- `firewall.state` is what Woodshed can see of the OS firewall for this port. It's always `"unknown"` on Linux and
  macOS, where `command` is `""` and Settings shows the commands for the common firewalls instead (SPEC §10.3.6). On
  Windows it's also `"unknown"` when the firewall's answer can't be read.

**Renew:** `POST /api/tls/renew` body `{"new_ca": false}` → `200` with the object above.
- `new_ca: false` makes a new leaf with a new key and the current host names, signed by the same CA, so devices need
  no change. New connections get it at once; open ones keep theirs.
- `new_ca: true` also replaces the CA, and every device must import the new one. The UI asks for confirmation first.
- With `source: "file"` it's a `409 {"error": "This server uses your own certificate; replace the files instead."}`.
- Nothing renews on its own: this route, and `woodshed tls renew [--new-ca]`, are the only ways. Each renewal is an
  event (in the export's `woodshed-events.log`) with the old and new fingerprints.

**CA download, PEM:** `GET /api/tls/ca.pem` → the CA certificate as PEM (`application/x-pem-file`,
`Content-Disposition: attachment; filename="woodshed-ca.pem"`).

**CA download, DER:** `GET /api/tls/ca.der` → the same certificate as DER (`application/pkix-cert`,
`filename="woodshed-ca.cer"`).

Both are a `404` when TLS has never been turned on (`{"error": "TLS has never been turned on, so there's no CA
certificate yet."}`), or with `source: "file"` (`{"error": "This server uses your own certificate; get its CA from
whoever issued it."}`). With a login, the UI fetches the file with the session header and saves the response, so no
download ticket is needed.

`GET /api/tls/failures` → senders whose TLS handshakes failed in the last 24 h, most failures first, at most 200:
```json
[{"ip": "198.51.100.7", "count_24h": 144, "last_seen": "2026-11-13T15:10:00Z", "reason": "cert_rejected",
  "detail": "remote error: tls: unknown certificate authority", "device_id": ""}]
```
- `reason` is the latest failure's: `cert_rejected`, `version`, `cipher`, `not_tls`, `timeout`, `closed`, `busy` or
  `other` (SPEC §10.3.4). `detail` is the TLS error text or the alert, with nothing from the sender's data.
- Every failing sender is listed, including known devices; `device_id` is then set (`""` otherwise). A sender that
  only fails appears here and nowhere else. At most 10,000 addresses are tracked, and the least recently seen is
  evicted.

**Banners** (warn, action `tls_renew`, which opens Settings → TLS, unless noted). They show only while the listener
is on:
- `tls_cert_expiring`: from 60 days before the certificate or the CA expires; the text gives the date, and says
  whether devices need the new CA.
- `tls_cert_names`: the host has a DNS name the certificate doesn't cover (`cert.missing_names`; Woodshed's own
  certificate only).
- `tls_legacy` (action `""`): `allow_legacy_tls` is on.
- `tls_firewall` (action `""`): Windows only, while the listener is on and its firewall rule is disabled, missing or
  on another port; the text gives the command to run as an administrator (`firewall.command`).

**CLI** (not HTTP; as an administrator): `woodshed tls on|off|renew [--new-ca]|status`, described in SPEC §10.3.6.
`woodshed status` also prints the TLS listener, both fingerprints and the expiry.

## SNMP trap receiver

SPEC §11.2 (since 1.2). The listener is off until `listeners.snmp.enabled` is set (see "Settings"). Traps are
stored in `logs/<device>/traps/` and searched with `type=trap` (see "Search"). The receiver's state, its engine, the
MIB folder and the v3 users are here whether or not the listener is on.

`GET /api/snmp`
```json
{"enabled": true, "port": 162,
 "engine": {"id": "8000000005a1b2c3d4e5f60718", "boots": 12, "time": 86400},
 "counts_24h": {"received": 15230, "informs_answered": 212, "replies_rate_limited": 0, "discovery_reports": 3,
                "time_resyncs": 0, "by_status": {"ok": 15201, "malformed": 4, "auth_failed": 25}},
 "mibs": {"dir": "/var/lib/woodshed/mibs", "files": 41, "names": 18234, "loaded_at": "2026-11-14T08:00:03Z",
          "errors": [{"file": "EXAMPLE-MIB.my", "line": 212, "message": "unexpected token \"SEQUENCE\""}],
          "warnings": []},
 "firewall": {"state": "disabled", "command": "woodshed snmp on"}}   // state: "ok" | "missing" | "disabled" | "wrong_port" | "unknown"
```
- `engine` is Woodshed's own v3 engine (authoritative for informs): `id` in hex (RFC 3411's "administratively
  assigned" format, `80000000` `05` and 8 random bytes, made at the first start, or `listeners.snmp.engine_id`),
  `boots` (one more at every start) and `time` (seconds since the start). Devices sending v3 informs to a fixed
  engine ID need `id`.
- `counts_24h` covers the last 24 hours, since the server started. `received` counts every datagram the listener
  read (community refusals and discovery probes included, which aren't stored). `by_status` counts the stored ones by
  status, and lists only the statuses with a count.
  `discovery_reports` counts every Report sent (a discovery probe, an inform to another engine ID, a v3 message
  outside the time window). `replies_rate_limited` counts the Responses and Reports not sent because of the reply
  limits (100 a second per source address, 1,000 in all). `time_resyncs` counts authenticated v3 traps outside the
  time window whose clock was relearned (SPEC §11.8 #28).
- `mibs`: the MIB folder in effect, the files read, the names known (the built-in set included) and when it was
  read. `errors` are files that didn't load (and a folder that can't be read); `warnings` don't stop a file (a
  missing import, an unresolvable parent).
- `firewall` is as for TLS: what Woodshed can see of the Windows rule for the port, for the installed service only;
  always `"unknown"` elsewhere, with `command` `""`.

**Reload MIBs:** `POST /api/snmp/mibs/reload` → `200` with the `mibs` object above. MIBs load only at start, when
`mib_dir` changes, and here. Records already stored keep the names they were written with; search results and the
field panel name OIDs from the current set.

`GET /api/snmp/failures` → senders whose v3 traps failed, or whose packets were malformed, in the last 24 h, most
first, at most 200:
```json
[{"ip": "198.51.100.7", "count_24h": 25, "last_seen": "2026-11-14T09:10:00Z", "status": "auth_failed",
  "detail": "user monitor: wrong digest (sha-256)", "device_id": "198.51.100.7", "time_resyncs_24h": 0}]
```
- `status` and `detail` are the latest failure's. `detail` names the user, engine or decoding error, never key
  material.
- `time_resyncs_24h` counts the sender's v3 clock relearns; a sender with only relearns (`count_24h` 0) is listed
  with `status` `not_in_time`, so a replay shows as a burst.
- At most 10,000 addresses are tracked; the least recently seen is evicted.

**v3 users** (SPEC §11.2.6). They're kept in the SNMP credentials file in the data folder, never in the TOML or in
`/api/settings`. Secrets are never returned, logged, exported or accepted on a command line.

`GET /api/snmp/users`
```json
[{"name": "monitor", "level": "authPriv", "auth": "sha-256", "priv": "aes-128", "key_ext": "draft",
  "engine_ids": [], "auth_set": true, "priv_set": true, "stored": "passphrase", "readable": true, "weak": []}]
```
- Sorted by name. `auth`: `none`, `md5`, `sha`, `sha-224`, `sha-256`, `sha-384`, `sha-512`. `priv`: `none`, `des`,
  `aes-128`, `aes-192`, `aes-256`. `key_ext` is `draft` or `alt` for AES-192/256 (`draft` otherwise); a body may send `draft` with any `priv`, while `alt` with anything but AES-192/256 is a `400`. `level` follows
  from them; a user accepts its own level and above, never below.
- `weak` lists the user's protocols Settings labels weak (`md5`, `sha`, `des`). They're accepted.
- `stored`: `"passphrase"`, or `"localized"` when `engine_ids` is set: then only the keys localized to those engines
  (and to Woodshed's own, for informs) are kept and the passphrases are discarded.
- `auth_set` / `priv_set` say a secret is stored for the protocol (passphrase or keys).
- `readable` is false when the credentials file's secrets can't be decrypted here (Windows, after the data folder
  moved to another machine or account): the user then needs its passphrases again (banner `snmp_credentials`).

`POST /api/snmp/users` body `{"name": "monitor", "auth": "sha-256", "auth_pass": "…", "priv": "aes-128",
"priv_pass": "…", "key_ext": "draft", "engine_ids": []}` → `201` with the user (without secrets).

`PUT /api/snmp/users/{name}` (the same body; GET's read-only fields `level`, `auth_set`, `priv_set`, `stored`, `readable` and `weak` are accepted and ignored, so a GET → PUT round trip works) → `200` with the user. A missing or empty `auth_pass` / `priv_pass`
keeps the stored one, unless the protocol changes (then it's required). A user can't be renamed: a `name` other than
the path's is a `400` on `name` (delete it and add the new name). `404` if unknown.

`DELETE /api/snmp/users/{name}` → `204`, `404` if unknown.

- Names are 1–32 bytes without control characters, unique (exact match, as USM compares them). Passphrases are
  8–256 bytes. `engine_ids` holds at most 32 hex engine IDs (5–32 bytes each). Privacy needs authentication. At most
  100 users.
- Validation errors: `400 {"errors": {"auth_pass": "…", "engine_ids[1]": "…"}}`. A duplicate name: `409`.
- Every change applies at once and is an event naming the user and its level.

**Banners:**
- `snmp_firewall` (warn, action `""`): the installed service on Windows, while the SNMP listener is on and its
  firewall rule "Woodshed SNMP traps (UDP 162)" is disabled, missing or on another port; the text gives
  `woodshed snmp on`.
- `snmp_credentials` (warn, action `""`): v3 users whose secrets can't be decrypted here (`readable: false`).
- `snmp_mibs` (info, action `""`): files in the MIB folder didn't load; Settings lists them.

**CLI** (not HTTP; as an administrator): `woodshed snmp on|off|status` (SPEC §11.2.7). `woodshed status` also prints
the SNMP listener, the engine ID, the last 24 h counts and the failing senders. `woodshed search --type trap`,
`woodshed send --proto trap` and `woodshed bench --proto trap` are in docs/user-guide.md.

## SNMP poller

Since 1.3 (SPEC §12). With no targets nothing is polled and nothing is sent. Communities are write-only: `GET` says
only `community_set`, and nothing else ever returns them.

### Poll targets
`GET /api/poll/targets` → every target, sorted by device then address (`GET /api/poll/targets/{id}` → one, with an
`ETag`):
```json
[{"id": "pt_5c1e9a2b", "address": "10.1.0.1", "port": 161, "device_id": "10.1.0.1", "enabled": true,
  "version": "3", "community_set": false, "v3_user": "monitor",
  "interval_s": 60, "timeout_ms": 2000, "retries": 1,
  "presets": ["system", "system-info", "interfaces"], "interfaces": "all", "max_interfaces": 64, "pinned": [],
  "custom": [{"oid": "1.3.6.1.4.1.32473.1.2.0", "kind": "scalar", "label": "queue depth", "max_rows": 0}],
  "state": {"status": "ok", "last_attempt": "2026-11-15T10:00:00Z", "last_ok": "2026-11-15T10:00:00Z",
            "failing_since": null, "backoff_s": 0, "error": "", "rtt_ms": 4,
            "engine_id": "80001f8880a1b2c3d4", "sys_name": "edge-fw-01", "sys_descr": "…",
            "hc_counters": true, "host_resources": true, "interfaces_polled": 24, "interfaces_total": 26}}]
```
- `version`: `"1"`, `"2c"` or `"3"`. `community_set` says whether a v1/v2c community is stored; the community itself
  is never returned. `v3_user` names a user from `/api/snmp/users`.
- `interfaces`: `"all"` (up to `max_interfaces`) or a list of `ifName`s and indexes (`["eth1", "eth2", 7]`).
- `pinned` (since 1.3, SPEC §12.11 #3): `ifName`s and indexes polled first when `max_interfaces` leaves interfaces out
  (default `[]`); the device page's "pin" adds to it.
- `state` may also have `"wrong_source": "192.0.2.9:161"`: replies with this target's request IDs came from another
  address (they're dropped; the agent needs fixing).
- `custom[].kind`: `"scalar"` or `"walk"`; `max_rows` (walks only) 1–1,024, default 128. At most 32 entries.
- Fields left out of a body take the Settings defaults (`poll` in `/api/settings`) at the time of the request; on a
  `PUT`, the target's current values. The read-only `id`, `community_set` and `state` are accepted and ignored, so a
  `GET` body can be sent back as it is.
- `state.status`: `ok`, `failing` (no answer or an error for 1–2 cycles), `backing_off`, `disabled`, or `pending` (not
  polled yet). `error` is the last failure's text, without secrets.

**Add:** `POST /api/poll/targets` body `{"address": "10.1.0.1", "version": "2c", "community": "…", …}` → `201` with the
target. `device_id` defaults to the address; a new address becomes a device on its first answer.

**Change:** `PUT /api/poll/targets/{id}` (the same body) → `200`. A missing `community` keeps the stored one; `""`
with `version` `"1"` or `"2c"` is a `400`. If-Match with the target's `ETag`, as for saved searches.

**Delete:** `DELETE /api/poll/targets/{id}` → `204`. The device's poll files stay until retention deletes them.

- Limits: at most 500 targets (`poll.max_targets`; `409` beyond); one target per address and port (`409`, with
  `errors.address`); one target per device (a second with the same `device_id` is a `400` on `device_id`, so a
  device's poll files hold one target's cycles). `address` is an IP address (no names: nothing is looked up), and so
  is `device_id` (a device ID). `port` 1–65535.
- Validation errors: `400 {"errors": {"address": "…", "custom[2].oid": "…"}}`. A `v3_user` that doesn't exist is a
  `400` on `v3_user`.

**Test poll:** `POST /api/poll/test` body: a target as for **Add** (not saved), or `{"id": "pt_…"}` →
```json
{"ok": false, "exit": "partial",
 "steps": [{"step": "discovery", "ok": true, "detail": "engine 80001f8880a1b2c3d4, boots 7", "rtt_ms": 3},
           {"step": "system", "ok": true, "detail": "edge-fw-01, up 12 d 3 h", "rtt_ms": 4},
           {"step": "host_resources", "ok": false, "detail": "not available on this device (noSuchObject)", "rtt_ms": 4},
           {"step": "interfaces", "ok": true, "detail": "26 interfaces, 64-bit counters; 24 would be polled", "rtt_ms": 9}]}
```
`exit` is `ok`, `no_answer`, `auth` or `partial`, the CLI's exit codes by name (SPEC §12.7). At most one test per
target at a time, and 10 a minute in all (`429` with `Retry-After` beyond). `{"id": …}` with other fields tests the
stored target with those fields changed (a missing `community` uses the stored one). Step names: `discovery` (v3),
`system`, `host_resources`, `interfaces`, `oid <oid> (<label>)` per custom OID, and `replies` when replies came from
another address.

### Poll data for graphs
`GET /api/poll/series?device=10.1.0.1&from=…&to=…&bucket=60&series=in_bps,out_bps,cpu,if.eth3.in_bps` →
```json
{"device_id": "10.1.0.1", "bucket_seconds": 60, "source": "files",       // "files" | "rollup"
 "series": [{"key": "in_bps", "label": "In (all interfaces)", "unit": "bit/s",
             "points": [{"start": "2026-11-15T10:00:00Z", "avg": 81234567, "max": 90123456, "count": 1}]}],
 "markers": [{"time": "2026-11-15T10:04:00.410Z", "kind": "restart", "reboot": "1",
              "detail": "sysUpTime and hrSystemUptime reset"}],
 "partial": false, "next_cursor": ""}
```
- Series keys: `in_bps`, `out_bps` (summed over interfaces), `max_if_in_bps`, `max_if_out_bps`, `errors_d`,
  `discards_d`, `cpu`, `mem_used_pct`, `uptime_s`, `if.<ifName or index>.<in_bps|out_bps|in_err_d|out_err_d|in_disc_d|out_disc_d|oper>`,
  and `oid.<oid>[.<row>]`. At most 16 series per request. Unknown keys are a `400`.
- `bucket` as for the summary (SPEC §10.1.2), default from the range, so strips line up with the histogram.
- `source` is `rollup` when every requested series is a headline series and the bucket is at least an hour; otherwise
  the poll files are read with the search budget (`partial` and `next_cursor` as for the summary). A point with
  `count: 0` is "not measured", drawn as a gap.
- `markers` are the restarts and reboots in the range, and with any `if.` series, that interface's oper changes:
  `{"time", "kind": "oper", "if": "eth3", "oper": "down", "was": "up", "detail": "eth3 down (was up)"}`. At most 100
  per request.
- `from` defaults to a day before `to`, `to` to now. A `next_cursor` (when `partial`) is passed back as `cursor` to read
  on from where the budget stopped.

**Timeline strips:** `GET /api/poll/timeline?devices=a,b&group=…&ungrouped=true&from=…&to=…&bucket=…` → for the selected devices
that are polled (at most 4, the busiest by peak traffic, then `more`), the strips SPEC §12.5 describes, in the series
shape above, plus every selected device's markers: `{"devices": [{"device_id", "series": [...]}], "markers":
[{"device_id", "time", "kind", "reboot", "detail"}], "more": 2}`.

**Device panel:** `GET /api/poll/device/{id}?from=…&to=…` →
```json
{"device_id": "10.1.0.1", "target_id": "pt_5c1e9a2b", "address": "10.1.0.1",
 "system": {"sys_name": "edge-fw-01", "sys_descr": "…", "uptime_s": 1048512, "last_restart": "2026-11-15T10:04:00.410Z",
            "cpu": {"now": 12, "peak": 91, "peak_at": "2026-11-15T09:30:00Z"},
            "mem_used_pct": {"now": 40, "peak": 72, "peak_at": "2026-11-15T09:31:00Z"}},
 "interfaces": [{"index": 3, "name": "eth3", "alias": "uplink", "oper": "up", "speed_mbps": 1000,
                 "in_bps": 81234567, "out_bps": 3456789, "peak_in_bps": 812345678, "peak_out_bps": 95123456,
                 "in_err_d": 12, "out_err_d": 0, "in_disc_d": 340, "out_disc_d": 0, "oper_changes": 2}],
 "charted": ["eth1", "eth3", "eth2", "eth7"],
 "interfaces_left_out": 2}
```
`charted` is the 4 busiest interfaces in the range, the default chart set. The interface list is sorted by peak
traffic, highest first. The panel also has `hc_counters`, `host_resources` (`null` before the first answer),
`last_cycle`, `rtt_ms`, `markers` (restarts and every interface's oper changes, as above) and `partial`. A device no
target polls is a `404`.

### Polling state

`GET /api/poll` → the polling state, for Settings and `woodshed status`:
```json
{"targets": 12, "answering": 11, "failing": 1, "backing_off": 0, "last_cycle": "2026-11-15T10:00:00Z",
 "hour": {"cycles": 720, "failures": {"timeout": 3}, "overruns": 0, "unmatched": 0}}
```
`last_cycle` is `null` before the first; `failures` counts the last hour's failed cycles by status.

Banners (since 1.3): `poll_unreachable` (warn, action `""`): polled devices that haven't answered for 10 min, named in
the text. `poll_overrun` (warn, action `""`): cycles skipped in the last hour because polling couldn't keep up; the
text suggests a longer interval or a higher `poll.concurrency`.

**CLI** (not HTTP): `woodshed poll test <address> …`, `woodshed search --type poll`, and the `woodshed status`
Polling row, as in SPEC §12.7.

## Update check

The opt-in update check (SPEC §10.2): off until someone agrees, it asks once, and when it's on it fetches one public file
a day. It never downloads or installs anything.

`GET /api/updates`
```json
{"check": "on",                                 // "ask" | "on" | "off", from updates.check
 "available": true,                             // false in a build that can't check (not a release version, or no releases_url)
 "url": "https://gmccollu.github.io/woodshed/releases.json",
 "current": "1.1.0",
 "last_check": "2026-11-13T09:12:44Z",          // null until the first check
 "last_result": "ok",                           // "" (never checked) | "ok" | "error"
 "last_error": "", "last_error_kind": "",       // kinds: dns, connect, proxy, tls, timeout, http_status, redirect, too_large, bad_json, no_release
 "next_check": "2026-11-14T08:40:02Z",          // null unless check is "on"
 "latest": {"version": "1.2.0", "prerelease": false,
            "url": "https://github.com/gmccollu/woodshed/releases/tag/v1.2.0"},   // null until a check succeeds, while it isn't "on", and after turning it off
 "update_available": true,
 "dismissed_version": ""}
```
- `latest` is the newest release this build would offer: the stable one, or for a prerelease build the newer of
  stable and prerelease. `update_available` is true when it's newer than `current`. `latest.url` is
  `releases_url + "/tag/" + <the tag name>` when the file's `html_url` is exactly that, and `releases_url` when
  `html_url` is anything else on the releases page. An `html_url` outside the releases page makes the check fail
  (`bad_json`), with no banner.
- `last_error` is a short message Woodshed writes itself ("TLS certificate not trusted (a proxy that inspects
  HTTPS?)"); nothing from the response is shown.

`PUT /api/updates` body `{"check": "on"}` or `{"check": "off"}` → `200` with the object above. It writes
`updates.check` to the config like a Settings save (the settings ETag changes too). The banner's **Turn on** and
**No thanks** use it. `"ask"` isn't accepted here (`400`); Settings can set it. Turning it on checks within a
minute; turning it off cancels the next check and clears `latest` and the banner.

`POST /api/updates/check` → `202` (no body): check now. `409` unless `check` is `"on"` (and in a build that can't
check); `429` with `Retry-After` within 60 s of the last one started this way.

`POST /api/updates/dismiss` body `{"version": "1.2.0"}` → `204`: hide the `update_available` banner for that
version, for everyone. A newer version shows it again. `400` if `version` isn't a version.

**Banners** (in `/api/status`, after errors and warnings):
- `update_prompt` (info, action `update_choice`): shown while `updates.check` is `"ask"`, in a build that can check.
  The UI shows **Turn on** and **No thanks**, which send `PUT /api/updates`. Text: "Check for new Woodshed versions
  once a day? It fetches one public file from gmccollu.github.io and sends nothing about this server."
- `update_available` (info, action `update_dismiss`): "Woodshed 1.2.0 is available (this is 1.1.0)." It has a `url`
  with the release page (`latest.url`). `url` is an optional field on every banner, omitted when empty.

**In the TOML:**
```toml
[updates]
check = "ask"   # "ask" (the default: ask once in the UI), "on" or "off"
```
A config without `[updates]` (a fresh install, an upgrade from 1.0, portable mode) means `"ask"`. Setting `"on"` or
`"off"` before the first start skips the banner, and so does `woodshed update-check on|off` (an administrator
command, like `lan-mode`) or installing with `WOODSHED_UPDATE_CHECK=on|off|ask` (the MSI property, or the environment
variable for pkg, deb and rpm, which runs `woodshed update-check <value>`; see docs/install.md for which installers
pass it through). The request itself, the schedule and the state file (`<data>/update-check.json`) are in SPEC §10.2.

## Auth

Two modes, set by `ui.lan_mode` in `/api/settings`:
- **Localhost (default):** plain HTTP on `127.0.0.1:<ui.port>`, no login. The server still refuses a `Host` header
  other than `localhost`, `127.0.0.1` or `[::1]` with the UI port (`403`), so a web page can't reach it by
  rebinding its own name to 127.0.0.1. Names in `ui.trusted_hosts` (exact host or host:port, e.g. a reverse proxy's
  public name) are also accepted. The `403` body names the rejected Host and points at `ui.trusted_hosts`.
- **LAN:** HTTPS on every interface, with a password. Turning it on needs a password first: a `PUT /api/settings`
  with `"lan_mode": true` and no password set gets `400 {"errors": {"ui.lan_mode": "..."}}`. The certificate is
  self-signed and generated on the machine (or one the user configured). Plain `http://` on the same port gets a
  `301` to `https://`. Changing `lan_mode` or `port` restarts the UI server just after the PUT's response, which
  also closes open live tails; the UI has to reload at the new address (`https://` after turning LAN mode on,
  `http://localhost:<port>/` after turning it off). The PUT response then carries `"restarting": true`.
- **Certificate names:** the self-signed certificate covers localhost, the hostname, `<hostname>.local`, the
  hostname qualified with each DNS search domain (`/etc/resolv.conf` on Linux and macOS, the primary DNS suffix on
  Windows), every stable address, and every name in `ui.extra_hostnames`. It's regenerated (same key) when that set
  gains a name or address.

In both modes, a state-changing request (anything but GET/HEAD/OPTIONS) from another origin is refused with `403`
(`Sec-Fetch-Site` or `Origin` vs `Host`). In LAN mode every `/api/` route needs a session (`401 {"error": ...}`
otherwise) except `/api/session`, `/api/login`, `/api/logout` and `GET /healthz`; the static UI files are public.

`GET /api/session`
```json
{"mode": "lan", "auth_required": true, "authenticated": true, "password_set": true}
```
In localhost mode: `{"mode": "localhost", "auth_required": false, "authenticated": true, "password_set": false}`.
`authenticated` is true only when the request carries both the session cookie and the matching `X-Woodshed-Session`
header (below). `/api/session` never returns the session secret.
`password_set` reports the real state in both modes (the LAN checkbox depends on it).

`ui.require_login_local` (default false; **turned on automatically when a password is first set**, and can be
turned off): when true and a password is set, localhost mode also requires login
(the same session rules as LAN mode). It can't be turned on without a password.

`PUT /api/password` requires `current` whenever a password is already set, in both modes. `woodshed
reset-password` on the machine is the only way to replace a password without knowing it.

**Forgotten password:** on the Woodshed machine, an administrator runs `woodshed reset-password`. It deletes the
password hash, turns LAN mode off in the config, and restarts the UI on `http://localhost:<port>/`. There's no
recovery over the network by design.

**After a `ui.lan_mode` or `ui.port` change** the server restarts after sending the response. The new address is
`https://<host the browser used>:<port>/` with LAN mode on, or `http://localhost:<port>/` with it off. There's no
"restarted" signal (the new address is a different origin, so the UI can't poll it under the CSP); the UI shows the
link straight away.

**`ui.cert_file` / `ui.key_file`:** both empty (self-signed) or both set, absolute paths to readable files. A
mismatched or unreadable pair is a 400 on `ui.cert_file` and/or `ui.key_file`.
The UI calls this first: in LAN mode with `authenticated: false` it shows the login form.

`POST /api/login` body `{"password": "..."}` → `200` with the session object above plus `"session_secret": "opaque"`
(returned only here, once per login), and a session cookie
(`__Host-woodshed_session`, `Secure; HttpOnly; SameSite=Strict; Path=/`; with `require_login_local` on plain
localhost, `woodshed_session`, the same without `Secure`). `401` for a wrong password, `400` in localhost mode
without `require_login_local`. Limits (`429` with `Retry-After`): each IP (each /64 for IPv6) gets 5 quick attempts,
then one a second; from the 5th failure (the count resets after 15 minutes without one), each address (the full
address, zone included) and each IPv4 address or IPv6 /64 waits 1 s, 2 s, 4 s … up to 15 minutes before its next
attempt, after which the right password works; and over 50 failures an hour across all clients spaces every attempt
60 s apart. A successful login also sets `woodshed_known_client` (`HttpOnly; SameSite=Strict`, `Secure` in LAN
mode, 90 days; stored hashed): attempts that carry it skip the per-network and global limits, though not their
own address's backoff.

`POST /api/logout` → `204`, ends the session and clears the cookie.

`PUT /api/password` body `{"current": "...", "new": "..."}` → `204`. `new` is 8–1024 bytes; a bad one gets
`400 {"error": ..., "errors": {"new": "..."}}`. Once a password is set, `current` is required in every mode (`403` if
wrong; it counts toward the login limits). With a session it also ends every other session. The password is stored only as an Argon2id hash in
`<data>/ui-password.hash` (mode 0600), never in the TOML.

**Session secret (replaces the CSRF token):** whenever login is required (LAN mode, or `require_login_local`),
every `/api/` request except `/api/session`, `/api/login`, `/api/logout` and `/healthz` must carry **both** the
session cookie **and** an `X-Woodshed-Session: <session_secret>` header; either one alone gets `401`. The cookie
isn't port-scoped, so another server on the same host could receive it; the secret lives only in the page's
`localStorage`, which is scoped to the exact origin (scheme, host and port), and a custom header can't be sent
cross-site, so it also does the CSRF token's job. The live tail therefore uses `fetch()` with a streaming reader
instead of `EventSource` (which can't send headers); the stream format is unchanged.

`GET /healthz` → `{"ok": true}` (no login in either mode).

## Run-state file

Not HTTP: a running server keeps `woodshed.state.json` in its data folder (mode 0640, rewritten within a second of
any change, deleted at a clean stop) for `woodshed status`, which reads it when the API needs a login or can't
answer. It only means something while the data folder's lock is held (a crash leaves it behind).
```json
{"pid": 4242, "version": "0.9.0", "started_at": "...", "config": "/etc/woodshed/woodshed.toml", "data_dir": "/var/lib/woodshed",
 "ui": {"listening": true, "url": "https://host:8514/", "lan_mode": true, "cert_fingerprint": "AB:CD:…"},
 "listeners": [{"proto": "udp", "addr": "0.0.0.0", "port": 514, "ok": true, "error": ""}],
 "udp_rcvbuf_bytes": 4194304, "udp_rcvbuf_requested_bytes": 33554432,
 "banners": [{"kind": "udp_buffer_small", "level": "warn", "text": "The UDP receive buffer is 4 MiB; …", "action": ""}]}
```
`listeners` and `banners` are exactly `/api/status`'s (banners sorted errors first); `listeners` is `[]` before the
listeners start. `ui.error` and `ui.cert_fingerprint` are omitted when empty. Once TLS syslog has been turned on, a
`tls` object gives `enabled`, `port`, `source`, `ca_sha256`, `ca_sha1`, `ca_not_after`, `cert_sha256`,
`cert_not_after`, `error` (when the certificate can't be loaded) and `failures` (the 5 senders failing most:
`ip`, `count_24h`, `reason`, `last_seen`), for `woodshed status` and `woodshed tls status`. While the SNMP listener
is on (or a v3 user is set, or a trap was received), an `snmp` object gives `enabled`, `port`, `answer_informs`,
`engine_id`, `engine_boots`, `received_24h`, `informs_answered_24h`, `replies_rate_limited_24h`, `time_resyncs_24h`,
`by_status_24h`, `users`, `unreadable_users`, `mib_names`, `mib_errors` and `failures` (the 5 senders failing most:
`ip`, `count_24h`, `status`, `detail`, `last_seen`), for `woodshed status` and `woodshed snmp status`. While any
SNMP poll target is configured (since 1.3), a `poll` object gives `targets`, `answering`, `not_answering` (each
`device_id`, `address`, `since`) and `last_cycle`, for `woodshed status`'s Polling row.

## Errors

Any non-2xx returns `{"error": "human-readable message"}`.

## Flows

Since 2.0 (SPEC §13): the flow listener (flow v5/v9, IPFIX), `type=flow` in search, the summary, saved searches and
exports, and the flow routes. Everything is additive (SPEC §13.9).

### Flow listener and state

**Settings:** `/api/settings` gains `listeners.flow` and `storage.flow_budget_bytes`:
```json
{"listeners": {"flow": {"enabled": false, "addr": "0.0.0.0", "flow_port": 2055, "ipfix_port": 4739,
                        "template_timeout": "30m", "rule_id_ies": []}},
 "storage": {"flow_budget_bytes": 0}}
```
- Shown here as fragments of the settings object. `flow_port` / `ipfix_port`: 0 (off) or 1–65535, not shared with
  another UDP listener on an overlapping address; at least one non-zero while enabled. `template_timeout` 1 min to
  24 h. `rule_id_ies`: up to 8 `"<enterprise number>:<element ID>"` strings naming the IEs that carry a rule or ACL
  identifier (there's no standard one; SPEC §13.2.1); the first one a record has fills `rule_id`.
- `flow_budget_bytes`: 0 means 40 % of `storage.retention_bytes`; otherwise at least 1 GiB and at most 90 % of it
  (a `400` on the key otherwise). File-only: `listeners.flow.pending_bytes`, `queue_messages`, `queue_bytes`.
- `/api/status.listeners` gains `{"proto": "flow", …}` and `{"proto": "ipfix", …}` entries while enabled.

**Flow state:**

`GET /api/flows` →
```json
{"enabled": true,
 "budget": {"bytes": 8589934592, "used_bytes": 5100000000, "estimated_days": 4.8},
 "exporters": [{"device_id": "10.1.0.1", "domains": [{"id": 1, "sampling": 1000, "templates": 6, "last_template": "2026-11-16T09:58:01Z"}],
                "records_per_sec": 1180.5, "pending_bytes": 0,
                "counts_24h": {"records": 101000000, "late": 120, "no_template": 0, "malformed": 0, "sequence_gaps": 3, "duplicates": 0},
                "clock_skew_ms": 210, "time_source": "exporter", "last_seen": "2026-11-16T10:00:01Z"}]}
```

### Flow search and top-N

`type=flow` is accepted by `/api/search`, `/api/search/summary`, saved searches, exports and `woodshed search`.

**Filters** (with `type=flow` only; the other types' filters are a `400` with it, and `q` is
`400 {"error": "q: flows have no text; use src, dst, ip, port or proto."}`):
- `src`, `dst`, `ip` and `exclude_src`, `exclude_dst`, `exclude_ip`: comma-separated addresses or CIDR prefixes.
- `src_port`, `dst_port`, `port` and their `exclude_` forms: comma-separated ports or ranges (`8000-8100`).
- `proto`, `exclude_proto`: names (`tcp`, `udp`, `icmp`, `icmpv6`, `gre`, `esp`, `sctp`) or numbers 0–255.
- `in_if`, `out_if` and excludes: interface indexes or names (from the exporter's options data).
- `domain`: observation domain or source IDs. `tcp_flags`: any of `fin,syn,rst,psh,ack,urg,ece,cwr`.
  `sampled`: `yes`, `no`, `unknown`. `status`: `ok`, `late`, `no_template`, `malformed`.
- Firewall events and NAT (SPEC §13.2.1): `fw_event` (`created`, `deleted`, `denied`, `alert`, `update`, or 0–255),
  `nat_event` (registry names or numbers), `post_nat_src`, `post_nat_dst`, `post_nat_ip` and their `exclude_` forms
  (addresses or prefixes), `post_nat_src_port`, `post_nat_dst_port`, `rule_id` and `exclude_rule_id`. `ip_any`
  matches pre- or post-NAT addresses on either side.
- `from` / `to` are flow time: a record matches when its start-to-end overlaps the range.

**Results** (`/api/search?type=flow`):
```json
{"received": "2026-11-16T09:31:02.004Z", "device_id": "10.1.0.1", "type": "flow", "ref": "opaque",
 "fields": {"start": "2026-11-16T09:30:11.200Z", "end": "2026-11-16T09:31:01.950Z",
            "src": "10.20.0.5", "src_port": 51544, "dst": "198.51.100.7", "dst_port": 443, "proto": 6, "proto_name": "tcp",
            "tcp_flags": "SAPF", "packets": 1840, "bytes": 2210444, "sampling": 1000,
            "packets_scaled": 1840000, "bytes_scaled": 2210444000,
            "in_if": 3, "in_if_name": "eth3", "out_if": 1, "out_if_name": "eth1", "domain": 1,
            "fw_event": "deleted", "nat_event": "nat44_session_delete", "event_time": null,
            "post_nat_src": "192.0.2.10", "post_nat_src_port": 40112, "post_nat_dst": "198.51.100.7", "post_nat_dst_port": 443,
            "initiator_bytes": null, "responder_bytes": null, "initiator_packets": null, "responder_packets": null,
            "rev_bytes": null, "rev_packets": null, "rule_id": "",
            "tos": 0, "src_as": 0, "dst_as": 0, "next_hop": "", "time_source": "exporter", "status": "ok", "late": false,
            "extras": [{"pen": 32473, "id": 1, "hex": "0a0b"}]}}
```
- Columns a record doesn't have are `null` (`rule_id` is `""`). An event with only an event time has `start` and
  `end` equal to `event_time`.
- `sampling` is `1` (unsampled), N (1 in N) or `0` (unknown); `packets_scaled` and `bytes_scaled` are `null` when it's
  `0`. There's no `raw`. `/api/context` isn't available for flows (`400`).
- The order is by flow end, newest first (`order=asc` for oldest first). Paging, the budget and the cursor work as for
  search; `partial` responses also carry `progress` (below).

**Summary:** `/api/search/summary?type=flow` uses the flow fields (`proto`, `dst_port`, `src_port`, `src`, `dst`,
`in_if`, `out_if`, `fw_event`, `nat_event`, `rule_id`, `domain`, `sampled`, `status`); each value's `count` is flows, plus `bytes` and `bytes_scaled`. The
histogram's `source` is `index` (from `flow_minute`) when unfiltered, with a `metric` parameter (`flows`, `bytes`,
`packets`; default `flows`). Instead of `counted_from`, a partial flow summary carries `progress`.

### Top-N

`GET /api/flows/top?by=src&metric=bytes&top=10&from=…&to=…` (and the flow filters) →

Parameters: the flow filters, the range, the device selection, plus `by` (`src`, `dst`, `conversation`, `dst_port`,
`src_port`, `proto`, `in_if`, `out_if`, `post_nat_src`, `post_nat_dst`, `fw_event`, `rule_id`), `metric` (`bytes`
default, or `flows` with `fw_event=denied`; `packets`, `flows`, `connections`), `top` (10, at most 100),
`budget_ms` (2,000, at most 10,000) and `cursor`.
```json
{"by": "src", "metric": "bytes", "from": "2026-11-16T09:00:00Z", "to": "2026-11-16T10:00:00Z",
 "total": {"flows": 1204332, "bytes": 18200000000, "packets": 21400000,
           "bytes_scaled": 1900000000000, "packets_scaled": 2100000000, "scaled_complete": false, "connections": 51112},
 "rows": [{"key": "10.20.0.5", "label": "10.20.0.5", "flows": 40211, "bytes": 5642000000, "packets": 4100000,
           "bytes_scaled": 564200000000, "packets_scaled": 410000000, "scaled_lower_bound": false, "connections": 40000,
           "share": 0.31, "first": "2026-11-16T09:00:02Z", "last": "2026-11-16T09:59:58Z", "approx": false, "max_error": 0}],
 "other": {"flows": 1000000, "bytes": 9000000000},
 "approx": false, "error_bound": 0,
 "progress": {"blocks_done": 1800, "blocks_total": 1800, "records_done": 1204332, "records_total": 1204332,
              "complete_from": "2026-11-16T09:00:00Z"},
 "partial": false, "next_cursor": "", "elapsed_ms": 2140}
```
- `key` for `conversation` is `"a ↔ b"` with the lower address first (both directions summed); for ports
  `"tcp/443"`; for interfaces the index, with the name as `label`.
- `share` is of the metric's exported total. `scaled_complete` is false when some records had unknown sampling; a row
  whose records include any is a lower bound (`scaled_lower_bound: true`, shown with "≥").
- "Top denied sources" is `by=src&fw_event=denied`. Totals follow SPEC §13.2.1's no-double-count rule for event
  records; `connections` counts `deleted` and `denied` events for event-style exporters.
- Memory is bounded whatever the window (SPEC §13.6): keys are counted exactly up to 1,000,000 across the request's
  workers and the server's shared query budget (`approx: false`, `error_bound: 0`). Past that, the keys already counted
  stay exact and new ones go to a fixed-size space-saving table with a count-min check. `approx` is then true, and:
  - a row from that table has `approx: true` and `max_error`. Its ranked metric is at most `max_error` over the true
    value, and its other counts cover only the records since the key entered the table;
  - a key in neither table has at most `error_bound` of the metric, and any key not in `rows` has at most the larger
    of `error_bound` and the last row's value.

  The totals stay exact.
- A saved continuation holds its counts in the shared budget. When a new request needs room, the least recently used
  continuation is dropped, and its `cursor` then gets `400 {"error": "This flow query expired; start it again."}`.
- `progress.complete_from`: every block whose flows end after it has been read. A continuation with `next_cursor`
  returns running totals, not deltas.

### Timeline strip

`GET /api/flows/timeline?devices=a,b&from=…&to=…&bucket=…&metric=bytes` → per exporting device (at most 4, the busiest
by bytes, then `more`), from `flow_minute`, on the histogram's bucket edges (`bucket` in seconds, 60 to 604800, at
most 1,000 buckets; picked from the range when absent):
```json
{"devices": [{"device_id": "10.1.0.1", "points": [{"start": "2026-11-16T09:00:00Z", "bytes": 5100000, "bytes_scaled": 5100000000,
  "flows": 812, "packets": 7300}]}], "more": 0}
```

### Templates

`GET /api/flows/templates?device=10.1.0.1` → the exporter's cached template definitions, per observation domain, so a
user can find the IE that carries a rule ID (Settings → Flows); `404` for a device that hasn't sent flows since the
start:
```json
{"device_id": "10.1.0.1", "domains": [{"id": 1, "templates": [{"id": 256, "options": false, "received": "2026-11-16T09:58:01Z",
  "fields": [{"pen": 0, "id": 8, "name": "sourceIPv4Address", "length": 4}, {"pen": 32473, "id": 7, "name": "", "length": 4}]}]}]}
```
`name` is `""` for IEs Woodshed doesn't know (enterprise-specific ones among them); `length` 65535 is variable.

### Exports and bundles
- `types` may include `"flow"`; `kind: "bundle"` includes it by default when there are flows in the window.
- `flow_formats`: `["csv", "ipfix"]` (default), `["csv"]` or `["ipfix"]`.
- The zip gets `flows/<device-id>/flows.csv` (the columns in SPEC §13.4, the event, NAT and biflow ones included), `flows.ipfix` (RFC 5655) and `raw.txt` when
  there are raw sets; `"folders"` gains `"flows": "flow"`.
- `/api/exports/estimate` gains `"by_type": {"syslog": {"lines", "bytes"}, "flow": {"records", "bytes"}, …}`. More than
  20,000,000 flow records for one device is a `400` at estimate and at build: "Too many flow records for one zip
  (24,113,002 for 10.1.0.1); narrow the window or add a flow filter."
- A bundle's manifest `summary` entries gain `"flow": {"records", "domains", "sampling": [{"domain", "sampling": [rates seen]}], "scaled_complete", "bytes", "bytes_scaled",
  "packets", "packets_scaled", "top_talkers": [{"key", "share"}], "top_dst_ports": [...], "top_conversations": [...],
  "fw_events": {"created", "deleted", "denied"}, "top_denied_sources": [{"key", "count"}], "top_denied_ports": [...],
  "nat_connections", "top_post_nat_sources": [...],
  "sequence_gaps", "lost_estimate", "no_template", "malformed"}`. `sequence_gaps` and `lost_estimate` are the
  collector's last 24 hours (`null` from `woodshed bundle`, which has no collector); entries whose count is 0 are left
  out of the top lists, which hold at most 3.

### Banners
- `flow_budget` (info, action `""`): flows hold less than 24 h within their budget at the current rate; the text gives
  the rate and the budget.
- `flow_templates` (warn, action `""`): an exporter's data has been waiting for a template for over 10 min, or was
  stored raw for lack of one.
- `flow_clock` (warn, action `""`): an exporter's clock is more than an hour off; its flows use received time.
- `flow_firewall` (warn, action `""`): Windows only, while the flow listener is on and a rule is disabled, missing or on
  another port; the text gives `woodshed flow on`.


**CLI** (not HTTP): `woodshed search --type flow`, `woodshed flows top`, `woodshed flow on|off|status`, `woodshed send
--proto flow-v5|flow-v9|ipfix`, `woodshed bench --proto ipfix` and `woodshed reindex --flows-redecode`, as in SPEC
§13.7 and §13.8.

## 2.0 (planned)

Not in 1.x builds: nothing in this section is served yet. It's the 2.0 contract (SPEC §13). As before, routes here sit
in a `###` heading or after a label, never at the start of a line in the usual "`GET /api/...`" form, so
`routes_test.go` doesn't request them; when one ships, move it into its section above. Everything is additive
(SPEC §13.9).

### Setup helper
**Families:** `GET /api/setup/families` →
```json
[{"id": "line-cli", "label": "Line-oriented CLI (global configuration mode)", "what": ["syslog", "trap", "flow", "poll"],
  "verification": "reference", "reference": "the device's own documentation"},
 {"id": "rsyslog", "label": "Linux: rsyslog", "what": ["syslog"], "verification": "tested", "reference": "rsyslog documentation, omfwd"}]
```
`verification`: `tested`, `lab_checked` (with `"checked_on"`) or `reference`.

**Snippet:** `POST /api/setup/snippet` body `{"family": "rsyslog", "what": "syslog", "transport": "tls", "address":
"logs-01.example.net"}` → `{"text": "…", "notes": ["…"], "placeholders": ["<CA-FILE>"], "verification": "tested"}`.
- `address` defaults to the first of this Woodshed's addresses the Setup page lists; `transport` per `what`: syslog
  `udp`, `tcp` or `tls`; trap `v2c` or `v3`; flow `v9` or `ipfix`; poll `v2c` or `v3`.
- Secrets are always placeholders; no stored community or key is ever put into a snippet. Nothing is changed on the
  server.

**CLI** (not HTTP): `woodshed setup snippet`, as in SPEC §13.5.
