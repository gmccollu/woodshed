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
                                               // (see "SNMP trap receiver"); an optional "url" on any banner
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
  "types": ["syslog", "trap"], "lines_by_type": {"syslog": 9120000, "trap": 3456}}]
```
`total_msgs` counts every data type (syslog and SNMP traps, SPEC §11.1), so a device that sends only traps is online.
`types` lists the data types the device has files of on disk now (`[]` when none), and `lines_by_type` their stored
lines (records), from the index.
`tls`, once the device has tried syslog over TLS (counts since the server started, kept 24 h):
```json
{"connections_24h": 288, "version": "TLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256", "last_connected": "2026-11-13T15:09:51Z",
 "failures_24h": 2, "last_failure": {"time": "2026-11-13T09:00:12Z", "reason": "timeout", "detail": ""}}
```
`version` and `cipher` are the last successful connection's (`last_connected` is `null` if none succeeded);
`last_failure` is `null` when there was none. Reasons are those of `/api/tls/failures`.

Hidden devices are included, with `"hidden": true`.

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
- `type`: the data type: `syslog` (the default) or `trap` (SNMP traps, below). Any other value is a
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
  with `type=trap` each is a `400` (`{"error": "severities: not a filter for SNMP traps."}`). A parameter sent with an
  empty value doesn't count as present.

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
  neighbouring part or day file. A trap `ref` returns trap lines, in the trap result shape.
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
- `kind` (since 1.2): `"export"` (the default). `"bundle"` (the incident bundle, below in "1.2 (planned)") isn't in
  this build: a `400` "kind: the incident bundle isn't in this build yet."
- One export builds at a time; a second `POST` while one is building is queued.

`POST /api/exports/estimate` (same body) → `{"lines": 123456, "bytes": 45678901, "files": 12}`: an upper bound
from the index, without scanning, so the UI can show the size before building.

`GET /api/exports` → `[{"id", "created", "devices", "from", "to", "state": "queued|building|ready|failed|expired",
"progress": 0.42, "lines": 0, "size_bytes": 0, "error": "", "ready_at": null, "expires_at": null,
"filters": {"group": "", "ungrouped": false, "severities": [], "q": "", "regex": false, "case": false, "app": [], "host": [],
"exclude": "", "type": "syslog", "syntax": "text", "facilities": [], "exclude_devices": [], "exclude_app": [],
"exclude_host": [], "kind": "export", "types": ["syslog"]}}]`, newest
first. `ready_at` / `expires_at` are set once the export is ready; `filters` echoes the request. For an export of
traps with trap filters, `filters` also has `"trap"`, an object of the trap lists given (`{"trap_oid": ["1.3.6.1.6.3.1.1.5.3"]}`,
MIB names resolved, prefixes kept with `.*`), and `type` is `"trap"`; `trap` is omitted when there are none.

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
- `manifest.json`: Woodshed version, export time, the request (devices with names and groups, range, filters:
  `severities`, `q`, `regex`, `case`, `app`, `host`, `exclude`, `type`, `syntax`, `facilities`, `exclude_devices`,
  `exclude_app` and `exclude_host`), and per-file line count and SHA-256. Also `gaps`: periods inside the range when Woodshed wasn't running or a listener
  was down, from the event log (the SNMP listener's as `proto` `"snmp"`). Since 1.2 also `"kind": "export"`,
  `"types"` (the data types exported) and `"folders"` (each zip folder's type: `{"logs": "syslog", "traps": "trap"}`
  for the types exported); `request.filters.type` is `"trap"` for an export of traps alone.
- `woodshed-events.log`: the service's own events in the range (start, stop, bind errors, rotations, deletions,
  drops, pauses).
- `README.txt`: a short note on what each file is, with the range and the filters in plain words ("Filters: none"
  when there are none). A zip with traps also explains the record, and that a community is shown only as a hash
  prefix in `cred=` and masked with `*` in `raw=`.

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
  "updates": {"check": "ask"}
}
```
`updates.check` must be `"ask"`, `"on"` or `"off"` (a `400` on `updates.check` otherwise); see "Update check". A PUT
without `updates` (a 1.0 client or script) leaves it as it is.

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
  `aes-128`, `aes-192`, `aes-256`. `key_ext` is `draft` or `alt` for AES-192/256 (`draft` otherwise). `level` follows
  from them; a user accepts its own level and above, never below.
- `weak` lists the user's protocols Settings labels weak (`md5`, `sha`, `des`). They're accepted.
- `stored`: `"passphrase"`, or `"localized"` when `engine_ids` is set: then only the keys localized to those engines
  (and to Woodshed's own, for informs) are kept and the passphrases are discarded.
- `auth_set` / `priv_set` say a secret is stored for the protocol (passphrase or keys).
- `readable` is false when the credentials file's secrets can't be decrypted here (Windows, after the data folder
  moved to another machine or account): the user then needs its passphrases again (banner `snmp_credentials`).

`POST /api/snmp/users` body `{"name": "monitor", "auth": "sha-256", "auth_pass": "…", "priv": "aes-128",
"priv_pass": "…", "key_ext": "draft", "engine_ids": []}` → `201` with the user (without secrets).

`PUT /api/snmp/users/{name}` (the same body) → `200` with the user. A missing or empty `auth_pass` / `priv_pass`
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
`ip`, `count_24h`, `status`, `detail`, `last_seen`), for `woodshed status` and `woodshed snmp status`.

## Errors

Any non-2xx returns `{"error": "human-readable message"}`.

## 1.2 (planned)

Not served yet: the incident bundle (SPEC §11.3, step (e) of the 1.2 build). Everything else 1.2 adds is in the
sections above. As in 1.1's planned section, routes here sit in a `###` heading or after a label, never at the start
of a line in the usual "`GET /api/...`" form, so `routes_test.go` doesn't request them; when one ships, move it into
its section above in the usual form. Everything is additive: every 1.1 request keeps its meaning (SPEC §11.7).

### The incident bundle

**Changed:** `POST /api/exports` (and `POST /api/exports/estimate`) take `kind: "bundle"`. Today that's a `400`
("kind: the incident bundle isn't in this build yet.").

**Bundle body:**
```json
{"kind": "bundle", "at": "2026-11-14T09:42:00Z", "before": "30m", "after": "10m",
 "active_devices": true, "devices": [], "group": "", "ungrouped": false, "types": []}
```
- `at` (RFC 3339) is required. `before` and `after` are durations (`0s` to `7d`, at least one non-zero); the window is
  `[at − before, at + after)`, cut at now. `from`/`to` aren't accepted with `kind: "bundle"` (`400`).
- Devices: `active_devices: true` (every non-hidden device with a stored record of any type in the window), or
  `devices`, `group` or `ungrouped` as for exports. At least one must select a device.
- `types`: empty means every type with data in the window.
- No filters: any of them with `kind: "bundle"` is a `400` naming it.
- Response: `202 {"id": "exp_..."}`, as for exports. The export list, download, ticket, delete and 24 h expiry are the
  same; each entry's `filters` has `kind: "bundle"`, `types`, `at`, `before` and `after`.

**Zip:** as for exports (`logs/`, `traps/`, `manifest.json` with `kind`, `types` and `folders`), and:
- `manifest.json` gains `"at"`, `"before"`, `"after"` and `"summary"` (the README's numbers per device, as JSON:
  `{"device_id", "name", "group", "types": {"syslog": {"lines", "first", "last", "by_severity"}, "trap": {"lines",
  "first", "last", "by_trap"}}, "reboots": [{"time", "source"}], "gaps": [...], "dropped", "truncated"}`).
- `README.txt`: the per-device summary of SPEC §11.3.

**Active devices:** `GET /api/devices` gains `active_from` and `active_to` (RFC 3339, both or neither): only devices
with a stored record of any type in `[active_from, active_to)`.

**CLI** (not HTTP): `woodshed bundle`, as in SPEC §11.3.
