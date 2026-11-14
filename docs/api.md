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
    {"proto": "tls", "addr": "0.0.0.0", "port": 6514, "ok": true, "error": ""}   // only while listeners.tls.enabled
  ],
  "host_ips": ["10.1.0.50", "fd00::50"],
  "ui_cert_fingerprint": "",                  // LAN mode: SHA-256 of the UI's certificate, "AB:CD:…" (64 hex pairs); "" on localhost
  "banners": [{"kind": "listener_bind", "level": "error", "text": "TCP 514 is in use by syslogd (pid 312).",
               "action": "retry_listeners"}]   // action: "" | "retry_listeners" | "update_choice" | "update_dismiss" | "tls_renew";
                                               // kinds: listener_bind, writes_paused, low_disk, ui_port_busy, udp_buffer_small,
                                               // update_prompt, update_available (see "Update check"), tls_legacy, tls_cert_expiring,
                                               // tls_cert_names, tls_firewall (see "TLS syslog listener"), udp_queue_full
                                               // (see "UDP receive queue"); an optional "url" on any banner
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
                 "high_water_by_hour": [120, 3210, 88]}]   // oldest first, the last 24 hours
}
```
**Drops by reason** (since 1.2): `dropped_by_reason` splits `dropped_24h`: `paused` (the low-disk guard had paused
writing, UDP messages still in the queue included), `write_error` (a log file write failed), `refused` (new senders
over the device limits, see `device_limit`) and `queue_full` (a UDP listener's queue was full, below). `dropped_24h`
still counts every drop, `queue_full` included. The reasons are counted since the server started, so for a day after a
restart they can sum to less than `dropped_24h`, which comes from the index.

**UDP receive queue** (since 1.2, SPEC §11.5): each UDP socket's reader only reads, stamps, applies the blocklist and
allowlist and queues; one drainer parses and stores in arrival order, so a slow disk fills the queue instead of the OS
socket buffer. `udp_queue` has one entry per enabled UDP listener (syslog's `"udp"`, and later `"snmp"` while the trap
listener is on), with `port` 0 while it isn't bound:
- `capacity_messages` and `capacity_bytes`: the limits, whichever fills first. `capacity_bytes` counts message bytes.
- `depth`: messages waiting now. `high_water_24h`: the most waiting at once in the last 24 hours.
- `high_water_by_hour`: the most waiting at once in each hour, oldest first, the current hour last: 24 entries, or
  fewer within a day of the start (the About page draws it, to show stalls that cluster at the top of the hour).
- `dropped_24h`: messages dropped because this queue was full. A queue drop counts for the sender's device, so it's in
  the device's `dropped` stats, the top-level `dropped_24h` and an export's losses, and the events log gets one
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
senders). `reason` is the latest refusal's reason: `allowlist`, `blocked` (on the blocklist) or `per_source` (over the TCP
connections-per-source limit).
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
  "tls": null}]                                // null until the device has tried TLS since the server started; see below
```
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
- `type`: the data type, `syslog`, which is the default and the only value in 1.1. Any other value is a
  `400 {"error": "type: unknown data type \"x\"."}`.
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
- Lines come from the same device, in file order, and can cross into the neighbouring part or day file.
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
- One export builds at a time; a second `POST` while one is building is queued.

`POST /api/exports/estimate` (same body) → `{"lines": 123456, "bytes": 45678901, "files": 12}`: an upper bound
from the index, without scanning, so the UI can show the size before building.

`GET /api/exports` → `[{"id", "created", "devices", "from", "to", "state": "queued|building|ready|failed|expired",
"progress": 0.42, "lines": 0, "size_bytes": 0, "error": "", "ready_at": null, "expires_at": null,
"filters": {"group": "", "ungrouped": false, "severities": [], "q": "", "regex": false, "case": false, "app": [], "host": [],
"exclude": "", "type": "syslog", "syntax": "text", "facilities": [], "exclude_devices": [], "exclude_app": [],
"exclude_host": []}}]`, newest
first. `ready_at` / `expires_at` are set once the export is ready; `filters` echoes the request.

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
  (`README.txt` shows how to unescape). Search and context results still return the raw message unescaped.
- `manifest.json`: Woodshed version, export time, the request (devices with names and groups, range, filters:
  `severities`, `q`, `regex`, `case`, `app`, `host`, `exclude`, `type`, `syntax`, `facilities`, `exclude_devices`,
  `exclude_app` and `exclude_host`), and per-file line count and SHA-256. Also `gaps`: periods inside the range when Woodshed wasn't running or a listener
  was down, from the event log.
- `woodshed-events.log`: the service's own events in the range (start, stop, bind errors, rotations, deletions,
  drops, pauses).
- `README.txt`: a short note on what each file is, with the range and the filters in plain words ("Filters: none"
  when there are none).

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
   ]}
]}
```
- `param` is the filter parameter a value is added to; a value goes in exactly as its `value`.
- `exclude_param` is the parameter that excludes a value. It's `""` for a field with a `domain`: to exclude a value
  there, send every other value of the domain in `param`.
- `domain` is the complete value set of a closed field (severity, facility), or `null`. The facility labels are kern,
  user, mail, daemon, auth, syslog, lpr, news, uucp, cron, authpriv, ftp, ntp, audit, alert, clock and local0–local7
  (0–23), then unknown.
- The panel shows the fields in this order. 1.1 has one type; a later type is another entry in `types`.

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

`GET /api/storage/history` → `[{"time", "file", "device_id", "bytes", "reason": "age|cap|low_disk"}]`

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
`ip`, `count_24h`, `reason`, `last_seen`), for `woodshed status` and `woodshed tls status`.

## Errors

Any non-2xx returns `{"error": "human-readable message"}`.

## 1.2 (planned)

Not in 1.1 builds: nothing in this section is served yet. It's the 1.2 contract (SPEC §11). As in 1.1's planned
section, routes here sit in a `###` heading or after a label, never at the start of a line in the usual
"`GET /api/...`" form, so `routes_test.go` doesn't request them; when one ships, move it into its section above in the
usual form. Everything is additive: every 1.1 request keeps its meaning (SPEC §11.7).

### Data types: `type=trap`

`type` (search, summary, saved searches, the CLI) gains the value `trap`. Without `type`, everything is syslog as in
1.1.

**Schema:** `GET /api/search/schema`'s `types` list gains a second entry:
```json
{"type": "trap", "label": "SNMP traps", "default": false,
 "fields": [
   {"key": "device",     "label": "Device",            "param": "devices",       "exclude_param": "exclude_devices",    "domain": null},
   {"key": "version",    "label": "Version",           "param": "snmp_versions", "exclude_param": "",
    "domain": [{"value": "1", "label": "v1"}, {"value": "2c", "label": "v2c"}, {"value": "3", "label": "v3"}]},
   {"key": "pdu",        "label": "PDU",               "param": "pdus",          "exclude_param": "",
    "domain": [{"value": "v1trap", "label": "v1 trap"}, {"value": "trap", "label": "trap"}, {"value": "inform", "label": "inform"},
               {"value": "unexpected", "label": "other PDU"}]},
   {"key": "trap_oid",   "label": "Trap",              "param": "trap_oid",      "exclude_param": "exclude_trap_oid",   "domain": null},
   {"key": "enterprise", "label": "Enterprise (v1)",   "param": "enterprise",    "exclude_param": "exclude_enterprise", "domain": null},
   {"key": "generic",    "label": "Generic trap (v1)", "param": "generic",       "exclude_param": "",
    "domain": [{"value": "0", "label": "coldStart"}, {"value": "1", "label": "warmStart"}, {"value": "2", "label": "linkDown"},
               {"value": "3", "label": "linkUp"}, {"value": "4", "label": "authenticationFailure"},
               {"value": "5", "label": "egpNeighborLoss"}, {"value": "6", "label": "enterpriseSpecific"}]},
   {"key": "specific",   "label": "Specific trap (v1)", "param": "specific",     "exclude_param": "exclude_specific",   "domain": null},
   {"key": "cred",       "label": "Community or user", "param": "cred",          "exclude_param": "exclude_cred",       "domain": null},
   {"key": "status",     "label": "Status",            "param": "status",        "exclude_param": "",
    "domain": [{"value": "ok", "label": "ok"}, {"value": "malformed", "label": "malformed"}, {"value": "auth_failed", "label": "wrong auth"}]}   // and the rest, below
 ]}
```
- `status`'s domain: `ok`, `malformed`, `unexpected_pdu`, `unknown_user`, `unknown_engine`, `not_in_time`,
  `auth_failed`, `decrypt_failed`, `level`.
- In the field panel, a `trap_oid` value's `label` is its MIB name when the current MIB set has one.

**Trap filters** (only with `type=trap`; with `type=syslog` each is a `400` "`<name>: not a filter for syslog.`"):
- `snmp_versions=1,2c,3`, `pdus=v1trap,trap,inform,unexpected`, `generic=0,6`, `status=ok,auth_failed`: sets, like
  `severities` (empty means all, `none` means nothing).
- `trap_oid`, `enterprise` and their `exclude_` forms: comma-separated OIDs, each exact or a prefix written with a
  trailing `.*` (`1.3.6.1.4.1.99999.*`), or a MIB name (`linkDown`) resolved with the current MIB set; an unknown
  name is a `400`.
- `specific`, `exclude_specific`: comma-separated integers.
- `cred`, `exclude_cred`: comma-separated community hashes (`#3f9a1c07`) or v3 user names, exact, ignoring case.
- `q`, `syntax`, `regex`, `case` and `exclude` match the record text without its `raw=` part. The device selection
  and the range work as for syslog.
- Syslog's filters (`severities`, `min_severity`, `facilities`, `app`, `host`, `exclude_app`, `exclude_host`) with
  `type=trap` are a `400`, for example `{"error": "severities: not a filter for SNMP traps."}`.

**Search results** for `type=trap` (syslog results keep the 1.1 shape):
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
- `generic` and `specific` are integers for v1 traps, `null` otherwise. `value` is always a string.
- `/api/context` returns trap lines in this shape for a trap `ref`.

**Summary and histogram:** `/api/search/summary` with `type=trap` uses the trap fields above and the `type_stats`
tables for the index histogram; its response shape is unchanged.

**Saved searches:** `type` may be `trap`; `query` then takes the trap filters (lists as JSON lists) and refuses
syslog's, with dotted error keys as before (`query.severities`).

### Exports and the incident bundle

**Changed:** `POST /api/exports` (and `POST /api/exports/estimate`) gain:
- `types`: a list of data types, `["syslog"]` by default (so a 1.1 body builds exactly the 1.1 zip). Filters
  (`q`, `severities`, …, or the trap filters) are allowed only when `types` has one entry; otherwise a `400` on
  `types`: "Filters apply to one data type; pick one, or leave the filters out."
- `kind`: `"export"` (the default) or `"bundle"`.

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
  same; each entry's `filters` gains `kind`, `types`, and for a bundle `at`, `before` and `after`.

**Zip layout (every export from 1.2):**
- `logs/<device-id>/<YYYY-MM-DD>.log`: syslog, exactly as in 1.0 and 1.1.
- `traps/<device-id>/<YYYY-MM-DD>.log`: trap record lines as stored (escaped like syslog lines).
- `manifest.json` gains `"kind"`, `"types"` and `"folders": {"logs": "syslog", "traps": "trap"}`, and for a bundle
  `"at"`, `"before"`, `"after"` and `"summary"` (the README's numbers per device, as JSON:
  `{"device_id", "name", "group", "types": {"syslog": {"lines", "first", "last", "by_severity"}, "trap": {"lines",
  "first", "last", "by_trap"}}, "reboots": [{"time", "source"}], "gaps": [...], "dropped", "truncated"}`).
- `README.txt`: for a bundle, the per-device summary of SPEC §11.3; for every zip with traps, a line saying that
  communities are shown as a hash prefix and masked with `*` in `raw=`.

**Active devices:** `GET /api/devices` gains `active_from` and `active_to` (RFC 3339, both or neither): only devices
with a stored record of any type in `[active_from, active_to)`. Each device also gains `types`: the data types it has
on disk (`["syslog", "trap"]`).

### SNMP trap listener

**Settings:** `/api/settings` gains `listeners.snmp`:
```json
{"enabled": false, "addr": "0.0.0.0", "port": 162, "answer_informs": true, "communities": [], "mib_dir": "", "engine_id": ""}
```
- `port` 1–65535, not shared with another UDP listener on an overlapping address.
- `communities` holds at most 100 strings of 1–255 bytes. They're secrets, so they're kept in the SNMP credentials
  file (SPEC §11.2.6), not in the TOML. `GET` returns each as `"#<hash8>"`; a `PUT` that sends a `"#…"` value back
  keeps the community it stands for, and a plain string adds a new one, so the settings round trip never carries a
  stored secret. `mib_dir` is an absolute path or
  `""`. `engine_id` is `""` or 5–32 bytes as hex (10–64 hex digits), validated against RFC 3411's rules.
- `/api/status.listeners` gains `{"proto": "snmp", "addr": "0.0.0.0", "port": 162, "ok": true, "error": ""}` while
  it's enabled.

### SNMP state: `GET /api/snmp`
```json
{"enabled": true, "port": 162,
 "engine": {"id": "8000000005a1b2c3d4e5f60718", "boots": 12, "time": 86400},
 "counts_24h": {"received": 15230, "informs_answered": 212, "replies_rate_limited": 0, "discovery_reports": 3,
                "by_status": {"ok": 15201, "malformed": 4, "auth_failed": 25}},
 "mibs": {"dir": "/var/lib/woodshed/mibs", "files": 41, "names": 18234, "loaded_at": "2026-11-14T08:00:03Z",
          "errors": [{"file": "EXAMPLE-MIB.my", "line": 212, "message": "unexpected token \"SEQUENCE\""}]},
 "firewall": {"state": "disabled", "command": "woodshed snmp on"}}   // state: "ok" | "missing" | "disabled" | "wrong_port" | "unknown"
```
- `by_status` lists only statuses with a count. `firewall` is as for TLS: always `"unknown"` off Windows.

**Reload MIBs:** `POST /api/snmp/mibs/reload` → `200` with the `mibs` object above. MIBs load only at start and here.

**Failures:** `GET /api/snmp/failures` → senders whose v3 traps failed, or whose packets were malformed, in the last
24 h, most first, at most 200:
```json
[{"ip": "198.51.100.7", "count_24h": 25, "last_seen": "2026-11-14T09:10:00Z", "status": "auth_failed",
  "detail": "user monitor: wrong digest (sha-256)", "device_id": "198.51.100.7"}]
```
`detail` names the user, engine or decoding error, never key material. At most 10,000 addresses are tracked.

### SNMP v3 users

**List:** `GET /api/snmp/users` →
```json
[{"name": "monitor", "level": "authPriv", "auth": "sha-256", "priv": "aes-128", "key_ext": "draft",
  "engine_ids": [], "auth_set": true, "priv_set": true, "stored": "passphrase", "readable": true}]
```
- `auth`: `none`, `md5`, `sha`, `sha-224`, `sha-256`, `sha-384`, `sha-512`. `priv`: `none`, `des`, `aes-128`,
  `aes-192`, `aes-256`. `key_ext` (AES-192/256 only): `draft` or `alt`. `level` follows from them.
- `stored`: `"passphrase"`, or `"localized"` when `engine_ids` is set and only the localized keys are kept.
- `readable` is false when the credentials file can't be decrypted here (Windows, after the data folder moved to
  another machine or account); the user then needs its passphrases again.

**Add:** `POST /api/snmp/users` body `{"name": "monitor", "auth": "sha-256", "auth_pass": "…", "priv": "aes-128",
"priv_pass": "…", "key_ext": "draft", "engine_ids": []}` → `201` with the user (without secrets).

**Change:** `PUT /api/snmp/users/{name}` (the same body) → `200`. A missing or empty `auth_pass` / `priv_pass` keeps
the stored one, unless the protocol changes (then it's required).

**Delete:** `DELETE /api/snmp/users/{name}` → `204`, `404` if unknown.

- Names are 1–32 bytes, unique (exact match, as USM compares them). Passphrases are 8–256 bytes. `engine_ids` holds
  at most 32 hex engine IDs. At most 100 users.
- Validation errors: `400 {"errors": {"auth_pass": "…", "engine_ids[1]": "…"}}`. A duplicate name: `409`.
- Secrets are never returned, logged or exported. The routes need a session like every other `/api/` route.

### UDP queue and drops

Shipped: see "Status and stats" (`dropped_by_reason`, `udp_queue`, the `udp_queue_full` banner). The SNMP trap
listener adds its own `udp_queue` entry, `"listener": "snmp"`, while it's on.

### Banners (1.2)
- `udp_queue_full`: shipped, see "Status and stats".
- `snmp_firewall` (warn, action `""`): Windows only, while the SNMP listener is on and its firewall rule is disabled,
  missing or on another port; the text gives `woodshed snmp on`.
- `snmp_credentials` (warn, action `""`): v3 users whose credentials can't be decrypted here (`readable: false`).
- `snmp_mibs` (info, action `""`): files in the MIB folder failed to load; Settings lists them.

`/api/rejected` gains the reason `community` (v1/v2c traps refused by `listeners.snmp.communities`).

**CLI** (not HTTP): `woodshed search`, `woodshed bundle` and `woodshed snmp on|off|status`, and `woodshed send
--proto trap`, as in SPEC §11.2.7, §11.3, §11.4 and §11.6.
