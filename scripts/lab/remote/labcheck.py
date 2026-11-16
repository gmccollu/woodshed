#!/usr/bin/env python3
"""Woodshed lab checks that run on a Linux lab VM (stdlib only; copied by `wl stage`). Read-only.

  labcheck.py secret-scan [--journal UNIT] PATH...
      Needles arrive on stdin, one per line (never on a command line). Every file under PATH (gzip
      files decompressed) and the unit's journal are searched for each needle. Prints one JSON line:
      the files and bytes read and, per hit, the needle's index and the file. Never the content.
  labcheck.py window ZIP --from T --to T [--run RUN:N[:BLOCKS]]... [--data DIR]
      An export or incident-bundle zip against its window [from, to): every line's received time is
      inside it; per run, the sequence numbers seen, duplicates, and the holes inside each sender block
      (wl-send gives each of BLOCKS senders a contiguous block of RUN's N numbers). With --data, the
      same window read from the data dir: lines in the dir but not the zip, and in the zip but not the dir.
      Also the manifest's per-device line counts against the zip's own files, and its reboots and gaps.
  labcheck.py missing SRC --run RUN --n N [--blocks K --rate R --start EPOCH] [--list 50]
      The run's missing sequence numbers in a data dir or a zip. With the send schedule (K senders,
      R msg/s in all, from EPOCH), each missing number is mapped to its send time: per hour and bursts.
  labcheck.py netdev --iface IF --secs S --out CSV [--interval 1]
      Sample /proc/net/dev for IF every second (writes only CSV).
  labcheck.py poll-rates SRC --device D --if NAME --netdev CSV [--offset S] [--from T --to T]
      SNMP polls (1.3): the poller's per-cycle bit and packet rates for one interface against the target's own
      /proc/net/dev over the same windows. SRC is the poller's data dir or `woodshed search --type poll --json` output.
  labcheck.py poll-cycles SRC --device D [--interval 60] [--from T --to T]
      Cycles answered, failed by status, spacing and late gaps, cycle-number jumps, restarts; per interface the
      lines with and without rates, discontinuities, wraps and oper states.
  labcheck.py poll-size DATA --device D [--from T --to T]
      The device's poll lines in the window: by kind, bytes, and gzip -6 of those bytes, scaled per day.
  labcheck.py poll-csv ZIP --lines SRC [--from T --to T]
      A bundle's or export's poll/<device>/*.csv against the poll lines: the documented header, CRLF, the manifest's
      rows and sha256, every row equal to its line's values; and the README's poll and reboot lines.
  secret-scan also reads every member of a .zip (exports and bundles), decompressed.
"""
import argparse, base64, datetime as dt, gzip, io, json, os, re, subprocess, sys, zipfile

ENV_RE = re.compile(rb"^(\S+) (\S+) (.*)$")


def ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def seqs_in(line, tag):
    """The sequence number after tag ('seq=RUN:') in an escaped stored line, or None."""
    i = line.find(tag)
    if i < 0:
        return None
    j = i + len(tag)
    k = j
    while k < len(line) and 48 <= line[k] <= 57:
        k += 1
    if k == j or (k < len(line) and line[k] not in b' "'):
        return None
    return int(line[j:k])


def iter_dir(data):
    for root, dirs, files in os.walk(os.path.join(data, "logs")):
        dirs.sort()
        for f in sorted(files):
            if not (f.endswith(".log") or f.endswith(".log.gz")):
                continue
            p = os.path.join(root, f)
            rel = os.path.relpath(p, data)
            op = gzip.open if f.endswith(".gz") else open
            try:
                with op(p, "rb") as fh:
                    for line in fh:
                        yield rel, line.rstrip(b"\n")
            except (OSError, EOFError) as e:      # a file rotated or compressed mid-read
                sys.stderr.write(f"labcheck: {rel}: {e}\n")


def iter_zip(path):
    z = zipfile.ZipFile(path)
    for m in z.infolist():
        if re.fullmatch(r"(logs|traps)/[^/]+/[^/]+\.log", m.filename):
            with z.open(m) as fh:
                for line in io.TextIOWrapper(fh, encoding="latin-1", newline="\n"):
                    yield m.filename, line.rstrip("\n").encode("latin-1")


def blocks_of(n, k):
    base, extra = divmod(n, k)
    out, s = [], 0
    for j in range(k):
        c = base + (1 if j < extra else 0)
        out.append((s, s + c))
        s += c
    return out


def cmd_secret_scan(a):
    needles = [l.rstrip("\r\n").encode() for l in sys.stdin if l.rstrip("\r\n")]
    hits, files, nbytes = [], 0, 0

    def scan(name, data):
        for i, n in enumerate(needles):
            c = data.count(n)
            if c:
                hits.append({"needle": i, "file": name, "count": c})
    for top in a.paths:
        for root, dirs, fs in os.walk(top):
            dirs.sort()
            for f in sorted(fs):
                p = os.path.join(root, f)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                try:
                    data = open(p, "rb").read()
                    if f.endswith(".gz"):
                        try:
                            data = gzip.decompress(data)
                        except (OSError, EOFError):
                            pass
                except OSError:
                    continue
                files += 1; nbytes += len(data)
                scan(p, data)
                if f.endswith(".zip"):          # export and bundle zips: every member, decompressed
                    try:
                        z = zipfile.ZipFile(io.BytesIO(data))
                        for m in z.infolist():
                            d = z.read(m)
                            if m.filename.endswith(".gz"):
                                try:
                                    d = gzip.decompress(d)
                                except (OSError, EOFError):
                                    pass
                            files += 1; nbytes += len(d)
                            scan(f"{p}!{m.filename}", d)
                    except (zipfile.BadZipFile, OSError, EOFError):
                        pass
    if a.journal:
        j = subprocess.run(["journalctl", "-u", a.journal, "--no-pager", "-o", "cat"], capture_output=True).stdout
        files += 1; nbytes += len(j)
        scan(f"journal:{a.journal}", j)
    print(json.dumps({"needles": len(needles), "files": files, "bytes": nbytes, "hits": hits}))


def cmd_window(a):
    t0, t1 = ts(a.from_), ts(a.to)
    runs = {}
    for spec in a.run or []:
        p = spec.split(":")
        runs[p[0]] = {"n": int(p[1]), "k": int(p[2]) if len(p) > 2 else 1}
    out_of_window, lines_by_file, first, last = 0, {}, None, None
    seen = {r: {} for r in runs}
    for name, line in iter_zip(a.zip):
        lines_by_file[name] = lines_by_file.get(name, 0) + 1
        m = ENV_RE.match(line)
        if not m:
            continue
        t = ts(m.group(1).decode())
        first = t if first is None else min(first, t)
        last = t if last is None else max(last, t)
        if not (t0 <= t < t1):
            out_of_window += 1
        for r in runs:
            s = seqs_in(line, b"seq=" + r.encode() + b":")
            if s is not None:
                seen[r][s] = seen[r].get(s, 0) + 1
    res = {"zip": os.path.basename(a.zip), "window": [a.from_, a.to], "lines": sum(lines_by_file.values()),
           "out_of_window": out_of_window,
           "first": dt.datetime.fromtimestamp(first, dt.timezone.utc).isoformat() if first else None,
           "last": dt.datetime.fromtimestamp(last, dt.timezone.utc).isoformat() if last else None, "runs": {}}
    z = zipfile.ZipFile(a.zip)
    if "manifest.json" in z.namelist():
        m = json.loads(z.read("manifest.json"))
        bad = []
        for f in m.get("files", []):
            if lines_by_file.get(f["path"], 0) != f["lines"]:
                bad.append(f["path"])
        res["manifest"] = {"kind": m.get("kind"), "files": len(m.get("files", [])), "lines": m.get("lines"),
                           "line_count_mismatch": bad, "gaps": m.get("gaps"),
                           "summary": [{"device": d.get("device_id"), "types": {k: v.get("lines") for k, v in (d.get("types") or {}).items()},
                                        "reboots": d.get("reboots"), "dropped": d.get("dropped")} for d in (m.get("summary") or [])]}
        per_dev = {}
        for name, n in lines_by_file.items():
            folder, dev = name.split("/")[:2]
            per_dev.setdefault(dev, {}).setdefault("syslog" if folder == "logs" else "trap", 0)
            per_dev[dev]["syslog" if folder == "logs" else "trap"] += n
        mism = []
        for d in m.get("summary") or []:
            for typ, v in (d.get("types") or {}).items():
                if (v.get("lines") or 0) != per_dev.get(d.get("device_id"), {}).get(typ, 0):
                    mism.append(f"{d.get('device_id')} {typ}: summary {v.get('lines')} vs zip {per_dev.get(d.get('device_id'), {}).get(typ, 0)}")
        res["manifest"]["summary_vs_zip"] = mism
    dirseen = None
    if a.data:
        dirseen = {r: set() for r in runs}
        for name, line in iter_dir(a.data):
            m = ENV_RE.match(line)
            if not m or not (t0 <= ts(m.group(1).decode()) < t1):
                continue
            for r in runs:
                s = seqs_in(line, b"seq=" + r.encode() + b":")
                if s is not None:
                    dirseen[r].add(s)
    for r, spec in runs.items():
        sv = seen[r]
        dups = sum(c - 1 for c in sv.values() if c > 1)
        holes, per_block = 0, []
        for lo, hi in blocks_of(spec["n"], spec["k"]):
            inb = sorted(s for s in sv if lo <= s < hi)
            if not inb:
                per_block.append({"block": [lo, hi], "present": 0}); continue
            h = (inb[-1] - inb[0] + 1) - len(inb)
            holes += h
            per_block.append({"block": [lo, hi], "present": len(inb), "min": inb[0], "max": inb[-1], "holes": h})
        rr = {"present": len(sv), "duplicates": dups, "holes_inside_blocks": holes, "blocks": per_block}
        if dirseen is not None:
            zs = set(sv)
            rr["in_dir_not_zip"] = len(dirseen[r] - zs)
            rr["in_zip_not_dir"] = len(zs - dirseen[r])
            rr["dir_present"] = len(dirseen[r])
        res["runs"][r] = rr
    print(json.dumps(res))


def cmd_missing(a):
    seen = bytearray(a.n)
    src = iter_zip(a.src) if a.src.endswith(".zip") else iter_dir(a.src)
    tag = b"seq=" + a.run.encode() + b":"
    for _, line in src:
        s = seqs_in(line, tag)
        if s is not None and 0 <= s < a.n and seen[s] < 255:
            seen[s] += 1
    miss = [i for i in range(a.n) if not seen[i]]
    dup = sum(c - 1 for c in seen if c > 1)
    out = {"run": a.run, "n": a.n, "missing": len(miss), "duplicates": dup, "first_missing": miss[:a.list]}
    if a.blocks and a.rate and a.start:
        per = a.rate / a.blocks
        bl = blocks_of(a.n, a.blocks)
        hours, secs = {}, {}
        for s in miss:
            k = next(j for j, (lo, hi) in enumerate(bl) if lo <= s < hi)
            t = a.start + (s - bl[k][0]) / per
            h = dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%HZ")
            hours[h] = hours.get(h, 0) + 1
            sec = int(t)
            secs[sec] = secs.get(sec, 0) + 1
        bursts, cur = [], None
        for sec in sorted(secs):
            if cur and sec - cur[1] <= 2:
                cur[1] = sec; cur[2] += secs[sec]
            else:
                if cur:
                    bursts.append(cur)
                cur = [sec, sec, secs[sec]]
        if cur:
            bursts.append(cur)
        bursts.sort(key=lambda b: -b[2])
        fmt = lambda x: dt.datetime.fromtimestamp(x, dt.timezone.utc).strftime("%H:%M:%SZ")
        out["per_hour"] = hours
        out["bursts"] = [{"from": fmt(b[0]), "to": fmt(b[1]), "missing": b[2]} for b in bursts[:15]]
    print(json.dumps(out))


# ---- SNMP poller (1.3) ----
REC_TOKEN = re.compile(r'([a-z_][a-z0-9_]*)=("((?:[^"\\]|\\.)*)"|\S*)')


def unescape_env(b):
    """A stored line's envelope escapes (\\r, \\n, \\\\) undone."""
    out, i = [], 0
    while i < len(b):
        c = b[i]
        if c == "\\" and i + 1 < len(b) and b[i + 1] in "rn\\":
            out.append({"r": "\r", "n": "\n", "\\": "\\"}[b[i + 1]]); i += 2
        else:
            out.append(c); i += 1
    return "".join(out)


def parse_rec(raw):
    """A poll record (key=value ..., strings quoted with \\" and \\\\ escapes) -> dict of text values."""
    d = {}
    for m in REC_TOKEN.finditer(raw):
        k, v = m.group(1), m.group(2)
        if v.startswith('"'):
            v = re.sub(r"\\(.)", r"\1", m.group(3))
        d[k] = v
    return d


def iter_poll(src, device, t0=None, t1=None):
    """(received epoch, received text, record dict) for device's poll lines, in time order, from a data dir
    (logs/<dev>/poll/) or an NDJSON file of `woodshed search --type poll --json` results."""
    rows = []
    if os.path.isdir(src):
        d = os.path.join(src, "logs", device, "poll")
        for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if not re.fullmatch(r"[0-9-]+(\.[0-9]+)?\.log(\.gz)?", f):
                continue
            op = gzip.open if f.endswith(".gz") else open
            with op(os.path.join(d, f), "rb") as fh:
                for line in fh:
                    m = ENV_RE.match(line.rstrip(b"\n"))
                    if not m:
                        continue
                    t = ts(m.group(1).decode())
                    if (t0 and t < t0) or (t1 and t >= t1):
                        continue
                    rows.append((t, m.group(1).decode(), parse_rec(unescape_env(m.group(3).decode("utf-8", "replace")))))
    else:
        for line in open(src, encoding="utf-8-sig", errors="replace"):
            line = line.strip()
            if not line.startswith("{"):
                continue
            j = json.loads(line)
            if j.get("type") != "poll" or j.get("device_id") != device:
                continue
            t = ts(j["received"])
            if (t0 and t < t0) or (t1 and t >= t1):
                continue
            rows.append((t, j["received"], parse_rec(j["raw"])))
    rows.sort(key=lambda r: r[0])
    return rows


def tsopt(v):
    return ts(v) if v else None


def utc(t, fmt="%H:%M:%S"):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime(fmt)


def cmd_netdev(a):
    """Sample /proc/net/dev for one interface every --interval s: t,rx_bytes,rx_packets,rx_multicast,tx_bytes,tx_packets."""
    import time
    end = time.time() + a.secs
    with open(a.out, "w") as o:
        o.write("t,rx_bytes,rx_packets,rx_multicast,tx_bytes,tx_packets\n")
        while time.time() < end:
            t = time.time()
            for l in open("/proc/net/dev"):
                if ":" in l and l.split(":", 1)[0].strip() == a.iface:
                    f = l.split(":", 1)[1].split()
                    o.write(f"{t:.3f},{f[0]},{f[1]},{f[7]},{f[8]},{f[9]}\n"); o.flush()
            time.sleep(max(0, a.interval - (time.time() - t)))


def interp(rows, t, col):
    """col of the netdev samples linearly interpolated at time t (None outside the samples)."""
    import bisect
    i = bisect.bisect_left([r[0] for r in rows], t)
    if i == 0 or i >= len(rows):
        return None
    (ta, va), (tb, vb) = (rows[i - 1][0], rows[i - 1][1][col]), (rows[i][0], rows[i][1][col])
    return va + (vb - va) * (t - ta) / (tb - ta)


def cmd_poll_rates(a):
    """The poller's per-cycle rates for one interface against the target's own /proc/net/dev over the same windows."""
    import csv, statistics
    nd = [(float(r["t"]), {k: int(r[k]) for k in r if k != "t"}) for r in csv.DictReader(open(a.netdev))]
    lines = [(t, rec) for t, _, rec in iter_poll(a.src, a.device, tsopt(a.from_), tsopt(a.to))
             if rec.get("kind") == "if" and rec.get("name") == a.iface]
    out, errs, lags = [], {k: [] for k in ("in_bps", "out_bps", "in_pps", "out_pps")}, []
    tot = {"ws_in": 0.0, "true_in": 0.0, "ws_out": 0.0, "true_out": 0.0}
    for (ta, ra), (tb, rb) in zip(lines, lines[1:]):
        if "in_bps" not in rb:
            continue
        A, B = ta + a.offset, tb + a.offset
        if A < nd[0][0] + a.margin or B > nd[-1][0] - a.margin:
            continue
        d = {c: interp(nd, B, c) - interp(nd, A, c) for c in ("rx_bytes", "rx_packets", "tx_bytes", "tx_packets")}
        span = tb - ta
        truth = {"in_bps": d["rx_bytes"] * 8 / span, "out_bps": d["tx_bytes"] * 8 / span,
                 "in_pps": d["rx_packets"] / span, "out_pps": d["tx_packets"] / span}
        ws = {"in_bps": float(rb["in_bps"]), "out_bps": float(rb["out_bps"]),
              "in_pps": sum(float(rb.get(k, 0)) for k in ("in_ucast_pps", "in_mcast_pps", "in_bcast_pps")),
              "out_pps": sum(float(rb.get(k, 0)) for k in ("out_ucast_pps", "out_mcast_pps", "out_bcast_pps"))}
        row = {"t": utc(tb, "%H:%M:%S.%f")[:-3], "span_s": round(span, 3)}
        for k in truth:
            e = 100 * (ws[k] - truth[k]) / truth[k] if truth[k] else None
            row[k], row["true_" + k], row["err_pct_" + k] = round(ws[k], 1), round(truth[k], 1), None if e is None else round(e, 3)
            if e is not None and truth[k] >= a.min_rate[k[-3:]]:
                errs[k].append(e)
        tot["ws_in"] += ws["in_bps"] * span; tot["true_in"] += truth["in_bps"] * span
        tot["ws_out"] += ws["out_bps"] * span; tot["true_out"] += truth["out_bps"] * span
        o = int(rb["in_octets"])   # when did the target's own counter equal the polled ifHCInOctets? (read time vs receive time)
        for (t1, r1), (t2, r2) in zip(nd, nd[1:]):
            if r1["rx_bytes"] <= o <= r2["rx_bytes"] and r2["rx_bytes"] > r1["rx_bytes"]:
                lags.append(B - (t1 + (t2 - t1) * (o - r1["rx_bytes"]) / (r2["rx_bytes"] - r1["rx_bytes"])))
                break
        out.append(row)
    for r in out:
        print(json.dumps(r))
    summ = {"cycles": len(out), "offset_s": a.offset}
    for k, v in errs.items():
        if v:
            summ[k] = {"n": len(v), "mean_err_pct": round(statistics.mean(v), 3), "mean_abs_err_pct": round(statistics.mean(abs(x) for x in v), 3),
                       "max_abs_err_pct": round(max(abs(x) for x in v), 3)}
    for k in ("in", "out"):
        if tot["true_" + k]:
            summ[f"window_{k}_bits_err_pct"] = round(100 * (tot["ws_" + k] - tot["true_" + k]) / tot["true_" + k], 3)
    if lags:
        summ["in_octets_read_lag_s"] = {"median": round(statistics.median(lags), 3), "min": round(min(lags), 3), "max": round(max(lags), 3)}
    print(json.dumps({"summary": summ}))


def cmd_poll_cycles(a):
    """Cycle timing and outcomes for one device: answered and failed cycles, spacing, late gaps, cycle-number jumps,
    restarts, and per interface the lines with and without rates, discontinuities, wraps and oper states."""
    import statistics
    cyc, status, restarts, kinds, ifl = {}, {}, [], {}, {}
    for t, txt, r in iter_poll(a.src, a.device, tsopt(a.from_), tsopt(a.to)):
        k = r.get("kind", "")
        kinds[k] = kinds.get(k, 0) + 1
        c = int(r.get("cycle", -1))
        if k in ("sys", "status"):
            if k == "status":
                status[r.get("status")] = status.get(r.get("status"), 0) + 1
            cyc.setdefault(c, (t, k))
        elif k == "restart":
            restarts.append({"t": txt, "cycle": c, **{x: r.get(x) for x in ("reboot", "source", "uptime", "prev_uptime", "hr_uptime")}})
        elif k == "if":
            st = ifl.setdefault(r.get("name") or r.get("if"), {"lines": 0, "with_rate": 0, "no_rate": [], "disc": 0, "wraps": 0, "oper": {}})
            st["lines"] += 1
            if "in_bps" in r:
                st["with_rate"] += 1
            else:
                st["no_rate"].append(txt[11:19])
            st["disc"] += r.get("disc") == "1"
            st["wraps"] += bool(r.get("wraps"))
            st["oper"][r.get("oper", "")] = st["oper"].get(r.get("oper", ""), 0) + 1
    ok = sorted(t for t, k in cyc.values() if k == "sys")
    gaps = [y - x for x, y in zip(ok, ok[1:])]
    late = [(utc(ok[i]), round(g, 1)) for i, g in enumerate(gaps) if g > 1.5 * a.interval]
    nums = sorted(cyc)
    out = {"device": a.device, "lines_by_kind": kinds, "cycles": len(cyc), "answered": len(ok), "failed_by_status": status,
           "first": utc(ok[0], "%Y-%m-%dT%H:%M:%SZ") if ok else None, "last": utc(ok[-1], "%Y-%m-%dT%H:%M:%SZ") if ok else None,
           "expected_cycles": round((ok[-1] - ok[0]) / a.interval) + 1 if ok else 0,
           "spacing_s": {"median": round(statistics.median(gaps), 3), "min": round(min(gaps), 3), "max": round(max(gaps), 3),
                         "p99_abs_dev": round(sorted(abs(g - a.interval) for g in gaps)[int(0.99 * (len(gaps) - 1))], 3)} if gaps else None,
           "late_gap_count": len(late), "late_gaps": late[:50],
           "cycle_number_jumps": [(x, y) for x, y in zip(nums, nums[1:]) if y != x + 1][:20], "restarts": restarts,
           "interfaces": {k: dict(v, no_rate=v["no_rate"][:10], no_rate_count=len(v["no_rate"])) for k, v in ifl.items()}}
    print(json.dumps(out))


def cmd_poll_size(a):
    """One device's poll lines in a window: count by kind, bytes, gzip -6 of exactly those bytes, scaled per day."""
    t0, t1 = tsopt(a.from_), tsopt(a.to)
    d = os.path.join(a.data, "logs", a.device, "poll")
    raw, n, kinds, first, last, files = io.BytesIO(), 0, {}, None, None, {}
    for f in sorted(os.listdir(d)):
        files[f] = os.path.getsize(os.path.join(d, f))
        op = gzip.open if f.endswith(".gz") else open
        with op(os.path.join(d, f), "rb") as fh:
            for line in fh:
                m = ENV_RE.match(line.rstrip(b"\n"))
                if not m:
                    continue
                t = ts(m.group(1).decode())
                if (t0 and t < t0) or (t1 and t >= t1):
                    continue
                raw.write(line); n += 1
                k = re.search(rb" kind=(\w+)", line)
                k = k.group(1).decode() if k else ""
                kinds[k] = kinds.get(k, 0) + 1
                first = first or t; last = t
    b = raw.getvalue()
    gz = len(gzip.compress(b, 6))
    span = (last - first) if first and last and last > first else 0
    f = 86400 / span if span else 0
    print(json.dumps({"device": a.device, "files": files, "lines": n, "lines_by_kind": kinds, "bytes": len(b), "gzip_bytes": gz,
                      "ratio": round(len(b) / gz, 2) if gz else None, "span_h": round(span / 3600, 3),
                      "per_day": {"lines": round(n * f), "bytes": round(len(b) * f), "gzip_bytes": round(gz * f)}}))


POLL_CSV_COLS = {
    "system.csv": "time,cycle,uptime_s,hr_uptime_s,cpu_pct,mem_used_bytes,mem_total_bytes,rtt_ms,status,detail".split(","),
    "interfaces.csv": ("time,cycle,if_index,if_name,if_alias,oper,speed_mbps,in_octets,out_octets,in_bps,out_bps,in_errors,out_errors,"
                       "in_errors_delta,out_errors_delta,in_discards,out_discards,in_discards_delta,out_discards_delta,discontinuity").split(","),
    "oids.csv": "time,cycle,oid,label,row,type,value,rate".split(","),
}


def ticks_s(v):
    """TimeTicks as the CSVs' seconds ("1045123.45", trailing zero dropped)."""
    if not v:
        return ""
    n = int(v)
    return str(n // 100) if n % 100 == 0 else f"{n // 100}.{n % 100:02d}".rstrip("0")


def cmd_poll_csv(a):
    """A bundle's or export's poll CSVs against the poll lines: header, CRLF, manifest rows and sha256, and every row
    equal to the values of the line it came from (same device, cycle, kind, interface or OID, and time)."""
    import csv, hashlib
    z = zipfile.ZipFile(a.zip)
    names = set(z.namelist())
    man = json.loads(z.read("manifest.json"))
    mfiles = {f["path"]: f for f in man["files"]}
    res = {"zip": os.path.basename(a.zip), "devices": {}}
    for dev in sorted({n.split("/")[1] for n in names if n.startswith("poll/")}):
        lines = iter_poll(a.lines, dev, tsopt(a.from_), tsopt(a.to))
        by, alias, lk = {}, {}, {}
        for t, txt, r in lines:
            k = r.get("kind")
            lk[k] = lk.get(k, 0) + 1
            key = r.get("if", "") if k == "if" else (r.get("oid", "") + "|" + r.get("row", "") if k == "oid" else "")
            by.setdefault((k, r.get("cycle"), key), []).append((txt, r))
            if k == "info" and "if" in r:
                alias.setdefault(r["if"], []).append((t, r.get("alias", "")))
        dres = {"lines_in_window_by_kind": lk}
        for fn, cols in POLL_CSV_COLS.items():
            path = f"poll/{dev}/{fn}"
            if path not in names:
                dres[fn] = "absent"; continue
            data = z.read(path)
            rows = list(csv.reader(io.StringIO(data.decode("utf-8"), newline="")))
            hdr, body = rows[0], rows[1:]
            bad, checked = [], 0
            for row in body:
                c = dict(zip(hdr, row))
                if fn == "system.csv":
                    kind = {"ok": "sys", "restart": "restart"}.get(c.get("status"), "status")
                    cands = by.get((kind, c.get("cycle"), ""), [])
                elif fn == "interfaces.csv":
                    cands = by.get(("if", c.get("cycle"), c.get("if_index")), [])
                else:
                    cands = by.get(("oid", c.get("cycle"), c.get("oid", "") + "|" + c.get("row", "")), [])
                r = next((r for txt, r in cands if txt[:23] == c.get("time", "")[:23]), None)
                if r is None:
                    bad.append(["no line", row[:5]]); continue
                if fn == "system.csv":
                    if kind == "sys":
                        want = [c["time"], r.get("cycle"), ticks_s(r.get("uptime")), ticks_s(r.get("hr_uptime"))] + \
                            [r.get(x, "") for x in ("cpu", "mem_used", "mem_total", "rtt_ms")] + ["ok", ""]
                    elif kind == "status":
                        want = [c["time"], r.get("cycle"), "", "", "", "", "", "", r.get("status", ""), r.get("detail", "")]
                    else:
                        want = [c["time"], r.get("cycle"), ticks_s(r.get("uptime")), ticks_s(r.get("hr_uptime")), "", "", "", "", "restart", c["detail"]]
                        if r.get("reboot") == "?" and "may have rebooted" not in c["detail"]:
                            bad.append(["reboot=? but the detail doesn't say 'may have rebooted'", row])
                elif fn == "interfaces.csv":
                    l, al = alias.get(r.get("if"), []), ""
                    if l:
                        prior = [x for x in l if x[0] <= ts(c["time"])]
                        al = (prior[-1] if prior else l[0])[1]
                    want = [c["time"], r.get("cycle"), r.get("if"), r.get("name", ""), al, r.get("oper", ""), r.get("speed_mbps", "")] + \
                        [r.get(x, "") for x in ("in_octets", "out_octets", "in_bps", "out_bps", "in_err", "out_err", "in_err_d", "out_err_d",
                                                "in_disc", "out_disc", "in_disc_d", "out_disc_d")] + ["1" if r.get("disc") == "1" else ""]
                else:
                    want = [c["time"], r.get("cycle")] + [r.get(x, "") for x in ("oid", "label", "row", "type", "value", "rate")]
                checked += 1
                if [str(x) for x in want] != row:
                    bad.append(["differs", row, [str(x) for x in want]])
            mf = mfiles.get(path, {})
            dres[fn] = {"header_ok": hdr == cols, "crlf_only": data.count(b"\r\n") == data.count(b"\n") > 0, "rows": len(body),
                        "manifest_lines": mf.get("lines"), "sha256_ok": mf.get("sha256") == hashlib.sha256(data).hexdigest(),
                        "rows_checked": checked, "mismatches": len(bad), "first_mismatches": bad[:5],
                        "rows_by_status": {s: sum(1 for x in body if dict(zip(hdr, x)).get("status") == s)
                                           for s in sorted({dict(zip(hdr, x)).get("status") for x in body})} if fn == "system.csv" else None}
        res["devices"][dev] = dres
    readme = z.read("README.txt").decode("utf-8", "replace") if "README.txt" in names else ""
    keep, out = False, []
    for l in readme.splitlines():
        if re.match(r"\s+(Polls|Reboots)\b", l):
            keep = True; out.append(l)
        elif keep and re.match(r"\s{12,}\S", l):
            out.append(l)
        else:
            keep = False
            if re.match(r"\S", l) and re.search(r"\d+\.\d+\.\d+\.\d+", l):
                out.append(l)
    res["readme_device_and_poll_lines"] = out[:80]
    res["manifest_devices"] = [{k: d.get(k) for k in ("device_id", "id", "reboots", "poll", "gaps") if k in d} for d in man.get("devices", [])
                               if d.get("reboots") or d.get("poll")]
    print(json.dumps(res))


def main():
    ap = argparse.ArgumentParser(prog="labcheck.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("secret-scan"); p.add_argument("--journal"); p.add_argument("paths", nargs="+")
    p = sub.add_parser("window"); p.add_argument("zip"); p.add_argument("--from", dest="from_", required=True)
    p.add_argument("--to", required=True); p.add_argument("--run", action="append"); p.add_argument("--data")
    p = sub.add_parser("missing"); p.add_argument("src"); p.add_argument("--run", required=True); p.add_argument("--n", type=int, required=True)
    p.add_argument("--blocks", type=int); p.add_argument("--rate", type=float); p.add_argument("--start", type=float)
    p.add_argument("--list", type=int, default=50)
    p = sub.add_parser("netdev"); p.add_argument("--iface", required=True); p.add_argument("--secs", type=float, required=True)
    p.add_argument("--out", required=True); p.add_argument("--interval", type=float, default=1.0)
    p = sub.add_parser("poll-rates"); p.add_argument("src"); p.add_argument("--device", required=True)
    p.add_argument("--if", dest="iface", required=True); p.add_argument("--netdev", required=True)
    p.add_argument("--offset", type=float, default=0.0); p.add_argument("--margin", type=float, default=2.0)
    p.add_argument("--from", dest="from_"); p.add_argument("--to")
    p = sub.add_parser("poll-cycles"); p.add_argument("src"); p.add_argument("--device", required=True)
    p.add_argument("--interval", type=float, default=60); p.add_argument("--from", dest="from_"); p.add_argument("--to")
    p = sub.add_parser("poll-size"); p.add_argument("data"); p.add_argument("--device", required=True)
    p.add_argument("--from", dest="from_"); p.add_argument("--to")
    p = sub.add_parser("poll-csv"); p.add_argument("zip"); p.add_argument("--lines", required=True)
    p.add_argument("--from", dest="from_"); p.add_argument("--to")
    a = ap.parse_args()
    a.min_rate = {"bps": 1000, "pps": 1}   # poll-rates: error % only where the true rate is at least this
    {"secret-scan": cmd_secret_scan, "window": cmd_window, "missing": cmd_missing, "netdev": cmd_netdev,
     "poll-rates": cmd_poll_rates, "poll-cycles": cmd_poll_cycles, "poll-size": cmd_poll_size, "poll-csv": cmd_poll_csv}[a.cmd](a)


if __name__ == "__main__":
    main()
