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
  labcheck.py flow-seq SRC --run RUN --n N [--first S] [--truth T] [--devices D,..] [--list 20]
      Flows (2.0): exactly once by the generator's run and sequence numbers. SRC is `woodshed search --type flow --json`
      output (a file, .gz, or - for stdin). Each record's run and number come from its extras (IPFIX PEN 32473 IEs 1 and 2,
      flow v9 field types 40001 and 40002) or, for flow v5, src_as/dst_as and the header's engine fields (the run's last 4
      hex digits). Prints received, missing (as ranges), duplicates and per-device counts. With --truth (the senders'
      `--flow-log` files: a dir or .tgz holding flowlog-*.jsonl), every stored record is compared with what was sent
      (addresses, ports, protocol, packets, bytes, sampling, domain, firewall event) and the sums are checked.
  labcheck.py flow-top --truth T --top JSON --by KEY [--metric M] [--fw-event E] [--from T --to T] [--manifest ZIP --device D]
      `woodshed flows top --json` (or /api/flows/top) against the top-N computed from the senders' logs: every row's value,
      the ranking (ties aside) and the totals. With --manifest, the bundle summary's top lists and counts for D too.
      The window and devices of the top must hold exactly the run's records (the totals check says when they don't); with
      --from/--to, only the logged records whose [start, end] overlaps that window count (flow time, as the query's window).
      Packets and conversations need a run without --events or --biflow (the logs carry neither the initiator packets
      nor the responder and reverse counts).
  labcheck.py flow-csv ZIP --lines SRC
      A bundle's or export's flows/<device>/flows.csv against the stored records (SRC as for flow-seq, the same window):
      the documented header, CRLF only, the manifest's rows and sha256, and every row equal to one record, as multisets.
  labcheck.py flow-ipfix FILE|ZIP [--tshark OUT]
      An IPFIX file (RFC 5655), or every flows/<device>/flows.ipfix in a zip, read by this script's own reader: message and
      set lengths, template field specifiers (an enterprise bit must have its PEN), data records ending at their set.
      In a zip, each file's 5-tuples are compared with its flows.csv. --tshark: also compare the output of
      `tshark -r FILE -T fields -E occurrence=a -E aggregator=';' -e cflow.srcaddr -e cflow.dstaddr -e cflow.srcport
      -e cflow.dstport -e cflow.protocol` (one file) with the CSV, as CI does. IPv4 only (the generator's addresses); a
      record missing one of the fields would shift tshark's occurrence lists, so use it on generator data.
  labcheck.py flow-match SRC --src A --dst B [--dst-port P] [--proto N] [--expect-packets N --expect-bytes N]
      The stored flows for one conversation (a real exporter's records of known traffic): records, packets, bytes, by version.
  labcheck.py flow-size DATA [--devices D,..] [--records N]
      The flow segments' bytes per device (logs/<device>/flows/*.wsf) and, with N, the bytes per stored record.
  labcheck.py udp-snmp [--ports 514,2055,4739] [--iface IF]
      The kernel's UDP counters (/proc/net/snmp), each listed port's socket drops (/proc/net/udp, udp6), and the
      interface's rx counters: one JSON line, for before/after loss checks at the receiving end.
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


# ---- flows (2.0) ----
FLOW_CSV_COLS = ("start,end,event_time,src,src_port,dst,dst_port,proto,tcp_flags,packets,bytes,sampling,packets_scaled,"
                 "bytes_scaled,in_if,in_if_name,out_if,out_if_name,domain,fw_event,nat_event,post_nat_src,post_nat_src_port,"
                 "post_nat_dst,post_nat_dst_port,initiator_bytes,responder_bytes,initiator_packets,responder_packets,rev_bytes,"
                 "rev_packets,rule_id,tos,src_as,dst_as,next_hop,time_source,status,received").split(",")
GEN_PEN = 32473                      # the generator's IEs (IANA's documentation enterprise number)
V9_RUN, V9_SEQ = 40001, 40002        # its flow v9 field types
PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmpv6", 132: "sctp"}


def open_src(src):
    """A text stream: stdin for '-', gzip for .gz, else the file."""
    if src == "-":
        return sys.stdin
    if src.endswith(".gz"):
        return gzip.open(src, "rt", encoding="utf-8")
    return open(src, encoding="utf-8")


def iter_flows(src, devices=None):
    """(device_id, received, fields) for each flow record of `woodshed search --type flow --json` output."""
    for line in open_src(src):
        line = line.strip()
        if not line.startswith("{"):
            continue
        d = json.loads(line)
        if d.get("type") != "flow" or "fields" not in d:
            continue
        if devices and d.get("device_id") not in devices:
            continue
        yield d.get("device_id"), d.get("received"), d["fields"]


def flow_seq_of(f):
    """(run tag, seq) the generator put in a stored record, or None (the rules of the generator's FlowSeq)."""
    run = seq = None
    eng = {}
    for e in f.get("extras") or []:
        pen, i, h = e.get("pen"), e.get("id"), e.get("hex", "")
        if (pen == GEN_PEN and i == 1) or (pen == 0 and i == V9_RUN):
            if len(h) == 8:
                run = h
        elif (pen == GEN_PEN and i == 2) or (pen == 0 and i == V9_SEQ):
            if len(h) == 16:
                seq = int(h, 16)
        elif pen == 0 and i in (38, 39) and len(h) == 2:
            eng[i] = h
    if run is not None and seq is not None:
        return run, seq
    if 38 in eng and 39 in eng and f.get("src_as") is not None and f.get("dst_as") is not None:
        return eng[38] + eng[39], (int(f["src_as"]) << 16) | int(f["dst_as"])
    return None


def run_matches(tag, run):
    return tag == run or (len(tag) == 4 and run.endswith(tag))


def iter_truth(src):
    """Every line of the senders' --flow-log files (flowlog-*.jsonl, in a dir tree or a .tgz)."""
    import tarfile
    if os.path.isdir(src):
        for root, dirs, files in os.walk(src):
            dirs.sort()
            for fn in sorted(files):
                if re.fullmatch(r"flowlog-[0-9]+\.jsonl", fn):
                    for line in open(os.path.join(root, fn), encoding="utf-8"):
                        if line.strip():
                            yield json.loads(line)
        return
    with tarfile.open(src) as tf:
        for m in tf.getmembers():
            if m.isfile() and re.fullmatch(r"flowlog-[0-9]+\.jsonl", os.path.basename(m.name)):
                for line in io.TextIOWrapper(tf.extractfile(m), encoding="utf-8"):
                    if line.strip():
                        yield json.loads(line)


def bit_ranges(bits, n, first, limit, want_set):
    """(count, the first `limit` ranges) of the positions whose bit is set (want_set) or clear, without listing them all.
    Whole bytes of 0x00/0xFF are skipped at once, so a soak-sized map with nothing (or everything) stored stays cheap."""
    count, out, start, prev = 0, [], None, None
    skip = 0x00 if want_set else 0xFF
    nb = (n + 7) // 8
    b = 0
    while b < nb:
        v = bits[b]
        if v == skip and (b + 1) * 8 <= n:
            if start is not None:
                if len(out) < limit:
                    out.append(f"{start}-{prev}" if prev != start else str(start))
                start = None
            b += 1
            continue
        if v == (0xFF ^ skip) and (b + 1) * 8 <= n:     # all 8 count
            count += 8
            lo = b * 8 + first
            if start is None:
                start = lo
            elif prev != lo - 1:
                if len(out) < limit:
                    out.append(f"{start}-{prev}" if prev != start else str(start))
                start = lo
            prev = lo + 7
            b += 1
            continue
        for i in range(b * 8, min(b * 8 + 8, n)):
            hit = bool(v & (1 << (i & 7))) == want_set
            x = i + first
            if hit:
                count += 1
                if start is None:
                    start = prev = x
                elif x == prev + 1:
                    prev = x
                else:
                    if len(out) < limit:
                        out.append(f"{start}-{prev}" if prev != start else str(start))
                    start = prev = x
        b += 1
    if start is not None and len(out) < limit:
        out.append(f"{start}-{prev}" if prev != start else str(start))
    return count, out


def ranges(nums, limit):
    out, start, prev = [], None, None
    for x in nums:
        if start is None:
            start = prev = x
        elif x == prev + 1:
            prev = x
        else:
            out.append(f"{start}-{prev}" if prev != start else str(start))
            start = prev = x
            if len(out) >= limit:
                break
    if start is not None and len(out) < limit:
        out.append(f"{start}-{prev}" if prev != start else str(start))
    return out


TRUTH_FIELDS = (("src", "src"), ("dst", "dst"), ("src_port", "src_port"), ("dst_port", "dst_port"), ("proto", "proto"),
                ("packets", "packets"), ("bytes", "bytes"), ("sampling", "sampling"), ("domain", "domain"),
                ("fw_event", "fw_event"))


def flow_seq_check(src, run, n, first=0, truth=None, devices=None, limit=20):
    """The flow-seq result as a dict (see the module doc)."""
    seen = bytearray((n + 7) // 8)
    dup = bytearray((n + 7) // 8)
    want = {}
    if truth:
        if n > 1_000_000:
            raise SystemExit("labcheck: --truth holds every record in memory: at most 1,000,000")
        for t in iter_truth(truth):                 # only the compared fields, as a tuple
            want[int(t["seq"])] = tuple(t.get(tk) for _, tk in TRUTH_FIELDS) + (t.get("sum_bytes"),)
    res = {"run": run, "n": n, "first": first, "received": 0, "duplicates": 0, "out_of_range": 0, "other_runs": 0,
           "untagged": 0, "by_device": {}}
    mism, msample, sums = 0, [], {"bytes": 0, "packets": 0}
    for dev, received, f in iter_flows(src, devices):
        tag = flow_seq_of(f)
        if tag is None:
            res["untagged"] += 1; continue
        if not run_matches(tag[0], run):
            res["other_runs"] += 1; continue
        i = tag[1] - first
        if not 0 <= i < n:
            res["out_of_range"] += 1; continue
        b, bit = i >> 3, 1 << (i & 7)
        if seen[b] & bit:
            dup[b] |= bit
            res["duplicates"] += 1
        else:
            seen[b] |= bit
            res["received"] += 1
        res["by_device"][dev] = res["by_device"].get(dev, 0) + 1
        sums["bytes"] += f.get("bytes") or 0
        sums["packets"] += f.get("packets") or 0
        if truth:
            t = want.get(tag[1])
            if t is None:
                mism += 1
                if len(msample) < 5:
                    msample.append({"seq": tag[1], "problem": "not in the senders' logs"})
                continue
            diff = {}
            for (sk, tk), tv in zip(TRUTH_FIELDS, t):
                sv = f.get(sk)
                if tk in ("src", "dst", "fw_event") and tv in ("", None):
                    tv = None
                if tk in ("domain", "packets", "bytes") and sv is None:
                    sv = 0                             # not reported vs the generator's zero value (event records)
                if sv != tv and not (tk == "sampling" and tv == 0 and sv == 0):
                    diff[sk] = [sv, tv]
            if diff:
                mism += 1
                if len(msample) < 5:
                    msample.append({"seq": tag[1], "device": dev, "stored_vs_sent": diff})
    res["missing"], res["missing_ranges"] = bit_ranges(seen, n, first, limit, want_set=False)
    _, res["duplicate_seqs"] = bit_ranges(dup, n, first, limit, want_set=True)
    res["stored_sums"] = sums
    if truth:
        ib, ip = [tk for _, tk in TRUTH_FIELDS].index("bytes"), [tk for _, tk in TRUTH_FIELDS].index("packets")
        tb = sum(int(t[ib] or 0) for t in want.values())
        tp = sum(int(t[ip] or 0) for t in want.values())
        res["truth"] = {"records": len(want), "bytes": tb, "packets": tp, "sum_bytes": sum(int(t[-1] or 0) for t in want.values()),
                        "mismatches": mism, "first_mismatches": msample,
                        "sums_exact": sums["bytes"] == tb and sums["packets"] == tp and len(want) == n}
    res["ok"] = (res["missing"] == 0 and res["duplicates"] == 0 and res["out_of_range"] == 0 and
                 (not truth or (res["truth"]["mismatches"] == 0 and res["truth"]["sums_exact"])))
    return res


def cmd_flow_seq(a):
    devs = set(a.devices.split(",")) if a.devices else None
    print(json.dumps(flow_seq_check(a.src, a.run, a.n, a.first, a.truth, devs, a.list)))


def _ipkey(x):
    import ipaddress
    try:
        return (0, ipaddress.ip_address(x))
    except ValueError:
        return (1, x)


def truth_key(t, by):
    """The top-N key of a logged record, or None when it lacks that column (the product skips such records)."""
    pn = lambda p: PROTO_NAMES.get(int(p or 0), str(p))
    if by in ("src", "dst"):
        return t.get(by) or None
    if by == "dst_port":
        return f"{pn(t.get('proto'))}/{t.get('dst_port')}"
    if by == "src_port":
        return f"{pn(t.get('proto'))}/{t.get('src_port')}"
    if by == "proto":
        return str(t.get("proto"))                      # the key is the number (its label is the name)
    if by == "conversation":
        if not t.get("src") or not t.get("dst"):
            return None
        a, b = sorted([t["src"], t["dst"]], key=_ipkey)
        return f"{a} ↔ {b}"
    if by in ("fw_event", "rule_id", "post_nat_src"):
        return t.get(by) or None
    raise SystemExit(f"labcheck: flow-top --by {by} isn't computed from the logs")


def truth_value(t, metric, event_style):
    if metric == "bytes":
        return int(t.get("sum_bytes") or 0)
    if metric == "packets":
        # the logs carry no initiator packets, so packet sums are known only for runs without --events
        return None if event_style else int(t.get("packets") or 0)
    if metric == "flows":
        return 1
    if metric == "connections":
        return 1 if (not event_style or t.get("fw_event") in ("deleted", "denied")) else 0
    raise SystemExit(f"labcheck: unknown metric {metric}")


def in_window(t, t0, t1):
    """Flow time: the record's [start, end] overlaps [t0, t1)."""
    s, e = ts(t["start"]), ts(t["end"])
    return s < t1 and e >= t0


def flow_top_check(truth, top, by, metric=None, fw_event=None, manifest=None, device=None, t0=None, t1=None, want_rows=None):
    page = json.load(open(top)) if isinstance(top, str) else top
    metric = metric or page.get("metric") or ("flows" if fw_event == "denied" else "bytes")
    allrecs = list(iter_truth(truth))
    if t0 is not None or t1 is not None:
        allrecs = [t for t in allrecs if in_window(t, t0 if t0 is not None else float("-inf"), t1 if t1 is not None else float("inf"))]
    recs = [t for t in allrecs if not fw_event or t.get("fw_event") == fw_event]
    event_style = any(t.get("fw_event") for t in allrecs)
    if (metric == "packets" or by == "conversation") and event_style:
        # conversations add the responder (or reverse) counts and packet sums the initiator packets: not in the logs
        return {"by": by, "metric": metric, "ok": False,
                "problem": "the senders' logs can't give this for --events runs: use a run without --events or --biflow"}
    agg = {}
    for t in recs:
        k = truth_key(t, by)
        if k is not None:
            agg[k] = agg.get(k, 0) + truth_value(t, metric, event_style)
    totals = {"flows": len(recs), "bytes": sum(truth_value(t, "bytes", event_style) for t in recs),
              "connections": sum(truth_value(t, "connections", event_style) for t in recs)}
    if not event_style:
        totals["packets"] = sum(truth_value(t, "packets", event_style) for t in recs)
    rows = page.get("rows") or []
    n = len(rows)
    ranked = sorted(agg.items(), key=lambda kv: -kv[1])
    res = {"by": by, "metric": metric, "rows": n, "keys_in_truth": len(agg), "row_mismatches": [], "rank_ok": True}
    for r in rows:
        k = r.get("key")
        want = agg.get(k)
        got = r.get(metric)
        if want != got:
            res["row_mismatches"].append({"key": k, "stored": got, "truth": want})
    nonzero = [k for k, v in ranked if v]
    if want_rows is not None and n != min(want_rows, len(nonzero)):   # the top asked for N rows: it must give them
        res["rank_ok"] = False
        res["short"] = {"rows": n, "expected": min(want_rows, len(nonzero))}
    if not n and nonzero:                                      # an empty top (all in "other") while the logs have keys
        res["missing_from_top"], res["rank_ok"] = nonzero[:10], False
        res["note"] = ("no rows: the stored records have no value for this key (rule_id needs listeners.flow.rule_id_ies, "
                       "e.g. 32473:3 for IPFIX and 0:40003 for flow v9)") if by == "rule_id" else "no rows"
    if n:
        cut = ranked[n - 1][1] if len(ranked) >= n else 0
        must = {k for k, v in ranked if v > cut}              # keys above the boundary value must all be there,
        ties = {k for k, v in ranked if v == cut}             # and enough of those tied at it to fill the rows
        have = {r.get("key") for r in rows}
        missing = sorted(must - have)
        if len(have & ties) < n - len(must & have) and len(have & ties) < len(ties):
            missing += sorted(ties - have)
        res["missing_from_top"] = missing[:10]
        res["rank_ok"] = res["rank_ok"] and not missing and not (have - must - ties) and \
            [r.get(metric) for r in rows] == [v for _, v in ranked[:n]]
    pt = page.get("total") or {}
    res["totals"] = {m: {"stored": pt.get(m), "truth": totals[m]} for m in totals if m in pt}
    tot_ok = all(v["stored"] == v["truth"] for v in res["totals"].values())
    res["approx"] = page.get("approx")
    res["partial"] = page.get("partial")
    res["ok"] = not res["row_mismatches"] and res["rank_ok"] and tot_ok and not page.get("approx") and not page.get("partial")
    if manifest:
        res["manifest"] = manifest_flow_check(manifest, device, truth)
        res["ok"] = res["ok"] and res["manifest"]["ok"]
    return res


def manifest_flow_check(zpath, device, truth):
    """The bundle manifest's flow summary for device against the logs: records, bytes, the top-3 lists' keys and shares,
    the firewall event counts and the denied tops."""
    z = zipfile.ZipFile(zpath)
    man = json.loads(z.read("manifest.json"))
    ent = next((d for d in man.get("summary") or [] if d.get("device_id") == device), None)
    if ent is None or "flow" not in ent:
        return {"ok": False, "problem": f"no flow summary for {device}"}
    fl = ent["flow"]
    recs = list(iter_truth(truth))
    ev = any(t.get("fw_event") for t in recs)

    def top3(by, metric, filt=None):
        agg = {}
        for t in recs:
            if filt and t.get("fw_event") != filt:
                continue
            k = truth_key(t, by)
            if k is not None:
                agg[k] = agg.get(k, 0) + truth_value(t, metric, ev)
        tot = sum(agg.values()) or 1
        return sorted(agg.items(), key=lambda kv: -kv[1]), tot

    out, ok = {}, True
    tb = sum(truth_value(t, "bytes", ev) for t in recs)
    out["records"] = {"manifest": fl.get("records"), "truth": len(recs)}
    out["bytes"] = {"manifest": fl.get("bytes"), "truth": tb}
    ok &= fl.get("records") == len(recs) and fl.get("bytes") == tb
    for name, by in (("top_talkers", "src"), ("top_dst_ports", "dst_port"), ("top_conversations", "conversation")):
        if by == "conversation" and ev:
            out[name] = {"manifest": fl.get(name), "truth": "not in the logs for --events runs"}
            continue
        ranked, tot = top3(by, "bytes")
        got = fl.get(name) or []
        want = [{"key": k, "share": round(v / tot, 4)} for k, v in ranked[:len(got)]]
        good = len(got) == min(3, sum(1 for _, v in ranked if v)) and all(g["key"] == w["key"] or dict(ranked).get(g["key"]) == dict(ranked).get(w["key"]) for g, w in zip(got, want)) and \
            all(abs(g.get("share", 0) - dict(ranked).get(g["key"], 0) / tot) < 0.00051 for g in got)
        out[name] = {"manifest": got, "truth": want, "ok": good}
        ok &= good
    if ev:
        fe = {}
        for t in recs:
            if t.get("fw_event"):
                fe[t["fw_event"]] = fe.get(t["fw_event"], 0) + 1
        want = {k: fe.get(k, 0) for k in ("created", "deleted", "denied")}
        out["fw_events"] = {"manifest": fl.get("fw_events"), "truth": want}
        ok &= {k: (fl.get("fw_events") or {}).get(k, 0) for k in want} == want
        for name, by in (("top_denied_sources", "src"), ("top_denied_ports", "dst_port")):
            ranked, _ = top3(by, "flows", "denied")
            got = fl.get(name) or []
            d = dict(ranked)
            good = len(got) == min(3, sum(1 for _, v in ranked if v)) and all(d.get(g["key"]) == g.get("count") for g in got) and [g.get("count") for g in got] == [v for _, v in ranked[:len(got)]]
            out[name] = {"manifest": got, "truth": [{"key": k, "count": v} for k, v in ranked[:len(got)]], "ok": good}
            ok &= good
    out["ok"] = bool(ok)
    return out


def cmd_flow_top(a):
    print(json.dumps(flow_top_check(a.truth, a.top, a.by, a.metric, a.fw_event, a.manifest, a.device, tsopt(a.from_), tsopt(a.to), a.n)))


def csv_cell(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "1" if v else "0"
    return str(v)


def flow_csv_check(zpath, lines):
    import csv, hashlib
    z = zipfile.ZipFile(zpath)
    names = set(z.namelist())
    man = json.loads(z.read("manifest.json"))
    mfiles = {f["path"]: f for f in man["files"]}
    stored = {}
    for dev, received, f in iter_flows(lines):
        row = tuple(csv_cell(received if c == "received" else f.get(c)) for c in FLOW_CSV_COLS)
        stored.setdefault(dev, {})
        stored[dev][row] = stored[dev].get(row, 0) + 1
    res = {"zip": os.path.basename(zpath), "devices": {}, "ok": True}
    for path in sorted(n for n in names if re.fullmatch(r"flows/[^/]+/flows\.csv", n)):
        dev = path.split("/")[1]
        data = z.read(path)
        rows = list(csv.reader(io.StringIO(data.decode("utf-8"), newline="")))
        hdr, body = rows[0], rows[1:]
        got = {}
        for r in body:
            got[tuple(r)] = got.get(tuple(r), 0) + 1
        want = stored.get(dev, {})
        only_csv = [list(k) for k, v in got.items() if v > want.get(k, 0)]
        only_lines = [list(k) for k, v in want.items() if v > got.get(k, 0)]
        mf = mfiles.get(path, {})
        d = {"rows": len(body), "records_in_lines": sum(want.values()), "header_ok": hdr == FLOW_CSV_COLS,
             "crlf_only": data.count(b"\r\n") == data.count(b"\n") > 0, "manifest_lines": mf.get("lines"),
             "sha256_ok": mf.get("sha256") == hashlib.sha256(data).hexdigest(),
             "only_in_csv": len(only_csv), "only_in_lines": len(only_lines), "first_only_in_csv": only_csv[:3],
             "first_only_in_lines": only_lines[:3]}
        d["ok"] = (d["header_ok"] and d["crlf_only"] and d["sha256_ok"] and mf.get("lines") == len(body) and
                   not only_csv and not only_lines)
        res["devices"][dev] = d
        res["ok"] = res["ok"] and d["ok"]
    for dev in sorted(set(stored) - set(res["devices"])):
        res["devices"][dev] = {"ok": False, "problem": "records in the lines but no flows.csv in the zip"}
        res["ok"] = False
    if not res["devices"] or not any(d.get("rows") for d in res["devices"].values()):
        res["ok"] = False
        res["problem"] = "nothing to compare: no flows.csv rows in the zip"
    readme = z.read("README.txt").decode("utf-8", "replace") if "README.txt" in names else ""
    blk, keep = [], False
    for l in readme.splitlines():
        if re.match(r"\s+Flows\b", l):
            keep = True; blk.append(l)
        elif keep and re.match(r"\s{12,}\S", l):
            blk.append(l)
        elif re.match(r"\S", l) and re.search(r"\d+\.\d+\.\d+\.\d+|:", l) and len(l) < 60:
            keep = False; blk.append(l)
        else:
            keep = False
    res["readme_flows_lines"] = blk[:60]
    return res


def cmd_flow_csv(a):
    print(json.dumps(flow_csv_check(a.zip, a.lines)))


def ipfix_read(data):
    """This script's own IPFIX file reader: {"messages", "records", "errors", "templates", "tuples": {5-tuple: n},
    "runs": {run: set count}}. Structure errors are listed, never raised."""
    import ipaddress, struct
    out = {"messages": 0, "records": 0, "options_records": 0, "undecodable_sets": 0, "errors": [], "templates": 0,
           "tuples": {}, "bytes": 0, "packets": 0}
    tmpl, bad = {}, set()
    off = 0
    while off < len(data):
        if len(data) - off < 16:
            out["errors"].append(f"{len(data) - off} trailing bytes at {off}"); break
        ver, ln, _, _, dom = struct.unpack(">HHIII", data[off:off + 16])
        if ver != 10 or ln < 16 or off + ln > len(data):
            out["errors"].append(f"bad message header at {off} (version {ver}, length {ln})"); break
        out["messages"] += 1
        p, end = off + 16, off + ln
        while p < end:
            if end - p < 4:
                out["errors"].append(f"set header cut at {p}"); break
            sid, sl = struct.unpack(">HH", data[p:p + 4])
            if sl < 4 or p + sl > end:
                out["errors"].append(f"set {sid} at {p}: length {sl} past its message"); break
            body, q, send = data, p + 4, p + sl
            if sid in (2, 3):
                while send - q >= 4:
                    tid, fc = struct.unpack(">HH", body[q:q + 4]); q += 4
                    if tid == 0 and fc == 0:
                        break                                  # padding
                    if fc == 0:                                # a withdrawal (RFC 7011 §8.1); 2 / 3 withdraw all
                        if tid in (2, 3):
                            for k in [k for k in tmpl if k[0] == dom]:
                                tmpl.pop(k)
                        else:
                            tmpl.pop((dom, tid), None)
                        out["withdrawals"] = out.get("withdrawals", 0) + 1
                        continue
                    sc = 0
                    if sid == 3:
                        if send - q < 2:
                            out["errors"].append(f"options template {tid}: cut"); break
                        sc = struct.unpack(">H", body[q:q + 2])[0]; q += 2
                    fields, ok = [], True
                    for _ in range(fc):
                        if send - q < 4:
                            ok = False; break
                        fid, fl = struct.unpack(">HH", body[q:q + 4]); q += 4
                        pen = 0
                        if fid & 0x8000:
                            if send - q < 4:
                                ok = False; break
                            pen = struct.unpack(">I", body[q:q + 4])[0]; q += 4
                        fields.append((pen, fid & 0x7FFF, fl))
                    if not ok:
                        out["errors"].append(f"domain {dom} template {tid}: field specifiers run past the set "
                                             "(an enterprise bit without its PEN?)")
                        bad.add((dom, tid)); break
                    tmpl[(dom, tid)] = (sid == 3, sc, fields)
                    bad.discard((dom, tid))
                    out["templates"] += 1
            elif sid >= 256:
                t = tmpl.get((dom, sid))
                if t is None:
                    out["undecodable_sets"] += 1
                    if (dom, sid) in bad and len(out["errors"]) < 50:
                        out["errors"].append(f"domain {dom} data set {sid}: its template was unreadable")
                    p += sl; continue
                is_opt, _, fields = t
                minlen = sum(0 if fl == 0xFFFF else fl for _, _, fl in fields) + sum(1 for _, _, fl in fields if fl == 0xFFFF)
                while send - q >= max(minlen, 1):
                    rec, q0 = {}, q
                    for pen, fid, fl in fields:
                        if fl == 0xFFFF:
                            if q >= send or (body[q] == 255 and q + 3 > send):
                                out["errors"].append(f"domain {dom} set {sid}: a variable-length field's length runs past its set")
                                q = send; rec = None; break
                            fl = body[q]; q += 1
                            if fl == 255:
                                fl = struct.unpack(">H", body[q:q + 2])[0]; q += 2
                        if q + fl > send:
                            out["errors"].append(f"domain {dom} set {sid}: a record runs past its set"); q = send; rec = None; break
                        rec[(pen, fid)] = body[q:q + fl]; q += fl
                    if rec is None:
                        break
                    if q == q0:                                # a record of no bytes would never end
                        out["errors"].append(f"domain {dom} set {sid}: a record of zero length"); q = send; break
                    if is_opt:
                        out["options_records"] += 1; continue
                    out["records"] += 1
                    ip = lambda v: str(ipaddress.ip_address(v)) if v and len(v) in (4, 16) else ""
                    num = lambda v: str(int.from_bytes(v, "big")) if v is not None else ""
                    src = ip(rec.get((0, 8)) or rec.get((0, 27)))
                    dst = ip(rec.get((0, 12)) or rec.get((0, 28)))
                    k = (src, dst, num(rec.get((0, 7))), num(rec.get((0, 11))), num(rec.get((0, 4))))
                    out["tuples"][k] = out["tuples"].get(k, 0) + 1
                    for ids, key in (((1, 85), "bytes"), ((2, 86), "packets")):
                        v = next((rec[(0, i)] for i in ids if (0, i) in rec), None)
                        if v is not None:
                            out[key] += int.from_bytes(v, "big")
                rest = body[q:send]
                if rest.strip(b"\0"):
                    out["errors"].append(f"domain {dom} set {sid}: {len(rest)} bytes after the last record aren't padding")
            else:
                out["errors"].append(f"set ID {sid} at {p} is reserved (RFC 7011 §3.3.2)")
            p += sl
        off = end
    return out


def tshark_tuples(text):
    """The 5-tuples in `tshark -T fields -E occurrence=a -E aggregator=;` output (srcaddr dstaddr srcport dstport protocol)."""
    out = {}
    for line in text.splitlines():
        cols = line.split("\t")
        if len(cols) != 5 or not cols[0]:
            continue
        parts = [c.split(";") for c in cols]
        for j in range(min(len(x) for x in parts)):
            k = tuple(x[j] for x in parts)
            out[k] = out.get(k, 0) + 1
    return out


def csv_tuples(data):
    import csv
    rows = list(csv.reader(io.StringIO(data.decode("utf-8"), newline="")))
    col = {h: i for i, h in enumerate(rows[0])}
    out = {}
    for r in rows[1:]:
        k = tuple(r[col[c]] for c in ("src", "dst", "src_port", "dst_port", "proto"))
        out[k] = out.get(k, 0) + 1
    return out


def tuple_diff(a, b):
    """Counts of 5-tuples in a but not b and the reverse (multisets)."""
    only_a = sum(v - b.get(k, 0) for k, v in a.items() if v > b.get(k, 0))
    only_b = sum(v - a.get(k, 0) for k, v in b.items() if v > a.get(k, 0))
    return only_a, only_b


def flow_ipfix_check(path, tshark_out=None):
    files = {}
    csvs = {}
    if zipfile.is_zipfile(path):
        z = zipfile.ZipFile(path)
        for n in z.namelist():
            m = re.fullmatch(r"flows/([^/]+)/flows\.(ipfix|csv)", n)
            if m:
                (files if m.group(2) == "ipfix" else csvs)[m.group(1)] = z.read(n)
    else:
        files["file"] = open(path, "rb").read()
    res = {"files": {}, "ok": bool(files)}
    if not files:
        res["problem"] = "no flows/<device>/flows.ipfix in the zip"
    for dev, data in sorted(files.items()):
        r = ipfix_read(data)
        d = {k: r[k] for k in ("messages", "records", "options_records", "templates", "undecodable_sets", "bytes", "packets")}
        d["errors"] = r["errors"][:10]
        d["error_count"] = len(r["errors"])
        ok = not r["errors"] and not r["undecodable_sets"] and r["records"] > 0
        if dev in csvs:
            ct = csv_tuples(csvs[dev])
            oa, ob = tuple_diff(r["tuples"], ct)
            d["vs_csv"] = {"csv_rows": sum(ct.values()), "only_in_ipfix": oa, "only_in_csv": ob}
            ok = ok and oa == 0 and ob == 0
        if tshark_out:
            tt = tshark_tuples(open(tshark_out, encoding="utf-8", errors="replace").read())
            ref = csv_tuples(csvs[dev]) if dev in csvs else r["tuples"]
            oa, ob = tuple_diff(tt, ref)
            d["tshark"] = {"records": sum(tt.values()), "only_in_tshark": oa, "only_in_reference": ob}
            ok = ok and oa == 0 and ob == 0
        d["ok"] = ok
        res["files"][dev] = d
        res["ok"] = res["ok"] and ok
    return res


def cmd_flow_ipfix(a):
    print(json.dumps(flow_ipfix_check(a.file, a.tshark)))


def flow_match_check(src, s, d, dport=None, proto=None, devices=None):
    res = {"src": s, "dst": d, "dst_port": dport, "proto": proto, "records": 0, "packets": 0, "bytes": 0, "by_device": {}}
    for dev, received, f in iter_flows(src, devices):
        if f.get("src") != s or f.get("dst") != d:
            continue
        if dport is not None and f.get("dst_port") != dport:
            continue
        if proto is not None and f.get("proto") != proto:
            continue
        res["records"] += 1
        res["packets"] += f.get("packets") or 0
        res["bytes"] += f.get("bytes") or 0
        bd = res["by_device"].setdefault(dev, {"records": 0, "packets": 0, "bytes": 0})
        bd["records"] += 1; bd["packets"] += f.get("packets") or 0; bd["bytes"] += f.get("bytes") or 0
    return res


def cmd_flow_match(a):
    devs = set(a.devices.split(",")) if a.devices else None
    r = flow_match_check(a.src, a.src_addr, a.dst, a.dst_port, a.proto, devs)
    if a.expect_packets is not None or a.expect_bytes is not None:
        r["expect"] = {"packets": a.expect_packets, "bytes": a.expect_bytes}
        r["ok"] = ((a.expect_packets is None or r["packets"] == a.expect_packets) and
                   (a.expect_bytes is None or r["bytes"] == a.expect_bytes))
    print(json.dumps(r))


def cmd_flow_size(a):
    devs = set(a.devices.split(",")) if a.devices else None
    base = os.path.join(a.data, "logs")
    res = {"devices": {}, "bytes": 0, "segments": 0}
    for dev in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        if devs and dev not in devs:
            continue
        fd = os.path.join(base, dev, "flows")
        if not os.path.isdir(fd):
            continue
        segs = [os.path.join(fd, f) for f in os.listdir(fd) if f.endswith(".wsf")]
        b = sum(os.path.getsize(x) for x in segs)
        res["devices"][dev] = {"segments": len(segs), "bytes": b}
        res["bytes"] += b; res["segments"] += len(segs)
    if a.records:
        res["records"] = a.records
        res["bytes_per_record"] = round(res["bytes"] / a.records, 2)
    print(json.dumps(res))


def udp_snmp(ports=(514, 2055, 4739), iface=None, root="/proc"):
    res = {"t": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
    lines = [l.split() for l in open(os.path.join(root, "net/snmp")) if l.startswith("Udp:")]
    if len(lines) >= 2:
        res["udp"] = dict(zip(lines[0][1:], (int(x) for x in lines[1][1:])))
    drops = {str(p): 0 for p in ports}
    for f in ("net/udp", "net/udp6"):
        try:
            for l in open(os.path.join(root, f)).readlines()[1:]:
                c = l.split()
                port = int(c[1].rsplit(":", 1)[1], 16)
                if str(port) in drops:
                    drops[str(port)] += int(c[-1])
        except OSError:
            pass
    res["socket_drops"] = drops
    if iface:
        for l in open(os.path.join(root, "net/dev")):
            if l.strip().startswith(iface + ":"):
                v = [int(x) for x in l.split(":", 1)[1].split()]
                res["iface"] = {"name": iface, "rx_bytes": v[0], "rx_packets": v[1], "rx_errs": v[2], "rx_drop": v[3],
                                "rx_fifo": v[4], "tx_packets": v[9], "tx_drop": v[11]}
    return res


def cmd_udp_snmp(a):
    print(json.dumps(udp_snmp(tuple(int(x) for x in a.ports.split(",")), a.iface)))


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
    p = sub.add_parser("flow-seq"); p.add_argument("src"); p.add_argument("--run", required=True); p.add_argument("--n", type=int, required=True)
    p.add_argument("--first", type=int, default=0); p.add_argument("--truth"); p.add_argument("--devices"); p.add_argument("--list", type=int, default=20)
    p = sub.add_parser("flow-top"); p.add_argument("--truth", required=True); p.add_argument("--top", required=True)
    p.add_argument("--by", required=True); p.add_argument("--metric"); p.add_argument("--fw-event"); p.add_argument("--manifest"); p.add_argument("--device")
    p.add_argument("--from", dest="from_"); p.add_argument("--to"); p.add_argument("--n", type=int, help="the --top the query was given")
    p = sub.add_parser("flow-csv"); p.add_argument("zip"); p.add_argument("--lines", required=True)
    p = sub.add_parser("flow-ipfix"); p.add_argument("file"); p.add_argument("--tshark")
    p = sub.add_parser("flow-match"); p.add_argument("src"); p.add_argument("--src", dest="src_addr", required=True); p.add_argument("--dst", required=True)
    p.add_argument("--dst-port", type=int); p.add_argument("--proto", type=int); p.add_argument("--devices")
    p.add_argument("--expect-packets", type=int); p.add_argument("--expect-bytes", type=int)
    p = sub.add_parser("flow-size"); p.add_argument("data"); p.add_argument("--devices"); p.add_argument("--records", type=int)
    p = sub.add_parser("udp-snmp"); p.add_argument("--ports", default="514,2055,4739"); p.add_argument("--iface")
    a = ap.parse_args()
    a.min_rate = {"bps": 1000, "pps": 1}   # poll-rates: error % only where the true rate is at least this
    {"secret-scan": cmd_secret_scan, "window": cmd_window, "missing": cmd_missing, "netdev": cmd_netdev,
     "poll-rates": cmd_poll_rates, "poll-cycles": cmd_poll_cycles, "poll-size": cmd_poll_size, "poll-csv": cmd_poll_csv,
     "flow-seq": cmd_flow_seq, "flow-top": cmd_flow_top, "flow-csv": cmd_flow_csv, "flow-ipfix": cmd_flow_ipfix,
     "flow-match": cmd_flow_match, "flow-size": cmd_flow_size, "udp-snmp": cmd_udp_snmp}[a.cmd](a)


if __name__ == "__main__":
    main()
