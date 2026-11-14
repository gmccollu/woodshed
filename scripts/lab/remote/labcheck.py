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


def main():
    ap = argparse.ArgumentParser(prog="labcheck.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("secret-scan"); p.add_argument("--journal"); p.add_argument("paths", nargs="+")
    p = sub.add_parser("window"); p.add_argument("zip"); p.add_argument("--from", dest="from_", required=True)
    p.add_argument("--to", required=True); p.add_argument("--run", action="append"); p.add_argument("--data")
    p = sub.add_parser("missing"); p.add_argument("src"); p.add_argument("--run", required=True); p.add_argument("--n", type=int, required=True)
    p.add_argument("--blocks", type=int); p.add_argument("--rate", type=float); p.add_argument("--start", type=float)
    p.add_argument("--list", type=int, default=50)
    a = ap.parse_args()
    {"secret-scan": cmd_secret_scan, "window": cmd_window, "missing": cmd_missing}[a.cmd](a)


if __name__ == "__main__":
    main()
