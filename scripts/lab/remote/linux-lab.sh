#!/bin/bash
# Woodshed lab, Linux VM side. Copied to /opt/woodpile-lab on the VM by `wl stage`; called by
# the driver over ssh as the lab login, which needs passwordless sudo (a disposable test VM).
#
#   linux-lab.sh install PKG               apt/dnf install the package
#   linux-lab.sh svc                       JSON: service state, account, caps, sockets, UI, woodshed status
#   linux-lab.sh fw-state                  JSON: which host firewall is active and whether 514 is open
#   linux-lab.sh fw-enable                 turn the firewall on if it's off (keeping SSH open)
#   linux-lab.sh fw-open | fw-close        open / close UDP+TCP 514 exactly as docs/install.md says
#   linux-lab.sh verify RUN N [MISSING_OK] [WAIT]   verifyseq -json against the service's data dir
#   linux-lab.sh stats                     GET /api/stats (localhost UI)
#   linux-lab.sh integrity [SERVICES]      JSON: /usr/bin/woodshed present + sha256, service, 514 sockets, and the state of the
#                                          comma-separated endpoint protection (EDR) services/processes ("-" skips; from lab.env)
#   linux-lab.sh api METHOD PATH [BODY]    any local API call; download PATH OUT saves a body (export zips)
#   linux-lab.sh devices                   the device folders under logs/
#   linux-lab.sh sample OUT INTERVAL SECS [PID]     CSV of RSS, CPU seconds, fds, threads, UDP drops; with INTERVAL >= 30 also
#                                          OUT-stats.jsonl: the UDP queues (depth, high-water), drops by reason, SNMP counts
#   linux-lab.sh ports                     JSON: which of UDP 514/162 and TCP 514/6514 the service holds
#   linux-lab.sh soak-sampler start|stop|status SECS   the sampler as a transient systemd unit
#   linux-lab.sh verify-detached RUN N OUTJSON      verifyseq as a transient unit (long runs)
#   linux-lab.sh portable start|stop|status PORT    the tarball binary by hand, unprivileged, on PORT
#   linux-lab.sh reboot                    reboot in 2 s (the ssh session returns first)
#   linux-lab.sh collect OUT.tgz           journal, unit, config, status, data listing, samples
set -euo pipefail
L=/opt/woodpile-lab
DATA=/var/lib/woodshed
UI=http://127.0.0.1:8514
S="sudo -n"
act=${1:?action}
shift

svc_pid() { systemctl show -p MainPID --value woodshed.service 2>/dev/null | grep -v '^0$' || true; }

fw_kind() {
	if command -v ufw >/dev/null && $S ufw status 2>/dev/null | grep -q "^Status: active"; then echo ufw
	elif command -v firewall-cmd >/dev/null && $S firewall-cmd --state >/dev/null 2>&1; then echo firewalld
	elif command -v ufw >/dev/null; then echo ufw-inactive
	elif command -v firewall-cmd >/dev/null; then echo firewalld-inactive
	else echo none; fi
}

case "$act" in
install)
	pkg=${1:?package path}
	case "$pkg" in
	*.deb) $S env DEBIAN_FRONTEND=noninteractive apt-get install -y "$(realpath "$pkg")" ;;
	*.rpm) # the lab VM may not reach its distro mirrors: try without repos first (the rpm needs nothing beyond the base OS)
		$S dnf install -y --disablerepo='*' "$(realpath "$pkg")" || $S dnf install -y "$(realpath "$pkg")" ;;
	*) echo "install: unknown package type $pkg" >&2; exit 2 ;;
	esac
	;;
svc)
	pid=$(svc_pid)
	user="" caps="" udp="" tcp=""
	if [ -n "$pid" ]; then
		user=$(ps -o user= -p "$pid" | tr -d ' ')
		caps=$(grep '^CapEff:' /proc/"$pid"/status | awk '{print $2}')
		udp=$($S ss -H -lnup 'sport = :514' | grep -c "pid=$pid," || true)
		tcp=$($S ss -H -lntp 'sport = :514' | grep -c "pid=$pid," || true)
	fi
	active=$(systemctl is-active woodshed.service || true)
	enabled=$(systemctl is-enabled woodshed.service || true)
	health=$(curl -fsS --max-time 3 "$UI/healthz" 2>/dev/null || echo "")
	status=$(woodshed status 2>&1 | head -20 || true)
	rmem=$(sysctl -n net.core.rmem_max)
	u162=0 t6514=0
	if [ -n "$pid" ]; then
		u162=$($S ss -H -lnup 'sport = :162' | grep -c "pid=$pid," || true)
		t6514=$($S ss -H -lntp 'sport = :6514' | grep -c "pid=$pid," || true)
	fi
	python3 - "$active" "$enabled" "$pid" "$user" "$caps" "$udp" "$tcp" "$health" "$status" "$rmem" "$u162" "$t6514" <<'PY'
import json, sys
a = sys.argv[1:]
print(json.dumps({"active": a[0], "enabled": a[1], "pid": a[2], "user": a[3], "cap_eff": a[4],
                  "udp514_sockets": int(a[5] or 0), "tcp514_listen": int(a[6] or 0), "healthz": a[7],
                  "woodshed_status": a[8], "rmem_max": a[9], "udp162_sockets": int(a[10] or 0), "tcp6514_listen": int(a[11] or 0)}))
PY
	;;
fw-state)
	k=$(fw_kind)
	open=unknown
	case "$k" in
	ufw) $S ufw status | grep -Eq '^514(/(tcp|udp))? +ALLOW' && open=yes || open=no ;;
	firewalld) ports=$($S firewall-cmd --list-ports); { echo "$ports" | grep -q '514/udp' && echo "$ports" | grep -q '514/tcp'; } && open=yes || open=no ;;
	*) open=n/a ;;
	esac
	echo "{\"firewall\": \"$k\", \"port514_open\": \"$open\"}"
	;;
fw-enable)
	case "$(fw_kind)" in
	ufw-inactive) $S ufw allow 22/tcp >/dev/null && $S ufw --force enable ;;
	firewalld-inactive) $S systemctl enable --now firewalld && $S firewall-cmd --permanent --add-service=ssh >/dev/null && $S firewall-cmd --reload >/dev/null ;;
	ufw | firewalld) echo "already active" ;;
	none) echo "no host firewall installed" >&2; exit 3 ;;
	esac
	fw_kind
	;;
fw-open)
	case "$(fw_kind)" in
	ufw) $S ufw allow 514 ;;                                                     # docs/install.md, Ubuntu
	firewalld) $S firewall-cmd --permanent --add-port=514/udp --add-port=514/tcp && $S firewall-cmd --reload ;; # docs, firewalld
	*) echo "fw-open: no active firewall" >&2; exit 3 ;;
	esac
	;;
fw-close)
	case "$(fw_kind)" in
	ufw) $S ufw delete allow 514 || true ;;
	firewalld) $S firewall-cmd --permanent --remove-port=514/udp --remove-port=514/tcp && $S firewall-cmd --reload ;;
	*) echo "fw-close: no active firewall" >&2; exit 3 ;;
	esac
	;;
verify)
	run=${1:?run} n=${2:?n} miss=${3:-0} wait=${4:-30s}
	$S "$L/verifyseq" -data "${WL_DATA:-$DATA}" -run "$run" -n "$n" -missing-ok "$miss" -wait "$wait" -json || true
	;;
verify-detached)
	run=${1:?run} n=${2:?n} out=${3:?out json}
	$S systemd-run --unit="woodpile-lab-verify-$run" --collect --quiet --nice=10 \
		/bin/sh -c "$L/verifyseq -data $DATA -run $run -n $n -json > $out.tmp 2>&1; mv $out.tmp $out"
	echo "started woodpile-lab-verify-$run -> $out"
	;;
stats) curl -fsS --max-time 5 "$UI/api/stats" ;;
integrity) # what endpoint protection (EDR) did to the product: binary, service, sockets (and whether the EDR runs here)
	exe=/usr/bin/woodshed pid=$(svc_pid) sha="" size=0 mtime="" udp=0 tcp=0
	if [ -f "$exe" ]; then sha=$(sha256sum "$exe" | cut -d' ' -f1); size=$(stat -c %s "$exe"); mtime=$(date -u -r "$exe" +%FT%TZ); fi
	if [ -n "$pid" ]; then
		udp=$($S ss -H -lnup 'sport = :514' | grep -c "pid=$pid," || true)
		tcp=$($S ss -H -lntp 'sport = :514' | grep -c "pid=$pid," || true)
	fi
	edr=""
	if [ "${1:--}" != - ]; then
		IFS=, read -r -a names <<<"$1"
		for x in "${names[@]}"; do
			[[ "$x" =~ ^[A-Za-z0-9._@-]+$ ]] || continue
			if systemctl is-active --quiet "$x" 2>/dev/null || pgrep -x "$x" >/dev/null; then edr="$edr,$x=running"; else edr="$edr,$x=absent"; fi
		done
	fi
	python3 - "$exe" "$sha" "$size" "$mtime" "$(systemctl is-active woodshed.service || true)" "$(systemctl is-enabled woodshed.service || true)" \
		"$(ps -o user= -p "${pid:-1}" 2>/dev/null | tr -d ' ')" "${pid:-0}" "$udp" "$tcp" "${edr#,}" <<'PY'
import json, sys
a = sys.argv[1:]
print(json.dumps({"exe": a[0], "exe_present": bool(a[1]), "exe_sha256": a[1], "exe_size": int(a[2] or 0), "exe_mtime_utc": a[3],
                  "service_state": a[4], "start_mode": a[5], "account": a[6], "pid": a[7], "udp514": int(a[8] or 0), "tcp514": int(a[9] or 0),
                  "defender_detections": [], "edr_services": [x for x in a[10].split(",") if x]}))
PY
	;;
api) # api METHOD PATH [BODYFILE]: the local UI API (no auth on localhost); prints the body
	m=${1:?method} path=${2:?path} body=${3:-}
	if [ -n "$body" ]; then curl -fsS --max-time 30 -X "$m" -H 'Content-Type: application/json' --data @"$body" "$UI$path"
	else curl -fsS --max-time 30 -X "$m" "$UI$path"; fi
	;;
download) curl -fsS --max-time 300 -o "${2:?out}" "$UI${1:?path}" && ls -l "$2" ;;
devices) $S ls -1 "${WL_DATA:-$DATA}/logs" ;;
ports)
	pid=$(svc_pid)
	c() { if [ -n "$pid" ]; then $S ss -H "$1" "sport = :$2" | grep -c "pid=$pid," || true; else echo 0; fi; }
	echo "{\"pid\": \"$pid\", \"udp514\": $(c -lnup 514), \"tcp514\": $(c -lntp 514), \"udp162\": $(c -lnup 162), \"tcp6514\": $(c -lntp 6514)}"
	;;
sample)
	out=${1:?out} iv=${2:?interval} secs=${3:?seconds} pid=${4:-}
	[ -n "$pid" ] || pid=$(svc_pid)
	tck=$(getconf CLK_TCK)
	echo "time,elapsed_s,pid,rss_kb,cpu_s,fds,threads,udp_drops" >"$out"
	t0=$(date +%s)
	end=$((t0 + secs))
	while [ "$(date +%s)" -lt "$end" ]; do
		[ -n "$pid" ] && [ -d "/proc/$pid" ] || { pid=$(svc_pid); sleep "$iv"; continue; }
		read -r ut st <<<"$(awk '{print $14, $15}' /proc/"$pid"/stat)"
		rss=$(awk '/^VmRSS:/ {print $2}' /proc/"$pid"/status)
		thr=$(awk '/^Threads:/ {print $2}' /proc/"$pid"/status)
		fds=$($S ls /proc/"$pid"/fd 2>/dev/null | wc -l)
		# kernel drops on the :514 UDP sockets (port 0202 hex), the last column of /proc/net/udp{,6}
		drops=$(awk '$2 ~ /:0202$/ {d += $NF} END {print d + 0}' /proc/net/udp /proc/net/udp6)
		cpu=$(python3 -c "print(round(($ut + $st) / $tck, 2))")
		echo "$(date -u +%H:%M:%S),$(($(date +%s) - t0)),$pid,$rss,$cpu,$fds,$thr,$drops" >>"$out"
		if [ "$iv" -ge 30 ]; then # the service's own view: UDP queues, drops by reason, SNMP counts (one JSON line)
			{ curl -fsS --max-time 5 "$UI/api/stats" 2>/dev/null; echo; curl -fsS --max-time 5 "$UI/api/snmp" 2>/dev/null; echo; } |
				python3 -c '
import json, sys, datetime
ls = [l for l in sys.stdin.read().splitlines() if l.strip()]
st = json.loads(ls[0]) if ls else {}; sn = json.loads(ls[1]) if len(ls) > 1 else {}
print(json.dumps({"t": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "msgs_per_sec": st.get("msgs_per_sec"),
  "dropped_24h": st.get("dropped_24h"), "dropped_by_reason": st.get("dropped_by_reason"), "kernel_dropped_24h": st.get("kernel_dropped_24h"),
  "udp_queue": [{k: q.get(k) for k in ("listener", "depth", "high_water_24h", "dropped_24h", "high_water_by_hour")} for q in st.get("udp_queue") or []],
  "snmp": sn.get("counts_24h")}))' >>"${out%.csv}-stats.jsonl" 2>/dev/null || true
		fi
		sleep "$iv"
	done
	;;
soak-sampler)
	op=${1:?start|stop|status}
	case "$op" in
	start)
		secs=${2:?seconds}
		$S mkdir -p /var/tmp/woodpile-lab
		$S systemd-run --unit=woodpile-lab-soak-sampler --collect --quiet --nice=5 \
			"$L/linux-lab.sh" sample /var/tmp/woodpile-lab/soak-samples.csv 60 "$secs"
		echo "sampler started for $secs s -> /var/tmp/woodpile-lab/soak-samples.csv"
		;;
	stop) $S systemctl stop woodpile-lab-soak-sampler || true ;;
	status) systemctl is-active woodpile-lab-soak-sampler || true; $S tail -n 3 /var/tmp/woodpile-lab/soak-samples.csv 2>/dev/null || true ;;
	esac
	;;
portable)
	op=${1:?start|stop|status} port=${2:-15514}
	P=$HOME/woodshed-portable
	case "$op" in
	start)
		mkdir -p "$P/data"
		cat >"$P/woodshed.toml" <<EOF
[listeners.udp]
enabled = true
port = $port

[listeners.tcp]
enabled = true
port = $port

[storage]
data_dir = "$P/data"

[ui]
port = 18514
EOF
		nohup "$P/woodshed" run --config "$P/woodshed.toml" >"$P/console.out" 2>&1 &
		echo $! >"$P/pid"
		for _ in $(seq 30); do curl -fsS --max-time 1 http://127.0.0.1:18514/healthz >/dev/null 2>&1 && break; sleep 1; done
		echo "portable pid $(cat "$P/pid") as $(id -un) on UDP/TCP $port, data $P/data"
		# a hand-run binary on another port needs its own firewall opening (removed by stop)
		case "$(fw_kind)" in
		ufw) $S ufw allow "$port" >/dev/null && echo "ufw: opened $port for the portable run" ;;
		firewalld) $S firewall-cmd --add-port="$port/udp" --add-port="$port/tcp" >/dev/null && echo "firewalld: opened $port (runtime only)" ;;
		esac
		;;
	stop)
		pid=$(cat "$P/pid")
		kill -TERM "$pid"
		for _ in $(seq 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
		kill -0 "$pid" 2>/dev/null && { echo "portable didn't stop" >&2; exit 1; }
		case "$(fw_kind)" in
		ufw) $S ufw delete allow "$port" >/dev/null || true ;;
		firewalld) $S firewall-cmd --remove-port="$port/udp" --remove-port="$port/tcp" >/dev/null || true ;;
		esac
		tail -n 5 "$P/console.out"
		;;
	status) cat "$P/pid" 2>/dev/null && tail -n 5 "$P/console.out" ;;
	esac
	;;
reboot) $S systemd-run --on-active=2 --quiet /bin/systemctl reboot && echo "rebooting in 2 s" ;;
collect)
	out=${1:?out.tgz}
	d=$(mktemp -d)
	$S journalctl -u woodshed --no-pager -n 5000 >"$d/journal.log" 2>&1 || true
	systemctl status woodshed --no-pager >"$d/systemctl-status.txt" 2>&1 || true
	systemctl cat woodshed >"$d/unit.txt" 2>&1 || true
	$S cat /etc/woodshed/woodshed.toml >"$d/woodshed.toml" 2>/dev/null || true
	woodshed status >"$d/woodshed-status.txt" 2>&1 || true
	$S ls -laR "$DATA" >"$d/data-listing.txt" 2>&1 || true
	$S cp /var/tmp/woodpile-lab/*.csv /var/tmp/woodpile-lab/*.json "$d/" 2>/dev/null || true
	$S ss -lunpt >"$d/sockets.txt" 2>&1 || true
	uname -a >"$d/uname.txt"; cat /etc/os-release >>"$d/uname.txt"
	$S chown -R "$(id -un)" "$d"
	tar -C "$d" -czf "$out" .
	rm -rf "$d"
	echo "$out"
	;;
*) echo "linux-lab.sh: unknown action $act" >&2; exit 2 ;;
esac
