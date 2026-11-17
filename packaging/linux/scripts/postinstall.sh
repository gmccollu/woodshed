#!/bin/sh
# Woodshed deb/rpm post-install script (nfpm).
#
# Called as:
#   deb: postinst configure <old-version>   (old-version is empty on a first install)
#        postinst abort-upgrade|abort-remove|abort-deconfigure ...
#   rpm: %post <count>                        (1 = first install, 2+ = upgrade)
#
# A first install creates the user and directories, applies the sysctl drop-in,
# and enables and starts the service. An upgrade only restarts a running service.
set -e

SERVICE=woodshed.service
USER_NAME=woodshed
DATA_DIR=/var/lib/woodshed
CONF_DIR=/etc/woodshed
SYSCTL_FILE=/etc/sysctl.d/60-woodshed.conf
UI_URL=http://127.0.0.1:8514/

action=install
case "$1" in
	configure)
		if [ -n "$2" ]; then action=upgrade; fi
		;;
	abort-upgrade | abort-remove | abort-deconfigure)
		action=upgrade
		;;
	*)
		if [ "$1" -ge 2 ] 2>/dev/null; then action=upgrade; fi
		;;
esac

# The system user and group (no home, no login shell).
if ! getent group "$USER_NAME" >/dev/null 2>&1; then
	groupadd --system "$USER_NAME"
fi
if ! getent passwd "$USER_NAME" >/dev/null 2>&1; then
	nologin=/usr/sbin/nologin
	[ -x "$nologin" ] || nologin=/sbin/nologin
	[ -x "$nologin" ] || nologin=/bin/false
	useradd --system --gid "$USER_NAME" --home-dir "$DATA_DIR" --no-create-home \
		--shell "$nologin" --comment "Woodshed service" "$USER_NAME"
fi

# Data and config directories. Existing ones are left as the admin set them.
for dir in "$DATA_DIR" "$CONF_DIR"; do
	if [ ! -d "$dir" ]; then
		install -d -m 0750 -o "$USER_NAME" -g "$USER_NAME" "$dir"
	fi
done

# WOODSHED_UPDATE_CHECK=on|off|ask (SPEC §10.2), for silent fleet installs:
#   sudo WOODSHED_UPDATE_CHECK=off apt install ./woodshed_X.Y.Z_amd64.deb
# An explicit choice, applied on a first install and on an upgrade alike (before the
# service starts or restarts below). Unset leaves the config alone; an invalid value
# is ignored with a warning, never failing the install.
if [ -n "${WOODSHED_UPDATE_CHECK:-}" ]; then
	if out=$(/usr/bin/woodshed update-check "$WOODSHED_UPDATE_CHECK" --config "$CONF_DIR/woodshed.toml" --no-restart 2>&1); then
		echo "woodshed: WOODSHED_UPDATE_CHECK=$WOODSHED_UPDATE_CHECK: $(printf '%s\n' "$out" | head -n 1)"
	else
		echo "woodshed: warning: ignored WOODSHED_UPDATE_CHECK=$WOODSHED_UPDATE_CHECK (use on, off or ask): $(printf '%s\n' "$out" | head -n 1)" >&2
	fi
fi

# Woodpile, this package's old name: its data isn't migrated or touched; say where it is.
if [ "$action" = install ]; then
	old=""
	for dir in /var/lib/woodpile /etc/woodpile; do
		if [ -d "$dir" ]; then old="${old:+$old and }$dir"; fi
	done
	if [ -n "$old" ]; then
		echo "woodshed: the old Woodpile data in $old isn't used by Woodshed; you can delete it."
	fi
fi

# Raise net.core.rmem_max now; the drop-in keeps it across reboots.
WANT_RMEM=33554432
if [ -f "$SYSCTL_FILE" ] && command -v sysctl >/dev/null 2>&1; then
	sysctl -q -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
fi
# Inside an unprivileged container (LXC, Docker) this is the host's setting and can't be
# raised from here: say so in one line, it isn't an error. Woodshed's UI also shows it.
have=$(cat /proc/sys/net/core/rmem_max 2>/dev/null || echo 0)
if [ "${have:-0}" -lt "$WANT_RMEM" ] 2>/dev/null; then
	if { command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container >/dev/null 2>&1; } || [ -f /.dockerenv ]; then
		echo "woodshed: note: net.core.rmem_max is $have in this container; for bursty senders set it to $WANT_RMEM on the host (see \"Containers\" in docs/install.md)."
	else
		echo "woodshed: note: net.core.rmem_max is still $have; $SYSCTL_FILE sets it to $WANT_RMEM at the next boot (or now: sudo sysctl --system)."
	fi
fi

if [ ! -d /run/systemd/system ]; then
	# Containers and chroots: no running systemd to talk to.
	if command -v systemctl >/dev/null 2>&1; then
		systemctl enable "$SERVICE" >/dev/null 2>&1 || true
	fi
	echo "woodshed: systemd is not running; start it with: woodshed run --config $CONF_DIR/woodshed.toml"
	exit 0
fi

systemctl daemon-reload >/dev/null 2>&1 || true

# The old Woodpile service would hold port 514. rpm removes an obsoleted package after
# this runs, and a `woodpile install` service isn't a package at all: stop and disable it
# here, and say so if it was running or enabled.
# The deb's Conflicts makes dpkg run the old package's prerm (which stops and disables the
# service) and remove it before this package's preinst would run, so no script of ours sees
# the old service. There systemd's "Stopped" record in the journal shows it was running,
# and the same line is printed.
old_stopped=""
if systemctl cat woodpile.service >/dev/null 2>&1; then
	if systemctl is-active --quiet woodpile.service || systemctl is-enabled --quiet woodpile.service; then
		old_stopped=yes
	fi
	systemctl disable --now woodpile.service >/dev/null 2>&1 || true
elif [ "$action" = install ] && command -v journalctl >/dev/null 2>&1; then
	journalctl --sync >/dev/null 2>&1 || true
	# The MESSAGE_ID is systemd's "unit stopped" message (SD_MESSAGE_UNIT_STOPPED).
	if [ -n "$(journalctl -q --no-pager -o cat --since=-10min UNIT=woodpile.service \
		MESSAGE_ID=9d1aaa27d60140bd96365438aad20286 2>/dev/null)" ]; then
		old_stopped=yes
	fi
fi
if [ -n "$old_stopped" ]; then
	echo "woodshed: stopped and disabled the old Woodpile service (woodpile.service)."
fi

if [ "$action" = upgrade ]; then
	# Keep the admin's choice: restart only if it was running.
	systemctl try-restart "$SERVICE" >/dev/null 2>&1 || true
	echo "woodshed: upgraded; a running service was restarted."
	exit 0
fi

systemctl enable "$SERVICE" >/dev/null 2>&1 || true
if systemctl start "$SERVICE"; then
	echo ""
	echo "Woodshed is running and listening for syslog on UDP and TCP port 514."
	echo "Open $UI_URL in a browser on this machine."
	echo "Config: $CONF_DIR/woodshed.toml   Logs: $DATA_DIR/logs   Service log: journalctl -u woodshed"
	echo ""
else
	echo "woodshed: the service did not start; see: journalctl -u woodshed" >&2
fi
exit 0
