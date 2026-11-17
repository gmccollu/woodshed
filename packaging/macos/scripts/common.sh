#!/bin/sh
# Shared by the pkg preinstall and postinstall scripts (sourced, not run).
# The variables below are used by the scripts that source this file.
# shellcheck shell=sh disable=SC2034

LABEL=com.woodshed.daemon
PLIST=/Library/LaunchDaemons/$LABEL.plist
SVC_USER=_woodshed
SVC_GROUP=_woodshed
DATA_DIR="/Library/Application Support/Woodshed"
LOG_DIR=/Library/Logs/Woodshed
LOG_FILE=$LOG_DIR/woodshed.log
UI_URL=http://127.0.0.1:8514/

log() {
	echo "woodshed: $*"
}

# The daemon is loaded in the system domain.
daemon_loaded() {
	launchctl print "system/$LABEL" >/dev/null 2>&1
}

# First ID in 499..300 that is free both as a UniqueID and as a PrimaryGroupID.
# macOS reserves IDs below 500 for system accounts; Apple's own sit mostly below 300.
free_system_id() {
	used=$(
		dscl . -list /Users UniqueID | awk '{print $2}'
		dscl . -list /Groups PrimaryGroupID | awk '{print $2}'
	)
	id=499
	while [ "$id" -ge 300 ]; do
		if ! printf '%s\n' "$used" | grep -qx "$id"; then
			echo "$id"
			return 0
		fi
		id=$((id - 1))
	done
	return 1
}

# Creates the _woodshed group and user if they are missing. Idempotent.
ensure_service_account() {
	if dscl . -read "/Groups/$SVC_GROUP" PrimaryGroupID >/dev/null 2>&1; then
		gid=$(dscl . -read "/Groups/$SVC_GROUP" PrimaryGroupID | awk '{print $2}')
	else
		gid=$(free_system_id) || {
			log "no free system ID between 300 and 499" >&2
			return 1
		}
		dscl . -create "/Groups/$SVC_GROUP"
		dscl . -create "/Groups/$SVC_GROUP" PrimaryGroupID "$gid"
		dscl . -create "/Groups/$SVC_GROUP" RealName "Woodshed service"
		dscl . -create "/Groups/$SVC_GROUP" Password '*'
		log "created group $SVC_GROUP ($gid)"
	fi

	if ! dscl . -read "/Users/$SVC_USER" UniqueID >/dev/null 2>&1; then
		# Reuse the group's ID for the user when it's free, like Apple's own accounts.
		uid=$gid
		if dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "$uid"; then
			uid=$(free_system_id) || {
				log "no free system ID between 300 and 499" >&2
				return 1
			}
		fi
		dscl . -create "/Users/$SVC_USER"
		dscl . -create "/Users/$SVC_USER" UniqueID "$uid"
		dscl . -create "/Users/$SVC_USER" PrimaryGroupID "$gid"
		dscl . -create "/Users/$SVC_USER" UserShell /usr/bin/false
		dscl . -create "/Users/$SVC_USER" NFSHomeDirectory /var/empty
		dscl . -create "/Users/$SVC_USER" RealName "Woodshed service"
		dscl . -create "/Users/$SVC_USER" Password '*'
		dscl . -create "/Users/$SVC_USER" IsHidden 1
		log "created user $SVC_USER ($uid)"
	fi

	if ! dscl . -read "/Groups/$SVC_GROUP" GroupMembership 2>/dev/null | grep -qw "$SVC_USER"; then
		dscl . -append "/Groups/$SVC_GROUP" GroupMembership "$SVC_USER"
	fi
}

# The daemon's own log (launchd's StandardOutPath/StandardErrorPath), rotated by newsyslog
# as root. The folder is root-owned and not writable by _woodshed, so the daemon can't put
# a symlink or other name there for root to follow when it rotates; only the log file
# itself belongs to _woodshed. Idempotent; heals a folder from an older install that
# _woodshed owned, deleting any symlinks it holds.
prepare_log_dir() {
	mkdir -p "$LOG_DIR"
	chown root:wheel "$LOG_DIR"
	chmod 0755 "$LOG_DIR"
	find "$LOG_DIR" -mindepth 1 -type l -delete
	if [ ! -f "$LOG_FILE" ]; then
		rm -rf "$LOG_FILE"
		: >"$LOG_FILE"
	fi
	chown -h "$SVC_USER:$SVC_GROUP" "$LOG_FILE"
	chmod 0640 "$LOG_FILE"
}

# WOODSHED_UPDATE_CHECK=on|off|ask (SPEC §10.2), for silent installs:
#   sudo WOODSHED_UPDATE_CHECK=off installer -pkg woodshed_X.Y.Z_macos_universal.pkg -target /
# Applied on a first install and on an upgrade alike, before the daemon starts. Unset
# leaves the config alone; an invalid value is ignored with a warning, never failing the
# install. Whether installer passes the variable through to this script at all is checked
# by the install smoke test (docs/install.md says what to do when it doesn't).
apply_update_check() {
	[ -n "${WOODSHED_UPDATE_CHECK:-}" ] || return 0
	if out=$(/usr/local/bin/woodshed update-check "$WOODSHED_UPDATE_CHECK" --config "$DATA_DIR/woodshed.toml" --no-restart 2>&1); then
		log "WOODSHED_UPDATE_CHECK=$WOODSHED_UPDATE_CHECK: $(printf '%s\n' "$out" | head -n 1)"
	else
		log "warning: ignored WOODSHED_UPDATE_CHECK=$WOODSHED_UPDATE_CHECK (use on, off or ask): $(printf '%s\n' "$out" | head -n 1)" >&2
	fi
	return 0
}
