#!/bin/bash
# Static checks for the packaging files: shell syntax, shellcheck (when installed),
# the launchd plist and the XML files. Read-only; safe to run anywhere.
set -euo pipefail

cd "$(dirname "$0")/.."

sh_scripts=(
	packaging/linux/scripts/postinstall.sh
	packaging/linux/scripts/preremove.sh
	packaging/linux/scripts/postremove.sh
	packaging/macos/scripts/common.sh
	packaging/macos/scripts/preinstall
	packaging/macos/scripts/postinstall
	packaging/macos/uninstall.sh
	packaging/macos/app/Woodshed
)
bash_scripts=(
	packaging/macos/build-pkg.sh
	scripts/fuzz.sh
	scripts/release-notes.sh
	scripts/check-asset-names.sh
	scripts/smoke/mac-launcher.sh
	scripts/lint-packaging.sh
	scripts/soak.sh
	scripts/smoke/unix.sh
)

status=0

echo "==> sh -n / bash -n"
for f in "${sh_scripts[@]}"; do sh -n "$f" || status=1; done
for f in "${bash_scripts[@]}"; do bash -n "$f" || status=1; done

if command -v shellcheck >/dev/null 2>&1; then
	echo "==> shellcheck $(shellcheck --version | sed -n 's/^version: //p')"
	shellcheck -x -s sh "${sh_scripts[@]}" || status=1
	shellcheck -x -s bash "${bash_scripts[@]}" || status=1
else
	echo "==> shellcheck not installed; skipped"
fi

if command -v plutil >/dev/null 2>&1; then
	echo "==> plutil -lint"
	plutil -lint packaging/macos/com.woodshed.daemon.plist || status=1
fi

if command -v xmllint >/dev/null 2>&1; then
	echo "==> xmllint (well-formed)"
	xmllint --noout packaging/windows/woodshed.wxs packaging/macos/distribution.xml \
		packaging/macos/com.woodshed.daemon.plist || status=1
fi

# The MSI's firewall-rule custom actions (TLS, SNMP, flows): each one is sequenced, and each remove
# runs only on a real uninstall, never when a major upgrade removes the old product (which
# would bring an enabled rule back disabled).
echo "==> woodshed.wxs firewall custom actions"
wxs=packaging/windows/woodshed.wxs
for rule in Tls Snmp Flow; do
	for act in Ensure Remove; do
		id="Woodshed${rule}Firewall${act}"
		grep -q "<CustomAction Id=\"$id\"" "$wxs" || { echo "$wxs: no CustomAction $id"; status=1; continue; }
		seq=$(grep -A1 "<Custom Action=\"$id\"" "$wxs" | tr -d '\n')
		[ -n "$seq" ] || { echo "$wxs: $id isn't in InstallExecuteSequence"; status=1; continue; }
		if [ "$act" = Remove ] && ! echo "$seq" | grep -q 'NOT UPGRADINGPRODUCTCODE'; then
			echo "$wxs: $id must not run when an upgrade removes the old product (NOT UPGRADINGPRODUCTCODE)"
			status=1
		fi
	done
done

exit "$status"
