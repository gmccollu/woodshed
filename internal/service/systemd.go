package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/packaging"
)

// Linux paths for `woodshed install` (the deb/rpm use /usr/bin and
// /usr/lib/systemd/system).
const (
	linuxBin       = "/usr/local/bin/woodshed"
	linuxSysctl    = "/etc/sysctl.d/60-woodshed.conf"
	linuxPkgExec   = "/usr/bin/woodshed run --service --config /etc/woodshed/woodshed.toml"
	linuxPkgRW     = "ReadWritePaths=/var/lib/woodshed /etc/woodshed"
	linuxPkgWD     = "WorkingDirectory=/var/lib/woodshed"
	installedByTag = "# Installed by `woodshed install`; remove it with `woodshed uninstall`."
)

// systemdUnit is the packaged unit (packaging/linux/woodshed.service) with this
// install's binary, config and data paths. Everything else (the woodshed user,
// CAP_NET_BIND_SERVICE, the sandboxing) is the package's, unchanged.
func systemdUnit(bin, cfgPath, dataDir string) (string, error) {
	u := packaging.SystemdUnit
	for _, want := range []string{linuxPkgExec, linuxPkgRW, linuxPkgWD} {
		if !strings.Contains(u, want) {
			return "", fmt.Errorf("the packaged unit no longer has %q; update systemdUnit", want)
		}
	}
	for what, p := range map[string]string{"the binary": bin, "the config path": cfgPath, "the data folder": dataDir} {
		if err := checkServicePath(what, p); err != nil {
			return "", err
		}
		if strings.Contains(p, `\`) {
			return "", fmt.Errorf("%s %q contains a backslash", what, p)
		}
	}
	rw := []string{unitPath(dataDir)}
	if d := filepath.Dir(cfgPath); d != dataDir {
		rw = append(rw, unitPath(d))
	}
	u = strings.Replace(u, linuxPkgExec, unitPath(bin)+" run --service --config "+unitPath(cfgPath), 1)
	u = strings.Replace(u, linuxPkgRW, "ReadWritePaths="+strings.Join(rw, " "), 1)
	u = strings.Replace(u, linuxPkgWD, "WorkingDirectory="+unitPath(dataDir), 1)
	return installedByTag + "\n" + u, nil
}

// unitPath is a checked path as a unit-file value: % (a systemd specifier) is
// doubled, and a path with spaces is quoted.
func unitPath(p string) string { return quoteIfSpace(strings.ReplaceAll(p, "%", "%%")) }

// nologinShell is the first of the shells the package's postinstall tries.
func nologinShell(h *host) string {
	for _, s := range []string{"/usr/sbin/nologin", "/sbin/nologin"} {
		if h.exists(s) {
			return s
		}
	}
	return "/bin/false"
}

func installSystemd(h *host, o InstallOptions, dataDir string) (Result, error) {
	res := Result{Where: linuxManualUnit, Exe: linuxBin, Config: o.ConfigPath, DataDir: dataDir, Account: LinuxUser}
	if !h.exists("/run/systemd/system") {
		return res, fmt.Errorf("systemd isn't running here, so there's no service to install; run `woodshed run --config %s` instead", o.ConfigPath)
	}
	// The system user and group, exactly as packaging/linux/scripts/postinstall.sh.
	if _, err := h.run("getent", "group", LinuxUser); err != nil {
		if _, err := h.run("groupadd", "--system", LinuxUser); err != nil {
			return res, err
		}
		h.say("created group %s", LinuxUser)
	}
	// The comment names the account, not what Woodshed collects: no comma (GECOS splits
	// fields on commas), and nothing that goes stale. An existing account keeps its comment.
	if _, err := h.run("getent", "passwd", LinuxUser); err != nil {
		if _, err := h.run("useradd", "--system", "--gid", LinuxUser, "--home-dir", "/var/lib/woodshed", "--no-create-home",
			"--shell", nologinShell(h), "--comment", "Woodshed service", LinuxUser); err != nil {
			return res, err
		}
		h.say("created user %s", LinuxUser)
	}

	// Data and config folders, owned by the service user (0750), checked first.
	notes, err := prepareFolders(h, "linux", o.ConfigPath, dataDir, LinuxUser, LinuxUser)
	res.Notes = append(res.Notes, notes...)
	if err != nil {
		return res, err
	}

	if err := h.copyFile(o.Exe, linuxBin, 0o755); err != nil {
		return res, fmt.Errorf("copy the binary to %s: %w", linuxBin, err)
	}
	h.say("installed %s", linuxBin)

	unit, err := systemdUnit(linuxBin, o.ConfigPath, dataDir)
	if err != nil {
		return res, err
	}
	if err := h.writeFile(linuxManualUnit, unit, 0o644); err != nil {
		return res, err
	}
	h.say("installed %s (runs as %s with CAP_NET_BIND_SERVICE only)", linuxManualUnit, LinuxUser)

	// The receive-buffer drop-in, as the package installs it.
	if err := h.writeFile(linuxSysctl, packaging.SysctlDropIn, 0o644); err != nil {
		return res, err
	}
	if _, err := h.run("sysctl", "-q", "-p", linuxSysctl); err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("couldn't apply %s now (%v); it applies at the next boot", linuxSysctl, err))
	}

	if _, err := h.run("systemctl", "daemon-reload"); err != nil {
		return res, err
	}
	if _, err := h.run("systemctl", "enable", LinuxName+".service"); err != nil {
		return res, err
	}
	if _, err := h.run("systemctl", "start", LinuxName+".service"); err != nil {
		return res, fmt.Errorf("the service is installed but didn't start (see journalctl -u woodshed): %w", err)
	}
	return res, nil
}

// unitPaths reads the binary, config and data dir back from an installed unit.
func unitPaths(unit string) (bin, cfgPath, dataDir string) {
	for _, line := range strings.Split(unit, "\n") {
		switch {
		case strings.HasPrefix(line, "ExecStart="):
			f := splitUnitWords(strings.ReplaceAll(strings.TrimPrefix(line, "ExecStart="), "%%", "%"))
			if len(f) > 0 {
				bin = f[0]
			}
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "--config" {
					cfgPath = f[i+1]
				}
			}
		case strings.HasPrefix(line, "WorkingDirectory="):
			if f := splitUnitWords(strings.ReplaceAll(strings.TrimPrefix(line, "WorkingDirectory="), "%%", "%")); len(f) > 0 {
				dataDir = f[0]
			}
		}
	}
	return bin, cfgPath, dataDir
}

// splitUnitWords splits a unit value on spaces, honouring double quotes.
func splitUnitWords(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, have := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQ, have = !inQ, true
		case (r == ' ' || r == '\t') && !inQ:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}

func uninstallSystemd(h *host, o UninstallOptions) (Result, error) {
	res := Result{Where: linuxManualUnit, Account: LinuxUser}
	unit, err := h.readFile(linuxManualUnit)
	if err != nil {
		return res, err
	}
	bin, cfgPath, dataDir := unitPaths(unit)
	res.Exe, res.Config, res.DataDir = bin, cfgPath, dataDir
	if h.exists("/run/systemd/system") {
		_, _ = h.run("systemctl", "stop", LinuxName+".service")
		_, _ = h.run("systemctl", "disable", LinuxName+".service")
	}
	if err := h.remove(linuxManualUnit); err != nil {
		return res, err
	}
	if h.exists("/run/systemd/system") {
		_, _ = h.run("systemctl", "daemon-reload")
		_, _ = h.run("systemctl", "reset-failed", LinuxName+".service")
	}
	h.say("removed %s", linuxManualUnit)
	if err := h.remove(linuxSysctl); err != nil {
		return res, err
	}
	_, _ = h.run("sysctl", "-q", "--system")
	if bin == linuxBin {
		if err := h.remove(linuxBin); err != nil {
			return res, err
		}
		h.say("removed %s", linuxBin)
	}
	return res, deleteData(h, "linux", o, &res, cfgPath, dataDir)
}

// deleteData deletes the data folder and the config with DeleteLogs, or notes
// where they were kept. The paths come from the installed unit, plist or
// registry (never the config), and it refuses system and home folders, and a
// folder that doesn't look like Woodshed's.
func deleteData(h *host, goos string, o UninstallOptions, res *Result, cfgPath, dataDir string) error {
	if !o.DeleteLogs {
		if dataDir != "" {
			res.Notes = append(res.Notes, "kept the logs, index and config in "+dataDir)
		}
		return nil
	}
	if err := checkDataDir(goos, dataDir, homeDirs()); err != nil {
		return fmt.Errorf("not deleting it: %w", err)
	}
	if err := h.checkDataDirContents(dataDir); err != nil {
		return fmt.Errorf("not deleting it: %w", err)
	}
	if err := h.removeAll(dataDir); err != nil {
		return err
	}
	h.say("deleted %s", dataDir)
	if cfgPath != "" && filepath.Dir(cfgPath) != dataDir && filepath.Base(cfgPath) == "woodshed.toml" {
		if err := h.checkConfigPath(cfgPath); err != nil {
			return fmt.Errorf("not deleting the config: %w", err)
		}
		if err := h.remove(cfgPath); err != nil {
			return err
		}
		// The config folder goes too if nothing else is in it (Remove fails otherwise).
		_ = h.remove(filepath.Dir(cfgPath))
		h.say("deleted %s", cfgPath)
	}
	return nil
}

// prepareFolders checks and creates the data and config folders for a service
// install, writes a new config naming dataDir if there's none, and gives both
// to the service account without following links. An existing config must
// already name dataDir: the installer never takes the data folder from it.
func prepareFolders(h *host, goos, cfgPath, dataDir, user, group string) (notes []string, err error) {
	homes := homeDirs()
	if err := checkDataDir(goos, dataDir, homes); err != nil {
		return nil, err
	}
	if err := h.checkDataDirContents(dataDir); err != nil {
		return nil, err
	}
	if err := h.checkConfigPath(cfgPath); err != nil {
		return nil, err
	}
	cfgDir := filepath.Dir(cfgPath)
	if cfgDir != dataDir {
		if err := checkConfigDir(goos, cfgDir, homes); err != nil {
			return nil, fmt.Errorf("the config's folder: %w", err)
		}
		if err := h.checkConfigDirContents(cfgDir); err != nil {
			return nil, err
		}
	}
	if h.exists(cfgPath) {
		c, err := config.Load(h.path(cfgPath))
		if err != nil {
			return nil, err
		}
		if filepath.Clean(c.Storage.DataDir) != dataDir {
			return nil, fmt.Errorf("%s names data_dir %q, but the service is being installed with %s; "+
				"set data_dir to %s, or pass --data-dir %q if that folder is really meant to be the data folder",
				cfgPath, c.Storage.DataDir, dataDir, dataDir, c.Storage.DataDir)
		}
	}
	for _, d := range []string{dataDir, cfgDir} {
		if err := h.mkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	if !h.exists(cfgPath) {
		c := config.Default()
		c.Storage.DataDir = dataDir
		if err := config.Save(h.path(cfgPath), c); err != nil {
			return nil, err
		}
		h.say("wrote %s", cfgPath)
	}
	skipped, err := h.chownTree(dataDir, user, group)
	if err != nil {
		return nil, err
	}
	if skipped > 0 {
		notes = append(notes, fmt.Sprintf("left %d symlinks or hard-linked files in %s as they were", skipped, dataDir))
	}
	if cfgDir != dataDir {
		if err := h.chownDir(cfgDir, user, group); err != nil {
			return notes, err
		}
		if err := h.chmod(cfgDir, 0o750); err != nil {
			return notes, err
		}
	}
	if err := h.chownFile(cfgPath, user, group); err != nil {
		return notes, err
	}
	return notes, h.chmod(dataDir, 0o750)
}

// checkConfigDirContents refuses a config folder (other than the data folder)
// holding anything but Woodshed's config: an install gives that folder to the
// service account.
func (h *host) checkConfigDirContents(dir string) error {
	entries, err := os.ReadDir(h.path(dir))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		n := e.Name()
		if n == "woodshed.toml" || (strings.HasPrefix(n, ".woodshed.toml-") && strings.HasSuffix(n, ".tmp")) {
			continue
		}
		return fmt.Errorf("the config's folder %s holds other files (%s); put the config in a folder of its own, such as %s/woodshed",
			dir, n, dir)
	}
	return nil
}

func statusSystemd(h *host) (State, error) {
	if !h.exists(linuxManualUnit) && !h.exists(linuxPackageUnits[0]) && !h.exists(linuxPackageUnits[1]) {
		return StateNotInstalled, nil
	}
	out, err := h.run("systemctl", "is-active", LinuxName+".service")
	switch strings.TrimSpace(out) {
	case "active", "reloading", "deactivating":
		return StateRunning, nil
	case "inactive", "failed":
		return StateStopped, nil
	case "activating":
		return State("starting"), nil
	}
	if err != nil {
		return StateUnknown, err
	}
	return StateUnknown, nil
}

func restartSystemd(h *host) error {
	_, err := h.run("systemctl", "restart", LinuxName+".service")
	return err
}
