package service

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/gmccollu/woodshed/internal/config"

	"github.com/gmccollu/woodshed/packaging"
)

// fakeRunner records commands; fail lists command prefixes that fail.
type fakeRunner struct {
	cmds   []string
	fail   []string
	outs   map[string]string
	inputs []string
	// chowned lists the paths (relative to the fake root) given away.
	chowned []string
}

func (f *fakeRunner) run(name string, args ...string) (string, error) {
	c := strings.Join(append([]string{name}, args...), " ")
	f.cmds = append(f.cmds, c)
	for _, p := range f.fail {
		if strings.HasPrefix(c, p) {
			return "", errors.New("exit status 2")
		}
	}
	return f.outs[c], nil
}

func (f *fakeRunner) runInput(input, name string, args ...string) (string, error) {
	f.inputs = append(f.inputs, input)
	return f.run(name, args...)
}

func (f *fakeRunner) ran(prefix string) bool {
	for _, c := range f.cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// unixOnly skips tests of the systemd and launchd installers on Windows: they only
// ever run on Linux and macOS, and handle Unix paths with path/filepath.
func unixOnly(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the systemd and launchd installers run only on Unix")
	}
}

func fakeHost(t *testing.T, r *fakeRunner, dirs ...string) *host {
	t.Helper()
	h := &host{runner: r, root: t.TempDir(), out: io.Discard}
	h.lookupIDs = func(u, g string) (int, int, error) { return 1001, 1001, nil }
	h.fchown = func(f *os.File, uid, gid int) error {
		rel, _ := filepath.Rel(h.root, f.Name())
		r.chowned = append(r.chowned, "/"+filepath.ToSlash(rel))
		return nil
	}
	for _, d := range dirs {
		if err := os.MkdirAll(h.path(d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func fakeExe(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "woodshed")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSystemdUnitIsThePackagedOne(t *testing.T) {
	unixOnly(t)
	u, err := systemdUnit(linuxBin, "/etc/woodshed/woodshed.toml", "/var/lib/woodshed")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(packaging.SystemdUnit, "/usr/bin/woodshed run", "/usr/local/bin/woodshed run", 1)
	if got := strings.TrimPrefix(u, installedByTag+"\n"); got != want {
		t.Errorf("default install differs from the package's unit beyond the binary path:\n%s", got)
	}
	for _, line := range []string{"User=woodshed", "AmbientCapabilities=CAP_NET_BIND_SERVICE", "ProtectSystem=strict", "NoNewPrivileges=yes"} {
		if !strings.Contains(u, line+"\n") {
			t.Errorf("unit lacks %s", line)
		}
	}
	// A custom config: ExecStart, ReadWritePaths and WorkingDirectory follow it.
	u, err = systemdUnit(linuxBin, "/srv/wp conf/woodshed.toml", "/srv/wp data")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		`ExecStart=/usr/local/bin/woodshed run --service --config "/srv/wp conf/woodshed.toml"`,
		`ReadWritePaths="/srv/wp data" "/srv/wp conf"`,
		`WorkingDirectory="/srv/wp data"`,
	} {
		if !strings.Contains(u, line+"\n") {
			t.Errorf("custom unit lacks %s:\n%s", line, u)
		}
	}
	bin, cfg, data := unitPaths(u)
	if bin != linuxBin || cfg != "/srv/wp conf/woodshed.toml" || data != "/srv/wp data" {
		t.Errorf("unitPaths = %q %q %q", bin, cfg, data)
	}
}

func TestInstallSystemd(t *testing.T) {
	unixOnly(t)
	r := &fakeRunner{fail: []string{"getent"}} // neither the group nor the user exists yet
	h := fakeHost(t, r, "/run/systemd/system", "/usr/sbin")
	os.WriteFile(h.path("/usr/sbin/nologin"), nil, 0o755)
	o := InstallOptions{ConfigPath: "/etc/woodshed/woodshed.toml", Exe: fakeExe(t)}
	res, err := installSystemd(h, o, "/var/lib/woodshed")
	if err != nil {
		t.Fatal(err)
	}
	if res.Account != "woodshed" || res.Exe != linuxBin {
		t.Errorf("result %+v", res)
	}
	for _, c := range []string{
		"groupadd --system woodshed",
		"useradd --system --gid woodshed --home-dir /var/lib/woodshed --no-create-home --shell /usr/sbin/nologin --comment Woodshed service woodshed",
		"sysctl -q -p /etc/sysctl.d/60-woodshed.conf",
		"systemctl daemon-reload",
		"systemctl enable woodshed.service",
		"systemctl start woodshed.service",
	} {
		if !r.ran(c) {
			t.Errorf("didn't run %q; ran:\n%s", c, strings.Join(r.cmds, "\n"))
		}
	}
	for path, want := range map[string]string{linuxSysctl: packaging.SysctlDropIn} {
		if got, _ := h.readFile(path); got != want {
			t.Errorf("%s = %q", path, got)
		}
	}
	if u, _ := h.readFile(linuxManualUnit); !strings.Contains(u, "ExecStart=/usr/local/bin/woodshed run --service --config /etc/woodshed/woodshed.toml\n") {
		t.Errorf("unit:\n%s", u)
	}
	if fi, err := os.Stat(h.path(linuxBin)); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("binary: %v %v", fi, err)
	}
	for _, p := range []string{"/var/lib/woodshed", "/etc/woodshed", "/etc/woodshed/woodshed.toml"} {
		if !slices.Contains(r.chowned, p) {
			t.Errorf("%s not given to woodshed; chowned %v", p, r.chowned)
		}
	}
	if c, err := config.Load(h.path("/etc/woodshed/woodshed.toml")); err != nil || c.Storage.DataDir != "/var/lib/woodshed" {
		t.Errorf("the new config: %+v %v", c.Storage, err)
	}

	// Uninstall keeps the data by default...
	os.MkdirAll(h.path("/var/lib/woodshed/logs"), 0o750)
	r.cmds = nil
	res, err = uninstallSystemd(h, UninstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if h.exists(linuxManualUnit) || h.exists(linuxBin) || h.exists(linuxSysctl) || !h.exists("/var/lib/woodshed/logs") || !h.exists("/etc/woodshed/woodshed.toml") {
		t.Error("uninstall removed the wrong things")
	}
	if !r.ran("systemctl stop woodshed.service") || !r.ran("systemctl disable woodshed.service") || len(res.Notes) == 0 {
		t.Errorf("uninstall: %v %+v", r.cmds, res)
	}
	// ...and --delete-logs deletes it.
	installSystemd(h, o, "/var/lib/woodshed")
	if _, err := uninstallSystemd(h, UninstallOptions{DeleteLogs: true}); err != nil {
		t.Fatal(err)
	}
	if h.exists("/var/lib/woodshed") || h.exists("/etc/woodshed/woodshed.toml") {
		t.Error("--delete-logs left the data")
	}
}

func TestInstallSystemdNeedsSystemd(t *testing.T) {
	unixOnly(t)
	h := fakeHost(t, &fakeRunner{})
	_, err := installSystemd(h, InstallOptions{ConfigPath: "/etc/woodshed/woodshed.toml", Exe: fakeExe(t)}, "/var/lib/woodshed")
	if err == nil || !strings.Contains(err.Error(), "systemd isn't running") {
		t.Fatalf("err = %v", err)
	}
}

func TestLaunchdPlistIsThePackagedOne(t *testing.T) {
	unixOnly(t)
	p, err := launchdPlist(darwinPkgConfig, darwinPkgData)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, "Installed by `woodshed install`") {
		t.Error("no marker comment")
	}
	stripped := strings.Replace(p, "<!-- Installed by `woodshed install`; remove it with `woodshed uninstall`. -->\n", "", 1)
	if stripped != packaging.LaunchdPlist {
		t.Errorf("the default plist isn't the package's:\n%s", p)
	}
	p, err = launchdPlist("/Users/x/w & p/woodshed.toml", "/Users/x/w & p")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, "<string>/Users/x/w &amp; p/woodshed.toml</string>") {
		t.Errorf("custom plist:\n%s", p)
	}
	if cfg, data := plistPaths(p); cfg != "/Users/x/w & p/woodshed.toml" || data != "/Users/x/w & p" {
		t.Errorf("plistPaths = %q %q", cfg, data)
	}
}

func TestInstallLaunchd(t *testing.T) {
	unixOnly(t)
	r := &fakeRunner{fail: []string{"launchctl print"}}
	h := fakeHost(t, r)
	o := InstallOptions{ConfigPath: darwinPkgConfig, Exe: fakeExe(t)}
	if _, err := installLaunchd(h, o, darwinPkgData); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{
		"/bin/sh -s",
		"chown root:wheel " + darwinPlist,
		"launchctl enable system/com.woodshed.daemon",
		"launchctl bootstrap system " + darwinPlist,
	} {
		if !r.ran(c) {
			t.Errorf("didn't run %q; ran:\n%s", c, strings.Join(r.cmds, "\n"))
		}
	}
	if len(r.inputs) != 2 || !strings.HasSuffix(r.inputs[0], "\nensure_service_account\n") ||
		!strings.HasSuffix(r.inputs[1], "\nprepare_log_dir\n") || !strings.Contains(r.inputs[1], "prepare_log_dir() {") {
		t.Errorf("the pkg's ensure_service_account and prepare_log_dir weren't fed to sh: %d inputs", len(r.inputs))
	}
	if slices.Contains(r.chowned, darwinLogDir) {
		t.Error("the log folder was given to _woodshed (the pkg keeps it root-owned)")
	}
	for _, p := range []string{darwinPkgData, darwinPkgConfig} {
		if !slices.Contains(r.chowned, p) {
			t.Errorf("%s not given to _woodshed; chowned %v", p, r.chowned)
		}
	}
	if got, _ := h.readFile(darwinNewsyslog); got != packaging.NewsyslogConf {
		t.Errorf("newsyslog = %q", got)
	}
	// The pkg's launcher app, with a version in its plist.
	if got, _ := h.readFile(darwinApp + "/Contents/MacOS/Woodshed"); got != packaging.MacAppLauncher {
		t.Error("the launcher app's executable isn't the pkg's")
	}
	if fi, err := os.Stat(h.path(darwinApp + "/Contents/MacOS/Woodshed")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("the launcher isn't executable: %v", err)
	}
	if got, _ := h.readFile(darwinApp + "/Contents/Info.plist"); !strings.Contains(got, "com.woodshed.launcher") || strings.Contains(got, "@VERSION@") {
		t.Errorf("Info.plist = %q", got)
	}
	if !h.exists(darwinApp + "/Contents/Resources/woodshed.icns") {
		t.Error("no icon in the launcher app")
	}
	r.fail = nil // loaded now
	r.cmds = nil
	if _, err := uninstallLaunchd(h, UninstallOptions{DeleteLogs: true}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"launchctl bootout system/com.woodshed.daemon", "dscl . -delete /Users/_woodshed", "dscl . -delete /Groups/_woodshed"} {
		if !r.ran(c) {
			t.Errorf("uninstall didn't run %q: %v", c, r.cmds)
		}
	}
	if h.exists(darwinPlist) || h.exists(darwinBin) || h.exists(darwinPkgData) || h.exists(darwinLogDir) || h.exists(darwinApp) {
		t.Error("uninstall --delete-logs left files")
	}
}

func TestMacAccountScriptIsSourceable(t *testing.T) {
	if !strings.Contains(packaging.MacAccountScript, "ensure_service_account()") {
		t.Fatal("packaging/macos/scripts/common.sh no longer defines ensure_service_account")
	}
}

func TestStatusParsers(t *testing.T) {
	unixOnly(t)
	r := &fakeRunner{outs: map[string]string{"systemctl is-active woodshed.service": "active"}}
	h := fakeHost(t, r, "/etc/systemd/system")
	if st, _ := statusSystemd(h); st != StateNotInstalled {
		t.Errorf("no unit: %s", st)
	}
	os.WriteFile(h.path(linuxManualUnit), nil, 0o644)
	if st, _ := statusSystemd(h); st != StateRunning {
		t.Errorf("active: %s", st)
	}
	r.outs["systemctl is-active woodshed.service"] = "inactive"
	if st, _ := statusSystemd(h); st != StateStopped {
		t.Errorf("inactive: %s", st)
	}
	r.outs["launchctl print system/com.woodshed.daemon"] = "system/com.woodshed.daemon = {\n\tactive count = 1\n\tstate = running\n}"
	os.MkdirAll(filepath.Dir(h.path(darwinPlist)), 0o755)
	os.WriteFile(h.path(darwinPlist), nil, 0o644)
	if st, _ := statusLaunchd(h); st != StateRunning {
		t.Errorf("launchd running: %s", st)
	}
	r.fail = []string{"launchctl print"}
	if st, _ := statusLaunchd(h); st != StateStopped {
		t.Errorf("launchd not loaded: %s", st)
	}
}

// The pkg's prepare_log_dir, as `woodshed install` runs it, removes symlinks
// planted in the log folder and leaves one plain log file (chown is stubbed: no root).
func TestPrepareLogDirRemovesSymlinks(t *testing.T) {
	unixOnly(t)
	dir := filepath.Join(t.TempDir(), "Logs")
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	os.MkdirAll(dir, 0o755)
	os.Symlink(victim, filepath.Join(dir, "woodshed.log"))
	os.Symlink(victim, filepath.Join(dir, "other.log"))
	script := packaging.MacAccountScript + "\nchown() { :; }\nLOG_DIR='" + dir + "'\nLOG_FILE=\"$LOG_DIR/woodshed.log\"\nset -e\nprepare_log_dir\n"
	if out, err := (execRunner{}).runInput(script, "/bin/sh", "-s"); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	fi, err := os.Lstat(filepath.Join(dir, "woodshed.log"))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("woodshed.log isn't a plain file: %v %v", fi, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "other.log")); !os.IsNotExist(err) {
		t.Error("a planted symlink survived")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Error("the symlink's target was changed")
	}
}
