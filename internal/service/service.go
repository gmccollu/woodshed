// Package service runs Woodshed under the OS service manager (Windows SCM,
// systemd, launchd) and installs or removes the service, with the names, paths,
// accounts and log destinations in docs/service-contract.md.
//
// `woodshed install` is for machines without a package, and sets the service up
// the way the package does: the same service definition (the packaged systemd unit
// and launchd plist are embedded, see package packaging), the same least-privilege
// account (`woodshed`, `_woodshed`, `NT SERVICE\Woodshed`), the same data-folder
// permissions, the same log destination. The binary is copied to a system location
// (/usr/local/bin/woodshed, or %ProgramFiles%\Woodshed\woodshed.exe) the account can
// read.
//
// install and uninstall refuse when the package installed the service (the unit in
// /usr/lib/systemd/system, the pkg receipt, the MSI's registry key), so a machine
// never ends up with two services or a package whose service vanished. install also
// refuses while a service from Woodpile, the old name, is still there (legacy.go).
package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	ksvc "github.com/kardianos/service"

	"github.com/gmccollu/woodshed/internal/config"
)

// Service names (docs/service-contract.md §2). Don't change them: the packages
// and the Windows data-folder ACL (the service SID) depend on them.
const (
	WindowsName = "Woodshed"            // SCM service name
	LinuxName   = "woodshed"            // woodshed.service
	DarwinName  = "com.woodshed.daemon" // launchd label
)

// DisplayName and Description are shown by the service managers.
const (
	DisplayName = "Woodshed syslog, SNMP and flow collector"
	Description = "Collects syslog, SNMP traps, SNMP polls and flows, and stores them as files. UI: http://127.0.0.1:8514/"
)

// Service accounts, as the packages create them.
const (
	LinuxUser  = "woodshed"
	DarwinUser = "_woodshed"
	// WindowsAccount is the service's virtual account.
	WindowsAccount = `NT SERVICE\` + WindowsName
)

// Name returns the service name on goos.
func Name(goos string) string {
	switch goos {
	case "windows":
		return WindowsName
	case "darwin":
		return DarwinName
	}
	return LinuxName
}

// runConfig is the kardianos definition used to run under the service manager.
// Install doesn't use it: it installs the packaged definitions instead.
func runConfig(cfgPath string) *ksvc.Config {
	return &ksvc.Config{
		Name:        Name(runtime.GOOS),
		DisplayName: DisplayName,
		Description: Description,
		Arguments:   []string{"run", "--service", "--config", cfgPath},
	}
}

// ---- running under the service manager ----

// RunFunc runs the server until ctx is done. It gets the logger to use.
type RunFunc func(ctx context.Context, log *slog.Logger) error

// Run runs fn as the service. Logs go to the Windows Application event log
// (source "Woodshed", registered by the MSI or `woodshed install`) on Windows and
// to stdout elsewhere (journald and the launchd log file pick them up). It
// returns when the service manager stops the service; if fn fails on its own, the
// process exits with status 1 so the manager can restart it.
func Run(cfgPath string, stopTimeout time.Duration, fn RunFunc) error {
	prg := &program{run: fn, stopTimeout: stopTimeout}
	s, err := ksvc.New(prg, runConfig(cfgPath))
	if err != nil {
		return err
	}
	prg.log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	if runtime.GOOS == "windows" {
		l, err := s.Logger(nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "woodshed: the event log source %q isn't available (%v); logging to stderr\n", WindowsName, err)
			prg.log = slog.New(slog.NewTextHandler(os.Stderr, nil))
		} else {
			prg.log = slog.New(newLoggerHandler(l, slog.LevelInfo))
		}
	}
	return s.Run()
}

type program struct {
	run         RunFunc
	log         *slog.Logger
	stopTimeout time.Duration

	cancel context.CancelFunc
	done   chan error
	stop   chan struct{}
}

func (p *program) Start(s ksvc.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan error, 1)
	p.stop = make(chan struct{})
	go func() {
		err := p.run(ctx, p.log)
		select {
		case <-p.stop:
			p.done <- err
		default:
			// Stopped without being asked: a startup error or a failure.
			if err == nil {
				err = errors.New("the server stopped unexpectedly")
			}
			p.log.Error("woodshed stopped", "err", err)
			os.Exit(1)
		}
	}()
	return nil
}

func (p *program) Stop(s ksvc.Service) error {
	close(p.stop)
	p.cancel()
	timeout := p.stopTimeout + 2*time.Second
	select {
	case err := <-p.done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("the server didn't stop within %v", timeout)
	}
}

// ---- detecting an installed service ----

// Installed describes the Woodshed service found on this machine.
type Installed struct {
	Exists  bool   // a Woodshed service is defined
	Package bool   // and the package installed it
	Where   string // the unit, plist or SCM entry found
	// Remove is how to remove a package-installed service.
	Remove string
}

// prober is how Detect looks at the machine (faked in tests).
type prober interface {
	exists(path string) bool
	// windowsService reports whether the SCM has the service, and whether the
	// MSI's registry key (HKLM\<msiKey>, Software\Woodshed) exists.
	windowsService(name, msiKey string) (exists, msi bool, err error)
}

// windowsMSIKey is the MSI's registry key under HKLM (its Start-menu component).
const windowsMSIKey = `Software\Woodshed`

// Package and install paths (docs/install.md, packaging/).
var (
	linuxPackageUnits = []string{"/usr/lib/systemd/system/woodshed.service", "/lib/systemd/system/woodshed.service"}
	linuxManualUnit   = "/etc/systemd/system/woodshed.service"
	darwinPlist       = "/Library/LaunchDaemons/" + DarwinName + ".plist"
	darwinPkgMarkers  = []string{"/var/db/receipts/com.woodshed.pkg.plist", "/var/db/receipts/com.woodshed.pkg.bom", "/usr/local/share/woodshed/uninstall.sh"}
)

func detect(goos string, p prober) (Installed, error) {
	switch goos {
	case "windows":
		ok, msi, err := p.windowsService(WindowsName, windowsMSIKey)
		if err != nil {
			return Installed{}, fmt.Errorf("read the service list: %w", err)
		}
		in := Installed{}
		if ok {
			in.Exists, in.Where = true, `service "`+WindowsName+`"`
		}
		if msi {
			// The MSI's key without its service still means the package is installed.
			in.Exists, in.Package = true, true
			if in.Where == "" {
				in.Where = `HKLM\` + windowsMSIKey
			}
			in.Remove = "Settings > Apps > Woodshed > Uninstall (or msiexec /x with the MSI)"
		}
		return in, nil
	case "darwin":
		in := Installed{}
		if p.exists(darwinPlist) {
			in.Exists, in.Where = true, darwinPlist
		}
		for _, m := range darwinPkgMarkers {
			if p.exists(m) {
				in.Package = true
				in.Remove = "sudo /usr/local/share/woodshed/uninstall.sh"
				if !in.Exists {
					in.Exists, in.Where = true, m
				}
				break
			}
		}
		return in, nil
	default:
		for _, u := range linuxPackageUnits {
			if p.exists(u) {
				return Installed{Exists: true, Package: true, Where: u,
					Remove: "your package manager (apt remove woodshed, dnf remove woodshed)"}, nil
			}
		}
		if p.exists(linuxManualUnit) {
			return Installed{Exists: true, Where: linuxManualUnit}, nil
		}
		return Installed{}, nil
	}
}

// checkInstall refuses an install when any Woodshed service already exists.
func checkInstall(in Installed) error {
	if !in.Exists {
		return nil
	}
	if in.Package {
		return fmt.Errorf("Woodshed's package already installed the service (%s); it's managed by the package, so there's nothing to install. "+
			"To remove it use %s", in.Where, in.Remove)
	}
	return fmt.Errorf("a Woodshed service is already installed (%s); run `woodshed uninstall` first to replace it", in.Where)
}

// checkUninstall refuses to remove a package's service, or a missing one.
func checkUninstall(in Installed) error {
	if !in.Exists {
		return errors.New("no Woodshed service is installed")
	}
	if in.Package {
		return fmt.Errorf("the Woodshed service was installed by the package (%s); remove it with %s, so the package and the service stay in step",
			in.Where, in.Remove)
	}
	return nil
}

// Detect looks for an installed Woodshed service on this machine.
func Detect() (Installed, error) { return detect(runtime.GOOS, osProber{}) }

type osProber struct{}

func (osProber) exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (osProber) windowsService(name, msiKey string) (bool, bool, error) {
	return windowsServiceState(name, msiKey)
}

// ---- install and uninstall ----

// InstallOptions configures Install.
type InstallOptions struct {
	ConfigPath string // the config the service runs with (default: this OS's)
	// DataDir is the data folder (default: this OS's). It's never taken from the
	// config, which the service account can write (security review M1).
	DataDir string
	Exe     string    // the binary to install (default: this program)
	Out     io.Writer // progress lines (default: discarded)
	// Version goes into the macOS launcher app's Info.plist (default "1.0").
	Version string
}

// UninstallOptions configures Uninstall.
type UninstallOptions struct {
	// DeleteLogs also deletes the data folder (logs, index, config) and, on macOS,
	// the _woodshed account, as the package uninstallers do when asked.
	DeleteLogs bool
	Out        io.Writer
}

// Result says what Install or Uninstall did, for the CLI.
type Result struct {
	Where   string // the unit, plist or service installed or removed
	Exe     string // the installed binary
	Config  string
	DataDir string
	Account string
	Notes   []string // anything the user should know (kept data, a binary left behind)
}

// Install installs the service as the package would and starts it. It needs
// administrator rights.
func Install(o InstallOptions) (Result, error) {
	in, err := Detect()
	if err != nil {
		return Result{}, err
	}
	if err := checkInstall(in); err != nil {
		return Result{}, err
	}
	legacy, err := DetectLegacy()
	if err != nil {
		return Result{}, err
	}
	if err := checkLegacy(legacy); err != nil {
		return Result{}, err
	}
	if o.ConfigPath == "" {
		o.ConfigPath = config.DefaultConfigPath()
	}
	if o.ConfigPath, err = filepath.Abs(o.ConfigPath); err != nil {
		return Result{}, err
	}
	if o.DataDir == "" {
		o.DataDir = config.DefaultDataDir()
	}
	if o.DataDir, err = filepath.Abs(o.DataDir); err != nil {
		return Result{}, err
	}
	if o.Exe == "" {
		if o.Exe, err = os.Executable(); err != nil {
			return Result{}, fmt.Errorf("find this program's path: %w", err)
		}
	}
	if real, err := filepath.EvalSymlinks(o.Exe); err == nil {
		o.Exe = real
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	if err := requireAdmin(); err != nil {
		return Result{}, err
	}
	res, err := installOS(o)
	if err == nil && legacy.DataNote() != "" {
		res.Notes = append(res.Notes, legacy.DataNote())
	}
	return res, err
}

// Uninstall stops and removes a service installed by Install. It keeps the
// config and the logs unless DeleteLogs is set.
func Uninstall(o UninstallOptions) (Result, error) {
	in, err := Detect()
	if err != nil {
		return Result{}, err
	}
	if err := checkUninstall(in); err != nil {
		return Result{}, err
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	if err := requireAdmin(); err != nil {
		return Result{}, err
	}
	return uninstallOS(o)
}

// ---- status ----

// State is what the service manager says about the service.
type State string

// Service states.
const (
	StateRunning      State = "running"
	StateStopped      State = "stopped"
	StateNotInstalled State = "not installed"
	StateUnknown      State = "unknown"
)

// Status asks the service manager about the service. It never needs
// administrator rights; when the manager can't say, it returns StateUnknown and
// the reason.
func Status() (State, error) { return statusOS(execRunner{}) }

// Restart asks the service manager to restart the service (administrator
// rights needed).
func Restart() error { return adminHint(restartOS(execRunner{})) }

// Platform names the service manager in use, for messages.
func Platform() string { return ksvc.Platform() }

// adminHint adds how to get the rights to a permission error.
func adminHint(err error) error {
	if err == nil {
		return nil
	}
	if !isPermission(err) {
		return err
	}
	if runtime.GOOS == "windows" {
		return fmt.Errorf("%w (run it from an administrator prompt)", err)
	}
	return fmt.Errorf("%w (run it with sudo)", err)
}

func isPermission(err error) bool {
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "permission denied") || strings.Contains(s, "access is denied") ||
		strings.Contains(s, "operation not permitted") || strings.Contains(s, "must be run as root")
}
