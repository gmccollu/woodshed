//go:build windows

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	ksvc "github.com/kardianos/service"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/fwrule"
	"github.com/gmccollu/woodshed/internal/winacl"
)

// Firewall rules, named as the MSI names them (packaging/windows/woodshed.wxs).
var windowsFirewallRules = []struct{ name, proto string }{
	{"Woodshed syslog (UDP 514)", "UDP"},
	{"Woodshed syslog (TCP 514)", "TCP"},
}

func requireAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("installing or removing the service needs administrator rights: run it from an administrator prompt")
	}
	return nil
}

func windowsExe() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "Woodshed", "woodshed.exe")
}

// paramsKey holds what `woodshed install` recorded for uninstall (only
// administrators can write it, unlike the config).
const paramsKey = `SYSTEM\CurrentControlSet\Services\` + WindowsName + `\Parameters`

// prepareWindowsDataDir checks the data folder (security review M1d, M2, M3):
// not a system or home folder, not a reparse point, empty or Woodshed's; one that
// isn't owned by SYSTEM or Administrators is moved aside first. Then it gets the MSI's
// protected ACL, and everything inside loses any explicit entries (a planted
// Everyone:F) and inherits it; links inside are removed (winacl.ResetDataDir).
func prepareWindowsDataDir(h *host, dir string) error {
	if err := checkDataDir("windows", dir, homeDirs()); err != nil {
		return err
	}
	// Like the MSI (security review N6, W2): a folder that isn't owned by SYSTEM,
	// Administrators or TrustedInstaller is moved aside (contents kept), and a missing one
	// is created in one step with the protected ACL, so nobody gets a handle to it first.
	if err := winacl.EnsureDataDir(dir, h.say); err != nil {
		return err
	}
	if err := h.checkDataDirContents(dir); err != nil {
		return err
	}
	// The same reset the MSI runs (winacl.ResetDataDir): the protected DACL on dir; owner
	// Administrators and only inherited entries below it (a planted Everyone:F goes); links,
	// junctions and extra hard-link names inside are removed, never followed.
	if err := winacl.ResetDataDir(dir, h.say); err != nil {
		return fmt.Errorf("set the permissions on %s: %w", dir, err)
	}
	return nil
}

func installOS(o InstallOptions) (Result, error) {
	h := realHost(o.Out)
	exe := windowsExe()
	dataDir := o.DataDir
	res := Result{Where: `service "` + WindowsName + `"`, Exe: exe, Config: o.ConfigPath, DataDir: dataDir, Account: WindowsAccount}
	if err := checkServicePath("the config path", o.ConfigPath); err != nil {
		return res, err
	}
	if err := h.checkConfigPath(o.ConfigPath); err != nil {
		return res, err
	}
	if cd := filepath.Dir(o.ConfigPath); !strings.EqualFold(cd, dataDir) {
		return res, fmt.Errorf("on Windows the config must be in the data folder (%s)", dataDir)
	}
	if h.exists(o.ConfigPath) {
		c, err := config.Load(o.ConfigPath)
		if err != nil {
			return res, err
		}
		if !strings.EqualFold(filepath.Clean(c.Storage.DataDir), dataDir) {
			return res, fmt.Errorf("%s names data_dir %q, but the service is being installed with %s; set data_dir to %s, or pass --data-dir",
				o.ConfigPath, c.Storage.DataDir, dataDir, dataDir)
		}
	}

	if err := h.copyFile(o.Exe, exe, 0o755); err != nil {
		return res, fmt.Errorf("copy the binary to %s: %w", exe, err)
	}
	h.say("installed %s", exe)
	if err := prepareWindowsDataDir(h, dataDir); err != nil {
		return res, err
	}
	if !h.exists(o.ConfigPath) {
		c := config.Default()
		c.Storage.DataDir = dataDir
		if err := config.Save(o.ConfigPath, c); err != nil {
			return res, err
		}
	}
	h.say("%s is writable only by %s, SYSTEM and Administrators", dataDir, WindowsAccount)

	// The event source the service logs to, registered as the MSI does.
	if err := eventlog.InstallAsEventCreate(WindowsName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return res, fmt.Errorf("register the event log source: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return res, adminHint(err)
	}
	defer m.Disconnect()
	s, err := m.CreateService(WindowsName, exe, mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		ServiceStartName: WindowsAccount,
		DisplayName:      DisplayName,
		Description:      Description,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "run", "--service", "--config", o.ConfigPath)
	if err != nil {
		return res, fmt.Errorf("create the service: %w", err)
	}
	defer s.Close()
	// Restart on failure, also when it exits with an error (the MSI's ServiceConfig).
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 86400); err != nil {
		return res, err
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return res, err
	}
	// Only the privilege it needs (security review L4): a virtual account gets
	// SeImpersonatePrivilege and others by default.
	if err := setRequiredPrivileges(s.Handle, []string{"SeChangeNotifyPrivilege"}); err != nil {
		return res, fmt.Errorf("limit the service's privileges: %w", err)
	}
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, paramsKey, registry.SET_VALUE); err == nil {
		err = k.SetStringValue("DataDir", dataDir)
		k.Close()
		if err != nil {
			return res, err
		}
	} else {
		return res, err
	}
	h.say("created service %s, running as %s with only SeChangeNotifyPrivilege", WindowsName, WindowsAccount)

	for _, r := range windowsFirewallRules {
		_, _ = h.run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+r.name)
		if _, err := h.run("netsh", "advfirewall", "firewall", "add", "rule", "name="+r.name, "dir=in", "action=allow",
			"program="+exe, "protocol="+r.proto, "localport=514", "profile=any",
			"description=Lets devices send syslog to Woodshed over "+r.proto+"."); err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("couldn't add the firewall rule %q: %v", r.name, err))
		}
	}
	// The TLS rule is created disabled (`woodshed tls on` enables it), and an
	// existing one is left as it is, so a reinstall keeps its state (SPEC §10.3.6).
	if created, err := fwrule.WindowsEnsure(h.run, exe); err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("couldn't add the firewall rule %q: %v", fwrule.RuleName, err))
	} else if created {
		h.say("added the firewall rule %q, disabled (`woodshed tls on` turns it on)", fwrule.RuleName)
	}
	// The SNMP trap rule likewise (`woodshed snmp on` enables it; SPEC §11.2.7).
	if created, err := fwrule.SNMPWindowsEnsure(h.run, exe); err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("couldn't add the firewall rule %q: %v", fwrule.SNMPRuleName, err))
	} else if created {
		h.say("added the firewall rule %q, disabled (`woodshed snmp on` turns it on)", fwrule.SNMPRuleName)
	}
	if err := s.Start(); err != nil {
		return res, fmt.Errorf("the service is installed but didn't start (see Event Viewer > Application): %w", err)
	}
	return res, nil
}

func uninstallOS(o UninstallOptions) (Result, error) {
	h := realHost(o.Out)
	res := Result{Where: `service "` + WindowsName + `"`, Account: WindowsAccount}
	m, err := mgr.Connect()
	if err != nil {
		return res, adminHint(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(WindowsName)
	if err != nil {
		return res, err
	}
	cfg, err := s.Config()
	if err != nil {
		s.Close()
		return res, err
	}
	exe, cfgPath := parseWindowsCommand(cfg.BinaryPathName)
	res.Exe, res.Config = exe, cfgPath
	// The data folder recorded at install, never the config's (M1d); read before
	// the service's registry key goes with it.
	dataDir := recordedDataDir()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err == nil {
			for i := 0; i < 60; i++ {
				if st, err := s.Query(); err != nil || st.State == svc.Stopped {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
		}
	}
	if err := s.Delete(); err != nil {
		s.Close()
		return res, fmt.Errorf("delete the service: %w", err)
	}
	s.Close()
	h.say("removed service %s", WindowsName)
	for _, r := range windowsFirewallRules {
		_, _ = h.run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+r.name)
	}
	_ = fwrule.WindowsRemove(h.run)
	_ = fwrule.SNMPWindowsRemove(h.run)
	_ = eventlog.Remove(WindowsName)

	if exe != "" && strings.EqualFold(filepath.Clean(exe), filepath.Clean(windowsExe())) {
		if err := removeExe(exe); err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("couldn't delete %s now (%v); it's deleted at the next restart", exe, err))
		} else {
			_ = os.Remove(filepath.Dir(exe))
			h.say("removed %s", exe)
		}
	}
	if cfgPath == "" {
		cfgPath = filepath.Join(dataDir, config.FileName)
	}
	res.DataDir = dataDir
	return res, deleteData(h, "windows", o, &res, cfgPath, dataDir)
}

func recordedDataDir() string {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, paramsKey, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if v, _, err := k.GetStringValue("DataDir"); err == nil && v != "" {
			return v
		}
	}
	return config.DefaultDataDir()
}

// setRequiredPrivileges limits a service's token to privs
// (SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO).
func setRequiredPrivileges(h windows.Handle, privs []string) error {
	var multi []uint16
	for _, p := range privs {
		u, err := windows.UTF16FromString(p)
		if err != nil {
			return err
		}
		multi = append(multi, u...)
	}
	multi = append(multi, 0)
	info := struct{ privs *uint16 }{&multi[0]}
	return windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&info)))
}

// removeExe deletes the installed binary, which may be the one running this
// command: then it's renamed out of the way and deleted at the next restart.
func removeExe(exe string) error {
	err := os.Remove(exe)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	old := exe + ".old"
	_ = os.Remove(old)
	if rerr := os.Rename(exe, old); rerr != nil {
		return err
	}
	p, perr := windows.UTF16PtrFromString(old)
	if perr != nil {
		return err
	}
	if merr := windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); merr != nil {
		return merr
	}
	return errors.New("it's in use")
}

// parseWindowsCommand reads the binary and --config back from a service's
// command line.
func parseWindowsCommand(cmdline string) (exe, cfgPath string) {
	args, err := windows.DecomposeCommandLine(cmdline)
	if err != nil || len(args) == 0 {
		return "", ""
	}
	exe = args[0]
	for i := 1; i+1 < len(args); i++ {
		if args[i] == "--config" {
			cfgPath = args[i+1]
		}
	}
	return exe, cfgPath
}

// statusOS asks the service manager with query-only access, which a standard user
// has: the service library's Status also asks for start and stop rights, so for a
// user who isn't an administrator it fails with "Access is denied".
func statusOS(runner) (State, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return StateUnknown, err
	}
	defer windows.CloseServiceHandle(m)
	name, err := windows.UTF16PtrFromString(Name("windows"))
	if err != nil {
		return StateUnknown, err
	}
	h, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return StateNotInstalled, nil
	}
	if err != nil {
		return StateUnknown, err
	}
	defer windows.CloseServiceHandle(h)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(h, &st); err != nil {
		return StateUnknown, err
	}
	switch st.CurrentState {
	case windows.SERVICE_RUNNING:
		return StateRunning, nil
	case windows.SERVICE_STOPPED:
		return StateStopped, nil
	}
	return StateUnknown, nil
}

func restartOS(runner) error {
	s, err := ksvc.New(nopProgram{}, runConfig(config.DefaultConfigPath()))
	if err != nil {
		return err
	}
	return s.Restart()
}

type nopProgram struct{}

func (nopProgram) Start(ksvc.Service) error { return nil }
func (nopProgram) Stop(ksvc.Service) error  { return nil }
