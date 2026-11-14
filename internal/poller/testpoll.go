package poller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/snmp"
)

// The test poll (SPEC §12.5, §12.7): the configured poll once, without
// saving, step by step. The UI's Test poll runs it in the service with the
// stored credentials; `woodshed poll test` runs it standalone.

// TestStep is one step's result.
type TestStep struct {
	Step   string `json:"step"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	RTTms  int64  `json:"rtt_ms"`
}

// TestResult is a test poll's result (docs/api.md "Test poll").
type TestResult struct {
	OK    bool       `json:"ok"`
	Exit  string     `json:"exit"` // ok, no_answer, auth, partial
	Steps []TestStep `json:"steps"`
}

// Test exits.
const (
	ExitOK       = "ok"
	ExitNoAnswer = "no_answer"
	ExitAuth     = "auth"
	ExitPartial  = "partial"
)

// ExitCode is the CLI's exit code for a test's exit (SPEC §12.7).
func ExitCode(exit string) int {
	switch exit {
	case ExitOK:
		return 0
	case ExitNoAnswer:
		return 1
	case ExitAuth:
		return 3
	}
	return 4
}

func authStatus(s string) bool {
	switch s {
	case snmp.FailAuth, snmp.FailUnknownUser, snmp.FailUnknownEngine, snmp.FailNotInTime, snmp.FailDecrypt:
		return true
	}
	return false
}

// Test runs a test poll on the poller's socket (opened for the test when no
// target holds it).
func (p *Poller) Test(ctx context.Context, s Settings, community []byte, user *snmp.User) TestResult {
	p.mu.Lock()
	if p.sock == nil {
		sk, err := openSocket(p.o.OnSend)
		if err != nil {
			p.mu.Unlock()
			return TestResult{Exit: ExitNoAnswer, Steps: []TestStep{{Step: "socket", Detail: err.Error()}}}
		}
		p.sock = sk
	}
	p.tests++
	sock := p.sock
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.tests--
		p.syncSocketLocked()
		p.mu.Unlock()
	}()
	return runTest(ctx, sock, p.now, s, community, user)
}

// StandaloneTest runs a test poll on a socket of its own (woodshed poll test).
func StandaloneTest(ctx context.Context, s Settings, community []byte, user *snmp.User) TestResult {
	sock, err := openSocket(nil)
	if err != nil {
		return TestResult{Exit: ExitNoAnswer, Steps: []TestStep{{Step: "socket", Detail: err.Error()}}}
	}
	defer sock.close()
	return runTest(ctx, sock, time.Now, s, community, user)
}

func runTest(ctx context.Context, sock *socket, now func() time.Time, s Settings, community []byte, user *snmp.User) (res TestResult) {
	a, err := netip.ParseAddr(s.Address)
	if err != nil {
		return TestResult{Exit: ExitNoAnswer, Steps: []TestStep{{Step: "address", Detail: "not an IP address"}}}
	}
	if s.MaxInterfaces == 0 {
		s.MaxInterfaces = config.DefaultPollMaxInterfaces
	}
	if s.DeviceID == "" {
		s.DeviceID = a.String()
	}
	st := newState(Target{ID: "test", Settings: s})
	st.to = netip.AddrPortFrom(a.Unmap(), uint16(s.Port))
	st.attach(sock)
	cfg := snmp.SessionConfig{Version: s.version(), Community: community, User: user,
		Timeout: time.Duration(s.TimeoutMS) * time.Millisecond, Retries: s.Retries, Now: now}
	sess, err := snmp.NewSession(cfg, st.tr)
	if err != nil {
		res.Exit = ExitAuth
		res.Steps = append(res.Steps, TestStep{Step: "credentials", Detail: strings.TrimPrefix(err.Error(), "snmp: ")})
		return res
	}
	st.sess = sess
	p := &Poller{now: now, o: Options{Creds: nil}}
	c := &cycleRun{p: p, st: st, t: st.t, sess: sess, dev: st.device}
	answered, failed, auth := false, false, false
	step := func(name string, err error, okDetail string) bool {
		ts := TestStep{Step: name, OK: err == nil, RTTms: sess.LastRTT().Milliseconds()}
		if err != nil {
			failed = true
			var re *snmp.RequestError
			if errors.As(err, &re) {
				ts.Detail = re.Status + ": " + re.Detail
				if authStatus(re.Status) {
					auth = true
				}
			} else {
				ts.Detail = err.Error()
			}
		} else {
			answered = true
			ts.Detail = okDetail
		}
		res.Steps = append(res.Steps, ts)
		return err == nil
	}
	defer func() {
		if w := st.tr.wrong(); w.IsValid() {
			res.Steps = append(res.Steps, TestStep{Step: "replies", Detail: fmt.Sprintf(
				"replies came from %s, not %s: the agent answers from another address; fix that on the agent (Woodshed accepts replies only from the address and port polled)", w, st.to)})
			failed = true
		}
		switch {
		case !answered && auth:
			res.Exit = ExitAuth
		case !answered:
			res.Exit = ExitNoAnswer
		case auth:
			res.Exit = ExitAuth
		case failed:
			res.Exit = ExitPartial
		default:
			res.Exit = ExitOK
		}
		res.OK = res.Exit == ExitOK
	}()

	if cfg.Version == snmp.V3 {
		e, err := sess.Discover(ctx)
		detail := ""
		if e.Known() {
			detail = fmt.Sprintf("engine %x, boots %d, time %d", e.ID, e.Boots, e.Time)
		}
		if err != nil && e.Known() {
			var re *snmp.RequestError
			if errors.As(err, &re) {
				err = &snmp.RequestError{Status: re.Status, Detail: re.Detail + " (" + detail + ")"}
			}
		}
		if !step("discovery", err, detail) {
			return res
		}
	}

	vbs, err := c.get(ctx, []snmp.OID{oidSysName, oidSysDescr, oidSysUpTime})
	if err != nil {
		step("system", err, "")
		return res
	}
	name, descr := "", ""
	if v := vbs[0].Value; v.Kind == snmp.KindOctetString {
		name = text(v.Bytes)
	}
	if v := vbs[1].Value; v.Kind == snmp.KindOctetString {
		descr = text(v.Bytes)
	}
	up := "no sysUpTime"
	if v := vbs[2].Value; v.Kind == snmp.KindTimeTicks {
		up = "up " + FormatUptime(v.Uint/100)
	}
	d := up
	if name != "" {
		d = name + ", " + up
	}
	if descr != "" {
		d += "; " + descr
	}
	step("system", nil, d)

	if s.has(config.PresetSystem) {
		if err := c.refreshHR(ctx); err != nil {
			step("host_resources", err, "")
		} else if !st.hrUptimeOK && len(st.hrCPUs) == 0 && len(st.hrRAM) == 0 {
			step("host_resources", errors.New("not available on this device (noSuchObject): CPU and memory won't be polled"), "")
		} else {
			parts := []string{}
			if len(st.hrCPUs) > 0 {
				parts = append(parts, fmt.Sprintf("%d processors", len(st.hrCPUs)))
			} else {
				parts = append(parts, "no CPU load")
			}
			if len(st.hrRAM) > 0 {
				parts = append(parts, "RAM")
			} else {
				parts = append(parts, "no RAM row")
			}
			if !st.hrUptimeOK {
				parts = append(parts, "no hrSystemUptime (reboots can't be told from agent restarts)")
			}
			step("host_resources", nil, strings.Join(parts, ", "))
		}
	}
	if s.has(config.PresetInterfaces) {
		ifs, _, err := c.refreshInterfaces(ctx)
		if err != nil {
			step("interfaces", err, "")
		} else {
			bits := "64-bit counters"
			if !st.hc {
				bits = "32-bit counters: rates above about 115 Mb/s at a 5-minute interval can be wrong"
			}
			d := fmt.Sprintf("%d interfaces, %s; %d would be polled", st.ifTotal, bits, len(ifs))
			if st.ifTotal == 0 {
				d = "no interfaces in ifTable"
			}
			if st.ifTotal > len(ifs) && s.Interfaces.All {
				d += fmt.Sprintf(" (%d left out by max_interfaces %d)", st.ifTotal-len(ifs), s.MaxInterfaces)
			}
			step("interfaces", nil, d)
		}
	}
	for _, cu := range s.Custom {
		o, err := snmp.ParseOID(cu.OID)
		if err != nil {
			continue
		}
		label := cu.OID
		if cu.Label != "" {
			label += " (" + cu.Label + ")"
		}
		if cu.Kind == CustomWalk {
			rows, capped, err := c.walk(ctx, o, cu.MaxRows)
			switch {
			case err != nil:
				step("oid "+label, err, "")
			case len(rows) == 0:
				step("oid "+label, errors.New("no rows (not available on this device)"), "")
			default:
				d := fmt.Sprintf("%d rows", len(rows))
				if capped {
					d += fmt.Sprintf(", stopped at max_rows %d", cu.MaxRows)
				}
				step("oid "+label, nil, d)
			}
			continue
		}
		vbs, err := c.get(ctx, []snmp.OID{o})
		if err != nil {
			step("oid "+label, err, "")
			continue
		}
		typ, val := typeName(vbs[0].Value)
		if missing(vbs[0].Value) {
			step("oid "+label, fmt.Errorf("not available on this device (%s)", typ), "")
		} else {
			step("oid "+label, nil, typ+" "+val)
		}
	}
	return res
}

// FormatUptime writes seconds as "12 d 3 h", "3 h 4 min" or "42 s".
func FormatUptime(sec uint64) string {
	d, h, m := sec/86400, sec%86400/3600, sec%3600/60
	switch {
	case d > 0:
		return fmt.Sprintf("%d d %d h", d, h)
	case h > 0:
		return fmt.Sprintf("%d h %d min", h, m)
	case m > 0:
		return fmt.Sprintf("%d min", m)
	}
	return fmt.Sprintf("%d s", sec)
}
