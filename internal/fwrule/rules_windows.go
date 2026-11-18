//go:build windows

package fwrule

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// listRules reads the firewall's rules through its COM API, in process: the
// HNetCfg.FwPolicy2 object's Rules collection (INetFwPolicy2::get_Rules),
// walked with its enumerator, reading each INetFwRule's properties. It's the
// same rule store netsh and the firewall control panel show, and reading it
// needs no administrator rights. No program runs and nothing localized is
// parsed. Interfaces, method order and GUIDs: netfw.h / netfw.idl
// (https://learn.microsoft.com/en-us/windows/win32/api/netfw/); the walk is the
// one in "Enumerating Firewall Rules"
// (https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ics/c-enumerating-firewall-rules).
func listRules(names ...string) ([]WinRule, error) {
	// COM is set up per OS thread: keep this goroutine on one for the walk.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	switch hr := hresult(procCoInitializeEx.Call(0, coinitMultithreaded)); hr {
	case sOK, sFalse: // S_FALSE: already initialized on this thread; still paired with CoUninitialize
		defer procCoUninitialize.Call()
	case rpcEChangedMode: // already a single-threaded apartment: in-process calls work there too
	default:
		return nil, hrError("CoInitializeEx", hr)
	}

	clsid, err := windows.GUIDFromString(clsidNetFwPolicy2)
	if err != nil {
		return nil, err
	}
	iid, err := windows.GUIDFromString(iidINetFwPolicy2)
	if err != nil {
		return nil, err
	}
	iidRule, err := windows.GUIDFromString(iidINetFwRule)
	if err != nil {
		return nil, err
	}
	iidEnum, err := windows.GUIDFromString(iidIEnumVARIANT)
	if err != nil {
		return nil, err
	}

	var policy *comObject
	if hr := hresult(procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsid)), 0, clsctxInprocServer,
		uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&policy)))); hr != sOK {
		return nil, hrError("CoCreateInstance(HNetCfg.FwPolicy2)", hr)
	}
	defer policy.release()

	var rules *comObject
	if hr := policy.call(slotPolicyGetRules, uintptr(unsafe.Pointer(&rules))); hr != sOK {
		return nil, hrError("INetFwPolicy2.Rules", hr)
	}
	defer rules.release()

	var unk *comObject
	if hr := rules.call(slotRulesGetNewEnum, uintptr(unsafe.Pointer(&unk))); hr != sOK {
		return nil, hrError("INetFwRules._NewEnum", hr)
	}
	var enum *comObject
	hr := unk.call(slotQueryInterface, uintptr(unsafe.Pointer(&iidEnum)), uintptr(unsafe.Pointer(&enum)))
	unk.release()
	if hr != sOK {
		return nil, hrError("QueryInterface(IEnumVARIANT)", hr)
	}
	defer enum.release()

	var out []WinRule
	for {
		var v variant
		var fetched uint32
		hr := enum.call(slotEnumNext, 1, uintptr(unsafe.Pointer(&v)), uintptr(unsafe.Pointer(&fetched)))
		if hr == sFalse || hr == sOK && fetched == 0 {
			return out, nil // the end
		}
		if hr != sOK {
			return nil, hrError("IEnumVARIANT.Next", hr)
		}
		r, ok, err := readRule(&v, &iidRule, names)
		procVariantClear.Call(uintptr(unsafe.Pointer(&v)))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, r)
		}
	}
}

// readRule reads one enumerated rule, when its name is one of names (or names
// is empty). ok is false for a rule that isn't wanted.
func readRule(v *variant, iidRule *windows.GUID, names []string) (r WinRule, ok bool, err error) {
	if v.vt != vtDispatch || v.val == nil {
		return r, false, nil
	}
	var rule *comObject
	if hr := (*comObject)(v.val).call(slotQueryInterface, uintptr(unsafe.Pointer(iidRule)), uintptr(unsafe.Pointer(&rule))); hr != sOK {
		return r, false, hrError("QueryInterface(INetFwRule)", hr)
	}
	defer rule.release()
	if r.Name, err = rule.getString(slotRuleGetName, "Name"); err != nil {
		return r, false, err
	}
	if len(names) > 0 && !nameIn(r.Name, names) {
		return r, false, nil
	}
	if r.ApplicationName, err = rule.getString(slotRuleGetApplicationName, "ApplicationName"); err != nil {
		return r, false, err
	}
	if r.LocalPorts, err = rule.getString(slotRuleGetLocalPorts, "LocalPorts"); err != nil {
		return r, false, err
	}
	if r.Protocol, err = rule.getInt32(slotRuleGetProtocol, "Protocol"); err != nil {
		return r, false, err
	}
	if r.Direction, err = rule.getInt32(slotRuleGetDirection, "Direction"); err != nil {
		return r, false, err
	}
	if r.Action, err = rule.getInt32(slotRuleGetAction, "Action"); err != nil {
		return r, false, err
	}
	var enabled int16 // VARIANT_BOOL: -1 true, 0 false
	if hr := rule.call(slotRuleGetEnabled, uintptr(unsafe.Pointer(&enabled))); hr != sOK {
		return r, false, hrError("INetFwRule.Enabled", hr)
	}
	r.Enabled = enabled != 0
	return r, true, nil
}

func nameIn(name string, names []string) bool {
	for _, n := range names {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	return false
}

// The GUIDs (netfw.h: CLSID_NetFwPolicy2, IID_INetFwPolicy2, IID_INetFwRule;
// oaidl.h: IID_IEnumVARIANT).
const (
	clsidNetFwPolicy2 = "{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}"
	iidINetFwPolicy2  = "{98325047-C671-4174-8D81-DEFCD3F03186}"
	iidINetFwRule     = "{AF230D27-BABA-4E42-ACED-F524F22CFCE2}"
	iidIEnumVARIANT   = "{00020404-0000-0000-C000-000000000046}"
)

// Vtable slots, in netfw.idl's declaration order. Every interface here starts
// with IUnknown's 3 methods; the dual ones (INetFwPolicy2, INetFwRules,
// INetFwRule) then have IDispatch's 4, so their own methods start at 7, each
// property's get before its put.
const (
	slotQueryInterface = 0
	slotRelease        = 2

	slotEnumNext = 3 // IEnumVARIANT::Next(celt, rgVar, pCeltFetched)

	// INetFwPolicy2: CurrentProfileTypes (get) 7, then FirewallEnabled,
	// ExcludedInterfaces, BlockAllInboundTraffic, NotificationsDisabled and
	// UnicastResponsesToMulticastBroadcastDisabled (get, put) 8-17, Rules 18.
	slotPolicyGetRules = 18

	// INetFwRules: Count 7, Add 8, Remove 9, Item 10, _NewEnum 11.
	slotRulesGetNewEnum = 11

	// INetFwRule: Name 7/8, Description 9/10, ApplicationName 11/12,
	// ServiceName 13/14, Protocol 15/16, LocalPorts 17/18, RemotePorts 19/20,
	// LocalAddresses 21/22, RemoteAddresses 23/24, IcmpTypesAndCodes 25/26,
	// Direction 27/28, Interfaces 29/30, InterfaceTypes 31/32, Enabled 33/34,
	// Grouping 35/36, Profiles 37/38, EdgeTraversal 39/40, Action 41/42.
	slotRuleGetName            = 7
	slotRuleGetApplicationName = 11
	slotRuleGetProtocol        = 15
	slotRuleGetLocalPorts      = 17
	slotRuleGetDirection       = 27
	slotRuleGetEnabled         = 33
	slotRuleGetAction          = 41
)

const (
	sOK                 = 0
	sFalse              = 1
	rpcEChangedMode     = 0x80010106
	coinitMultithreaded = 0x0
	clsctxInprocServer  = 0x1
	vtDispatch          = 9
)

var (
	modole32    = windows.NewLazySystemDLL("ole32.dll")
	modoleaut32 = windows.NewLazySystemDLL("oleaut32.dll")

	procCoInitializeEx   = modole32.NewProc("CoInitializeEx")
	procCoUninitialize   = modole32.NewProc("CoUninitialize")
	procCoCreateInstance = modole32.NewProc("CoCreateInstance")
	procSysFreeString    = modoleaut32.NewProc("SysFreeString")
	procVariantClear     = modoleaut32.NewProc("VariantClear")
)

// comObject is a COM interface pointer: the object starts with its vtable.
// The array's length is only an upper bound; just the slots above are read.
type comObject struct{ vtbl *[64]uintptr }

// call calls the method in slot with the object as its first argument and
// returns its HRESULT. Out-params are passed as uintptr(unsafe.Pointer(&x)),
// so like x/sys/windows' Proc.Call it's marked uintptrescapes: their
// variables move to the heap and stay put until the call returns (on an
// ordinary function a stack move could leave COM writing to the old frame).
//
//go:uintptrescapes
func (o *comObject) call(slot int, args ...uintptr) uint32 {
	r, _, _ := syscall.SyscallN(o.vtbl[slot], append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)...)
	return uint32(r)
}

func (o *comObject) release() { o.call(slotRelease) }

// getString reads a BSTR property and frees it ("" when it's unset).
func (o *comObject) getString(slot int, what string) (string, error) {
	var b *uint16
	if hr := o.call(slot, uintptr(unsafe.Pointer(&b))); hr != sOK {
		return "", hrError("INetFwRule."+what, hr)
	}
	if b == nil {
		return "", nil
	}
	s := windows.UTF16PtrToString(b)
	procSysFreeString.Call(uintptr(unsafe.Pointer(b)))
	return s, nil
}

// getInt32 reads a long or enum property.
func (o *comObject) getInt32(slot int, what string) (int32, error) {
	var n int32
	if hr := o.call(slot, uintptr(unsafe.Pointer(&n))); hr != sOK {
		return 0, hrError("INetFwRule."+what, hr)
	}
	return n, nil
}

// variant is a VARIANT (oaidl.h): a 2-byte type, 6 reserved bytes, then a
// union of at most two pointers (16 bytes on 32-bit Windows, 24 on 64-bit).
// Only VT_DISPATCH's pointer is read.
type variant struct {
	vt  uint16
	_   [3]uint16
	val unsafe.Pointer
	_   uintptr
}

// hresult is a LazyProc.Call's HRESULT (its low 32 bits).
func hresult(r uintptr, _ uintptr, _ error) uint32 { return uint32(r) }

func hrError(what string, hr uint32) error {
	return fmt.Errorf("fwrule: %s: HRESULT 0x%08X (%v)", what, hr, syscall.Errno(hr))
}
