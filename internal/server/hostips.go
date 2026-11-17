package server

import (
	"net"
	"net/netip"
	"slices"
	"time"
)

// hostIPs lists this machine's addresses that devices could send to: up,
// non-loopback interfaces, without link-local addresses. IPv4 comes first.
// The result is cached for 30 s.
func (b *backend) hostIPs() []string {
	b.ipMu.Lock()
	defer b.ipMu.Unlock()
	if b.ipCache != nil && time.Since(b.ipCached) < 30*time.Second {
		return slices.Clone(b.ipCache)
	}
	b.ipCache = hostAddrs()
	b.ipCached = time.Now()
	return slices.Clone(b.ipCache)
}

func hostAddrs() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return []string{}
	}
	var addrs []netip.Addr
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		as, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range as {
			pfx, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr().Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			addrs = append(addrs, ip)
		}
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int {
		if a.Is4() != b.Is4() {
			if a.Is4() {
				return -1
			}
			return 1
		}
		return a.Compare(b)
	})
	addrs = slices.Compact(addrs)
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

// HostAddrs is hostAddrs for the CLI (`woodshed setup snippet`), uncached.
func HostAddrs() []string { return hostAddrs() }
