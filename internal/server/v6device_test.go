package server

import (
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
)

// A sender whose device id starts with "_" (::1 is "__1", ::a.b.c.d too) is a
// device like any other: it's listed and its records are found. The index
// and the store used to skip every id starting with "_" as if it were the
// synthetic "_refused" stats id.
func TestIPv6LoopbackSenderIsADevice(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := writeConfig(t, dir, port, 0, func(c *config.Config) { c.Listeners.UDP.Addr, c.Listeners.TCP.Addr = "::1", "::1" })
	r := start(t, cfg)
	conn, err := net.Dial("udp", fmt.Sprintf("[::1]:%d", port))
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "<14>Nov 16 10:00:00 h app: v6-loopback-token")
	var page struct {
		Results []struct {
			DeviceID string `json:"device_id"`
		} `json:"results"`
	}
	waitFor(t, "the message in search", func() bool {
		r.srv.store.Flush()
		page.Results = nil
		r.do(t, "GET", "/api/search?"+url.Values{"q": {"v6-loopback-token"}}.Encode(), nil, &page)
		return len(page.Results) == 1
	})
	if page.Results[0].DeviceID != "__1" {
		t.Errorf("device id %q", page.Results[0].DeviceID)
	}
	var devs api.DevicePage
	waitFor(t, "the device listed", func() bool {
		r.do(t, "GET", "/api/devices", nil, &devs)
		return len(devs.Devices) == 1
	})
	if devs.Devices[0].ID != "__1" || devs.Devices[0].IP != "::1" {
		t.Errorf("device %+v", devs.Devices[0])
	}
}
