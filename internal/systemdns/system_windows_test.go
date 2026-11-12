package systemdns

import (
	"context"
	"net/netip"
	"os"
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func dnsAdapter(index, metric uint32, addresses ...string) *windows.IpAdapterAddresses {
	a := &windows.IpAdapterAddresses{IfIndex: index, Ipv6IfIndex: index, Ipv4Metric: metric, Ipv6Metric: metric, OperStatus: windows.IfOperStatusUp}
	tail := &a.FirstDnsServerAddress
	for _, text := range addresses {
		ip := netip.MustParseAddr(text)
		raw := new(syscall.RawSockaddrAny)
		length := int32(unsafe.Sizeof(windows.RawSockaddrInet4{}))
		if ip.Is4() {
			v4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(raw))
			v4.Family, v4.Addr = windows.AF_INET, ip.As4()
		} else {
			v6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(raw))
			v6.Family, v6.Addr = windows.AF_INET6, ip.As16()
			length = int32(unsafe.Sizeof(windows.RawSockaddrInet6{}))
		}
		*tail = &windows.IpAdapterDnsServerAdapter{Address: windows.SocketAddress{Sockaddr: raw, SockaddrLength: length}}
		tail = &(*tail).Next
	}
	return a
}

func exitRoute(index uint32, family uint16, metric uint32) windows.MibIpForwardRow2 {
	return windows.MibIpForwardRow2{InterfaceIndex: index, DestinationPrefix: windows.IpAddressPrefix{Prefix: windows.RawSockaddrInet{Family: family}}, Metric: metric, ValidLifetime: ^uint32(0)}
}

func TestWindowsDNSUsesExitInsteadOfLowMetricTunnel(t *testing.T) {
	tunnel := dnsAdapter(37, 5, "fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3", "192.0.2.53")
	wlan := dnsAdapter(12, 35, "10.255.255.156", "10.255.255.157")
	tunnel.Next = wlan
	routes := []windows.MibIpForwardRow2{exitRoute(12, windows.AF_INET, 0), exitRoute(12, windows.AF_INET6, 256)}
	want := []Server{{Address: netip.MustParseAddrPort("10.255.255.156:53"), Default: true}, {Address: netip.MustParseAddrPort("10.255.255.157:53"), Default: true}}
	if got := adapterServers(tunnel, routes); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestWindowsExitCostsAndAddressFamilies(t *testing.T) {
	a := dnsAdapter(1, 5, "192.0.2.1", "2001:db8::1")
	b := dnsAdapter(2, 35, "192.0.2.2", "fe80::53", "fec0:0:0:ffff::1", "fe80::53")
	a.Next = b
	routes := []windows.MibIpForwardRow2{exitRoute(1, windows.AF_INET, 100), exitRoute(2, windows.AF_INET, 0), exitRoute(1, windows.AF_INET6, 0)}
	want := []Server{{Address: netip.MustParseAddrPort("[2001:db8::1]:53"), Default: true}, {Address: netip.MustParseAddrPort("192.0.2.2:53"), Default: true}}
	if got := adapterServers(a, routes); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// Equal-cost IPv6 exits retain scoped link-local DNS, deduplicating addresses
	// and excluding legacy placeholder servers even on an actual exit interface.
	b.Ipv6Metric = 5
	routes = append(routes, exitRoute(2, windows.AF_INET6, 0))
	got := adapterServers(a, routes)
	if len(got) != 3 || got[1].Address != netip.MustParseAddrPort("[fe80::53%2]:53") {
		t.Fatalf("equal-cost exit DNS: %v", got)
	}
}

func TestWindowsRejectsMissingOrInactiveDefaultRoutes(t *testing.T) {
	a := dnsAdapter(12, 35, "10.255.255.156")
	for _, mode := range []string{"missing", "expired", "specific", "loopback", "disconnected"} {
		t.Run(mode, func(t *testing.T) {
			a.OperStatus = windows.IfOperStatusUp
			routes := []windows.MibIpForwardRow2{exitRoute(12, windows.AF_INET, 0)}
			switch mode {
			case "missing":
				routes = nil
			case "expired":
				routes[0].ValidLifetime = 0
			case "specific":
				routes[0].DestinationPrefix.PrefixLength = 24
			case "loopback":
				routes[0].Loopback = 1
			case "disconnected":
				a.OperStatus = windows.IfOperStatusDown
			}
			if got := adapterServers(a, routes); len(got) != 0 {
				t.Fatalf("unexpected DNS: %v", got)
			}
		})
	}
}

func TestWindowsDiscoverLive(t *testing.T) {
	if os.Getenv("PROXY_TEST_SYSTEM_DNS") != "1" {
		t.Skip("opt-in host DNS discovery")
	}
	servers, err := Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("default-route DNS: %v", servers)
}
