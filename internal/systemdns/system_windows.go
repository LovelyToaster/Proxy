package systemdns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

func Discover(ctx context.Context) ([]Server, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var routes *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &routes); err != nil {
		return nil, fmt.Errorf("discover Windows DNS exit routes: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(routes))
	size := uint32(15 << 10)
	var buffer []byte
	for range 3 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if size == 0 || size > 4<<20 {
			return nil, errors.New("invalid Windows adapter buffer size")
		}
		buffer = make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_UNICAST|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		servers := adapterServers(first, routes.Rows())
		if len(servers) == 0 {
			return nil, errors.New("no usable DNS servers on Windows default-route interfaces")
		}
		return servers, nil
	}
	return nil, errors.New("Windows adapter list changed during DNS discovery")
}

type exitInterface struct {
	index  uint32
	family uint16
}

// Interface metrics alone do not identify an exit: a tunnel may have a low
// metric without providing any Internet route. Compare complete default-route
// costs separately for each address family, retaining equal-cost exits.
func defaultExits(first *windows.IpAdapterAddresses, routes []windows.MibIpForwardRow2) map[exitInterface]uint64 {
	metrics := make(map[exitInterface]uint32)
	for iface := first; iface != nil; iface = iface.Next {
		if iface.OperStatus != windows.IfOperStatusUp || iface.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		metrics[exitInterface{iface.IfIndex, windows.AF_INET}] = iface.Ipv4Metric
		metrics[exitInterface{iface.Ipv6IfIndex, windows.AF_INET6}] = iface.Ipv6Metric
	}
	costs := make(map[exitInterface]uint64)
	best := make(map[uint16]uint64)
	for _, route := range routes {
		family := route.DestinationPrefix.Prefix.Family
		if family != windows.AF_INET && family != windows.AF_INET6 || route.DestinationPrefix.PrefixLength != 0 || route.Loopback != 0 || route.ValidLifetime == 0 {
			continue
		}
		key := exitInterface{route.InterfaceIndex, family}
		metric, ok := metrics[key]
		if !ok || key.index == 0 {
			continue
		}
		cost := uint64(route.Metric) + uint64(metric)
		if old, ok := costs[key]; !ok || cost < old {
			costs[key] = cost
		}
		if old, ok := best[family]; !ok || cost < old {
			best[family] = cost
		}
	}
	for key, cost := range costs {
		if cost != best[key.family] {
			delete(costs, key)
		}
	}
	return costs
}

func adapterServers(first *windows.IpAdapterAddresses, routes []windows.MibIpForwardRow2) []Server {
	type candidate struct {
		Server
		metric uint64
	}
	exits := defaultExits(first, routes)
	var list []candidate
	for iface := first; iface != nil; iface = iface.Next {
		if iface.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for server := iface.FirstDnsServerAddress; server != nil; server = server.Next {
			if server.Address.Sockaddr == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(server.Address.IP())
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || legacyDNSPlaceholder(addr) {
				continue
			}
			key := exitInterface{iface.IfIndex, windows.AF_INET}
			if addr.Is6() {
				key = exitInterface{iface.Ipv6IfIndex, windows.AF_INET6}
				if addr.IsLinkLocalUnicast() {
					scope := (*windows.RawSockaddrInet6)(unsafe.Pointer(server.Address.Sockaddr)).Scope_id
					if scope == 0 {
						scope = iface.Ipv6IfIndex
					}
					if scope == 0 {
						continue
					}
					addr = addr.WithZone(strconv.FormatUint(uint64(scope), 10))
				}
			}
			metric, ok := exits[key]
			if !ok {
				continue
			}
			list = append(list, candidate{Server{Address: netip.AddrPortFrom(addr, 53), Default: true}, metric})
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].metric < list[j].metric })
	var result []Server
	seen := make(map[netip.AddrPort]bool)
	for _, item := range list {
		if seen[item.Address] {
			continue
		}
		seen[item.Address] = true
		result = append(result, item.Server)
	}
	return result
}

func legacyDNSPlaceholder(addr netip.Addr) bool {
	return addr == netip.MustParseAddr("fec0:0:0:ffff::1") ||
		addr == netip.MustParseAddr("fec0:0:0:ffff::2") ||
		addr == netip.MustParseAddr("fec0:0:0:ffff::3")
}
