package windivert

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/sys/windows"
	"proxy.local/m0/internal/config"

	"proxy.local/m0/internal/systemdns"
)

type upstreamEndpoint struct {
	Address  netip.AddrPort `json:"address"`
	Protocol byte           `json:"protocol"`
}

// Bind bypass to the current listener owner, so a shared executable such as svchost.exe
// does not exempt unrelated services and a restarted upstream is recognized.
func upstreamExclusions(outbounds map[string]config.Outbound, infrastructureResolver *net.Resolver) ([]upstreamEndpoint, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	local := make(map[netip.Addr]bool)
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err == nil {
			local[prefix.Addr().Unmap()] = true
		}
	}
	var endpoints []upstreamEndpoint
	appendOwner := func(endpoint upstreamEndpoint) error {
		pid := endpointPID(packet{source: endpoint.Address, protocol: endpoint.Protocol})
		if pid == windows.GetCurrentProcessId() {
			return fmt.Errorf("upstream points to this proxy process")
		}
		if pid == 0 {
			return fmt.Errorf("local upstream must be running and its listener owner must be identifiable")
		}
		for _, existing := range endpoints {
			if existing == endpoint {
				return nil
			}
		}
		endpoints = append(endpoints, endpoint)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for name, proxy := range outbounds {
		dialer := net.Dialer{Resolver: infrastructureResolver}
		resolver := dialer.Resolver
		if proxy.Type == "direct" {
			continue
		}
		host, portText, err := net.SplitHostPort(proxy.Address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return nil, err
		}
		var addresses []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			addresses = []netip.Addr{ip}
		} else {
			addresses, err = resolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("resolve upstream %s: %w", name, err)
			}
		}
		foundLocal, excluded := false, false
		for _, ip := range addresses {
			ip = ip.Unmap().WithZone("")
			if !ip.IsLoopback() && !local[ip] {
				continue
			}
			foundLocal = true
			pid := endpointPID(packet{protocol: 6, source: netip.AddrPortFrom(ip, uint16(port))})
			if pid == 0 {
				continue
			}
			if err := appendOwner(upstreamEndpoint{netip.AddrPortFrom(ip, uint16(port)), 6}); err != nil {
				return nil, fmt.Errorf("outbound %s: %w", name, err)
			}
			excluded = true
			break
		}
		if foundLocal && !excluded {
			return nil, fmt.Errorf("outbound %s: local upstream is not listening", name)
		}
	}
	servers, err := systemdns.Discover(ctx)
	if err == nil {
		for _, server := range servers {
			ip := server.Address.Addr().Unmap().WithZone("")
			if ip.IsLoopback() || local[ip] {
				pid := endpointPID(packet{protocol: 17, source: netip.AddrPortFrom(ip, server.Address.Port())})
				if pid != windows.GetCurrentProcessId() {
					if err := appendOwner(upstreamEndpoint{netip.AddrPortFrom(ip, server.Address.Port()), 17}); err != nil {
						return nil, fmt.Errorf("local system DNS relay: %w", err)
					}
				}
			}
		}
	}
	return endpoints, nil
}
