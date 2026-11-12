package systemdns

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

func Discover(ctx context.Context) ([]Server, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	servers, stub, err := parseResolvConf(f)
	if err != nil {
		return nil, err
	}
	current, _ := os.Readlink("/proc/self/ns/net")
	init, _ := os.Readlink("/proc/1/ns/net")
	path, _ := filepath.EvalSymlinks("/etc/resolv.conf")
	if current != "" && current == init && (stub || strings.HasPrefix(path, "/run/systemd/resolve/")) {
		resolved, err := discoverResolved(ctx)
		if err == nil && len(resolved) > 0 {
			return resolved, nil
		}
		if stub {
			return nil, errors.New("systemd-resolved upstreams are unavailable")
		}
	}
	return servers, nil
}

func parseResolvConf(reader io.Reader) (servers []Server, stub bool, err error) {
	scanner := bufio.NewScanner(io.LimitReader(reader, 1<<16))
	for scanner.Scan() {
		text, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(text)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		address, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		address = address.Unmap()
		if address == netip.MustParseAddr("127.0.0.53") || address == netip.MustParseAddr("127.0.0.54") {
			stub = true
		}
		if address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() ||
			address.Is6() && address.IsLinkLocalUnicast() && address.Zone() == "" {
			continue
		}
		servers = append(servers, Server{Address: netip.AddrPortFrom(address, 53), Default: true})
	}
	return servers, stub, scanner.Err()
}

func discoverResolved(ctx context.Context) ([]Server, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	object := conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
	get := func(name string, target any) error {
		var value dbus.Variant
		if err := object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.resolve1.Manager", name).Store(&value); err != nil {
			return err
		}
		return dbus.Store([]any{value.Value()}, target)
	}
	var addresses []struct {
		Index, Family int32
		Address       []byte
		Port          uint16
		Name          string
	}
	if err := get("DNSEx", &addresses); err != nil {
		var plain []struct {
			Index, Family int32
			Address       []byte
		}
		if err := get("DNS", &plain); err != nil {
			return nil, err
		}
		for _, item := range plain {
			addresses = append(addresses, struct {
				Index, Family int32
				Address       []byte
				Port          uint16
				Name          string
			}{item.Index, item.Family, item.Address, 53, ""})
		}
	}
	var domains []struct {
		Index     int32
		Domain    string
		RouteOnly bool
	}
	if err := get("Domains", &domains); err != nil {
		return nil, err
	}
	routes := make(map[int32][]string)
	defaultRoutes := make(map[int32]bool)
	for _, item := range domains {
		routes[item.Index] = append(routes[item.Index], item.Domain)
		if item.RouteOnly && item.Domain != "." {
			defaultRoutes[item.Index] = false
		}
	}
	// Prefer the explicit DefaultRoute property when available.
	checked := make(map[int32]bool)
	var result []Server
	for _, item := range addresses {
		if item.Index > 0 && !checked[item.Index] {
			checked[item.Index] = true
			var path dbus.ObjectPath
			if err := object.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.GetLink", 0, item.Index).Store(&path); err == nil {
				var value dbus.Variant
				if err := conn.Object("org.freedesktop.resolve1", path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.resolve1.Link", "DefaultRoute").Store(&value); err == nil {
					if v, ok := value.Value().(bool); ok {
						defaultRoutes[item.Index] = v
					}
				}
			}
		}
		addr, ok := netip.AddrFromSlice(item.Address)
		if !ok || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() {
			continue
		}
		addr = addr.Unmap()
		if addr.Is6() && addr.IsLinkLocalUnicast() {
			if item.Index <= 0 {
				continue
			}
			zone := strconv.Itoa(int(item.Index))
			if iface, err := net.InterfaceByIndex(int(item.Index)); err == nil {
				zone = iface.Name
			}
			addr = addr.WithZone(zone)
		}
		port := item.Port
		if port == 0 {
			port = 53
		}
		isDefault, known := defaultRoutes[item.Index]
		result = append(result, Server{netip.AddrPortFrom(addr, port), routes[item.Index], !known || isDefault})
	}
	return result, nil
}
