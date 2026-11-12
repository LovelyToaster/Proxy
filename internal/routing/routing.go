package routing

import (
	"fmt"

	"net/netip"

	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/geoipdat"
)

type Table struct {
	rules []config.Rule
	db    map[string]*geoipdat.Set
}

var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
}

func Open(cfg config.Routing) (*Table, error) {
	table := &Table{rules: cfg.Rules}
	if cfg.GeoIPDB == "" {
		return table, nil
	}
	var codes []string
	for _, rule := range cfg.Rules {
		if rule.GeoIP != "" && rule.GeoIP != "private" {
			codes = append(codes, rule.GeoIP)
		}
	}
	var err error
	table.db, err = geoipdat.Load(cfg.GeoIPDB, codes)
	if err != nil {
		return nil, err
	}
	return table, nil
}
func (t *Table) Close() {}
func (t *Table) Select(target netip.AddrPort, network string) (string, error) {
	ip := target.Addr().Unmap().WithZone("")

	for _, r := range t.rules {
		if r.Network != "" && r.Network != network {
			continue
		}
		if r.CIDR.IsValid() && !r.CIDR.Contains(ip) {
			continue
		}
		if r.PortFirst != 0 && (target.Port() < r.PortFirst || target.Port() > r.PortLast) {
			continue
		}
		switch r.GeoIP {
		case "":
		case "private":
			if !private(ip) {
				continue
			}
		default:
			if set := t.db[r.GeoIP]; set == nil || !set.Match(ip) {
				continue
			}
		}
		return r.Outbound, nil
	}
	return "", fmt.Errorf("no route for %s", target)
}

func private(ip netip.Addr) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, prefix := range privatePrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
