package systemdns

import (
	"net/netip"
	"strings"
)

type Server struct {
	Address netip.AddrPort
	Domains []string
	Default bool
}

func Select(servers []Server, name string) []netip.AddrPort {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	best := -1
	var selected []netip.AddrPort
	for _, server := range servers {
		rank := -1
		if server.Default {
			rank = 0
		}
		for _, domain := range server.Domains {
			suffix := strings.TrimSuffix(strings.ToLower(domain), ".")
			if suffix == "" || name == suffix || strings.HasSuffix(name, "."+suffix) {
				rank = max(rank, 1+len(suffix))
			}
		}
		if rank < 0 || rank < best {
			continue
		}
		if rank > best {
			best, selected = rank, selected[:0]
		}
		duplicate := false
		for _, address := range selected {
			if address == server.Address {
				duplicate = true
				break
			}
		}
		if !duplicate {
			selected = append(selected, server.Address)
		}
	}
	return selected
}
