package routing

import (
	"net/netip"
	"os"
	"testing"

	"proxy.local/m0/internal/config"
)

func TestFirstMatch(t *testing.T) {
	table := &Table{rules: []config.Rule{
		{CIDR: netip.MustParsePrefix("10.0.0.0/8"), PortFirst: 443, PortLast: 443, Outbound: "cidr"},
		{GeoIP: "private", Outbound: "private"},
		{Outbound: "fallback"},
	}}
	for address, want := range map[string]string{
		"[::ffff:10.0.0.1]:443": "cidr",
		"10.0.0.1:80":           "private",
		"[fd00::1]:443":         "private",
		"198.51.100.1:80":       "fallback",
	} {
		got, err := table.Select(netip.MustParseAddrPort(address), "tcp")
		if err != nil || got != want {
			t.Errorf("select %s = %q, %v; want %q", address, got, err, want)
		}
	}
}

func TestCountryDAT(t *testing.T) {
	database := os.Getenv("PROXY_TEST_GEOIP_DAT")
	if database == "" {
		t.Skip("set PROXY_TEST_GEOIP_DAT to a v2ray GeoIP DAT file")
	}
	table, err := Open(config.Routing{GeoIPDB: database, Rules: []config.Rule{
		{GeoIP: "CN", Outbound: "country"},
		{Outbound: "fallback"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer table.Close()
	for address, want := range map[string]string{
		"223.5.5.5:443":    "country",
		"198.51.100.1:443": "fallback",
	} {
		got, err := table.Select(netip.MustParseAddrPort(address), "tcp")
		if err != nil || got != want {
			t.Errorf("select %s = %q, %v; want %q", address, got, err, want)
		}
	}
}
