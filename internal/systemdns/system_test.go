package systemdns

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestLongestRoutingDomain(t *testing.T) {
	global := netip.MustParseAddrPort("192.0.2.1:53")
	vpn := netip.MustParseAddrPort("192.0.2.2:53")
	specific := netip.MustParseAddrPort("[fe80::1%lab]:53")
	servers := []Server{
		{Address: global, Default: true},
		{Address: vpn, Domains: []string{"corp.test"}},
		{Address: specific, Domains: []string{"team.corp.test"}},
	}
	for name, want := range map[string]netip.AddrPort{
		"host.team.CORP.test.": specific, "corp.test": vpn, "notcorp.test": global,
	} {
		if got := Select(servers, name); !reflect.DeepEqual(got, []netip.AddrPort{want}) {
			t.Errorf("%s got %v, want %s", name, got, want)
		}
	}
}
