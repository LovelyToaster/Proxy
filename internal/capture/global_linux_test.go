package capture

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"proxy.local/m0/internal/config"
)

func TestGlobalRulesAndScope(t *testing.T) {
	c := config.Capture{Mode: "local", Scope: "global", IPv4: true, IPv6: true, Port: 15080, UDP: true}
	rules := nftRules("test", c)
	for _, required := range []string{"type route hook output", "ct direction reply return", "meta l4proto tcp tcp dport != 53", "tproxy ip to :15080", "tproxy ip6 to :15080", "meta skuid", "iifname != \"lo\" return"} {
		if !strings.Contains(rules, required) {
			t.Fatalf("missing %q:\n%s", required, rules)
		}
	}
	if strings.Contains(rules, "redirect") {
		t.Fatal("TCP still uses REDIRECT")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, target := range []string{"8.8.8.8:22", "[2001:4860:4860::8888]:65535"} {
			if !scopeAllows(c, netip.MustParseAddrPort(target), network) {
				t.Fatal("global target rejected")
			}
		}
		if scopeAllows(c, netip.MustParseAddrPort("8.8.8.8:53"), network) {
			t.Fatal("DNS captured without opt-in")
		}
	}
	c.UDP = false
	c.DNSHijack = true
	if scopeAllows(c, netip.MustParseAddrPort("8.8.8.8:443"), "udp") || !scopeAllows(c, netip.MustParseAddrPort("8.8.8.8:53"), "udp") {
		t.Fatal("UDP/DNS switches ignored")
	}
	rules = nftRules("test", c)
	if !strings.Contains(rules, "udp dport 53") {
		t.Fatal("DNS-only UDP rule missing")
	}
	c.Mode = "gateway"
	c.Interfaces = []string{"eth0"}
	rules = nftRules("test", c)
	if !strings.Contains(rules, `iifname "eth0"`) || strings.Contains(rules, "hook output") {
		t.Fatal("gateway scope incorrect")
	}
}

func TestNamespaceOptIn(t *testing.T) {
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkNamespace(current, true); err != nil {
		t.Fatal(err)
	}
	if err := checkNamespace("", true); err != nil {
		t.Fatal(err)
	}
	if checkNamespace("net:[0]", true) == nil {
		t.Fatal("namespace mismatch accepted")
	}
	if checkNamespace("") == nil {
		t.Fatal("lab missing namespace accepted")
	}
}

func TestLimitedTCPUsesTProxy(t *testing.T) {
	c := config.Capture{Mode: "local", IPv4: true, Port: 15080, CIDRs: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/16")}, Ports: []uint16{443}}
	rules := nftRules("test", c)
	if strings.Contains(rules, "redirect") || !strings.Contains(rules, "tcp dport 443 tproxy ip") {
		t.Fatal(rules)
	}
	if scopeAllows(c, netip.MustParseAddrPort("198.18.0.1:80"), "tcp") || scopeAllows(c, netip.MustParseAddrPort("8.8.8.8:443"), "tcp") {
		t.Fatal("limited scope expanded")
	}
}
