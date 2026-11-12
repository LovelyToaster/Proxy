package config

import (
	"net/netip"
	"testing"
)

func TestLinuxGlobalCapture(t *testing.T) {
	base := Capture{Mode: "local", Scope: "global", IPv4: true, IPv6: true, Port: 15080, UDP: true, DNSHijack: true}
	if err := ValidateCapture(base); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"local", "gateway"} {
		c := base
		c.Mode = mode
		if mode == "gateway" {
			c.Interfaces = []string{"eth0"}
		}
		c.CIDRs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
		c.Ports = []uint16{22, 443}
		if err := ValidateCapture(c); err != nil {
			t.Fatal(err)
		}
	}
	for name, change := range map[string]func(*Capture){
		"lab needs namespace":     func(c *Capture) { c.Scope = "lab" },
		"bad namespace":           func(c *Capture) { c.Namespace = "host" },
		"unknown scope":           func(c *Capture) { c.Scope = "application" },
		"windows exclusions":      func(c *Capture) { c.ExcludeApplications = []string{`C:\test.exe`} },
		"gateway needs interface": func(c *Capture) { c.Mode = "gateway" },
		"disabled family":         func(c *Capture) { c.IPv6 = false; c.CIDRs = []netip.Prefix{netip.MustParsePrefix("::/0")} },
		"DNS port":                func(c *Capture) { c.Ports = []uint16{53} },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			change(&c)
			if ValidateCapture(c) == nil {
				t.Fatal("invalid capture accepted")
			}
		})
	}
}
