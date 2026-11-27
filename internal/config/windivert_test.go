package config

import (
	"net/netip"
	"testing"
)

func TestWinDivertLabScope(t *testing.T) {
	base := Capture{
		Mode: "windivert", IPv4: true, IPv6: true, Port: 15090, Ports: []uint16{19090},
		WindowsApplication: `C:\ProxyLab\probe.exe`,
		CIDRs:              []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")},
	}
	if err := ValidateCapture(base); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Capture){
		"missing app":    func(c *Capture) { c.WindowsApplication = "" },
		"relative app":   func(c *Capture) { c.WindowsApplication = "probe.exe" },
		"external IP":    func(c *Capture) { c.CIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), c.CIDRs[1]} },
		"subnet":         func(c *Capture) { c.CIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/24"), c.CIDRs[1]} },
		"more ports":     func(c *Capture) { c.Ports = []uint16{19090, 19091} },
		"reserved port":  func(c *Capture) { c.Ports = []uint16{53} },
		"missing family": func(c *Capture) { c.CIDRs = c.CIDRs[:1] },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := ValidateCapture(candidate); err == nil {
				t.Fatal("unsafe WinDivert lab scope accepted")
			}
		})
	}
	base.UDP, base.DNSHijack = true, true
	if err := ValidateCapture(base); err != nil {
		t.Fatal(err)
	}
	base.UDP, base.Ports = false, nil
	if err := ValidateCapture(base); err != nil {
		t.Fatal(err)
	}
	rejected := base
	rejected.Mode = "wfp"
	if ValidateCapture(rejected) == nil {
		t.Fatal("removed wfp mode accepted")
	}
}

func TestWinDivertGlobalScope(t *testing.T) {
	c := Capture{Mode: "windivert", Scope: "global", IPv4: true, IPv6: true, Port: 15090, UDP: true, DNSHijack: true}
	if err := ValidateCapture(c); err != nil {
		t.Fatal(err)
	}
	c.WindowsApplication = `C:\ProxyLab\probe.exe`
	if ValidateCapture(c) == nil {
		t.Fatal("global scope accepted an application selector")
	}
	c.WindowsApplication = ""
	c.ExcludeApplications = []string{"relative.exe"}
	if ValidateCapture(c) == nil {
		t.Fatal("relative exclusion accepted")
	}
	c.ExcludeApplications = []string{`C:\ProxyLab\excluded.exe`}
	if err := ValidateCapture(c); err != nil {
		t.Fatal(err)
	}
}
