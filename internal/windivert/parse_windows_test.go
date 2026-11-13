package windivert

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"proxy.local/m0/internal/config"
)

func TestOfficialParserIPv6Headers(t *testing.T) {
	path, err := filepath.Abs("../../dist/windows-amd64/WinDivert.dll")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skip("WinDivert runtime not staged")
	}
	dll, err := windows.LoadDLL(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dll.Release()
	proc, err := dll.FindProc("WinDivertHelperParsePacket")
	if err != nil {
		t.Fatal(err)
	}
	lib := &library{parse: proc}
	original := udpFixturePacket(true)
	data := append([]byte(nil), original[:40]...)
	data[6] = 0
	data = append(data, []byte{60, 0, 0, 0, 0, 0, 0, 0}...)
	data = append(data, []byte{17, 0, 0, 0, 0, 0, 0, 0}...)
	data = append(data, original[40:]...)
	binary.BigEndian.PutUint16(data[4:], uint16(len(data)-40))
	p, err := lib.parseTransportPacket(data)
	if err != nil || p.offset != 56 || p.payload != 64 {
		t.Fatalf("native header offsets: %+v %v", p, err)
	}
	data[48] = 253
	var unknown unsupportedHeader
	if _, err := lib.parseTransportPacket(data); !errors.As(err, &unknown) {
		t.Fatalf("native parser did not report unknown header: %v", err)
	}
}

func TestGlobalBypassesOwnDNSAndFindsLocalUpstream(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	p := packet{protocol: 17, source: udp.LocalAddr().(*net.UDPAddr).AddrPort(), target: netip.MustParseAddrPort("198.51.100.1:53")}
	if pid := endpointPID(p); pid != windows.GetCurrentProcessId() {
		t.Fatalf("UDP owner PID=%d", pid)
	}
	g := Capture{}
	g.config.Scope = "global"
	g.config.DNSHijack = true
	if g.selected(p) {
		t.Fatal("proxy's own DNS was recaptured")
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	p = packet{protocol: 6, source: listener.Addr().(*net.TCPAddr).AddrPort()}
	if pid := endpointPID(p); pid != windows.GetCurrentProcessId() {
		t.Fatalf("local upstream PID=%d endpoint=%s validTarget=%v", pid, p.source, p.target.IsValid())
	}
}

func TestEstablishedTCPUsesRecordedDecision(t *testing.T) {
	source := netip.MustParseAddrPort("192.0.2.1:40000")
	target := netip.MustParseAddrPort("198.51.100.1:443")
	key := flowKey{source, target}
	alias := netip.MustParseAddrPort("198.51.100.1:41000")
	g := Capture{tcp: map[flowKey]*tcpFlow{key: {key: key, alias: alias}}, reverse: make(map[netip.AddrPort]*tcpFlow)}
	g.config.Scope, g.config.Port = "global", 15090
	data := make([]byte, 40)
	data[0], data[9], data[32], data[33] = 0x45, 6, 0x50, 0x10
	binary.BigEndian.PutUint16(data[2:], uint16(len(data)))
	p := packet{data: data, source: source, target: target, protocol: 6, offset: 20, payload: 40}
	address := [10]uint64{}
	modified, consumed := g.redirectTCP(p, &address)
	if !modified || consumed {
		t.Fatal("recorded TCP decision was lost; fixture has no OS endpoint and must not query ownership")
	}
	decoded, err := parsePacket(data)
	if err != nil || decoded.source != alias || decoded.target != netip.MustParseAddrPort("192.0.2.1:15090") {
		t.Fatalf("wrong fast-path rewrite: %+v %v", decoded, err)
	}
}

func TestUnknownPIDGlobalDNSCapture(t *testing.T) {
	g := Capture{}
	g.config.Scope = "global"
	g.config.DNSHijack = true
	p := packet{protocol: 17, source: netip.MustParseAddrPort("192.0.2.1:40000"), target: netip.MustParseAddrPort("198.51.100.1:53")}
	if !g.selectedPID(p, 0) {
		t.Fatal("unknown UDP53 ownership bypassed DNS capture")
	}
	p.target = netip.MustParseAddrPort("198.51.100.1:443")
	if g.selectedPID(p, 0) {
		t.Fatal("ordinary UDP unknown ownership changed")
	}
	p.target = netip.MustParseAddrPort("198.51.100.1:53")
	p.protocol = 6
	if g.selectedPID(p, 0) {
		t.Fatal("TCP unknown ownership changed")
	}
	p.protocol = 17
	if g.selectedPID(p, windows.GetCurrentProcessId()) {
		t.Fatal("unregistered own traffic recaptured")
	}
}

func TestSplitCaptureFiltersCompileWithOfficialDLL(t *testing.T) {
	path, err := filepath.Abs("../../dist/windows-amd64/WinDivert.dll")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skip("WinDivert runtime not staged")
	}
	dll, err := windows.LoadDLL(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dll.Release()
	compile, err := dll.FindProc("WinDivertHelperCompileFilter")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		cfg  config.Capture
	}{
		{name: "global-no-dns", cfg: config.Capture{Mode: "windivert", Scope: "global", Port: 15090, IPv4: true, IPv6: true, UDP: true}},
		{name: "global-dns", cfg: config.Capture{Mode: "windivert", Scope: "global", Port: 15090, IPv4: true, IPv6: true, UDP: true, DNSHijack: true}},
		{name: "application", cfg: config.Capture{Mode: "windivert", Scope: "application", Port: 15090, IPv4: true, IPv6: true, UDP: true}},
		{name: "cidrs", cfg: config.Capture{Mode: "windivert", Scope: "global", Port: 15090, IPv4: true, IPv6: true, CIDRs: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/16")}}},
	}
	for _, tc := range cases {
		req, rep := splitCaptureFilters(tc.cfg)
		for _, expr := range []string{req, rep} {
			raw, err := windows.BytePtrFromString(expr)
			if err != nil {
				t.Fatal(err)
			}
			var errStr *byte
			var errPos uint32
			ok, _, callErr := compile.Call(uintptr(unsafe.Pointer(raw)), layerNetwork, 0, 0, uintptr(unsafe.Pointer(&errStr)), uintptr(unsafe.Pointer(&errPos)))
			runtime.KeepAlive(raw)
			if ok == 0 {
				errMsg := ""
				if errStr != nil {
					errMsg = windows.BytePtrToString(errStr)
				}
				t.Fatalf("%s filter compile failed at token %d (%s / %v): %s", tc.name, errPos, errMsg, callErr, expr)
			}
		}
	}
}
