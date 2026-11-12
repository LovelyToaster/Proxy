package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"proxy.local/m0/internal/config"
)

func TestSocketGroupParsing(t *testing.T) {
	endpoint := netip.MustParseAddrPort("127.0.0.1:7891")
	output := "LISTEN 0 4096 0.0.0.0:7891 0.0.0.0:* cgroup:/system.slice/mihomo.service\n" +
		"LISTEN 0 4096 10.0.0.1:7891 0.0.0.0:* cgroup:/system.slice/other.service\n"
	got, err := parseSocketGroups(output, endpoint)
	if err != nil || !reflect.DeepEqual(got, []string{"/system.slice/mihomo.service"}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, line := range []string{"LISTEN 0 4096 *:7891 *:* cgroup:/system.slice/mihomo.service", "LISTEN 0 4096 [::]:7891 [::]:* cgroup:/system.slice/mihomo.service"} {
		got, err := parseSocketGroups(line, endpoint)
		if err != nil || len(got) != 1 {
			t.Fatalf("%v %v", got, err)
		}
	}
	if _, err := parseSocketGroups("LISTEN 0 4096 *:7891 *:*", endpoint); err == nil {
		t.Fatal("unknown identity accepted")
	}
}

func TestUpstreamGroupSafety(t *testing.T) {
	self := "/system.slice/proxyd.service"
	for _, path := range []string{"/", "/system.slice", "/user.slice/session-1.scope", self, "/system.slice/../mihomo.service", "/system.slice/a\nb.service"} {
		if validateUpstreamGroup(path, self) == nil {
			t.Fatalf("unsafe cgroup accepted: %q", path)
		}
	}
	for _, path := range []string{"/system.slice/mihomo.service", "/system.slice/docker-abcdef.scope"} {
		if err := validateUpstreamGroup(path, self); err != nil {
			t.Fatal(err)
		}
	}
	c := config.Capture{Mode: "local", Scope: "global", IPv4: true, Port: 15080}
	rules := nftRules("test", c, []upstreamGroup{{Path: "/system.slice/mihomo.service", Inode: 123}})
	if !strings.Contains(rules, `socket cgroupv2 level 2 "system.slice/mihomo.service" counter accept`) || strings.Index(rules, "jump local_upstreams") > strings.Index(rules, "ct direction reply") {
		t.Fatal(rules)
	}
	if strings.Contains(rules, "skuid 0 return") && os.Geteuid() != 0 {
		t.Fatal("root UID accidentally exempted")
	}
}

func TestLocalUpstreamEndpoints(t *testing.T) {
	c := config.Capture{Mode: "local", Scope: "global"}
	got, err := localUpstreamEndpoints(c, nil, map[string]config.Outbound{"local": {Type: "socks5", Address: "127.0.0.1:7891"}, "remote": {Type: "http", Address: "203.0.113.1:8080"}, "direct": {Type: "direct"}})
	if err != nil || !reflect.DeepEqual(got, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:7891")}) {
		t.Fatalf("%v %v", got, err)
	}
	c.Mode = "gateway"
	got, err = localUpstreamEndpoints(c, nil, map[string]config.Outbound{"bad": {Type: "http", Address: "bad"}})
	if err != nil || len(got) != 0 {
		t.Fatal("gateway local traffic must remain untouched")
	}
}

func TestUpstreamReloadRequiresRestart(t *testing.T) {
	c := config.Capture{Mode: "local", Scope: "global"}
	before := map[string]config.Outbound{"upstream": {Type: "socks5", Address: "127.0.0.1:7891"}}
	after := map[string]config.Outbound{"upstream": {Type: "socks5", Address: "127.0.0.1:7892"}}
	if ValidateUpstreamReload(c, before, after) == nil {
		t.Fatal("new local upstream accepted without capture refresh")
	}
	after["upstream"] = config.Outbound{Type: "socks5", Address: "127.0.0.1:7891", Password: "changed"}
	if err := ValidateUpstreamReload(c, before, after); err != nil {
		t.Fatal(err)
	}
}

func TestLiveUpstreamDiscovery(t *testing.T) {
	address := os.Getenv("PROXY_TEST_LOCAL_UPSTREAM")
	if address == "" {
		t.Skip("read-only live discovery probe")
	}
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := discoverUpstreamGroups([]netip.AddrPort{endpoint})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatal(groups)
	}
	t.Logf("upstream %s bypass identity: %s inode=%d", endpoint, groups[0].Path, groups[0].Inode)
}

// Real unmarked SOCKS5 outbound fixture, run in a dedicated test service cgroup.
func TestLocalUpstreamFixture(t *testing.T) {
	address := os.Getenv("PROXY_UPSTREAM_FIXTURE")
	if address == "" {
		t.Skip("integration fixture only")
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fmt.Println("upstream fixture ready")
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			var head [4]byte
			if _, err := io.ReadFull(conn, head[:2]); err != nil || head[0] != 5 {
				return
			}
			methods := make([]byte, int(head[1]))
			if _, err := io.ReadFull(conn, methods); err != nil {
				return
			}
			if _, err := conn.Write([]byte{5, 0}); err != nil {
				return
			}
			if _, err := io.ReadFull(conn, head[:]); err != nil || head[0] != 5 || head[1] != 1 {
				return
			}
			n := 4
			if head[3] == 4 {
				n = 16
			} else if head[3] != 1 {
				return
			}
			data := make([]byte, n+2)
			if _, err := io.ReadFull(conn, data); err != nil {
				return
			}
			ip, ok := netip.AddrFromSlice(data[:n])
			if !ok {
				return
			}
			target := netip.AddrPortFrom(ip, binary.BigEndian.Uint16(data[n:]))
			upstream, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(context.Background(), "tcp", target.String())
			if err != nil {
				return
			}
			defer upstream.Close()
			if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
				return
			}
			done := make(chan struct{})
			go func() {
				io.Copy(upstream, conn)
				if tcp, ok := upstream.(*net.TCPConn); ok {
					tcp.CloseWrite()
				}
				close(done)
			}()
			io.Copy(conn, upstream)
			<-done
		}()
	}
}
