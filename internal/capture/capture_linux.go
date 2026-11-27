package capture

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"

	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/linuxsocket"
	"proxy.local/m0/internal/logging"
)

const (
	bypassMark   = 0x20000000
	captureMark  = "0x40000000"
	mask         = "0x60000000"
	rulePriority = "11000"
	routeTable   = "100"
)

func checkNamespace(expected string, host ...bool) error {
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	allowHost := len(host) > 0 && host[0]
	if allowHost {
		if expected != "" && current != expected {
			return errors.New("capture network namespace does not match configuration")
		}
		return nil
	}
	parent, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		return err
	}
	if expected != current || current == parent {
		return errors.New("capture requires the configured isolated network namespace, distinct from PID 1")
	}
	return nil
}

func Listen(c config.Capture) ([]Listener, error) {
	if c.Mode == "windivert" {
		return nil, errors.New("WinDivert capture requires Windows")
	}
	if c.Mode == "off" {
		return nil, nil
	}
	if err := checkNamespace(c.Namespace, c.Scope == "global"); err != nil {
		return nil, err
	}
	if c.Scope == "global" && c.Mode == "local" && os.Geteuid() == 0 {
		return nil, errors.New("global local capture requires a dedicated non-root service UID with CAP_NET_ADMIN")
	}
	if _, err := ownedTools(); err != nil {
		return nil, err
	}

	var result []Listener
	for _, family := range []struct {
		enabled bool
		network string
		addr    netip.Addr
	}{
		{c.IPv4, "tcp4", netip.IPv4Unspecified()}, {c.IPv6, "tcp6", netip.IPv6Unspecified()},
	} {
		if !family.enabled {
			continue
		}
		lc := net.ListenConfig{Control: linuxsocket.TransparentControl(false, bypassMark)}
		listener, err := lc.Listen(context.Background(), family.network, netip.AddrPortFrom(family.addr, c.Port).String())
		if err != nil {
			for _, previous := range result {
				previous.Close()
			}
			return nil, err
		}
		result = append(result, Listener{Listener: listener, Transparent: true, Destination: func(conn *net.TCPConn) (netip.AddrPort, error) {
			target := conn.LocalAddr().(*net.TCPAddr).AddrPort()
			if !scopeAllows(c, target, "tcp") {
				return netip.AddrPort{}, errors.New("TCP connection is outside capture scope")
			}
			return target, nil
		}})
	}
	return result, nil
}

func scopeAllows(c config.Capture, target netip.AddrPort, network string) bool {
	if target.Port() == 53 {
		if !c.DNSHijack {
			return false
		}
	} else if network == "udp" && !c.UDP || !(c.Scope == "global" && len(c.Ports) == 0) && !slices.Contains(c.Ports, target.Port()) {
		return false
	}
	address := target.Addr().Unmap().WithZone("")
	if c.Scope == "global" && len(c.CIDRs) == 0 {
		if address.IsUnspecified() || address.IsMulticast() || address == netip.MustParseAddr("255.255.255.255") {
			return false
		}
		if target.Port() != 53 && (address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast()) {
			return false
		}
		return address.Is4() && c.IPv4 || address.Is6() && c.IPv6
	}
	for _, prefix := range c.CIDRs {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func Dialer(c config.Capture) net.Dialer {
	if c.Mode == "" || c.Mode == "off" {
		return net.Dialer{}
	}
	return linuxsocket.MarkedDialer(bypassMark)
}

type Guard struct {
	input io.WriteCloser
	done  chan struct{}
	stop  chan struct{}
	err   error
}

func Start(c config.Capture, directory string, upstreams ...map[string]config.Outbound) (*Guard, error) {
	return startLinux(c, directory, nil, upstreams...)
}

func startLinux(c config.Capture, directory string, resolver *net.Resolver, upstreams ...map[string]config.Outbound) (*Guard, error) {
	if c.Mode == "off" {
		return nil, nil
	}
	var endpoints []netip.AddrPort
	if len(upstreams) > 0 {
		var err error
		endpoints, err = localUpstreamEndpoints(c, resolver, upstreams[0])
		if err != nil {
			return nil, err
		}
	}
	if err := checkNamespace(c.Namespace, c.Scope == "global"); err != nil {
		return nil, err
	}
	// Persist the exact namespace even when global configuration omits it.
	if c.Namespace == "" {
		var err error
		c.Namespace, err = os.Readlink("/proc/self/ns/net")
		if err != nil {
			return nil, err
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	command := exec.Command(executable, "--capture-guard", directory)
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	command.Stderr = logging.Default.StdBridgeWriter(slog.LevelInfo)
	in, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := command.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	if err := command.Start(); err != nil {
		in.Close()
		out.Close()
		return nil, err
	}

	ready := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(out)
		line, err := reader.ReadString('\n')
		if err == nil && line != "ready\n" {
			err = fmt.Errorf("invalid capture guard response")
		}
		ready <- err
	}()
	g := &Guard{input: in, done: make(chan struct{}), stop: make(chan struct{})}
	if err := json.NewEncoder(in).Encode(linuxGuardInput{c, endpoints}); err != nil {
		in.Close()
		command.Wait()
		return nil, err
	}
	select {
	case err = <-ready:
	case <-time.After(30 * time.Second):
		err = errors.New("capture guard startup timed out")
	}
	if err != nil {
		in.Close()
		command.Wait()
		return nil, fmt.Errorf("capture guard: %w", err)
	}
	go func() {
		g.err = command.Wait()
		close(g.done)
	}()
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-g.done:
				return
			case <-g.stop:
				return
			case <-ticker.C:
				if _, err := in.Write([]byte{1}); err != nil {
					return
				}
			}
		}
	}()
	return g, nil
}

func (g *Guard) Done() <-chan struct{} { return g.done }
func (g *Guard) Close() error {
	close(g.stop)
	g.input.Close()
	<-g.done
	return g.err
}

func RunGuard(directory string) (result error) {
	decoder := json.NewDecoder(os.Stdin)
	var input linuxGuardInput
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	cfg := input.Capture
	if err := checkNamespace(cfg.Namespace, cfg.Scope == "global"); err != nil {
		return err
	}
	if err := config.ValidateCapture(cfg); err != nil {
		return err
	}
	tools, err := ownedTools()
	if err != nil {
		return err
	}
	lock, err := captureLock(cfg.Namespace)
	if err != nil {
		return err
	}
	defer lock.Close()

	groups, err := discoverUpstreamGroups(input.Upstreams)
	if err != nil {
		return err
	}
	for _, group := range groups {
		logging.Infof("local upstream bypass: %s", group.Path)
	}
	state, err := tools.prepare(cfg, directory, groups)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, tools.cleanup(state, directory)) }()
	if err := tools.activate(state, cfg, groups); err != nil {
		return err
	}
	fmt.Println("ready")
	heartbeats := make(chan struct{}, 1)
	go func() {
		defer close(heartbeats)
		input := io.MultiReader(decoder.Buffered(), os.Stdin)
		var b [64]byte
		for {
			if _, err := input.Read(b[:]); err != nil {
				return
			}
			select {
			case heartbeats <- struct{}{}:
			default:
			}
		}
	}()
	lease := time.NewTimer(3 * time.Second)
	defer lease.Stop()
	refresh := time.NewTicker(500 * time.Millisecond)
	defer refresh.Stop()
	for {
		select {
		case _, open := <-heartbeats:
			if !open {
				return nil
			}
			if !lease.Stop() {
				select {
				case <-lease.C:
				default:
				}
			}
			lease.Reset(3 * time.Second)
		case <-lease.C:
			return errors.New("capture lease expired")
		case <-refresh.C:
			if len(input.Upstreams) == 0 {
				continue
			}
			next, err := discoverUpstreamGroups(input.Upstreams)
			if err != nil {
				return fmt.Errorf("local upstream identity lost; withdrawing capture: %w", err)
			}
			if !slices.Equal(groups, next) {
				if err := tools.updateUpstreamGroups(state.Table, next); err != nil {
					return err
				}
				groups = next
				for _, group := range groups {
					logging.Infof("local upstream bypass refreshed: %s", group.Path)
				}
			}
		}
	}
}

func enabledFamilies(c config.Capture) []string {
	var result []string
	if c.IPv4 {
		result = append(result, "-4")
	}
	if c.IPv6 {
		result = append(result, "-6")
	}
	return result
}

func nftRules(table string, c config.Capture, upstreams ...[]upstreamGroup) string {
	var rules strings.Builder
	fmt.Fprintf(&rules, "table inet %s {\n", table)
	if c.Mode == "local" && c.Scope == "global" {
		rules.WriteString("chain local_upstreams {\n")
		if len(upstreams) > 0 {
			rules.WriteString(upstreamRules(upstreams[0]))
		}
		rules.WriteString("}\n")
	}
	if c.Mode == "local" {
		rules.WriteString("chain local_output {\ntype route hook output priority mangle; policy accept;\n")
		writeExclusions(&rules, c)
		if c.Scope == "global" {
			rules.WriteString("jump local_upstreams\n")
		}
		// Host services must keep replying directly to inbound connections.
		rules.WriteString("ct direction reply return\n")
		writeMatches(&rules, c, "tcp", "", false)
		if c.UDP || c.DNSHijack {
			writeMatches(&rules, c, "udp", "", false)
		}
		rules.WriteString("}\nchain local_capture {\ntype filter hook prerouting priority mangle; policy accept;\n")
		fmt.Fprintf(&rules, "iifname != \"lo\" return\nmeta mark & %s != %s return\n", captureMark, captureMark)
		writeTProxy(&rules, c, "tcp", "")
		if c.UDP || c.DNSHijack {
			writeTProxy(&rules, c, "udp", "")
		}
		rules.WriteString("}\n")
	} else {
		rules.WriteString("chain gateway_capture {\ntype filter hook prerouting priority mangle; policy accept;\n")
		writeExclusions(&rules, c)
		for _, iface := range c.Interfaces {
			writeTProxy(&rules, c, "tcp", iface)
			if c.UDP || c.DNSHijack {
				writeTProxy(&rules, c, "udp", iface)
			}
		}
		rules.WriteString("}\n")
	}
	rules.WriteString("}\n")
	return rules.String()
}
func nftFamily(prefix netip.Prefix) string {
	if prefix.Addr().Is6() {
		return "ip6"
	}
	return "ip"
}

func writeExclusions(rules *strings.Builder, c config.Capture) {
	if c.Mode == "local" && (c.DNSHijack || c.Scope == "global") {
		fmt.Fprintf(rules, "meta skuid %d return\n", os.Geteuid())
	}
	fmt.Fprintf(rules, "meta mark & 0x%x != 0 return\n", bypassMark)
	rules.WriteString("ip daddr { 0.0.0.0/8, 224.0.0.0/4, 255.255.255.255 } return\n")
	rules.WriteString("ip6 daddr { ::/128, ff00::/8 } return\n")
	localV4 := "127.0.0.0/8, 169.254.0.0/16"
	localV6 := "::1/128, fe80::/10"
	if c.Scope == "global" && len(c.CIDRs) == 0 {
		localV4 += ", 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
		localV6 += ", fc00::/7"
	}
	if !c.DNSHijack {
		fmt.Fprintf(rules, "ip daddr { %s } return\n", localV4)
		fmt.Fprintf(rules, "ip6 daddr { %s } return\n", localV6)
		return
	}
	for _, proto := range []string{"tcp", "udp"} {
		fmt.Fprintf(rules, "ip daddr { %s } %s dport != 53 return\n", localV4, proto)
		fmt.Fprintf(rules, "ip6 daddr { %s } %s dport != 53 return\n", localV6, proto)
	}
}

func writeTProxy(rules *strings.Builder, c config.Capture, network, iface string) {
	writeMatches(rules, c, network, iface, true)
}

func writeMatches(rules *strings.Builder, c config.Capture, network, iface string, transparent bool) {
	prefixes := c.CIDRs
	if c.Scope == "global" && len(prefixes) == 0 {
		if c.IPv4 {
			prefixes = append(prefixes, netip.MustParsePrefix("0.0.0.0/0"))
		}
		if c.IPv6 {
			prefixes = append(prefixes, netip.MustParsePrefix("::/0"))
		}
	}
	for _, prefix := range prefixes {
		family := nftFamily(prefix)
		ports := []string{}
		if c.Scope == "global" && len(c.Ports) == 0 && (network == "tcp" || c.UDP) {
			// DNS remains opt-in, even when all ordinary ports are captured.
			if c.DNSHijack {
				ports = append(ports, "")
			} else {
				ports = append(ports, fmt.Sprintf("%s dport != 53 ", network))
			}
		} else {
			for _, port := range capturePorts(c, network) {
				ports = append(ports, fmt.Sprintf("%s dport %d ", network, port))
			}
		}
		for _, port := range ports {
			if iface != "" {
				fmt.Fprintf(rules, "iifname %q ", iface)
			}
			fmt.Fprintf(rules, "%s daddr %s meta l4proto %s %s", family, prefix, network, port)
			if transparent {
				fmt.Fprintf(rules, "tproxy %s to :%d ", family, c.Port)
			}
			fmt.Fprintf(rules, "meta mark set meta mark | %s", captureMark)
			if transparent {
				rules.WriteString(" accept")
			}
			rules.WriteString("\n")
		}
	}
}
func capturePorts(c config.Capture, network string) []uint16 {
	ports := c.Ports
	if network == "udp" && !c.UDP {
		ports = nil
	}
	if c.DNSHijack {
		return append(append([]uint16(nil), ports...), 53)
	}
	return ports
}
