package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"proxy.local/m0/internal/config"
)

type linuxGuardInput struct {
	Capture   config.Capture
	Upstreams []netip.AddrPort
}

type upstreamGroup struct {
	Path  string
	Inode uint64
}

func localUpstreamEndpoints(c config.Capture, resolver *net.Resolver, outbounds map[string]config.Outbound) ([]netip.AddrPort, error) {
	if c.Mode != "local" || c.Scope != "global" {
		return nil, nil
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	local := map[netip.Addr]bool{}
	for _, addr := range addrs {
		if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
			local[prefix.Addr().Unmap()] = true
		}
	}
	if resolver == nil {
		d := Dialer(c)
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return d.DialContext(ctx, network, address)
		}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var result []netip.AddrPort
	for name, out := range outbounds {
		if out.Type == "direct" {
			continue
		}
		host, portText, err := net.SplitHostPort(out.Address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid upstream port: %s", name)
		}
		var ips []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			ips = []netip.Addr{ip}
		} else {
			ips, err = resolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("resolve upstream %s: %w", name, err)
			}
		}
		var candidates []netip.AddrPort
		remote := false
		for _, ip := range ips {
			ip = ip.Unmap().WithZone("")
			if ip.IsLoopback() || local[ip] {
				candidates = append(candidates, netip.AddrPortFrom(ip, uint16(port)))
			} else {
				remote = true
			}
		}
		if remote && len(candidates) > 0 {
			return nil, fmt.Errorf("upstream %s resolves to mixed local/remote addresses; use an explicit address", name)
		}
		for _, endpoint := range candidates {
			if !slices.Contains(result, endpoint) {
				result = append(result, endpoint)
			}
		}
	}
	return result, nil
}

func parseSocketGroups(output string, endpoint netip.AddrPort) ([]string, error) {
	var groups []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "LISTEN" {
			continue
		}
		host, portText, err := net.SplitHostPort(fields[3])
		if err != nil {
			continue
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || uint16(port) != endpoint.Port() {
			continue
		}
		host = strings.Trim(host, "[]")
		if host != "*" {
			ip, err := netip.ParseAddr(host)
			if err != nil || !ip.IsUnspecified() && ip.Unmap() != endpoint.Addr().Unmap() {
				continue
			}
		}
		group := ""
		for _, field := range fields[5:] {
			if strings.HasPrefix(field, "cgroup:") {
				group = strings.TrimPrefix(field, "cgroup:")
			}
		}
		if group == "" {
			return nil, errors.New("local upstream listener has no cgroup v2 identity")
		}
		if !slices.Contains(groups, group) {
			groups = append(groups, group)
		}
	}
	return groups, nil
}

func validateUpstreamGroup(path, self string) error {
	if !strings.HasPrefix(path, "/") || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n\t ") || path == "/" || path == self {
		return errors.New("local upstream needs a dedicated service/container cgroup, distinct from proxy")
	}
	base := filepath.Base(path)
	if !(strings.HasSuffix(base, ".service") || strings.HasPrefix(base, "docker-") && strings.HasSuffix(base, ".scope")) {
		return errors.New("local upstream is in a shared/unsupported cgroup; run it as a dedicated systemd service or Docker container")
	}
	return nil
}

func discoverUpstreamGroups(endpoints []netip.AddrPort) ([]upstreamGroup, error) {
	if len(endpoints) == 0 {
		return nil, nil
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return nil, errors.New("automatic local upstream bypass requires cgroup v2")
	}
	ss := ""
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		p := filepath.Join(dir, "ss")
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
			ss = p
			break
		}
	}
	if ss == "" {
		return nil, errors.New("automatic local upstream bypass requires iproute2 ss --cgroup")
	}
	own, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, err
	}
	self := ""
	for _, line := range strings.Split(string(own), "\n") {
		if strings.HasPrefix(line, "0::") {
			self = strings.TrimPrefix(line, "0::")
		}
	}
	outputs := map[bool]string{}
	for _, endpoint := range endpoints {
		family := endpoint.Addr().Is6()
		if _, ok := outputs[family]; ok {
			continue
		}
		flag := "-4"
		if family {
			flag = "-6"
		}
		data, err := command(ss, "", "-H", flag, "-lnt", "--cgroup")
		if err != nil {
			return nil, err
		}
		outputs[family] = string(data)
	}
	var result []upstreamGroup
	for _, endpoint := range endpoints {
		paths, err := parseSocketGroups(outputs[endpoint.Addr().Is6()], endpoint)
		if err != nil {
			return nil, fmt.Errorf("upstream %s: %w", endpoint, err)
		}
		// A dual-stack wildcard may own an IPv4 listener as well.
		if len(paths) == 0 && endpoint.Addr().Is4() {
			if _, ok := outputs[true]; !ok {
				data, err := command(ss, "", "-H", "-6", "-lnt", "--cgroup")
				if err != nil {
					return nil, err
				}
				outputs[true] = string(data)
			}
			paths, err = parseSocketGroups(outputs[true], endpoint)
			if err != nil {
				return nil, err
			}
		}
		if len(paths) != 1 {
			return nil, fmt.Errorf("local upstream %s must have exactly one identifiable listening cgroup", endpoint)
		}
		path := paths[0]
		if err := validateUpstreamGroup(path, self); err != nil {
			return nil, fmt.Errorf("upstream %s: %w", endpoint, err)
		}
		info, err := os.Stat(filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(path, "/")))
		if err != nil {
			return nil, err
		}
		group := upstreamGroup{path, info.Sys().(*syscall.Stat_t).Ino}
		if !slices.Contains(result, group) {
			result = append(result, group)
		}
	}
	slices.SortFunc(result, func(a, b upstreamGroup) int { return strings.Compare(a.Path, b.Path) })
	return result, nil
}

func upstreamRules(groups []upstreamGroup) string {
	var rules strings.Builder
	for _, group := range groups {
		path := strings.TrimPrefix(group.Path, "/")
		fmt.Fprintf(&rules, "socket cgroupv2 level %d %s counter accept\n", strings.Count(path, "/")+1, strconv.Quote(path))
	}
	return rules.String()
}

func (t tools) updateUpstreamGroups(table string, groups []upstreamGroup) error {
	input := fmt.Sprintf("flush chain inet %s local_upstreams\n", table)
	for _, line := range strings.Split(strings.TrimSpace(upstreamRules(groups)), "\n") {
		if line != "" {
			input += fmt.Sprintf("add rule inet %s local_upstreams %s\n", table, line)
		}
	}
	_, err := command(t.nft, input, "-f", "-")
	return err
}
