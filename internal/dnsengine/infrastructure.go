package dnsengine

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/geosite"
	"proxy.local/m0/internal/systemdns"
)

// Immutable policy snapshot. Dependency paths belong to each resolution, never
// a process-wide busy flag, so concurrent independent lookups cannot conflict.
type infrastructure struct {
	cfg       config.DNS
	outbounds map[string]config.Outbound
	matchers  map[string]*geosite.Matcher
	dialer    net.Dialer
	path      []string
}

func (r *infrastructure) policy(name string) string {
	for _, rule := range r.cfg.Rules {
		if rule.Default() || rule.MatchDomain(name) || rule.GeoSite != "" && r.matchers[strings.ToUpper(rule.GeoSite)].Match(name) {
			return rule.Upstream
		}
	}
	return ""
}

func (r *infrastructure) child(name string) (*infrastructure, error) {
	for _, entry := range r.path {
		if entry == name {
			return nil, fmt.Errorf("DNS dependency cycle: %s", strings.Join(append(append([]string(nil), r.path...), name), " -> "))
		}
	}
	if len(r.path) >= 32 {
		return nil, fmt.Errorf("DNS dependency depth exceeded: %v", r.path)
	}
	next := *r
	next.path = append(append([]string(nil), r.path...), name)
	return &next, nil
}

func (r *infrastructure) build(name string) (upstream.Upstream, func(), error) {
	next, err := r.child(name)
	if err != nil {
		return nil, nil, err
	}
	item, ok := r.cfg.Upstreams[name]
	if !ok {
		return nil, nil, fmt.Errorf("unknown DNS policy %q", name)
	}
	dialer := r.dialer
	dialer.Resolver = next.netResolver()
	if item.Type == "system" {
		// System server addresses are discovered as IP endpoints, not resolved names.
		return &systemUpstream{listen: r.cfg.Listen, timeout: r.cfg.Timeout, dialer: dialer, discover: systemdns.Discover}, func() {}, nil
	}
	if item.Outbound != "" {
		result, err := newProxiedDoH(item, r.cfg.Listen, r.cfg.Timeout, dialer, r.outbounds[item.Outbound], nil)
		if err != nil {
			return nil, nil, err
		}
		return result, func() { result.Close() }, nil
	}
	result, closers, err := buildUpstream(item, r.cfg.Listen, r.cfg.Timeout, nil, next)
	if err != nil {
		return nil, nil, err
	}
	return result, func() { result.Close(); closeAll(closers) }, nil
}

func (r *infrastructure) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	// Preflight before any network work gives immediate, explicit cycle errors.
	if err := r.checkName(host); err != nil {
		return nil, err
	}
	name := r.policy(host)
	server, closeServer, err := r.build(name)
	if err != nil {
		return nil, err
	}
	defer closeServer()
	var result []netip.Addr
	for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if network == "ip4" && kind == dns.TypeAAAA || network == "ip6" && kind == dns.TypeA {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		response, err := exchange(server, new(dns.Msg).SetQuestion(dns.Fqdn(host), kind))
		if err != nil {
			return nil, err
		}
		if response.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("DNS infrastructure lookup %s: %s", host, dns.RcodeToString[response.Rcode])
		}
		for _, rr := range response.Answer {
			var ip net.IP
			switch record := rr.(type) {
			case *dns.A:
				ip = record.A
			case *dns.AAAA:
				ip = record.AAAA
			}
			if addr, ok := netip.AddrFromSlice(ip); ok {
				result = append(result, addr.Unmap())
			}
		}
	}
	if len(result) == 0 {
		return nil, &net.DNSError{Name: host, Err: "no addresses", IsNotFound: true}
	}
	return result, nil
}

// Go's resolver speaks length-framed DNS on a stream connection. Keep it in
// memory: no local listener, OS DNS fallback, or re-entry through capture.
func (r *infrastructure) netResolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			stop := context.AfterFunc(ctx, func() { server.Close() })
			defer stop()
			server.SetDeadline(time.Now().Add(r.cfg.Timeout))
			wire := &dns.Conn{Conn: server}
			query, err := wire.ReadMsg()
			if err != nil || len(query.Question) != 1 {
				return
			}
			// Preserve a DNS error response; static dependency validation reports the
			// detailed path before this transport bridge is needed.
			name := r.policy(query.Question[0].Name)
			answer := new(dns.Msg).SetRcode(query, dns.RcodeServerFailure)
			if err := r.checkName(query.Question[0].Name); err == nil {
				if up, closeUp, err := r.build(name); err == nil {
					if response, err := exchange(up, query); err == nil {
						answer = response
					}
					closeUp()
				}
			} else {
				log.Printf("internal DNS resolution stopped: %v", err)
			}
			wire.WriteMsg(answer)
		}()
		return client, nil
	}}
}

func upstreamHost(item config.DNSUpstream) string {
	if item.Type == "system" || len(item.Bootstrap) > 0 {
		return ""
	}
	address := item.Address
	if !strings.Contains(address, "://") {
		address = "dns://" + address
	}
	parsed, err := url.Parse(address)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func (r *infrastructure) checkName(host string) error {
	if host == "" {
		return nil
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	return r.checkUpstream(r.policy(host))
}

func (r *infrastructure) checkUpstream(name string) error {
	next, err := r.child(name)
	if err != nil {
		return err
	}
	item, ok := r.cfg.Upstreams[name]
	if !ok {
		return fmt.Errorf("unknown DNS policy %q", name)
	}
	if err := next.checkName(upstreamHost(item)); err != nil {
		return err
	}
	if item.Outbound != "" {
		host, _, err := net.SplitHostPort(r.outbounds[item.Outbound].Address)
		if err == nil {
			return next.checkName(host)
		}
	}
	return nil
}
