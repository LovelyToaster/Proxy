package dnsengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"proxy.local/m0/internal/selfsocket"
)

type plainUpstream struct {
	host     string
	port     int
	network  string
	timeout  time.Duration
	resolver upstream.Resolver
}

func (p *plainUpstream) Address() string { return net.JoinHostPort(p.host, strconv.Itoa(p.port)) }
func (p *plainUpstream) Close() error    { return nil }
func (p *plainUpstream) Exchange(query *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(p.host); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		var err error
		addresses, err = p.resolver.LookupNetIP(ctx, "ip", p.host)
		if err != nil {
			return nil, err
		}
	}
	var failures error
	for _, ip := range addresses {
		d := selfsocket.Dialer(net.Dialer{})
		client := &dns.Client{Net: p.network, Timeout: p.timeout, Dialer: &d}
		target := net.JoinHostPort(ip.String(), strconv.Itoa(p.port))
		answer, _, err := client.ExchangeContext(ctx, query, target)
		if err == nil && answer.Truncated && p.network == "udp" {
			client.Net = "tcp"
			answer, _, err = client.ExchangeContext(ctx, query, target)
		}
		if err == nil {
			return answer, nil
		}
		failures = errors.Join(failures, err)
	}
	return nil, errors.Join(fmt.Errorf("DNS upstream %s failed", p.Address()), failures)
}

type plainResolver struct{ server *plainUpstream }

func (r *plainResolver) Close() error { return nil }
func (r *plainResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	var result []netip.Addr
	for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if network == "ip4" && kind == dns.TypeAAAA || network == "ip6" && kind == dns.TypeA {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		answer, err := exchange(r.server, new(dns.Msg).SetQuestion(dns.Fqdn(host), kind))
		if err != nil {
			return nil, err
		}
		if answer.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("bootstrap %s: %s", host, dns.RcodeToString[answer.Rcode])
		}
		for _, rr := range answer.Answer {
			var ip net.IP
			switch value := rr.(type) {
			case *dns.A:
				ip = value.A
			case *dns.AAAA:
				ip = value.AAAA
			}
			if address, ok := netip.AddrFromSlice(ip); ok {
				result = append(result, address.Unmap())
			}
		}
	}
	if len(result) == 0 {
		return nil, &net.DNSError{Name: host, Err: "no bootstrap addresses", IsNotFound: true}
	}
	return result, nil
}

func bootstrapResolver(address netip.AddrPort, timeout time.Duration) *plainResolver {
	return &plainResolver{server: &plainUpstream{host: address.Addr().String(), port: int(address.Port()), network: "udp", timeout: timeout}}
}
