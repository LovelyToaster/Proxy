package dnsengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/outbound"
)

type proxiedDoH struct {
	address   string
	client    *http.Client
	transport *http.Transport
	bootstrap []io.Closer
}

func newProxiedDoH(cfg config.DNSUpstream, listen []netip.AddrPort, timeout time.Duration,
	dialer net.Dialer, proxy config.Outbound, roots *x509.CertPool) (upstream.Upstream, error) {
	u, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery {
		return nil, errors.New("proxied DoH requires an HTTPS DNS endpoint")
	}
	if u.Path == "" {
		u.Path = "/dns-query"
	}
	port := "443"
	if u.Port() != "" {
		port = u.Port()
	}
	// Validate port and recursion without resolving the upstream hostname.
	parsed, err := net.LookupPort("tcp", port)
	if err != nil || parsed < 1 || parsed > 65535 {
		return nil, errors.New("invalid DoH port")
	}
	ip, ipErr := netip.ParseAddr(u.Hostname())
	if ipErr == nil && (ip.IsUnspecified() || ip.IsMulticast()) {
		return nil, errors.New("invalid DoH address")
	}
	for _, local := range listen {
		if local.Port() == uint16(parsed) && (ipErr != nil || local.Addr().Unmap() == ip.Unmap()) {
			return nil, errors.New("DoH upstream could recurse into a local listener")
		}
	}
	var resolver upstream.Resolver = net.DefaultResolver
	if dialer.Resolver != nil {
		resolver = dialer.Resolver
	}
	var boot upstream.ParallelResolver
	result := &proxiedDoH{address: u.String()}
	for _, addr := range cfg.Bootstrap {
		r := bootstrapResolver(addr, timeout)
		boot = append(boot, r)
		result.bootstrap = append(result.bootstrap, r)
	}
	if len(boot) > 0 {
		resolver = boot
	}
	result.transport = &http.Transport{
		ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		MaxIdleConns: 8, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 16, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, portString, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			port, err := net.LookupPort("tcp", portString)
			if err != nil {
				return nil, err
			}
			var addresses []netip.Addr
			if ip, err := netip.ParseAddr(host); err == nil {
				addresses = []netip.Addr{ip}
			} else {
				addresses, err = resolver.LookupNetIP(ctx, "ip", host)
				if err != nil {
					return nil, err
				}
			}
			var failures error
			for _, addr := range addresses {
				conn, err := outbound.Dial(ctx, dialer, proxy, netip.AddrPortFrom(addr.Unmap(), uint16(port)), timeout)
				if err == nil {
					return conn, nil
				}
				failures = errors.Join(failures, err)
			}
			return nil, errors.Join(errors.New("DoH outbound connection failed"), failures)
		},
	}
	result.client = &http.Client{Transport: result.transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return result, nil
}

func (p *proxiedDoH) Address() string { return p.address }
func (p *proxiedDoH) Close() error {
	p.transport.CloseIdleConnections()
	return closeAll(p.bootstrap)
}
func (p *proxiedDoH) Exchange(q *dns.Msg) (*dns.Msg, error) {
	request := q.Copy()
	request.Id = 0
	wire, err := request.Pack()
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequest(http.MethodPost, p.address, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/dns-message")
	r.Header.Set("Accept", "application/dns-message")
	response, err := p.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP status %d", response.StatusCode)
	}
	content, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || content != "application/dns-message" {
		return nil, errors.New("unexpected DoH response content type")
	}
	wire, err = io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return nil, err
	}
	if len(wire) > 65535 {
		return nil, errors.New("DoH response too large")
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(wire); err != nil {
		return nil, err
	}
	if !answer.Response || len(answer.Question) != len(request.Question) {
		return nil, errors.New("invalid DoH response")
	}
	for i, question := range request.Question {
		actual := answer.Question[i]
		if actual.Qclass != question.Qclass || actual.Qtype != question.Qtype || !strings.EqualFold(actual.Name, question.Name) {
			return nil, errors.New("DoH response question mismatch")
		}
	}
	answer.Id = q.Id
	return answer, nil
}
