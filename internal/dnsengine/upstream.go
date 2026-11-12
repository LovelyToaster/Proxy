package dnsengine

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"proxy.local/m0/internal/config"
)

func buildUpstream(cfg config.DNSUpstream, listen []netip.AddrPort, timeout time.Duration, roots *x509.CertPool, defaults ...upstream.Resolver) (upstream.Upstream, []io.Closer, error) {
	scheme, port := cfg.Type, 53
	switch cfg.Type {
	case "udp", "tcp":
	case "dot":
		scheme, port = "tls", 853
	case "doh":
		scheme, port = "https", 443
	case "doh3":
		scheme, port = "h3", 443
	case "doq":
		scheme, port = "quic", 853
	default:
		return nil, nil, errors.New("invalid DNS upstream protocol")
	}
	address := cfg.Address
	if !strings.Contains(address, "://") {
		if ip, err := netip.ParseAddr(address); err == nil {
			address = net.JoinHostPort(ip.String(), strconv.Itoa(port))
		}
		address = scheme + "://" + address
	}
	u, err := url.Parse(address)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Type == "doh3" && u.Scheme == "https" {
		u.Scheme = "h3"
	}
	if u.Scheme != scheme || u.Hostname() == "" || u.User != nil || u.Fragment != "" ||
		u.RawQuery != "" || u.ForceQuery || ((scheme != "https" && scheme != "h3") && u.Path != "") {
		return nil, nil, errors.New("DNS upstream URL does not match the configured protocol")
	}
	if (scheme == "https" || scheme == "h3") && u.Path == "" {
		u.Path = "/dns-query"
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, nil, errors.New("invalid DNS upstream port")
		}
	}
	ip, ipErr := netip.ParseAddr(u.Hostname())
	if ipErr == nil && (ip.IsUnspecified() || ip.IsMulticast()) {
		return nil, nil, errors.New("DNS upstream requires a concrete unicast address")
	}
	for _, local := range listen {
		if local.Port() == uint16(port) && (ipErr != nil || local.Addr().Unmap() == ip.Unmap()) {
			return nil, nil, errors.New("DNS upstream could recurse into a local listener")
		}
	}
	opts := &upstream.Options{Timeout: timeout, RootCAs: roots, Bootstrap: net.DefaultResolver}
	if len(defaults) > 0 && defaults[0] != nil {
		opts.Bootstrap = defaults[0]
	}
	var bootstrap upstream.ParallelResolver
	var closers []io.Closer
	for _, addr := range cfg.Bootstrap {
		resolver := bootstrapResolver(addr, timeout)
		closers = append(closers, resolver)
		bootstrap = append(bootstrap, resolver)
	}
	if len(bootstrap) > 0 {
		opts.Bootstrap = bootstrap
	}
	if cfg.Type == "udp" || cfg.Type == "tcp" {
		return &plainUpstream{host: u.Hostname(), port: port, network: cfg.Type, timeout: timeout, resolver: opts.Bootstrap}, closers, nil
	}
	result, err := upstream.AddressToUpstream(u.String(), opts)
	if err != nil {
		closeAll(closers)
		return nil, nil, fmt.Errorf("create DNS upstream: %w", err)
	}
	return result, closers, nil
}

func closeAll(items []io.Closer) error {
	var result error
	for _, item := range items {
		result = errors.Join(result, item.Close())
	}
	return result
}
