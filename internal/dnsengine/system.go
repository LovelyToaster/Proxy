package dnsengine

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	"proxy.local/m0/internal/systemdns"
)

type systemUpstream struct {
	mu        sync.Mutex
	servers   []systemdns.Server
	refreshed time.Time
	err       error
	lastSig   string
	listen    []netip.AddrPort
	dialer    net.Dialer
	timeout   time.Duration
	discover  func(context.Context) ([]systemdns.Server, error)
}

func (s *systemUpstream) Address() string { return "system" }
func (s *systemUpstream) Close() error    { return nil }

func (s *systemUpstream) candidates(name string) ([]netip.AddrPort, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.refreshed) >= 3*time.Second {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		servers, err := s.discover(ctx)
		cancel()
		s.servers, s.err, s.refreshed = servers, err, time.Now()
	}
	if s.err != nil {
		return nil, s.err
	}
	targets := systemdns.Select(s.servers, name)
	result := targets[:0]
	for _, target := range targets {
		recursive := false
		for _, local := range s.listen {
			if local == target {
				recursive = true
				break
			}
		}
		if !recursive {
			result = append(result, target)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("no usable system DNS upstream for this name")
	}
	return result, nil
}

func (s *systemUpstream) cacheKeyPolicy(base, name string) string {
	targets, err := s.candidates(name)
	if err == nil && len(targets) > 0 {
		h := fnv.New64a()
		for _, target := range targets {
			_, _ = h.Write([]byte(target.String()))
			_, _ = h.Write([]byte{0})
		}
		sig := fmt.Sprintf("%016x", h.Sum64())
		s.mu.Lock()
		s.lastSig = sig
		s.mu.Unlock()
		return base + "#" + sig
	}
	s.mu.Lock()
	sig := s.lastSig
	s.mu.Unlock()
	if sig != "" {
		return base + "#" + sig
	}
	return base
}

func (s *systemUpstream) Exchange(q *dns.Msg) (*dns.Msg, error) {
	targets, err := s.candidates(q.Question[0].Name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	var failures error
	for i, target := range targets {
		deadline, _ := ctx.Deadline()
		budget := time.Until(deadline) / time.Duration(len(targets)-i)
		if budget <= 0 {
			break
		}
		attempt, stop := context.WithTimeout(ctx, budget)
		udp := &dns.Client{Net: "udp", Dialer: &s.dialer, Timeout: budget}
		result, _, err := udp.ExchangeContext(attempt, q, target.String())
		if err == nil && result.Truncated {
			tcp := &dns.Client{Net: "tcp", Dialer: &s.dialer, Timeout: budget}
			result, _, err = tcp.ExchangeContext(attempt, q, target.String())
		}
		stop()
		if err == nil && result.Rcode != dns.RcodeServerFailure {
			return result, nil
		}
		failures = errors.Join(failures, err)
	}
	return nil, errors.Join(errors.New("system DNS upstreams did not answer"), failures)
}
