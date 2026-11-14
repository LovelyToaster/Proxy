package dnsengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/geosite"
	"proxy.local/m0/internal/logging"
	"proxy.local/m0/internal/systemdns"
)

type Engine struct {
	infrastructure       *infrastructure
	policyMu             sync.RWMutex
	listen               []netip.AddrPort
	upstreams            map[string]upstream.Upstream
	bootstrap            []io.Closer
	rules                []config.DNSRule
	compiled             []compiledRule
	matchers             map[string]*geosite.Matcher
	fallback             string
	cache                dnsCache
	cachePersist         config.DNSCachePersist
	persistMu            sync.Mutex
	persistStop          chan struct{}
	persistDone          chan struct{}
	refreshGroup         singleflight.Group
	missGroup            singleflight.Group
	fallbackLookupGroup  singleflight.Group
	fallbackMap          *fallbackRegistry
	workers              chan struct{}
	queries              atomic.Uint64
	hits                 atomic.Uint64
	staleHits            atomic.Uint64
	uncacheableQueries   atomic.Uint64
	uncacheableResponses atomic.Uint64
	negativeNoSOA        atomic.Uint64
	systemBypass         atomic.Uint64
	fallbacks            atomic.Uint64
	failed               atomic.Uint64
	packets              sync.WaitGroup
	upstreamRequests     sync.Map
}

type compiledRule struct {
	rule    config.DNSRule
	matcher *geosite.Matcher
}

func compileRules(rules []config.DNSRule, matchers map[string]*geosite.Matcher) []compiledRule {
	out := make([]compiledRule, len(rules))
	for i, r := range rules {
		var m *geosite.Matcher
		if r.GeoSite != "" {
			m = matchers[strings.ToUpper(r.GeoSite)]
		}
		out[i] = compiledRule{rule: r, matcher: m}
	}
	return out
}

type Status struct {
	Enabled              bool              `json:"enabled"`
	Listen               []netip.AddrPort  `json:"listen,omitempty"`
	Queries              uint64            `json:"queries"`
	CacheHits            uint64            `json:"cache_hits"`
	StaleHits            uint64            `json:"stale_hits"`
	UncacheableQueries   uint64            `json:"uncacheable_queries"`
	UncacheableResponses uint64            `json:"uncacheable_responses"`
	NegativeNoSOA        uint64            `json:"negative_no_soa"`
	SystemBypass         uint64            `json:"system_bypass"`
	Cached               int               `json:"cached"`
	Fallbacks            uint64            `json:"fallbacks"`
	Failures             uint64            `json:"failures"`
	UpstreamRequests     map[string]uint64 `json:"upstream_requests"`
}

func New(cfg config.DNS, dialer net.Dialer, outboundSets ...map[string]config.Outbound) (*Engine, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	var categories []string
	for _, rule := range cfg.Rules {
		if rule.GeoSite != "" {
			categories = append(categories, rule.GeoSite)
		}
	}
	matchers, err := geosite.Load(cfg.GeoSiteFile, categories)
	if err != nil {
		return nil, err
	}
	entries := 0
	if cfg.Cache.Enabled {
		entries = cfg.Cache.MaxEntries
	}
	cacheOpts := cacheOptions{
		algorithm:   cfg.Cache.Algorithm,
		maxEntries:  entries,
		negativeTTL: uint32(cfg.Cache.NegativeTTL.Seconds()),
		stale: staleOptions{
			enabled:  cfg.Cache.Enabled && cfg.Cache.Stale.IsEnabled(),
			staleTTL: cfg.Cache.Stale.StaleTTL,
			serveTTL: uint32(cfg.Cache.Stale.ServeTTL.Seconds()),
		},
	}
	cacheInstance := newCacheWithOptions(cacheOpts)
	if cfg.Cache.Enabled && cfg.Cache.Persist.IsEnabled() && cfg.Cache.Persist.File != "" && entries > 0 {
		if loaded, err := loadFromFile(cfg.Cache.Persist.File, time.Now(), cacheOpts.stale); err == nil && len(loaded) > 0 {
			cacheInstance.restore(loaded, time.Now())
		} else if err != nil && !os.IsNotExist(err) {
			logging.Warnf("DNS cache persistence: load failed: %v", err)
		}
	}
	e := &Engine{
		listen: cfg.Listen, upstreams: make(map[string]upstream.Upstream), rules: cfg.Rules,
		compiled: compileRules(cfg.Rules, matchers),
		matchers: matchers, fallback: cfg.Fallback, cache: cacheInstance, fallbackMap: newFallbackRegistry(fallbackMapCapacity), workers: make(chan struct{}, 128),
		cachePersist: cfg.Cache.Persist,
	}
	e.startPersistLocked()
	root := &infrastructure{cfg: cfg, matchers: matchers, dialer: dialer}
	if len(outboundSets) > 0 {
		root.outbounds = outboundSets[0]
	}
	e.infrastructure = root
	for name := range cfg.Upstreams {
		if err := root.checkUpstream(name); err != nil {
			return nil, err
		}
	}
	for name, item := range cfg.Upstreams {
		path, _ := root.child(name)
		dialer := dialer
		dialer.Resolver = path.netResolver()
		if item.Outbound != "" {
			if item.Type != "doh" || len(outboundSets) == 0 {
				e.Close()
				return nil, fmt.Errorf("dns.upstreams.%s: outbound requires doh and an outbound map", name)
			}
			proxy, ok := outboundSets[0][item.Outbound]
			if !ok {
				e.Close()
				return nil, fmt.Errorf("dns.upstreams.%s: unknown outbound", name)
			}
			resolver, err := newProxiedDoH(item, cfg.Listen, cfg.Timeout, dialer, proxy, nil)
			if err != nil {
				e.Close()
				return nil, fmt.Errorf("dns.upstreams.%s: %w", name, err)
			}
			e.upstreams[name] = resolver
			continue
		}
		if item.Type == "system" {
			e.upstreams[name] = &systemUpstream{listen: cfg.Listen, timeout: cfg.Timeout, dialer: dialer, discover: systemdns.Discover}
			continue
		}
		var bootstrap upstream.Resolver = path
		resolver, closers, err := buildUpstream(item, cfg.Listen, cfg.Timeout, nil, bootstrap)
		if err != nil {
			e.Close()
			return nil, fmt.Errorf("dns.upstreams.%s: %w", name, err)
		}
		e.bootstrap = append(e.bootstrap, closers...)
		e.upstreams[name] = resolver
	}
	return e, nil
}

func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.stopPersist()
	e.savePersist()
	e.packets.Wait()
	var err error
	for _, u := range e.upstreams {
		err = errors.Join(err, u.Close())
	}
	return errors.Join(err, closeAll(e.bootstrap))
}

func (e *Engine) Status() Status {
	if e == nil {
		return Status{}
	}
	e.policyMu.RLock()
	defer e.policyMu.RUnlock()
	requests := make(map[string]uint64)
	e.upstreamRequests.Range(func(key, value any) bool { requests[key.(string)] = value.(*atomic.Uint64).Load(); return true })
	return Status{
		Enabled: true, Listen: e.listen, Queries: e.queries.Load(), CacheHits: e.hits.Load(), StaleHits: e.staleHits.Load(),
		UncacheableQueries: e.uncacheableQueries.Load(), UncacheableResponses: e.uncacheableResponses.Load(),
		NegativeNoSOA: e.negativeNoSOA.Load(), SystemBypass: e.systemBypass.Load(),
		Cached: e.cache.size(), Fallbacks: e.fallbacks.Load(), Failures: e.failed.Load(), UpstreamRequests: requests,
	}
}

func (e *Engine) Flush() error {
	if e == nil {
		return errors.New("DNS is disabled")
	}
	e.policyMu.RLock()
	defer e.policyMu.RUnlock()
	e.cache.clear()
	if e.cachePersist.File != "" {
		_ = os.Remove(e.cachePersist.File)
	}
	return nil
}

func (e *Engine) savePersist() {
	if e == nil {
		return
	}
	e.policyMu.RLock()
	persist := e.cachePersist
	c := e.cache
	e.policyMu.RUnlock()

	if !persist.IsEnabled() || persist.File == "" || c == nil || c.capacity() == 0 {
		return
	}
	snapshots := c.snapshot()
	if err := saveToFile(persist.File, snapshots); err != nil {
		logging.Warnf("DNS cache persistence: save failed: %v", err)
	}
}

func (e *Engine) startPersistLocked() {
	if !e.cachePersist.IsEnabled() || e.cachePersist.File == "" || e.cachePersist.SyncInterval <= 0 || e.cache == nil || e.cache.capacity() == 0 {
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	e.persistStop = stop
	e.persistDone = done
	go e.periodicSync(e.cachePersist.SyncInterval, stop, done)
}

func (e *Engine) stopPersist() {
	e.persistMu.Lock()
	defer e.persistMu.Unlock()
	e.stopPersistLocked()
}

func (e *Engine) stopPersistLocked() {
	if e.persistStop == nil {
		return
	}
	close(e.persistStop)
	<-e.persistDone
	e.persistStop = nil
	e.persistDone = nil
}

func (e *Engine) periodicSync(interval time.Duration, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			e.savePersist()
		}
	}
}

func (e *Engine) policy(name string) string {
	norm := geosite.Normalize(name)
	if len(e.compiled) > 0 {
		for _, c := range e.compiled {
			if c.rule.Default() || c.rule.MatchDomain(norm) || (c.matcher != nil && c.matcher.MatchNormalized(norm)) {
				return c.rule.Upstream
			}
		}
		return ""
	}
	for _, rule := range e.rules {
		if rule.Default() || rule.MatchDomain(norm) || (rule.GeoSite != "" && e.matchers[strings.ToUpper(rule.GeoSite)].MatchNormalized(norm)) {
			return rule.Upstream
		}
	}
	return ""
}

func (e *Engine) ServeDNS(w dns.ResponseWriter, query *dns.Msg) {
	response := e.handle(query)
	if w.LocalAddr().Network() == "udp" {
		truncate(query, response)
	}
	w.WriteMsg(response)
}

func (e *Engine) handle(query *dns.Msg) *dns.Msg {
	e.queries.Add(1)
	select {
	case e.workers <- struct{}{}:
		defer func() { <-e.workers }()
	default:
		e.failed.Add(1)
		return new(dns.Msg).SetRcode(query, dns.RcodeServerFailure)
	}
	return e.answer(query)
}

func truncate(query, response *dns.Msg) {
	size := dns.MinMsgSize
	if opt := query.IsEdns0(); opt != nil {
		size = max(size, min(4096, int(opt.UDPSize())))
	}
	response.Truncate(size)
}

type missResult struct {
	response *dns.Msg
	err      error
}

func (e *Engine) recordPutReject(reason putRejectReason) {
	switch reason {
	case rejectNoSOA:
		e.negativeNoSOA.Add(1)
	case rejectUncacheable:
		e.uncacheableResponses.Add(1)
	}
}

func (e *Engine) exchangeWithFallback(policy string, up upstream.Upstream, fallbackName string, fallUp upstream.Upstream, query *dns.Msg) (*dns.Msg, bool, error) {
	e.countUpstream(policy)
	response, err := exchange(up, query)
	fallback := fallbackName != "" && fallbackName != policy && fallUp != nil && (err != nil || response.Rcode == dns.RcodeServerFailure)
	if fallback {
		e.fallbacks.Add(1)
		e.countUpstream(fallbackName)
		response, err = exchange(fallUp, query)
	}
	return response, fallback, err
}

func (e *Engine) answer(query *dns.Msg) *dns.Msg {
	resp := e.answerCore(query)
	if e.fallbackMap != nil && resp != nil && resp.Rcode == dns.RcodeSuccess && len(query.Question) == 1 {
		e.fallbackMap.record(query.Question[0].Name, resp.Answer, time.Now())
	}
	return resp
}

func (e *Engine) answerCore(query *dns.Msg) *dns.Msg {
	if query.Opcode != dns.OpcodeQuery {
		return new(dns.Msg).SetRcode(query, dns.RcodeNotImplemented)
	}
	if len(query.Question) != 1 {
		return new(dns.Msg).SetRcode(query, dns.RcodeFormatError)
	}
	question := query.Question[0]
	if question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR {
		return new(dns.Msg).SetRcode(query, dns.RcodeRefused)
	}
	e.policyMu.RLock()
	policy := e.policy(question.Name)
	up := e.upstreams[policy]
	fallbackName := e.fallback
	var fallUp upstream.Upstream
	if fallbackName != "" && fallbackName != policy {
		fallUp = e.upstreams[fallbackName]
	}
	cache := e.cache
	e.policyMu.RUnlock()

	cachePolicy := policy
	if sysUp, dynamic := up.(*systemUpstream); dynamic {
		cachePolicy = sysUp.cacheKeyPolicy(policy, question.Name)
	}
	key, cacheable := makeKey(cachePolicy, query)
	if !cacheable {
		e.uncacheableQueries.Add(1)
	}
	if cacheable && cache.capacity() > 0 {
		found, state := cache.get(key, query, time.Now())
		if state == entryFresh {
			e.hits.Add(1)
			logging.Debugf("DNS cache hit %s type=%s policy=%s", question.Name, dns.TypeToString[question.Qtype], policy)
			return found
		}
		if state == entryStale {
			e.hits.Add(1)
			e.staleHits.Add(1)
			logging.Debugf("DNS stale hit %s type=%s policy=%s", question.Name, dns.TypeToString[question.Qtype], policy)
			e.refreshAsync(policy, key)
			return found
		}
		v, _, _ := e.missGroup.Do(key.string(), func() (any, error) {
			response, fallback, err := e.exchangeWithFallback(policy, up, fallbackName, fallUp, query)
			if err == nil && response.Rcode != dns.RcodeServerFailure && !fallback {
				e.recordPutReject(cache.put(key, response, time.Now()))
			}
			if err == nil {
				logging.Debugf("DNS resolved %s type=%s policy=%s fallback=%v rcode=%s", question.Name, dns.TypeToString[question.Qtype], policy, fallback, dns.RcodeToString[response.Rcode])
			}
			return missResult{response: response, err: err}, nil
		})
		res := v.(missResult)
		if res.err != nil {
			e.failed.Add(1)
			logging.Warnf("DNS upstream %s: %v", policy, res.err)
			if staleMsg, state := cache.get(key, query, time.Now()); state == entryStale {
				e.staleHits.Add(1)
				return staleMsg
			}
			return new(dns.Msg).SetRcode(query, dns.RcodeServerFailure)
		}
		if res.response.Rcode == dns.RcodeServerFailure {
			e.failed.Add(1)
			if staleMsg, state := cache.get(key, query, time.Now()); state == entryStale {
				e.staleHits.Add(1)
				return staleMsg
			}
		}
		out := res.response.Copy()
		out.Id = query.Id
		out.Question = append(out.Question[:0], query.Question...)
		return out
	}

	response, fallback, err := e.exchangeWithFallback(policy, up, fallbackName, fallUp, query)
	if err != nil {
		e.failed.Add(1)
		logging.Warnf("DNS upstream %s: %v", policy, err)
		return new(dns.Msg).SetRcode(query, dns.RcodeServerFailure)
	}
	logging.Debugf("DNS resolved %s type=%s policy=%s fallback=%v rcode=%s", question.Name, dns.TypeToString[question.Qtype], policy, fallback, dns.RcodeToString[response.Rcode])
	if response.Rcode == dns.RcodeServerFailure {
		e.failed.Add(1)
	}
	response.Id = query.Id
	response.Question = append(response.Question[:0], query.Question...)
	return response
}

func (e *Engine) refreshAsync(policy string, key cacheKey) {
	e.refreshGroup.DoChan(key.string(), func() (any, error) {
		req := new(dns.Msg)
		req.Id = dns.Id()
		req.SetQuestion(key.question.Name, key.question.Qtype)
		req.Question[0].Qclass = key.question.Qclass
		req.RecursionDesired = (key.flags & 1) != 0
		req.CheckingDisabled = (key.flags & 2) != 0
		req.AuthenticatedData = (key.flags & 4) != 0
		if (key.flags & 16) != 0 {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.SetDo(true)
			req.Extra = []dns.RR{opt}
		}

		e.policyMu.RLock()
		up, ok := e.upstreams[policy]
		fallbackName := e.fallback
		var fallUp upstream.Upstream
		if fallbackName != "" && fallbackName != policy {
			fallUp = e.upstreams[fallbackName]
		}
		e.policyMu.RUnlock()

		if !ok || up == nil {
			return nil, errors.New("upstream unavailable")
		}

		e.countUpstream(policy)
		response, err := exchange(up, req)
		fallback := fallbackName != "" && fallbackName != policy && (err != nil || (response != nil && response.Rcode == dns.RcodeServerFailure))
		if fallback && fallUp != nil {
			e.fallbacks.Add(1)
			e.countUpstream(fallbackName)
			response, err = exchange(fallUp, req)
		}
		if err != nil || response == nil || response.Rcode == dns.RcodeServerFailure {
			return nil, err
		}

		response.Id = req.Id
		response.Question = append(response.Question[:0], req.Question...)
		if !fallback {
			e.cache.put(key, response, time.Now())
		}
		return nil, nil
	})
}

func (e *Engine) countUpstream(name string) {
	counter, _ := e.upstreamRequests.LoadOrStore(name, new(atomic.Uint64))
	counter.(*atomic.Uint64).Add(1)
}

// Replace takes ownership of the prepared policies while keeping listeners and counters.
func (e *Engine) Replace(next *Engine) {
	next.stopPersist()

	e.persistMu.Lock()
	e.stopPersistLocked()
	e.policyMu.Lock()
	old := &Engine{upstreams: e.upstreams, bootstrap: e.bootstrap}
	e.upstreams, e.bootstrap, e.rules, e.compiled, e.matchers, e.fallback, e.cache = next.upstreams, next.bootstrap, next.rules, next.compiled, next.matchers, next.fallback, next.cache
	e.infrastructure = next.infrastructure
	e.cachePersist = next.cachePersist
	if e.fallbackMap != nil {
		e.fallbackMap.clear()
	}
	e.startPersistLocked()
	e.policyMu.Unlock()
	e.persistMu.Unlock()
	old.Close()
}

// Dialer binds internal hostname lookups to an immutable DNS policy snapshot.
func (e *Engine) Dialer(d net.Dialer) net.Dialer {
	if e == nil {
		return d
	}
	e.policyMu.RLock()
	defer e.policyMu.RUnlock()
	d.Resolver = e.infrastructure.netResolver()
	return d
}

func exchange(up upstream.Upstream, query *dns.Msg) (*dns.Msg, error) {
	if up == nil {
		return nil, errors.New("no DNS upstream selected")
	}
	response, err := up.Exchange(query)
	if err != nil {
		return nil, err
	}
	if response == nil || !response.Response || response.Opcode != query.Opcode || len(response.Question) != 1 {
		return nil, errors.New("invalid DNS upstream response")
	}
	actual, expected := response.Question[0], query.Question[0]
	if actual.Qclass != expected.Qclass || actual.Qtype != expected.Qtype || !strings.EqualFold(actual.Name, expected.Name) {
		return nil, errors.New("DNS upstream question mismatch")
	}
	return response, nil
}

type Servers struct {
	items   []*dns.Server
	failure chan error
	workers sync.WaitGroup
	closing atomic.Bool
}

func (e *Engine) Start() (*Servers, error) {
	group := &Servers{failure: make(chan error, 1)}
	if e == nil {
		return group, nil
	}
	for _, address := range e.listen {
		tcp, err := net.Listen("tcp", address.String())
		if err != nil {
			group.closeBound()
			return nil, err
		}
		udp, err := net.ListenPacket("udp", address.String())
		if err != nil {
			tcp.Close()
			group.closeBound()
			return nil, err
		}
		group.items = append(group.items,
			&dns.Server{Listener: tcp, Handler: e, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, MaxTCPQueries: 32},
			&dns.Server{PacketConn: udp, Handler: e, UDPSize: 4096, WriteTimeout: 3 * time.Second})
	}
	for _, server := range group.items {
		ready := make(chan struct{})
		done := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		group.workers.Go(func() {
			defer close(done)
			if err := server.ActivateAndServe(); err != nil && !group.closing.Load() {
				select {
				case group.failure <- err:
				default:
				}
			}
		})
		select {
		case <-ready:
		case <-done:
			group.closeBound()
			group.workers.Wait()
			return nil, fmt.Errorf("start DNS listener: %w", <-group.failure)
		}
	}
	return group, nil
}

func (s *Servers) closeBound() {
	for _, server := range s.items {
		if server.Listener != nil {
			server.Listener.Close()
		}
		if server.PacketConn != nil {
			server.PacketConn.Close()
		}
	}
}

func (s *Servers) Failure() <-chan error { return s.failure }

func (s *Servers) Close() {
	s.closing.Store(true)
	var workers sync.WaitGroup
	for _, server := range s.items {
		workers.Go(func() { server.Shutdown() })
	}
	workers.Wait()
	s.workers.Wait()
}

func Probe(ctx context.Context, address netip.AddrPort, network, name string, qtype uint16) (*dns.Msg, error) {
	name = dns.Fqdn(name)
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, errors.New("invalid DNS name")
	}
	query := new(dns.Msg)
	query.SetQuestion(name, qtype)
	if network == "udp" {
		query.SetEdns0(1232, false)
	}
	client := &dns.Client{Net: network}
	if deadline, ok := ctx.Deadline(); ok {
		client.Timeout = time.Until(deadline)
	}
	response, _, err := client.ExchangeContext(ctx, query, address.String())
	return response, err
}
