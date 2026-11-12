package dnsengine

import (
	"math"
	"time"

	"github.com/miekg/dns"
)

const cacheByteLimit = 16 << 20

type entryState int

const (
	entryMiss entryState = iota
	entryFresh
	entryStale
)

type cacheKey struct {
	policy   string
	question dns.Question
	flags    uint8
}

type cacheValue struct {
	key      cacheKey
	response *dns.Msg
	stored   time.Time
	ttl      uint32
	size     int
}

type staleOptions struct {
	enabled  bool
	staleTTL time.Duration
	serveTTL uint32
}

type cacheOptions struct {
	algorithm  string
	maxEntries int
	stale      staleOptions
}

type dnsCache interface {
	get(key cacheKey, query *dns.Msg, now time.Time) (*dns.Msg, entryState)
	put(key cacheKey, response *dns.Msg, now time.Time)
	clear()
	size() int
	capacity() int
	snapshot() []cacheSnapshot
	restore(items []cacheSnapshot, now time.Time)
}

func newCache(maximum int) dnsCache {
	return newCacheWithOptions(cacheOptions{
		algorithm:  "arc",
		maxEntries: maximum,
	})
}

func newCacheWithOptions(opts cacheOptions) dnsCache {
	algo := opts.algorithm
	if algo == "" {
		algo = "arc"
	}
	switch algo {
	case "lru":
		return newLRUCache(opts.maxEntries, opts.stale)
	default:
		return newARCCache(opts.maxEntries, opts.stale)
	}
}

func (v *cacheValue) evaluate(query *dns.Msg, now time.Time, stale staleOptions) (*dns.Msg, entryState) {
	age := uint32(now.Sub(v.stored) / time.Second)
	if age < v.ttl {
		result := v.response.Copy()
		result.Id = query.Id
		result.Question = append(result.Question[:0], query.Question...)
		eachRR(result, func(rr dns.RR) { rr.Header().Ttl -= min(age, rr.Header().Ttl) })
		return result, entryFresh
	}
	if stale.enabled {
		staleLimit := v.ttl + uint32(math.Ceil(stale.staleTTL.Seconds()))
		if stale.staleTTL == 0 || age < staleLimit {
			result := v.response.Copy()
			result.Id = query.Id
			result.Question = append(result.Question[:0], query.Question...)
			serveTTL := stale.serveTTL
			if serveTTL == 0 {
				serveTTL = 5
			}
			eachRR(result, func(rr dns.RR) { rr.Header().Ttl = serveTTL })
			return result, entryStale
		}
	}
	return nil, entryMiss
}

func makeKey(policy string, query *dns.Msg) (cacheKey, bool) {
	// Other flags and sections can affect the response. Treat options such as ECS
	// and cookies as uncacheable, while separating DO and EDNS presence.
	if len(query.Answer) != 0 || len(query.Ns) != 0 || len(query.Extra) > 1 {
		return cacheKey{}, false
	}
	var flags uint8
	if query.RecursionDesired {
		flags |= 1
	}
	if query.CheckingDisabled {
		flags |= 2
	}
	if query.AuthenticatedData {
		flags |= 4
	}
	if len(query.Extra) == 1 {
		opt, ok := query.Extra[0].(*dns.OPT)
		if !ok || opt.Version() != 0 || len(opt.Option) != 0 || opt.Z() != 0 {
			return cacheKey{}, false
		}
		flags |= 8
		if opt.Do() {
			flags |= 16
		}
	}
	question := query.Question[0]
	question.Name = dns.CanonicalName(question.Name)
	return cacheKey{policy, question, flags}, true
}

func cacheTTL(response *dns.Msg, qtype uint16) uint32 {
	if response.Truncated || (response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError) {
		return 0
	}
	// Cached responses must not carry per-client EDNS data or transaction authentication.
	for _, rr := range response.Extra {
		if opt, ok := rr.(*dns.OPT); ok && len(opt.Option) != 0 {
			return 0
		}
		if rr.Header().Rrtype == dns.TypeTSIG || rr.Header().Rrtype == dns.TypeSIG {
			return 0
		}
	}
	ttl := uint32(86400)
	if response.Rcode == dns.RcodeNameError || !hasAnswerType(response, qtype) {
		var negative uint32
		for _, rr := range response.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				negative = min(soa.Hdr.Ttl, soa.Minttl)
				break
			}
		}
		if negative == 0 {
			return 0
		}
		ttl = min(ttl, negative)
	}
	eachRR(response, func(rr dns.RR) { ttl = min(ttl, rr.Header().Ttl) })
	return ttl
}

func hasAnswerType(response *dns.Msg, qtype uint16) bool {
	for _, rr := range response.Answer {
		if qtype == dns.TypeANY || rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

func eachRR(msg *dns.Msg, apply func(dns.RR)) {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT {
				apply(rr)
			}
		}
	}
}
