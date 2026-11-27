package dnsengine

import (
	"fmt"
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

type putRejectReason uint8

const (
	rejectNone putRejectReason = iota
	rejectUncacheable
	rejectNoSOA
)

type cacheKey struct {
	policy   string
	question dns.Question
	flags    uint8
}

func (k cacheKey) string() string {
	return fmt.Sprintf("%s:%s:%d:%d", k.policy, k.question.Name, k.question.Qtype, k.flags)
}

type cacheValue struct {
	key      cacheKey
	response *dns.Msg
	stored   time.Time
	ttl      uint32
	size     int
	negative bool
}

type staleOptions struct {
	enabled  bool
	staleTTL time.Duration
	serveTTL uint32
}

type cacheOptions struct {
	algorithm   string
	maxEntries  int
	negativeTTL uint32
	stale       staleOptions
}

type dnsCache interface {
	get(key cacheKey, query *dns.Msg, now time.Time) (*dns.Msg, entryState)
	put(key cacheKey, response *dns.Msg, now time.Time) putRejectReason
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
		c := newLRUCache(opts.maxEntries, opts.stale)
		c.negativeTTL = opts.negativeTTL
		return c
	default:
		c := newARCCache(opts.maxEntries, opts.stale)
		c.negativeTTL = opts.negativeTTL
		return c
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
	if !v.negative && stale.enabled {
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

func hasClientSpecificEDNS(opt *dns.OPT) bool {
	for _, o := range opt.Option {
		if _, ok := o.(*dns.EDNS0_SUBNET); ok {
			return true
		}
	}
	return false
}

func makeKey(policy string, query *dns.Msg) (cacheKey, bool) {
	// Other flags and sections can affect the response. Treat client-specific
	// options such as ECS as uncacheable, while ignoring stateless EDNS0 options
	// (e.g. Padding, Cookie, Keepalive) and sharing non-DO queries.
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
		if !ok || opt.Version() != 0 || opt.Z() != 0 || hasClientSpecificEDNS(opt) {
			return cacheKey{}, false
		}
		if opt.Do() {
			flags |= 16
		}
	}
	question := query.Question[0]
	question.Name = dns.CanonicalName(question.Name)
	return cacheKey{policy, question, flags}, true
}

func cacheTTL(response *dns.Msg, qtype uint16, negativeTTL uint32) (uint32, putRejectReason) {
	if response.Truncated || (response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError) {
		return 0, rejectUncacheable
	}
	// Cached responses must not carry client-specific EDNS data or transaction authentication.
	for _, rr := range response.Extra {
		if opt, ok := rr.(*dns.OPT); ok && hasClientSpecificEDNS(opt) {
			return 0, rejectUncacheable
		}
		if rr.Header().Rrtype == dns.TypeTSIG || rr.Header().Rrtype == dns.TypeSIG {
			return 0, rejectUncacheable
		}
	}
	ttl := uint32(86400)
	if isNegativeResponse(response, qtype) {
		var negative uint32
		for _, rr := range response.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				negative = min(soa.Hdr.Ttl, soa.Minttl)
				break
			}
		}
		if negative == 0 {
			if negativeTTL == 0 {
				return 0, rejectNoSOA
			}
			negative = negativeTTL
		} else if negativeTTL > 0 {
			negative = min(negative, negativeTTL)
		}
		ttl = min(ttl, negative)
	}
	eachRR(response, func(rr dns.RR) { ttl = min(ttl, rr.Header().Ttl) })
	if ttl == 0 {
		return 0, rejectUncacheable
	}
	return ttl, rejectNone
}

func prepareCacheValue(key cacheKey, response *dns.Msg, now time.Time, negativeTTL uint32) (*cacheValue, putRejectReason) {
	size := response.Len()
	if size > 16384 {
		return nil, rejectUncacheable
	}
	ttl, reason := cacheTTL(response, key.question.Qtype, negativeTTL)
	if ttl == 0 {
		return nil, reason
	}
	copyMsg := response.Copy()
	if len(copyMsg.Extra) > 0 {
		filtered := copyMsg.Extra[:0]
		for _, rr := range copyMsg.Extra {
			if rr.Header().Rrtype != dns.TypeOPT {
				filtered = append(filtered, rr)
			}
		}
		copyMsg.Extra = filtered
	}
	negative := isNegativeResponse(response, key.question.Qtype)
	if negative {
		eachRR(copyMsg, func(rr dns.RR) { rr.Header().Ttl = min(ttl, rr.Header().Ttl) })
	}
	return &cacheValue{
		key:      key,
		response: copyMsg,
		stored:   now,
		ttl:      ttl,
		size:     size,
		negative: negative,
	}, rejectNone
}

func isNegativeResponse(response *dns.Msg, qtype uint16) bool {
	return response.Rcode == dns.RcodeNameError || !hasAnswerType(response, qtype)
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
