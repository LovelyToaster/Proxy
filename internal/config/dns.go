package config

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type DNS struct {
	Hijack      *bool                  `yaml:"hijack"`
	Enabled     bool                   `yaml:"enabled"`
	Listen      []netip.AddrPort       `yaml:"listen"`
	Timeout     time.Duration          `yaml:"timeout"`
	Cache       DNSCache               `yaml:"cache"`
	GeoSiteFile string                 `yaml:"geosite_file"`
	Upstreams   map[string]DNSUpstream `yaml:"upstreams"`
	Rules       []DNSRule              `yaml:"rules"`
	Fallback    string                 `yaml:"fallback_upstream"`
}

type DNSCache struct {
	Enabled     bool            `yaml:"enabled"`
	MaxEntries  int             `yaml:"max_entries"`
	Algorithm   string          `yaml:"algorithm"`
	NegativeTTL time.Duration   `yaml:"negative_ttl"`
	Stale       DNSCacheStale   `yaml:"stale"`
	Persist     DNSCachePersist `yaml:"persist"`
}

type DNSCacheStale struct {
	Enabled  *bool         `yaml:"enabled"`
	StaleTTL time.Duration `yaml:"stale_ttl"`
	ServeTTL time.Duration `yaml:"serve_ttl"`
}

func (s DNSCacheStale) IsEnabled() bool {
	if s.Enabled == nil {
		return true
	}
	return *s.Enabled
}

type DNSCachePersist struct {
	Enabled      *bool         `yaml:"enabled"`
	File         string        `yaml:"file"`
	SyncInterval time.Duration `yaml:"sync_interval"`
}

func (p DNSCachePersist) IsEnabled() bool {
	if p.Enabled == nil {
		return true
	}
	return *p.Enabled
}

type DNSUpstream struct {
	Type      string           `yaml:"type"`
	Outbound  string           `yaml:"outbound"`
	Address   string           `yaml:"address"`
	Bootstrap []netip.AddrPort `yaml:"bootstrap"`
}

type DNSRule struct {
	GeoSite      string `yaml:"geosite"`
	Domain       string `yaml:"domain"`
	DomainSuffix string `yaml:"domain_suffix"`
	Upstream     string `yaml:"upstream"`
}

func (r DNSRule) Default() bool {
	return r.GeoSite == "" && r.Domain == "" && r.DomainSuffix == ""
}

func (r DNSRule) MatchDomain(name string) bool {
	name = normalizeDomain(name)
	if r.Domain != "" {
		return name == normalizeDomain(r.Domain)
	}
	if r.DomainSuffix != "" {
		suffix := normalizeDomain(r.DomainSuffix)
		return name == suffix || strings.HasSuffix(name, "."+suffix)
	}
	return false
}

func normalizeDomain(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

var domainLabel = regexp.MustCompile(`^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$`)

func validDomain(name string) bool {
	name = normalizeDomain(name)
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !domainLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func (c *DNS) resolvePaths(directory string) {
	if c.GeoSiteFile != "" && !filepath.IsAbs(c.GeoSiteFile) {
		c.GeoSiteFile = filepath.Join(directory, c.GeoSiteFile)
	}
	if c.Cache.Persist.File != "" && !filepath.IsAbs(c.Cache.Persist.File) {
		c.Cache.Persist.File = filepath.Join(directory, c.Cache.Persist.File)
	}
}

func (c DNS) validate(capture Capture, listeners []Listener) error {
	if !c.Enabled {
		if capture.DNSHijack {
			return errors.New("dns.hijack requires dns.enabled")
		}
		return nil
	}
	if capture.Mode != "off" && !capture.DNSHijack {
		return errors.New("DNS with active capture requires dns.hijack for upstream bypass")
	}
	if c.Timeout <= 0 || c.Timeout > 10*time.Second || len(c.Listen) == 0 && !capture.DNSHijack || len(c.Listen) > 8 ||
		(c.Cache.Enabled && c.Cache.MaxEntries < 1) || c.Cache.MaxEntries < 0 || c.Cache.MaxEntries > 16384 ||
		len(c.Upstreams) == 0 || len(c.Upstreams) > 32 {
		return errors.New("invalid DNS timeout, listener, cache or upstream limits")
	}
	if c.Cache.Algorithm != "" && c.Cache.Algorithm != "arc" && c.Cache.Algorithm != "lru" {
		return errors.New("dns.cache.algorithm must be 'arc' or 'lru'")
	}
	if c.Cache.NegativeTTL < 0 || c.Cache.NegativeTTL > time.Hour {
		return errors.New("dns.cache.negative_ttl out of range")
	}
	if c.Cache.Stale.StaleTTL < 0 || c.Cache.Stale.StaleTTL > 24*time.Hour {
		return errors.New("dns.cache.stale.stale_ttl out of range")
	}
	if c.Cache.Stale.ServeTTL < 0 || c.Cache.Stale.ServeTTL > 60*time.Second {
		return errors.New("dns.cache.stale.serve_ttl out of range")
	}
	if c.Cache.Persist.SyncInterval < 0 || c.Cache.Persist.SyncInterval > 24*time.Hour {
		return errors.New("dns.cache.persist.sync_interval out of range")
	}
	seen := make(map[netip.AddrPort]bool)
	for _, addr := range c.Listen {
		if !addr.Addr().IsLoopback() || addr.Port() < 1024 || seen[addr] {
			return errors.New("DNS listeners must use distinct loopback endpoints on high ports")
		}
		if capture.Mode != "off" && addr.Port() == capture.Port {
			return errors.New("DNS listener overlaps the capture port")
		}
		seen[addr] = true
		for _, listener := range listeners {
			if listener.Address == addr {
				return errors.New("DNS listener overlaps a proxy listener")
			}
		}
	}
	for name, up := range c.Upstreams {
		if strings.TrimSpace(name) == "" {
			return errors.New("DNS upstream names cannot be empty")
		}
		switch up.Type {
		case "udp", "tcp", "doh", "doh3", "dot", "doq":
		case "system":
			if up.Address != "" || len(up.Bootstrap) != 0 {
				return errors.New("system DNS does not accept address or bootstrap")
			}
			continue
		default:
			return fmt.Errorf("dns.upstreams.%s: unsupported type %q", name, up.Type)
		}
		if len(up.Bootstrap) > 4 || up.Address == "" {
			return fmt.Errorf("dns.upstreams.%s: invalid address or bootstrap count", name)
		}
		for _, b := range up.Bootstrap {
			if !b.IsValid() || b.Addr().IsUnspecified() || b.Port() == 0 || seen[b] {
				return fmt.Errorf("dns.upstreams.%s: invalid or recursive bootstrap", name)
			}
		}
	}
	if c.Fallback != "" {
		if _, ok := c.Upstreams[c.Fallback]; !ok {
			return errors.New("unknown DNS fallback upstream")
		}
	}
	if len(c.Rules) == 0 || len(c.Rules) > 256 {
		return errors.New("DNS requires an ordered rule list ending in a default")
	}
	for i, r := range c.Rules {
		if _, ok := c.Upstreams[r.Upstream]; !ok {
			return fmt.Errorf("dns.rules[%d]: unknown upstream", i)
		}
		selectors := 0
		for _, value := range []string{r.GeoSite, r.Domain, r.DomainSuffix} {
			if value != "" {
				selectors++
			}
		}
		if selectors > 1 {
			return fmt.Errorf("dns.rules[%d]: choose one of geosite, domain or domain_suffix", i)
		}
		if r.Default() != (i == len(c.Rules)-1) {
			return errors.New("DNS requires a single default rule at the end")
		}
		if r.Domain != "" && !validDomain(r.Domain) || r.DomainSuffix != "" && !validDomain(r.DomainSuffix) {
			return fmt.Errorf("dns.rules[%d]: invalid domain; use an ASCII/IDNA name without wildcards", i)
		}
		if r.GeoSite != "" && (c.GeoSiteFile == "" || strings.ContainsAny(r.GeoSite, "@ \t\r\n")) {
			return fmt.Errorf("dns.rules[%d]: GEOSITE requires a data file and category", i)
		}
	}
	return nil
}
