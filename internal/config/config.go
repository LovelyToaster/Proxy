package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	Version   int                 `yaml:"version"`
	Network   Network             `yaml:"network"`
	Capture   Capture             `yaml:"capture"`
	Listeners []Listener          `yaml:"listeners"`
	Outbounds map[string]Outbound `yaml:"outbounds"`
	Routing   Routing             `yaml:"routing"`
	DNS       DNS                 `yaml:"dns"`
	Geo       Geo                 `yaml:"geo"`
	Service   Service             `yaml:"service"`
	Web       Web                 `yaml:"web"`
}

type Web struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

type Service struct {
	Autostart   bool   `yaml:"autostart"`
	StatusGroup string `yaml:"status_group"`
}

type Network struct {
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	MaxConnections int           `yaml:"max_connections"`
	UDPTimeout     time.Duration `yaml:"udp_timeout"`
	MaxUDPSessions int           `yaml:"max_udp_sessions"`
}

type Capture struct {
	Mode                string         `yaml:"mode"`
	Scope               string         `yaml:"scope"`
	IPv4                bool           `yaml:"ipv4"`
	IPv6                bool           `yaml:"ipv6"`
	Port                uint16         `yaml:"port"`
	CIDRs               []netip.Prefix `yaml:"cidrs"`
	Ports               []uint16       `yaml:"ports"`
	Interfaces          []string       `yaml:"interfaces"`
	Namespace           string         `yaml:"namespace"`
	UDP                 bool           `yaml:"udp"`
	DNSHijack           bool           `yaml:"-"`
	WFPApplication      string         `yaml:"wfp_application"`
	WindowsApplication  string         `yaml:"windows_application"`
	ExcludeApplications []string       `yaml:"exclude_applications"`
}

type Listener struct {
	Address netip.AddrPort `yaml:"address"`
	Target  netip.AddrPort `yaml:"target"`
	Network string         `yaml:"network"`
}

type Outbound struct {
	Type        string `yaml:"type"`
	Address     string `yaml:"address"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	UDP         bool   `yaml:"udp"`
	UDPFallback string `yaml:"udp_fallback"`
}

type Routing struct {
	GeoIPDB string `yaml:"geoip_db"`
	Rules   []Rule `yaml:"rules"`
}

type Rule struct {
	CIDR      netip.Prefix `yaml:"cidr"`
	GeoIP     string       `yaml:"geoip"`
	Port      string       `yaml:"port"`
	Network   string       `yaml:"network"`
	Outbound  string       `yaml:"outbound"`
	PortFirst uint16       `yaml:"-"`
	PortLast  uint16       `yaml:"-"`
}

func (r Rule) Default() bool {
	return !r.CIDR.IsValid() && r.GeoIP == "" && r.Port == "" && r.Network == ""
}

var (
	wfpAppPath    = regexp.MustCompile(`(?i)^[a-z]:[\\/].+\.exe$`)
	interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
	namespaceID   = regexp.MustCompile(`^net:\[[0-9]+\]$`)
	countryCode   = regexp.MustCompile(`^[A-Z]{2}$`)
)

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	cfg := Config{
		Version: 1,
		Network: Network{ConnectTimeout: 10 * time.Second, IdleTimeout: 5 * time.Minute, MaxConnections: 256, UDPTimeout: 60 * time.Second, MaxUDPSessions: 256},
		Capture: Capture{Mode: "off", IPv4: true, IPv6: true, Port: 15080},
		DNS:     DNS{Listen: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:15353"), netip.MustParseAddrPort("[::1]:15353")}, Timeout: 4 * time.Second, Cache: DNSCache{Enabled: true, MaxEntries: 4096, Algorithm: "arc", Stale: DNSCacheStale{StaleTTL: 24 * time.Hour, ServeTTL: 5 * time.Second}, Persist: DNSCachePersist{File: "data/dns_cache.dat", SyncInterval: time.Hour}}},
	}
	info, err := file.Stat()
	if err != nil {
		return Config{}, err
	}
	const limit = 1 << 20
	if !info.Mode().IsRegular() || info.Size() > limit {
		return Config{}, errors.New("configuration must be a regular file at most 1 MiB")
	}
	decoder := yaml.NewDecoder(io.LimitReader(file, limit+1))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Config{}, errors.New("configuration must contain one YAML document")
	}
	if cfg.DNS.Cache.Algorithm == "" {
		cfg.DNS.Cache.Algorithm = "arc"
	}
	if cfg.DNS.Cache.Stale.StaleTTL == 0 {
		cfg.DNS.Cache.Stale.StaleTTL = 24 * time.Hour
	}
	if cfg.DNS.Cache.Stale.ServeTTL == 0 {
		cfg.DNS.Cache.Stale.ServeTTL = 5 * time.Second
	}
	if cfg.DNS.Cache.Persist.File == "" {
		cfg.DNS.Cache.Persist.File = "data/dns_cache.dat"
	}
	if cfg.DNS.Cache.Persist.SyncInterval < 0 {
		cfg.DNS.Cache.Persist.SyncInterval = 0
	}
	if cfg.DNS.Hijack != nil {
		cfg.Capture.DNSHijack = *cfg.DNS.Hijack
	}
	if cfg.Routing.GeoIPDB == "" {
		for _, rule := range cfg.Routing.Rules {
			if rule.GeoIP != "" && !strings.EqualFold(rule.GeoIP, "private") {
				cfg.Routing.GeoIPDB = "data/geoip.dat"
				break
			}
		}
	}
	if cfg.DNS.GeoSiteFile == "" {
		for _, rule := range cfg.DNS.Rules {
			if rule.GeoSite != "" {
				cfg.DNS.GeoSiteFile = "data/geosite.dat"
				break
			}
		}
	}
	if cfg.Routing.GeoIPDB != "" && !filepath.IsAbs(cfg.Routing.GeoIPDB) {
		cfg.Routing.GeoIPDB = filepath.Join(filepath.Dir(path), cfg.Routing.GeoIPDB)
	}
	cfg.DNS.resolvePaths(filepath.Dir(path))
	if cfg.Web.Listen != "" {
		cfg.Web.Enabled = true
	} else if cfg.Web.Enabled {
		cfg.Web.Listen = "127.0.0.1:9100"
	}
	return cfg, cfg.validate()
}

// Capture intent selects the native backend when mode is omitted or auto.
// An explicit mode (including off) always keeps its original meaning.
func (c *Capture) UnmarshalYAML(node *yaml.Node) error {
	type plain Capture
	value := plain(*c)
	known := make(map[string]bool)
	typ := reflect.TypeOf(value)
	for i := 0; i < typ.NumField(); i++ {
		known[typ.Field(i).Tag.Get("yaml")] = true
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if !known[node.Content[i].Value] {
			return fmt.Errorf("unknown capture field %q", node.Content[i].Value)
		}
	}
	if err := node.Decode(&value); err != nil {
		return err
	}
	modeSet := false
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == "mode" {
			modeSet = true
		}
	}
	if value.Mode == "auto" || !modeSet && (value.Scope != "" || value.WindowsApplication != "" || value.Namespace != "" || len(value.Interfaces) > 0) {
		resolved, err := nativeCaptureMode(Capture(value), runtime.GOOS)
		if err != nil {
			return err
		}
		value.Mode = resolved
	}
	*c = Capture(value)
	return nil
}

func nativeCaptureMode(c Capture, platform string) (string, error) {
	switch platform {
	case "windows":
		if c.Namespace != "" || len(c.Interfaces) != 0 {
			return "", errors.New("Linux namespace/interfaces capture options are unavailable on Windows")
		}
		return "windivert", nil
	case "linux":
		if c.Scope == "application" || c.WindowsApplication != "" || c.WFPApplication != "" || len(c.ExcludeApplications) != 0 {
			return "", errors.New("Windows application capture options are unavailable on Linux")
		}
		if len(c.Interfaces) > 0 {
			return "gateway", nil
		}
		return "local", nil
	default:
		return "", fmt.Errorf("automatic capture is unsupported on %s", platform)
	}
}

func (c *Config) validate() error {
	if c.Version != 1 {
		return errors.New("version must be 1")
	}
	if c.Service.StatusGroup != "" && !regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,32}$`).MatchString(c.Service.StatusGroup) {
		return errors.New("invalid service.status_group")
	}
	if c.Network.ConnectTimeout <= 0 || c.Network.ConnectTimeout > time.Minute ||
		c.Network.IdleTimeout <= 0 || c.Network.MaxConnections < 1 || c.Network.MaxConnections > 16384 {
		return errors.New("invalid network timeouts or connection limit")
	}
	if c.Network.UDPTimeout <= 0 || c.Network.UDPTimeout > 24*time.Hour || c.Network.MaxUDPSessions < 1 || c.Network.MaxUDPSessions > 1024 {
		return errors.New("invalid UDP timeout or session limit")
	}
	if err := ValidateCapture(c.Capture); err != nil {
		return err
	}
	if c.Web.Enabled {
		if c.Web.Listen == "" {
			return errors.New("web.listen cannot be empty when web is enabled")
		}
		ap, err := netip.ParseAddrPort(c.Web.Listen)
		if err != nil {
			return fmt.Errorf("invalid web.listen address: %w", err)
		}
		if ap.Port() == 0 {
			return errors.New("invalid web.listen port")
		}
		if c.Capture.Mode != "off" && ap.Port() == c.Capture.Port {
			return errors.New("web.listen overlaps the capture port")
		}
	}
	for i := range c.Listeners {
		if c.Listeners[i].Network == "" {
			c.Listeners[i].Network = "tcp"
		}
	}
	for i, l := range c.Listeners {
		if l.Network != "tcp" && l.Network != "udp" {
			return fmt.Errorf("listeners[%d]: expected tcp or udp", i)
		}
		if !l.Address.Addr().IsLoopback() || l.Address.Port() == 0 || !l.Target.IsValid() ||
			l.Target.Addr().IsUnspecified() || l.Target.Port() == 0 {
			return fmt.Errorf("listeners[%d]: expected a loopback address and a concrete target", i)
		}
		if c.Capture.Mode != "off" && l.Address.Port() == c.Capture.Port {
			return fmt.Errorf("listeners[%d]: address overlaps the capture port", i)
		}
		for _, other := range c.Listeners {
			if other.Network == l.Network && other.Address == l.Target {
				return fmt.Errorf("listeners[%d]: target is another listener", i)
			}
		}
	}
	for name, o := range c.Outbounds {
		if strings.TrimSpace(name) == "" {
			return errors.New("outbound names cannot be empty")
		}
		if err := o.validate(); err != nil {
			return fmt.Errorf("outbounds.%s: %w", name, err)
		}
		if o.UDPFallback != "" {
			fallback := c.Outbounds[o.UDPFallback]
			if o.Type != "http" || !(fallback.Type == "direct" || fallback.Type == "socks5" && fallback.UDP) {
				return fmt.Errorf("outbounds.%s: udp_fallback requires a direct or UDP-enabled socks5 outbound", name)
			}
		}
	}
	if len(c.Routing.Rules) == 0 {
		return errors.New("routing.rules requires a final default")
	}
	for i := range c.Routing.Rules {
		r := &c.Routing.Rules[i]
		if _, ok := c.Outbounds[r.Outbound]; !ok {
			return fmt.Errorf("routing.rules[%d]: unknown outbound", i)
		}
		if r.Default() != (i == len(c.Routing.Rules)-1) {
			return errors.New("routing.rules requires exactly one default as its final entry")
		}
		if r.Network != "" && r.Network != "tcp" && r.Network != "udp" {
			return fmt.Errorf("routing.rules[%d]: network must be tcp or udp", i)
		}
		if r.CIDR.IsValid() && r.CIDR.Addr().Is4In6() {
			return fmt.Errorf("routing.rules[%d]: use a native IPv4 prefix", i)
		}
		r.CIDR = r.CIDR.Masked()
		if r.Port != "" {
			first, last, err := portRange(r.Port)
			if err != nil {
				return fmt.Errorf("routing.rules[%d]: %w", i, err)
			}
			r.PortFirst, r.PortLast = first, last
		}
		if r.GeoIP != "" && !strings.EqualFold(r.GeoIP, "private") {
			r.GeoIP = strings.ToUpper(r.GeoIP)
			if !countryCode.MatchString(r.GeoIP) || c.Routing.GeoIPDB == "" {
				return fmt.Errorf("routing.rules[%d]: GeoIP country requires a two-letter code and routing.geoip_db", i)
			}
		} else {
			r.GeoIP = strings.ToLower(r.GeoIP)
		}
	}
	if err := c.DNS.validate(c.Capture, c.Listeners); err != nil {
		return err
	}
	for name, up := range c.DNS.Upstreams {
		if up.Outbound != "" {
			if _, ok := c.Outbounds[up.Outbound]; !ok {
				return fmt.Errorf("dns.upstreams.%s: unknown outbound", name)
			}
			if up.Type != "doh" {
				return fmt.Errorf("dns.upstreams.%s: outbound is supported for doh only", name)
			}
		}
	}
	return c.Geo.validate()
}

func ValidateCapture(c Capture) error {
	if c.Mode == "off" {
		if c.DNSHijack {
			return errors.New("DNS hijack requires an active capture mode")
		}
		return nil
	}
	if c.Mode == "wfp" {
		return validateWFP(c)
	}
	if c.Mode == "windivert" {
		if c.Scope != "global" && !wfpAppPath.MatchString(c.WindowsApplication) {
			return errors.New("WinDivert requires an absolute windows_application .exe path")
		}
		if c.Scope == "application" || c.Scope == "global" {
			if c.Scope == "global" && c.WindowsApplication != "" {
				return errors.New("global capture must omit windows_application")
			}
			if len(c.ExcludeApplications) > 64 {
				return errors.New("too many excluded applications")
			}
			for _, app := range c.ExcludeApplications {
				if !wfpAppPath.MatchString(app) {
					return errors.New("excluded applications require absolute .exe paths")
				}
			}
			if c.Namespace != "" || len(c.Interfaces) != 0 || !c.IPv4 && !c.IPv6 || c.Port < 1024 || len(c.CIDRs) > 128 || len(c.Ports) > 64 {
				return errors.New("invalid WinDivert application scope")
			}
			for _, prefix := range c.CIDRs {
				if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() ||
					prefix.Addr().Is4() && !c.IPv4 || prefix.Addr().Is6() && !c.IPv6 {
					return errors.New("invalid WinDivert target prefix")
				}
			}
			for _, port := range c.Ports {
				if port == 0 || port == c.Port || port == 53 {
					return errors.New("invalid WinDivert target port; DNS 53 uses dns.hijack")
				}
			}
			return nil
		}
		if c.Scope != "" && c.Scope != "lab" {
			return errors.New("WinDivert scope must be lab, application or global")
		}
		legacy := c
		legacy.WFPApplication = c.WindowsApplication
		if err := validateWFP(legacy); err != nil {
			return fmt.Errorf("WinDivert scope: %w", err)
		}
		for _, prefix := range c.CIDRs {
			if !prefix.Addr().IsLoopback() {
				return errors.New("WinDivert prototype requires loopback targets")
			}
		}
		return nil
	}
	if c.Mode != "local" && c.Mode != "gateway" {
		return errors.New("capture.mode must be off, local, gateway, wfp or windivert")
	}
	global := c.Scope == "global"
	if c.Scope != "" && c.Scope != "lab" && !global {
		return errors.New("Linux capture.scope must be lab or global")
	}
	if c.WindowsApplication != "" || c.WFPApplication != "" || len(c.ExcludeApplications) != 0 {
		return errors.New("Linux capture does not support Windows application selectors")
	}
	if (!global || c.Namespace != "") && !namespaceID.MatchString(c.Namespace) {
		return errors.New("capture.namespace must identify the isolated Linux network namespace")
	}
	if !c.IPv4 && !c.IPv6 || c.Port < 1024 || !global && (len(c.CIDRs) == 0 || len(c.Ports) == 0 && !c.DNSHijack) {
		return errors.New("capture requires an address family, listener port, target CIDRs and target ports")
	}
	if (c.Mode == "gateway") != (len(c.Interfaces) > 0) {
		return errors.New("capture.interfaces is required for gateway mode only")
	}
	if len(c.CIDRs) > 128 || len(c.Ports) > 64 || len(c.Interfaces) > 8 ||
		len(c.CIDRs)*len(c.Ports)*max(1, len(c.Interfaces)) > 4096 {
		return errors.New("capture scope would generate too many rules")
	}
	for _, name := range c.Interfaces {
		if name == "lo" || !interfaceName.MatchString(name) {
			return errors.New("invalid capture interface")
		}
	}
	for _, prefix := range c.CIDRs {
		if !prefix.IsValid() || !global && prefix.Bits() == 0 || prefix != prefix.Masked() || prefix.Addr().Is4In6() ||
			prefix.Addr().Is4() && !c.IPv4 || prefix.Addr().Is6() && !c.IPv6 {
			return fmt.Errorf("invalid or disabled-family capture prefix %s", prefix)
		}
	}
	for _, port := range c.Ports {
		if port == 0 || port == c.Port || !global && port == 22 || port == 53 {
			return fmt.Errorf("port %d is excluded from ordinary capture; use dns.hijack for DNS 53", port)
		}
	}
	return nil
}

func validateWFP(c Capture) error {
	if !wfpAppPath.MatchString(c.WFPApplication) || c.Namespace != "" || len(c.Interfaces) != 0 {
		return errors.New("WFP prototype requires an absolute local .exe path")
	}
	if !c.IPv4 && !c.IPv6 || c.Port < 1024 || len(c.Ports) > 1 ||
		len(c.Ports) == 0 && (!c.DNSHijack || c.UDP) ||
		len(c.Ports) == 1 && (c.Ports[0] < 1024 || c.Ports[0] == c.Port) {
		return errors.New("WFP requires one high target port distinct from the listener port, or DNS-only capture")
	}
	v4, v6 := false, false
	for _, prefix := range c.CIDRs {
		ip := prefix.Addr()
		if !ip.IsValid() || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() ||
			ip == netip.MustParseAddr("255.255.255.255") || prefix.Bits() != ip.BitLen() {
			return errors.New("WFP requires exact, unicast target addresses")
		}
		if (c.UDP || c.DNSHijack) && !ip.IsLoopback() {
			return errors.New("WFP UDP and DNS capture require loopback targets")
		}
		if ip.Is4() {
			if v4 {
				return errors.New("WFP accepts one target per address family")
			}
			v4 = true
		} else {
			if v6 {
				return errors.New("WFP accepts one target per address family")
			}
			v6 = true
		}
	}
	if v4 != c.IPv4 || v6 != c.IPv6 {
		return errors.New("WFP requires exactly one target for each enabled address family")
	}
	return nil
}

func (o Outbound) validate() error {
	if o.UDP && o.Type != "socks5" {
		return errors.New("udp applies to SOCKS5 only")
	}
	switch o.Type {
	case "direct":
		if o.Address != "" || o.Username != "" || o.Password != "" {
			return errors.New("direct does not accept proxy parameters")
		}
		return nil
	case "socks5", "http":
	default:
		return errors.New("type must be direct, socks5 or http")
	}
	host, port, err := net.SplitHostPort(o.Address)
	if err != nil || host == "" || strings.ContainsAny(host, " \t\r\n") {
		return errors.New("proxy address must contain a host and numeric port")
	}
	if p, err := strconv.ParseUint(port, 10, 16); err != nil || p == 0 {
		return errors.New("invalid proxy port")
	}
	if (o.Username == "") != (o.Password == "") {
		return errors.New("both username and password are required for authentication")
	}
	if o.Type == "socks5" && (len(o.Username) > 255 || len(o.Password) > 255) {
		return errors.New("SOCKS5 credentials exceed 255 bytes")
	}
	if o.Type == "http" && strings.Contains(o.Username, ":") {
		return errors.New("HTTP Basic username cannot contain a colon")
	}
	return nil
}

func portRange(value string) (uint16, uint16, error) {
	first, last, ranged := strings.Cut(value, "-")
	if !ranged {
		last = first
	}
	start, err1 := strconv.ParseUint(first, 10, 16)
	end, err2 := strconv.ParseUint(last, 10, 16)
	if err1 != nil || err2 != nil || start == 0 || end < start {
		return 0, 0, fmt.Errorf("invalid port or range %q", value)
	}
	return uint16(start), uint16(end), nil
}
