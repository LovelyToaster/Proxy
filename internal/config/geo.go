package config

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"net/url"
	"time"
)

type Geo struct {
	GeoIP    DataSource    `yaml:"geoip"`
	GeoSite  DataSource    `yaml:"geosite"`
	Interval time.Duration `yaml:"interval"`
}

type DataSource struct {
	URL    string `yaml:"url"`
	SHA256 string `yaml:"sha256"`
}

func (g Geo) validate() error {
	if g.Interval < 0 || g.Interval > 0 && g.Interval < time.Minute {
		return errors.New("geo.interval must be zero or at least one minute")
	}
	if g.Interval > 0 && g.GeoIP.URL == "" && g.GeoSite.URL == "" {
		return errors.New("automatic geo update requires a source")
	}
	for _, item := range []DataSource{g.GeoIP, g.GeoSite} {
		if item.URL == "" {
			if item.SHA256 != "" {
				return errors.New("geo.sha256 requires a source URL")
			}
			continue
		}
		u, err := url.Parse(item.URL)
		if err != nil || !AllowedGeoURL(u) {
			return errors.New("geo sources require HTTPS or an explicit loopback HTTP address")
		}
		if item.SHA256 != "" {
			value, err := hex.DecodeString(item.SHA256)
			if err != nil || len(value) != 32 {
				return errors.New("geo.sha256 must contain a SHA-256 digest")
			}
		}
	}
	return nil
}

func AllowedGeoURL(u *url.URL) bool {
	if u == nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return u.Scheme == "http" && err == nil && ip.IsLoopback()
}
