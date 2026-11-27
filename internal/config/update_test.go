package config

import "testing"

func TestUpdateAndDefaultGeoConfig(t *testing.T) {
	cfg, _, err := loadText(t, minimalDNS)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Update.Repo != DefaultUpdateRepo || cfg.Update.Channel != DefaultUpdateChannel || cfg.Update.BaseURL != "" {
		t.Fatalf("unexpected update defaults: %+v", cfg.Update)
	}
	if cfg.Geo.GeoIP.URL != DefaultGeoIPURL || cfg.Geo.GeoSite.URL != DefaultGeoSiteURL {
		t.Fatalf("unexpected geo URL defaults: %+v", cfg.Geo)
	}

	custom := minimalDNS + `
update:
  repo: my-org/ProxyFork
  base_url: https://mirror.example.com/releases/
  channel: prerelease
geo:
  geoip:
    url: https://example.com/custom-geoip.dat
`
	cfg, _, err = loadText(t, custom)
	if err != nil {
		t.Fatalf("valid custom update/geo config failed: %v", err)
	}
	if cfg.Update.Repo != "my-org/ProxyFork" || cfg.Update.BaseURL != "https://mirror.example.com/releases" || cfg.Update.Channel != "prerelease" {
		t.Fatalf("unexpected custom update: %+v", cfg.Update)
	}
	if cfg.Geo.GeoIP.URL != "https://example.com/custom-geoip.dat" || cfg.Geo.GeoSite.URL != DefaultGeoSiteURL {
		t.Fatalf("unexpected custom geo: %+v", cfg.Geo)
	}

	for _, bad := range []string{
		"update:\n  repo: invalid-repo\n",
		"update:\n  channel: nightly\n",
		"update:\n  base_url: http://example.com/mirror\n",
	} {
		if _, _, err := loadText(t, minimalDNS+"\n"+bad); err == nil {
			t.Fatalf("expected error for invalid update config: %s", bad)
		}
	}
}
