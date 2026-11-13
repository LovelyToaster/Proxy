package core

import (
	"context"
	"errors"
	"log"
	"reflect"
	"time"

	"proxy.local/m0/internal/capture"
	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/dnsengine"
	"proxy.local/m0/internal/geodata"
	"proxy.local/m0/internal/geosite"
	"proxy.local/m0/internal/routing"
)

func (s *state) reload(path string) (uint64, error) {
	s.updates.Lock()
	defer s.updates.Unlock()
	cfg, err := config.Load(path)
	if err != nil {
		return 0, err
	}
	if cfg.Service.StatusGroup != s.cfg.Service.StatusGroup || !reflect.DeepEqual(cfg.Capture, s.cfg.Capture) || !reflect.DeepEqual(cfg.Listeners, s.cfg.Listeners) ||
		cfg.DNS.Enabled != s.cfg.DNS.Enabled || !reflect.DeepEqual(cfg.DNS.Listen, s.cfg.DNS.Listen) {
		return 0, errors.New("capture and listener changes require a restart")
	}
	if err := capture.ValidateUpstreamReload(cfg.Capture, s.cfg.Outbounds, cfg.Outbounds); err != nil {
		return 0, err
	}
	routes, dns, err := s.prepare(cfg, s.geo)
	if err != nil {
		return 0, err
	}
	if s.applyAutostart != nil {
		if err := s.applyAutostart(cfg.Service.Autostart); err != nil {
			routes.Close()
			dns.Close()
			return 0, err
		}
	}
	return s.publish(cfg, routes, dns, s.geo), nil
}

func (s *state) prepare(cfg config.Config, manifest geodata.Manifest) (*routing.Table, *dnsengine.Engine, error) {
	effective := s.store.Apply(cfg, manifest)
	routes, err := routing.Open(effective.Routing)
	if err != nil {
		return nil, nil, err
	}
	dns, err := dnsengine.New(effective.DNS, capture.Dialer(cfg.Capture), effective.Outbounds)
	if err != nil {
		routes.Close()
		return nil, nil, err
	}
	return routes, dns, nil
}

func (s *state) publish(cfg config.Config, routes *routing.Table, dns *dnsengine.Engine, manifest geodata.Manifest) uint64 {
	if dns != nil {
		s.dns.Replace(dns)
	}
	s.mu.Lock()
	old := s.routes
	intervalChanged := s.cfg.Geo.Interval != cfg.Geo.Interval
	s.cfg, s.routes, s.geo = cfg, routes, manifest
	s.generation++
	generation := s.generation
	s.snap.Store(&routeSnapshot{cfg: cfg, routes: routes, generation: generation})
	s.mu.Unlock()
	if intervalChanged {
		select {
		case s.geoTimer <- struct{}{}:
		default:
		}
	}
	old.Close()
	return generation
}

type geoStatus struct {
	Generation      uint64    `json:"generation"`
	GeoIP           string    `json:"geoip_sha256,omitempty"`
	GeoSite         string    `json:"geosite_sha256,omitempty"`
	PreviousGeoIP   string    `json:"previous_geoip_sha256,omitempty"`
	PreviousGeoSite string    `json:"previous_geosite_sha256,omitempty"`
	Updated         time.Time `json:"updated_at"`
}

func (s *state) geoStatus() geoStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return geoStatus{s.generation, s.geo.Current.GeoIP.SHA256, s.geo.Current.GeoSite.SHA256, s.geo.Previous.GeoIP.SHA256, s.geo.Previous.GeoSite.SHA256, s.geo.Updated}
}

func (s *state) updateGeo(ctx context.Context) (geoStatus, error) {
	s.updates.Lock()
	defer s.updates.Unlock()
	cfg, before := s.cfg, s.geo
	next := before
	defer func() { s.store.Prune(s.geo) }()
	var err error
	next, err = s.store.Stage(ctx, cfg.Geo, before, s.dns.Dialer(capture.Dialer(cfg.Capture)))
	if err != nil {
		return geoStatus{}, err
	}
	if next == before {
		return s.geoStatus(), nil
	}
	effective := s.store.Apply(cfg, next)
	if next.Current.GeoSite != before.Current.GeoSite && effective.DNS.GeoSiteFile != "" {
		if err := geosite.Validate(effective.DNS.GeoSiteFile); err != nil {
			return geoStatus{}, err
		}
	}
	routes, dns, err := s.prepare(cfg, next)
	if err != nil {
		return geoStatus{}, err
	}
	if err := s.store.Commit(next); err != nil {
		routes.Close()
		dns.Close()
		return geoStatus{}, err
	}
	s.publish(cfg, routes, dns, next)
	if s.runtimeDirectory != "" {
		s.store.PruneLegacy(s.runtimeDirectory, next)
	}
	return s.geoStatus(), nil
}

func (s *state) autoGeo(ctx context.Context) {
	for {
		s.mu.Lock()
		interval := s.cfg.Geo.Interval
		s.mu.Unlock()
		var deadline <-chan time.Time
		var timer *time.Timer
		if interval > 0 {
			timer = time.NewTimer(interval)
			deadline = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-s.geoTimer:
			if timer != nil {
				timer.Stop()
			}
		case <-deadline:
			if _, err := s.updateGeo(ctx); err != nil && ctx.Err() == nil {
				log.Printf("geo update: %v", err)
			}
		}
	}
}
