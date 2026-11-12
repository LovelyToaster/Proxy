package core

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/dnsengine"
	"proxy.local/m0/internal/geodata"
	"proxy.local/m0/internal/routing"
)

func TestGeoUpdateReplacesAndDeletesOldData(t *testing.T) {
	field := func(dst []byte, n protowire.Number, value []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(dst, n, protowire.BytesType), value)
	}
	makeDAT := func(domain string) []byte {
		pattern := field(nil, 2, []byte(domain))
		category := field(nil, 1, []byte("CN"))
		return field(nil, 1, field(category, 2, pattern))
	}
	var content atomic.Value
	content.Store(makeDAT("first.test"))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(content.Load().([]byte))
	}))
	defer upstream.Close()
	cfg := config.Config{
		Geo: config.Geo{GeoSite: config.DataSource{URL: upstream.URL}},
		DNS: config.DNS{Enabled: true, Timeout: time.Second, Rules: []config.DNSRule{{Upstream: "dns"}},
			Upstreams: map[string]config.DNSUpstream{"dns": {Type: "udp", Address: "127.0.0.1:53530"}}},
	}
	routes, err := routing.Open(cfg.Routing)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := dnsengine.New(cfg.DNS, net.Dialer{})
	if err != nil {
		routes.Close()
		t.Fatal(err)
	}
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if err := os.Mkdir(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	bundled := filepath.Join(dataDir, "geosite.dat")
	if err := os.WriteFile(bundled, makeDAT("bundled.test"), 0600); err != nil {
		t.Fatal(err)
	}
	state := &state{cfg: cfg, routes: routes, dns: engine, store: geodata.ForConfig(filepath.Join(dir, "proxy.yaml")), generation: 1}
	defer func() { state.routes.Close(); state.dns.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	first, err := state.updateGeo(ctx)
	if err != nil || first.Generation != 2 || first.GeoSite == "" {
		t.Fatalf("first update: %+v, %v", first, err)
	}
	if _, err := os.Stat(bundled); !os.IsNotExist(err) {
		t.Fatal("bundled previous data was not deleted")
	}
	firstManifest, err := state.store.Read()
	if err != nil {
		t.Fatal(err)
	}
	firstPath := filepath.Join(dataDir, firstManifest.Current.GeoSite.File)
	unchanged, err := state.updateGeo(ctx)
	if err != nil || unchanged.Generation != first.Generation {
		t.Fatalf("unchanged update: %+v, %v", unchanged, err)
	}

	content.Store([]byte("invalid protobuf"))
	if _, err := state.updateGeo(ctx); err == nil {
		t.Fatal("invalid database was accepted")
	}
	if current, err := state.store.Read(); err != nil || current.Current.GeoSite.SHA256 != first.GeoSite ||
		state.geoStatus().Generation != first.Generation {
		t.Fatalf("invalid update changed active state: %+v, %v", current, err)
	}

	content.Store(makeDAT("second.test"))
	second, err := state.updateGeo(ctx)
	if err != nil || second.Generation != 3 || second.GeoSite == first.GeoSite || second.PreviousGeoSite != "" {
		t.Fatalf("second update: %+v, %v", second, err)
	}
	if _, err := os.Stat(firstPath); !os.IsNotExist(err) {
		t.Fatal("previous downloaded data was not deleted")
	}
	if current, err := state.store.Read(); err != nil || current.Current.GeoSite.SHA256 != second.GeoSite || current.Previous != (geodata.Pair{}) {
		t.Fatalf("current state: %+v %v", current, err)
	}
}
