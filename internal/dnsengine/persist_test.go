package dnsengine

import (
	"bytes"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"proxy.local/m0/internal/config"
)

func TestPersistRoundtrip(t *testing.T) {
	req1 := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	key1, _ := makeKey("default", req1)
	resp1 := new(dns.Msg).SetReply(req1)
	rr1, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	resp1.Answer = []dns.RR{rr1}

	req2 := new(dns.Msg).SetQuestion("ipv6.example.org.", dns.TypeAAAA)
	key2, _ := makeKey("custom", req2)
	resp2 := new(dns.Msg).SetReply(req2)
	rr2, _ := dns.NewRR("ipv6.example.org. 600 IN AAAA 2001:db8::1")
	resp2.Answer = []dns.RR{rr2}

	now := time.Now().Truncate(time.Second)
	entries := []cacheSnapshot{
		{Key: key1, Response: resp1, Stored: now, TTL: 300, Frequent: true},
		{Key: key2, Response: resp2, Stored: now, TTL: 600, Frequent: false},
	}

	var buf bytes.Buffer
	if err := savePersist(&buf, entries); err != nil {
		t.Fatalf("savePersist failed: %v", err)
	}

	loaded, err := loadPersist(&buf, now, staleOptions{})
	if err != nil {
		t.Fatalf("loadPersist failed: %v", err)
	}

	if len(loaded) != 2 {
		t.Fatalf("expected 2 loaded entries, got %d", len(loaded))
	}

	// Verify entry 1
	e1 := loaded[0]
	if e1.Key.policy != "default" || e1.Key.question.Name != "example.com." || e1.Key.question.Qtype != dns.TypeA {
		t.Fatalf("unexpected e1 key: %+v", e1.Key)
	}
	if !e1.Frequent || e1.TTL != 300 || len(e1.Response.Answer) != 1 {
		t.Fatalf("unexpected e1 meta: %+v", e1)
	}
	if e1.Response.Answer[0].(*dns.A).A.String() != "93.184.216.34" {
		t.Fatalf("unexpected IP: %v", e1.Response.Answer[0])
	}

	// Verify entry 2
	e2 := loaded[1]
	if e2.Key.policy != "custom" || e2.Key.question.Name != "ipv6.example.org." || e2.Frequent {
		t.Fatalf("unexpected e2: %+v", e2)
	}
	if e2.Response.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::1" {
		t.Fatalf("unexpected IPv6: %v", e2.Response.Answer[0])
	}
}

func TestPersistCRCAndCorruption(t *testing.T) {
	req := new(dns.Msg).SetQuestion("test.com.", dns.TypeA)
	key, _ := makeKey("default", req)
	resp := new(dns.Msg).SetReply(req)
	rr, _ := dns.NewRR("test.com. 100 IN A 1.2.3.4")
	resp.Answer = []dns.RR{rr}

	entries := []cacheSnapshot{
		{Key: key, Response: resp, Stored: time.Now(), TTL: 100},
	}

	var buf bytes.Buffer
	_ = savePersist(&buf, entries)
	data := buf.Bytes()

	// 1. Corrupt one byte in payload
	corrupted := make([]byte, len(data))
	copy(corrupted, data)
	corrupted[15] ^= 0xFF

	if _, err := loadPersist(bytes.NewReader(corrupted), time.Now(), staleOptions{}); err == nil {
		t.Fatal("expected CRC error on corrupted payload")
	}

	// 2. Corrupt magic header
	badMagic := make([]byte, len(data))
	copy(badMagic, data)
	badMagic[0] = 'X'
	// Fix CRC for this test
	if _, err := loadPersist(bytes.NewReader(badMagic), time.Now(), staleOptions{}); err == nil {
		t.Fatal("expected error on invalid magic")
	}

	// 3. Truncated data
	if _, err := loadPersist(bytes.NewReader(data[:8]), time.Now(), staleOptions{}); err == nil {
		t.Fatal("expected error on truncated data")
	}
}

func TestPersistExpirationFiltering(t *testing.T) {
	now := time.Now()
	req := new(dns.Msg).SetQuestion("expire.test.", dns.TypeA)
	key, _ := makeKey("p", req)
	resp := new(dns.Msg).SetReply(req)
	rr, _ := dns.NewRR("expire.test. 60 IN A 1.2.3.4")
	resp.Answer = []dns.RR{rr}

	entries := []cacheSnapshot{
		// Stored 100s ago, TTL=60s -> Expired (age 100 > TTL 60)
		{Key: key, Response: resp, Stored: now.Add(-100 * time.Second), TTL: 60},
	}

	var buf bytes.Buffer
	_ = savePersist(&buf, entries)

	// 1. Without stale enabled: expired entry is dropped
	loaded, err := loadPersist(bytes.NewReader(buf.Bytes()), now, staleOptions{enabled: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("expected expired entry to be filtered, got %d", len(loaded))
	}

	// 2. With stale enabled (staleTTL=300s): entry is in stale window (60 + 300 = 360 > 100), so kept!
	staleOpts := staleOptions{enabled: true, staleTTL: 300 * time.Second, serveTTL: 5}
	loaded, err = loadPersist(bytes.NewReader(buf.Bytes()), now, staleOpts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected stale entry to be preserved, got %d", len(loaded))
	}
}

func TestPersistFileAtomicSaveLoad(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "dns", "cache.dat")

	req := new(dns.Msg).SetQuestion("atomic.test.", dns.TypeA)
	key, _ := makeKey("default", req)
	resp := new(dns.Msg).SetReply(req)
	rr, _ := dns.NewRR("atomic.test. 300 IN A 8.8.8.8")
	resp.Answer = []dns.RR{rr}

	now := time.Now()
	entries := []cacheSnapshot{
		{Key: key, Response: resp, Stored: now, TTL: 300, Frequent: true},
	}

	// Save to file (directory does not exist yet; saveToFile will create it)
	if err := saveToFile(filePath, entries); err != nil {
		t.Fatalf("saveToFile failed: %v", err)
	}

	// Load from file
	loaded, err := loadFromFile(filePath, now, staleOptions{})
	if err != nil {
		t.Fatalf("loadFromFile failed: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Key.question.Name != "atomic.test." {
		t.Fatalf("unexpected loaded data: %+v", loaded)
	}

	// Load non-existent file returns nil, nil
	none, err := loadFromFile(filepath.Join(tempDir, "missing.dat"), now, staleOptions{})
	if err != nil || none != nil {
		t.Fatalf("expected nil for missing file, got %v, %v", none, err)
	}
}

func TestCacheSnapshotAndRestore(t *testing.T) {
	now := time.Now()
	arc := newARCCache(10, staleOptions{})

	// Add 2 items to ARC: 1 frequent (hit twice), 1 recency (hit once)
	req1 := new(dns.Msg).SetQuestion("t2.test.", dns.TypeA)
	key1, _ := makeKey("p", req1)
	arc.put(key1, makeTestMsg("t2.test.", 300), now)
	arc.get(key1, req1, now) // 2nd hit -> T2

	req2 := new(dns.Msg).SetQuestion("t1.test.", dns.TypeA)
	key2, _ := makeKey("p", req2)
	arc.put(key2, makeTestMsg("t1.test.", 300), now) // 1st hit -> T1

	snapshots := arc.snapshot()
	if len(snapshots) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snapshots))
	}

	// Restore into a fresh ARC cache
	arcNew := newARCCache(10, staleOptions{})
	arcNew.restore(snapshots, now)

	if arcNew.size() != 2 {
		t.Fatalf("expected restored size 2, got %d", arcNew.size())
	}

	// Verify both hit
	if msg, state := arcNew.get(key1, req1, now); state != entryFresh || msg == nil {
		t.Fatalf("expected key1 fresh hit, got state %v", state)
	}
	if msg, state := arcNew.get(key2, req2, now); state != entryFresh || msg == nil {
		t.Fatalf("expected key2 fresh hit, got state %v", state)
	}
}

func TestEnginePersistenceLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	cachePath := filepath.Join(tempDir, "dns_cache.dat")

	var upstreamCalls atomic.Uint64
	mock := &mockUpstream{
		fn: func(req *dns.Msg) (*dns.Msg, error) {
			upstreamCalls.Add(1)
			resp := new(dns.Msg).SetReply(req)
			rr, _ := dns.NewRR(req.Question[0].Name + " 300 IN A 1.2.3.4")
			resp.Answer = []dns.RR{rr}
			return resp, nil
		},
	}

	persistTrue := true
	cfg := config.DNS{
		Enabled: true,
		Timeout: time.Second,
		Cache: config.DNSCache{
			Enabled:    true,
			MaxEntries: 16,
			Algorithm:  "arc",
			Persist: config.DNSCachePersist{
				Enabled: &persistTrue,
				File:    cachePath,
			},
		},
	}

	// 1. First Engine session
	e1 := &Engine{
		upstreams:    map[string]upstream.Upstream{"default": mock},
		rules:        []config.DNSRule{{Upstream: "default"}},
		cache:        newARCCache(16, staleOptions{}),
		workers:      make(chan struct{}, 128),
		cachePersist: cfg.Cache.Persist,
	}

	req := new(dns.Msg).SetQuestion("lifecycle.test.", dns.TypeA)
	// Query e1 -> will call upstream
	ans1 := e1.handle(req)
	if len(ans1.Answer) != 1 || ans1.Answer[0].(*dns.A).A.String() != "1.2.3.4" {
		t.Fatalf("unexpected ans1: %v", ans1)
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("expected 1 upstream call, got %d", upstreamCalls.Load())
	}

	// Close e1 -> saves cache to cachePath
	if err := e1.Close(); err != nil {
		t.Fatalf("e1.Close failed: %v", err)
	}

	// Verify file was written
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected cache file %s to exist, err: %v", cachePath, err)
	}

	// 2. Second Engine session: simulate restart by restoring from file
	loaded, err := loadFromFile(cachePath, time.Now(), staleOptions{})
	if err != nil || len(loaded) != 1 {
		t.Fatalf("loadFromFile failed: err=%v, count=%d", err, len(loaded))
	}

	cache2 := newARCCache(16, staleOptions{})
	cache2.restore(loaded, time.Now())

	e2 := &Engine{
		upstreams:    map[string]upstream.Upstream{"default": mock},
		rules:        []config.DNSRule{{Upstream: "default"}},
		cache:        cache2,
		workers:      make(chan struct{}, 128),
		cachePersist: cfg.Cache.Persist,
	}

	// Query e2 -> should hit restored cache without calling upstream!
	ans2 := e2.handle(req)
	if len(ans2.Answer) != 1 || ans2.Answer[0].(*dns.A).A.String() != "1.2.3.4" {
		t.Fatalf("unexpected ans2: %v", ans2)
	}
	if calls := upstreamCalls.Load(); calls != 1 {
		t.Fatalf("expected upstream to NOT be called again (remains 1), got %d", calls)
	}
	if e2.Status().CacheHits != 1 {
		t.Fatalf("expected 1 cache hit on restored cache, got %d", e2.Status().CacheHits)
	}

	// 3. Flush e2 -> should delete cache file
	if err := e2.Flush(); err != nil {
		t.Fatalf("e2.Flush failed: %v", err)
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("expected cache file %s to be deleted on Flush", cachePath)
	}
}

func TestPersistSkipsNegativeEntries(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	posReq := new(dns.Msg).SetQuestion("pos.test.", dns.TypeA)
	posKey, _ := makeKey("default", posReq)
	posResp := makeTestMsg("pos.test.", 300)

	nxReq := new(dns.Msg).SetQuestion("nx.test.", dns.TypeA)
	nxKey, _ := makeKey("default", nxReq)
	nxResp := new(dns.Msg).SetRcode(nxReq, dns.RcodeNameError)

	ndReq := new(dns.Msg).SetQuestion("nd.test.", dns.TypeAAAA)
	ndKey, _ := makeKey("default", ndReq)
	ndResp := new(dns.Msg).SetReply(ndReq)

	// 1. snapshot() skips negative entries for both ARC and LRU
	for _, tc := range []struct {
		name  string
		cache dnsCache
	}{
		{"arc", newCacheWithOptions(cacheOptions{algorithm: "arc", maxEntries: 16, negativeTTL: 60})},
		{"lru", newCacheWithOptions(cacheOptions{algorithm: "lru", maxEntries: 16, negativeTTL: 60})},
	} {
		t.Run(tc.name+"_snapshot", func(t *testing.T) {
			tc.cache.put(posKey, posResp, now)
			tc.cache.put(nxKey, nxResp, now)
			tc.cache.put(ndKey, ndResp, now)
			if tc.cache.size() != 3 {
				t.Fatalf("expected 3 entries in memory, got %d", tc.cache.size())
			}
			snaps := tc.cache.snapshot()
			if len(snaps) != 1 || snaps[0].Key != posKey {
				t.Fatalf("expected snapshot to contain only positive entry, got %d entries", len(snaps))
			}
		})
	}

	// 2. loadPersist() skips both fresh and stale negative entries from legacy cache files
	legacyEntries := []cacheSnapshot{
		{Key: posKey, Response: posResp, Stored: now, TTL: 300, Frequent: true},
		{Key: nxKey, Response: nxResp, Stored: now, TTL: 60, Frequent: false},
		{Key: ndKey, Response: ndResp, Stored: now.Add(-100 * time.Second), TTL: 60, Frequent: false},
	}
	var buf bytes.Buffer
	if err := savePersist(&buf, legacyEntries); err != nil {
		t.Fatalf("savePersist failed: %v", err)
	}
	staleOpts := staleOptions{enabled: true, staleTTL: 24 * time.Hour, serveTTL: 5}
	loaded, err := loadPersist(bytes.NewReader(buf.Bytes()), now, staleOpts)
	if err != nil {
		t.Fatalf("loadPersist failed: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Key != posKey {
		t.Fatalf("expected loadPersist to keep only positive entry, got %d entries", len(loaded))
	}

	// 3. restore() also skips negative entries directly for both ARC and LRU
	for _, tc := range []struct {
		name  string
		cache dnsCache
	}{
		{"arc", newARCCache(16, staleOpts)},
		{"lru", newLRUCache(16, staleOpts)},
	} {
		t.Run(tc.name+"_restore", func(t *testing.T) {
			tc.cache.restore(legacyEntries, now)
			if tc.cache.size() != 1 {
				t.Fatalf("expected restore to keep only 1 positive entry, got %d", tc.cache.size())
			}
			if _, state := tc.cache.get(posKey, posReq, now); state != entryFresh {
				t.Fatalf("expected positive entry restored, got state=%v", state)
			}
			if _, state := tc.cache.get(nxKey, nxReq, now); state != entryMiss {
				t.Fatalf("expected NXDOMAIN skipped on restore, got state=%v", state)
			}
			if _, state := tc.cache.get(ndKey, ndReq, now); state != entryMiss {
				t.Fatalf("expected NODATA skipped on restore, got state=%v", state)
			}
		})
	}
}
