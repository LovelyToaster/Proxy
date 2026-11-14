package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy.local/m0/internal/logbuffer"
	"proxy.local/m0/internal/logging"
	"proxy.local/m0/internal/session"
)

type mockProvider struct {
	overview  OverviewData
	flushErr  error
	reloadErr error
	logsBuf   *logbuffer.Buffer
	logger    *logging.Logger
}

func (m *mockProvider) Overview() (OverviewData, error) {
	return m.overview, nil
}

func (m *mockProvider) Logs(after uint64) logbuffer.Snapshot {
	if m.logsBuf != nil {
		return m.logsBuf.Read(after)
	}
	return logbuffer.Snapshot{Next: 0, Entries: []logbuffer.Entry{}}
}

func (m *mockProvider) LogLevel() logging.LevelStatus {
	if m.logger != nil {
		return m.logger.Status()
	}
	return logging.LevelStatus{Configured: "info", Current: "info", Temporary: false}
}

func (m *mockProvider) SetLogLevel(level string) (logging.LevelStatus, error) {
	if m.logger != nil {
		return m.logger.SetTemporaryLevel(level)
	}
	return logging.LevelStatus{Configured: "info", Current: "info", Temporary: false}, nil
}

func (m *mockProvider) FlushDNS() error {
	return m.flushErr
}

func (m *mockProvider) Reload() error {
	return m.reloadErr
}

func TestWebServer(t *testing.T) {
	buf := &logbuffer.Buffer{}
	_, _ = buf.Write([]byte("proxyd test log line 1\nproxyd test log line 2\n"))

	mock := &mockProvider{
		overview: OverviewData{
			Driver:     "WinDivert",
			Scope:      "全局透明接管 (双栈)",
			Generation: 3,
			ActiveTCP:  5,
			MaxTCP:     256,
			Connected:  map[string]uint64{"direct": 100, "proxy": 50},
			ActiveConns: []ActiveConn{
				{ID: 1, Source: "127.0.0.1:1000", Destination: "1.1.1.1:443", Outbound: "direct", Duration: "10s"},
			},
			UDPStats: session.Stats{Active: 2},
			DNSStats: DNSOverview{Enabled: true, Queries: 200, CacheHits: 150, Cached: 40, HitRate: "75%"},
		},
		logsBuf: buf,
		logger:  logging.New(nil, buf),
	}

	server, err := New("127.0.0.1:0", mock)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	if server.Addr() == nil {
		t.Fatal("expected bound addr")
	}

	handler := server.Handler()
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}

	// 1. 测试静态资源服务
	t.Run("StaticFiles", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET / status = %d, expected 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "透明代理控制台") {
			t.Fatalf("unexpected index.html content: %s", rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "skeleton") {
			t.Fatalf("expected initial skeleton placeholders in index.html")
		}
		if !strings.Contains(rec.Body.String(), "log-runtime-level") || !strings.Contains(rec.Body.String(), "btn-reset-log-level") {
			t.Fatalf("expected runtime log level controls in index.html")
		}

		recCSS := httptest.NewRecorder()
		reqCSS := httptest.NewRequest(http.MethodGet, "/style.css", nil)
		handler.ServeHTTP(recCSS, reqCSS)
		if recCSS.Code != http.StatusOK {
			t.Fatalf("GET /style.css status = %d", recCSS.Code)
		}

		recJS := httptest.NewRecorder()
		reqJS := httptest.NewRequest(http.MethodGet, "/app.js", nil)
		handler.ServeHTTP(recJS, reqJS)
		if recJS.Code != http.StatusOK {
			t.Fatalf("GET /app.js status = %d", recJS.Code)
		}

		etag := rec.Header().Get("ETag")
		if etag == "" {
			t.Fatal("expected ETag header on /")
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
			t.Fatalf("expected Cache-Control: no-cache, got %q", cc)
		}

		rec304 := httptest.NewRecorder()
		req304 := httptest.NewRequest(http.MethodGet, "/", nil)
		req304.Header.Set("If-None-Match", etag)
		handler.ServeHTTP(rec304, req304)
		if rec304.Code != http.StatusNotModified {
			t.Fatalf("GET / with matching If-None-Match status = %d, expected 304", rec304.Code)
		}
	})

	// 2. 测试总览 API
	t.Run("OverviewAPI", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/overview status = %d", rec.Code)
		}
		var data OverviewData
		if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
			t.Fatalf("unmarshal overview failed: %v", err)
		}
		if data.Driver != "WinDivert" || data.ActiveTCP != 5 || len(data.Connected) != 2 {
			t.Fatalf("unexpected overview data: %+v", data)
		}
	})

	// 3. 测试日志快照 API
	t.Run("LogsAPI", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/logs?after=0", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/logs status = %d", rec.Code)
		}
		var snapshot logbuffer.Snapshot
		if err := json.Unmarshal(rec.Body.Bytes(), &snapshot); err != nil {
			t.Fatalf("unmarshal logs failed: %v", err)
		}
		if len(snapshot.Entries) != 2 {
			t.Fatalf("expected 2 log entries, got %d", len(snapshot.Entries))
		}
	})

	// 4. 测试操作 API
	t.Run("Actions", func(t *testing.T) {
		recFlush := httptest.NewRecorder()
		reqFlush := httptest.NewRequest(http.MethodPost, "/api/dns/flush", nil)
		handler.ServeHTTP(recFlush, reqFlush)
		if recFlush.Code != http.StatusOK {
			t.Fatalf("POST /api/dns/flush status = %d", recFlush.Code)
		}

		recReload := httptest.NewRecorder()
		reqReload := httptest.NewRequest(http.MethodPost, "/api/reload", nil)
		handler.ServeHTTP(recReload, reqReload)
		if recReload.Code != http.StatusOK {
			t.Fatalf("POST /api/reload status = %d", recReload.Code)
		}
	})

	// 5. 测试 SSE 日志流
	t.Run("LogsSSE", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/logs/events", nil).WithContext(ctx)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/logs/events status = %d", rec.Code)
		}
		output := rec.Body.String()
		if !strings.Contains(output, "data:") {
			t.Fatalf("expected SSE data format, got %q", output)
		}
	})

	// 6. 测试日志级别查询与临时切换 API
	t.Run("LogLevelAPI", func(t *testing.T) {
		recGet := httptest.NewRecorder()
		reqGet := httptest.NewRequest(http.MethodGet, "/api/logs/level", nil)
		handler.ServeHTTP(recGet, reqGet)
		if recGet.Code != http.StatusOK {
			t.Fatalf("GET /api/logs/level status = %d", recGet.Code)
		}
		var status logging.LevelStatus
		if err := json.Unmarshal(recGet.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Configured != "info" || status.Current != "info" || status.Temporary {
			t.Fatalf("unexpected initial log level status: %+v", status)
		}

		recPost := httptest.NewRecorder()
		reqPost := httptest.NewRequest(http.MethodPost, "/api/logs/level", strings.NewReader(`{"level":"debug"}`))
		handler.ServeHTTP(recPost, reqPost)
		if recPost.Code != http.StatusOK {
			t.Fatalf("POST /api/logs/level status = %d: %s", recPost.Code, recPost.Body.String())
		}
		if err := json.Unmarshal(recPost.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Current != "debug" || !status.Temporary {
			t.Fatalf("expected temporary debug status, got %+v", status)
		}

		recReset := httptest.NewRecorder()
		reqReset := httptest.NewRequest(http.MethodPost, "/api/logs/level", strings.NewReader(`{"level":"reset"}`))
		handler.ServeHTTP(recReset, reqReset)
		if recReset.Code != http.StatusOK {
			t.Fatalf("POST reset status = %d", recReset.Code)
		}
		if err := json.Unmarshal(recReset.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Current != "info" || status.Temporary {
			t.Fatalf("expected reset to info, got %+v", status)
		}

		recBad := httptest.NewRecorder()
		reqBad := httptest.NewRequest(http.MethodPost, "/api/logs/level", strings.NewReader(`{"level":"trace"}`))
		handler.ServeHTTP(recBad, reqBad)
		if recBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid level, got %d", recBad.Code)
		}

		recMethod := httptest.NewRecorder()
		reqMethod := httptest.NewRequest(http.MethodDelete, "/api/logs/level", nil)
		handler.ServeHTTP(recMethod, reqMethod)
		if recMethod.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 for DELETE, got %d", recMethod.Code)
		}
	})
}
