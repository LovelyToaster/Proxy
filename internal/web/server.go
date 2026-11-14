package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"proxy.local/m0/internal/logbuffer"
	"proxy.local/m0/internal/logging"
	"proxy.local/m0/internal/session"
)

// ActiveConn represents an active TCP connection summary.
type ActiveConn struct {
	ID          uint64 `json:"id"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Outbound    string `json:"outbound"`
	Duration    string `json:"duration"`
}

// DNSOverview represents DNS resolution statistics.
type DNSOverview struct {
	Enabled              bool              `json:"enabled"`
	Queries              uint64            `json:"queries"`
	CacheHits            uint64            `json:"cache_hits"`
	StaleHits            uint64            `json:"stale_hits"`
	FreshHits            uint64            `json:"fresh_hits"`
	UncacheableQueries   uint64            `json:"uncacheable_queries"`
	UncacheableResponses uint64            `json:"uncacheable_responses"`
	NegativeNoSOA        uint64            `json:"negative_no_soa"`
	SystemBypass         uint64            `json:"system_bypass"`
	Failures             uint64            `json:"failures"`
	Fallbacks            uint64            `json:"fallbacks"`
	OtherQueries         uint64            `json:"other_queries"`
	Cached               int               `json:"cached"`
	MaxEntries           int               `json:"max_entries"`
	HitRate              string            `json:"hit_rate"`
	UpstreamRequests     map[string]uint64 `json:"upstream_requests,omitempty"`
}

// OverviewData aggregates the dashboard status metrics.
type OverviewData struct {
	Driver      string            `json:"driver"`
	Scope       string            `json:"scope"`
	Generation  uint64            `json:"generation"`
	ActiveTCP   int               `json:"active_tcp"`
	MaxTCP      int               `json:"max_tcp"`
	Connected   map[string]uint64 `json:"connected"`
	ActiveConns []ActiveConn      `json:"active_conns"`
	UDPStats    session.Stats     `json:"udp_stats"`
	DNSStats    DNSOverview       `json:"dns_stats"`
}

// Provider defines the interface for fetching proxy state and issuing commands.
type Provider interface {
	Overview() (OverviewData, error)
	Logs(after uint64) logbuffer.Snapshot
	LogLevel() logging.LevelStatus
	SetLogLevel(level string) (logging.LevelStatus, error)
	FlushDNS() error
	Reload() error
}

// Server hosts the web dashboard HTTP service.
type Server struct {
	listener net.Listener
	http     *http.Server
	provider Provider
}

// New creates and binds a new dashboard HTTP server.
func New(listen string, provider Provider) (*Server, error) {
	if provider == nil {
		return nil, errors.New("provider cannot be nil")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}

	s := &Server{
		listener: ln,
		provider: provider,
	}

	mux := http.NewServeMux()
	mux.Handle("/", AssetHandler())
	mux.HandleFunc("/api/overview", s.handleOverview)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/logs/events", s.handleLogsEvents)
	mux.HandleFunc("/api/logs/level", s.handleLogLevel)
	mux.HandleFunc("/api/dns/flush", s.handleDNSFlush)
	mux.HandleFunc("/api/reload", s.handleReload)

	s.http = &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // Disabled for SSE streaming
	}

	return s, nil
}

// Addr returns the server's bound network address.
func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Handler returns the server's HTTP handler.
func (s *Server) Handler() http.Handler {
	if s.http != nil {
		return s.http.Handler
	}
	return nil
}

// Serve starts listening and serving HTTP requests.
func (s *Server) Serve() error {
	return s.http.Serve(s.listener)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// Close immediately closes the listener and active connections.
func (s *Server) Close() error {
	return s.http.Close()
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := s.provider.Overview()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	afterStr := r.URL.Query().Get("after")
	var after uint64
	if afterStr != "" {
		after, _ = strconv.ParseUint(afterStr, 10, 64)
	}
	snapshot := s.provider.Logs(after)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(snapshot)
}

func (s *Server) handleLogsEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	afterStr := r.URL.Query().Get("after")
	var cursor uint64
	if afterStr != "" {
		cursor, _ = strconv.ParseUint(afterStr, 10, 64)
	}

	// Send initial entries
	snapshot := s.provider.Logs(cursor)
	for _, entry := range snapshot.Entries {
		data, err := json.Marshal(entry)
		if err == nil {
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
	}
	cursor = snapshot.Next
	flusher.Flush()

	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			snap := s.provider.Logs(cursor)
			if len(snap.Entries) > 0 {
				for _, entry := range snap.Entries {
					data, err := json.Marshal(entry)
					if err == nil {
						fmt.Fprintf(w, "data: %s\n\n", data)
					}
				}
				cursor = snap.Next
				flusher.Flush()
			}
		}
	}
}

func (s *Server) handleLogLevel(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(s.provider.LogLevel())
	case http.MethodPost:
		var req struct {
			Level string `json:"level"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		status, err := s.provider.SetLogLevel(req.Level)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(status)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDNSFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.provider.FlushDNS(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]bool{"flushed": true})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.provider.Reload(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]bool{"reloaded": true})
}

// ScopeText formats the capture scope into a clean Chinese description without trailing parentheses.
func ScopeText(scope, mode string, ipv4, ipv6 bool) string {
	if mode == "off" || mode == "" {
		return "未启用"
	}
	switch strings.ToLower(scope) {
	case "global":
		return "全局透明接管"
	case "application":
		return "应用进程接管"
	default:
		return scope
	}
}

// FormatDurationChinese formats a duration into a readable Chinese representation (e.g. "2分10秒", "42秒").
func FormatDurationChinese(d time.Duration) string {
	d = d.Round(time.Second)
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%d秒", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s == 0 {
			return fmt.Sprintf("%d分", m)
		}
		return fmt.Sprintf("%d分%d秒", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if m == 0 {
		return fmt.Sprintf("%d小时", h)
	}
	return fmt.Sprintf("%d小时%d分", h, m)
}
