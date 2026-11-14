package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"proxy.local/m0/internal/logbuffer"
)

// LevelStatus describes both the configured default level and the active runtime level.
type LevelStatus struct {
	Configured string `json:"configured"`
	Current    string `json:"current"`
	Temporary  bool   `json:"temporary"`
}

// ParseLevel parses a textual log level into a slog.Level and canonical lowercase name.
func ParseLevel(raw string) (slog.Level, string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug, "debug", nil
	case "info":
		return slog.LevelInfo, "info", nil
	case "warn":
		return slog.LevelWarn, "warn", nil
	case "error":
		return slog.LevelError, "error", nil
	default:
		return slog.LevelInfo, "", fmt.Errorf("invalid log level %q: expected debug, info, warn, or error", raw)
	}
}

// FormatLevel converts a slog.Level into its canonical lowercase level name.
func FormatLevel(level slog.Level) string {
	switch {
	case level <= slog.LevelDebug:
		return "debug"
	case level < slog.LevelWarn:
		return "info"
	case level < slog.LevelError:
		return "warn"
	default:
		return "error"
	}
}

// Logger is a concurrency-safe leveled logger that writes to both an io.Writer and a logbuffer.Buffer.
type Logger struct {
	levelVar   slog.LevelVar
	mu         sync.RWMutex
	configured slog.Level
	writer     io.Writer
	buffer     *logbuffer.Buffer
}

// Default is the shared application logger.
var Default = New(os.Stderr, logbuffer.Default)

// New creates a Logger initialized to info level.
func New(writer io.Writer, buffer *logbuffer.Buffer) *Logger {
	l := &Logger{
		configured: slog.LevelInfo,
		writer:     writer,
		buffer:     buffer,
	}
	l.levelVar.Set(slog.LevelInfo)
	return l
}

// SetOutput replaces the destination writer used for formatted text output.
func (l *Logger) SetOutput(writer io.Writer) {
	l.mu.Lock()
	l.writer = writer
	l.mu.Unlock()
}

// Output returns the current destination writer.
func (l *Logger) Output() io.Writer {
	l.mu.RLock()
	w := l.writer
	l.mu.RUnlock()
	return w
}

// SetConfiguredLevel updates the configured default level and resets the active runtime level to match it.
func (l *Logger) SetConfiguredLevel(raw string) (LevelStatus, error) {
	level, _, err := ParseLevel(raw)
	if err != nil {
		return l.Status(), err
	}
	l.mu.Lock()
	l.configured = level
	l.levelVar.Set(level)
	status := l.statusLocked()
	l.mu.Unlock()
	return status, nil
}

// SetTemporaryLevel overrides the active runtime level without modifying the configured default.
// Passing "", "reset", or "default" restores the configured default level.
func (l *Logger) SetTemporaryLevel(raw string) (LevelStatus, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" || normalized == "reset" || normalized == "default" {
		return l.ResetLevel(), nil
	}
	level, _, err := ParseLevel(normalized)
	if err != nil {
		return l.Status(), err
	}
	l.mu.Lock()
	l.levelVar.Set(level)
	status := l.statusLocked()
	l.mu.Unlock()
	return status, nil
}

// ResetLevel restores the active runtime level to the configured default.
func (l *Logger) ResetLevel() LevelStatus {
	l.mu.Lock()
	l.levelVar.Set(l.configured)
	status := l.statusLocked()
	l.mu.Unlock()
	return status
}

// Status returns a snapshot of the configured and active log levels.
func (l *Logger) Status() LevelStatus {
	l.mu.RLock()
	status := l.statusLocked()
	l.mu.RUnlock()
	return status
}

func (l *Logger) statusLocked() LevelStatus {
	cur := l.levelVar.Level()
	return LevelStatus{
		Configured: FormatLevel(l.configured),
		Current:    FormatLevel(cur),
		Temporary:  cur != l.configured,
	}
}

// Enabled reports whether records at the given level should be logged.
func (l *Logger) Enabled(_ context.Context, level slog.Level) bool {
	return level >= l.levelVar.Level()
}

// Handle formats and dispatches a slog.Record to the configured outputs.
func (l *Logger) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteByte(' ')
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value.String())
		return true
	})
	ts := r.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	l.emit(r.Level, ts, b.String())
	return nil
}

// WithAttrs returns a slog.Handler with the given pre-formatted attributes.
func (l *Logger) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &attrHandler{logger: l, attrs: append([]slog.Attr(nil), attrs...)}
}

// WithGroup returns a slog.Handler with the given attribute group name.
func (l *Logger) WithGroup(name string) slog.Handler {
	return &attrHandler{logger: l, group: name}
}

// Logf formats and emits a message if level is enabled.
func (l *Logger) Logf(level slog.Level, format string, args ...any) {
	if !l.Enabled(context.Background(), level) {
		return
	}
	l.emit(level, time.Now(), fmt.Sprintf(format, args...))
}

// Debugf logs a debug-level message.
func (l *Logger) Debugf(format string, args ...any) {
	l.Logf(slog.LevelDebug, format, args...)
}

// Infof logs an info-level message.
func (l *Logger) Infof(format string, args ...any) {
	l.Logf(slog.LevelInfo, format, args...)
}

// Warnf logs a warning-level message.
func (l *Logger) Warnf(format string, args ...any) {
	l.Logf(slog.LevelWarn, format, args...)
}

// Errorf logs an error-level message.
func (l *Logger) Errorf(format string, args ...any) {
	l.Logf(slog.LevelError, format, args...)
}

func (l *Logger) emit(level slog.Level, ts time.Time, msg string) {
	msg = strings.TrimRight(msg, "\r\n")
	if msg == "" {
		return
	}
	levelName := FormatLevel(level)

	l.mu.RLock()
	w := l.writer
	buf := l.buffer
	l.mu.RUnlock()

	if w != nil {
		line := fmt.Sprintf("%s [%s] %s\n", ts.Format("2006/01/02 15:04:05"), strings.ToUpper(levelName), msg)
		_, _ = io.WriteString(w, line)
	}
	if buf != nil {
		buf.Append(levelName, ts.Format("15:04:05"), msg)
	}
}

// StdBridgeWriter returns an io.Writer for bridging Go's standard log package into l.
func (l *Logger) StdBridgeWriter(defaultLevel slog.Level) io.Writer {
	return &bridgeWriter{logger: l, defaultLevel: defaultLevel}
}

type bridgeWriter struct {
	logger       *Logger
	defaultLevel slog.Level
}

func (w *bridgeWriter) Write(p []byte) (int, error) {
	text := string(p)
	now := time.Now()
	for len(text) > 0 {
		line, rest, found := strings.Cut(text, "\n")
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line != "" {
			line = stripStdTimestamp(line)
			level, stripped := parsePrefixedLevel(line, w.defaultLevel)
			if w.logger.Enabled(context.Background(), level) {
				w.logger.emit(level, now, stripped)
			}
		}
		if !found {
			break
		}
		text = rest
	}
	return len(p), nil
}

// stripStdTimestamp removes Go's default log.LstdFlags prefix ("YYYY/MM/DD HH:MM:SS ").
func stripStdTimestamp(line string) string {
	if len(line) >= 20 && line[4] == '/' && line[7] == '/' && line[10] == ' ' && line[13] == ':' && line[16] == ':' && line[19] == ' ' {
		return strings.TrimSpace(line[20:])
	}
	return line
}

func parsePrefixedLevel(line string, fallback slog.Level) (slog.Level, string) {
	for _, item := range []struct {
		prefix string
		level  slog.Level
	}{
		{"[DEBUG]", slog.LevelDebug},
		{"[INFO]", slog.LevelInfo},
		{"[WARN]", slog.LevelWarn},
		{"[ERROR]", slog.LevelError},
	} {
		if len(line) >= len(item.prefix) && strings.EqualFold(line[:len(item.prefix)], item.prefix) {
			return item.level, strings.TrimSpace(line[len(item.prefix):])
		}
	}
	return fallback, line
}

type attrHandler struct {
	logger *Logger
	attrs  []slog.Attr
	group  string
}

func (h *attrHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.logger.Enabled(ctx, level)
}

func (h *attrHandler) Handle(ctx context.Context, r slog.Record) error {
	clone := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	for _, a := range h.attrs {
		if h.group != "" {
			a.Key = h.group + "." + a.Key
		}
		clone.AddAttrs(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		if h.group != "" {
			a.Key = h.group + "." + a.Key
		}
		clone.AddAttrs(a)
		return true
	})
	return h.logger.Handle(ctx, clone)
}

func (h *attrHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &attrHandler{logger: h.logger, attrs: merged, group: h.group}
}

func (h *attrHandler) WithGroup(name string) slog.Handler {
	group := name
	if h.group != "" && name != "" {
		group = h.group + "." + name
	} else if name == "" {
		group = h.group
	}
	return &attrHandler{logger: h.logger, attrs: h.attrs, group: group}
}

// Debugf logs a debug-level message to Default.
func Debugf(format string, args ...any) { Default.Debugf(format, args...) }

// Infof logs an info-level message to Default.
func Infof(format string, args ...any) { Default.Infof(format, args...) }

// Warnf logs a warn-level message to Default.
func Warnf(format string, args ...any) { Default.Warnf(format, args...) }

// Errorf logs an error-level message to Default.
func Errorf(format string, args ...any) { Default.Errorf(format, args...) }

// SetOutput updates the output writer on Default.
func SetOutput(writer io.Writer) { Default.SetOutput(writer) }

// SetConfiguredLevel updates the configured level on Default.
func SetConfiguredLevel(raw string) (LevelStatus, error) { return Default.SetConfiguredLevel(raw) }

// SetTemporaryLevel updates the active level on Default temporarily.
func SetTemporaryLevel(raw string) (LevelStatus, error) { return Default.SetTemporaryLevel(raw) }

// ResetLevel restores the active level on Default to its configured default.
func ResetLevel() LevelStatus { return Default.ResetLevel() }

// Status returns the current level status of Default.
func Status() LevelStatus { return Default.Status() }
