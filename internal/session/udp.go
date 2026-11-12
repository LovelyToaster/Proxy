package session

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"proxy.local/m0/internal/capture"
	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/outbound"
)

const (
	maxPendingBytes = 8 << 20
	queueSize       = 8
)

type Route struct {
	Name     string
	Outbound config.Outbound
	Dialer   net.Dialer
	Network  config.Network
}

type Stats struct {
	Active         int               `json:"active"`
	Dropped        uint64            `json:"dropped"`
	Failed         uint64            `json:"failed"`
	Opened         map[string]uint64 `json:"opened"`
	KernelDropped  *uint64           `json:"kernel_dropped,omitempty"`
	CaptureDropped *uint64           `json:"capture_dropped,omitempty"`
}

type UDP struct {
	ctx          context.Context
	cancel       context.CancelFunc
	resolve      func(netip.AddrPort) (Route, error)
	mu           sync.Mutex
	sessions     map[flow]*association
	opened       map[string]uint64
	pendingBytes atomic.Int64
	dropped      atomic.Uint64
	failed       atomic.Uint64
	workers      sync.WaitGroup
}

type flow struct {
	listener *capture.PacketListener
	peer     netip.AddrPort
	target   netip.AddrPort
}

type association struct {
	packets chan []byte
}

func NewUDP(resolve func(netip.AddrPort) (Route, error)) *UDP {
	ctx, cancel := context.WithCancel(context.Background())
	return &UDP{ctx: ctx, cancel: cancel, resolve: resolve, sessions: make(map[flow]*association), opened: make(map[string]uint64)}
}

func (m *UDP) Serve(listener *capture.PacketListener, intercept func([]byte, netip.AddrPort, netip.AddrPort) bool) error {
	payload := make([]byte, 65535)
	for {
		n, peer, target, err := listener.ReadPacket(payload)
		if errors.Is(err, capture.ErrInvalidDatagram) {
			m.dropped.Add(1)
			continue
		}
		if err != nil {
			return err
		}
		if intercept != nil && intercept(payload[:n], peer, target) {
			continue
		}
		m.submit(flow{listener, peer, target}, payload[:n])
	}
}

// Close is called after the listeners have stopped submitting datagrams.
func (m *UDP) Close() {
	m.cancel()
	m.workers.Wait()
}

func (m *UDP) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	opened := make(map[string]uint64, len(m.opened))
	for name, n := range m.opened {
		opened[name] = n
	}
	return Stats{Active: len(m.sessions), Dropped: m.dropped.Load(), Failed: m.failed.Load(), Opened: opened}
}

func (m *UDP) submit(key flow, payload []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	size := int64(len(payload) + 1)
	if m.pendingBytes.Add(size) > maxPendingBytes {
		m.pendingBytes.Add(-size)
		m.dropped.Add(1)
		return
	}
	session := m.sessions[key]
	if session == nil {
		route, err := m.resolve(key.target)
		if err != nil || len(m.sessions) >= route.Network.MaxUDPSessions {
			m.pendingBytes.Add(-size)
			m.dropped.Add(1)
			if err != nil {
				m.failed.Add(1)
			}
			return
		}
		session = &association{packets: make(chan []byte, queueSize)}
		m.sessions[key] = session
		m.workers.Go(func() { m.run(key, session, route) })
	}
	if len(session.packets) >= cap(session.packets) {
		m.pendingBytes.Add(-size)
		m.dropped.Add(1)
		return
	}
	session.packets <- append([]byte(nil), payload...)
}

func (m *UDP) run(key flow, session *association, route Route) {
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.sessions, key)
		close(session.packets)
		for pending := range session.packets {
			m.pendingBytes.Add(-int64(len(pending) + 1))
			m.dropped.Add(1)
		}
	}()
	conn, err := outbound.DialUDP(m.ctx, route.Dialer, route.Outbound, key.target, route.Network.ConnectTimeout)
	if err != nil {
		m.failed.Add(1)
		return
	}
	defer conn.Close()
	reply, err := key.listener.Reply(key.peer, key.target)
	if err != nil {
		m.failed.Add(1)
		return
	}
	defer reply.Close()
	m.mu.Lock()
	m.opened[route.Name]++
	m.mu.Unlock()

	var activity sync.Mutex
	touch := func() {
		activity.Lock()
		defer activity.Unlock()
		conn.SetDeadline(time.Now().Add(route.Network.UDPTimeout))
	}
	touch()
	stop := context.AfterFunc(m.ctx, func() { conn.Close() })
	defer stop()
	received := make(chan struct{})
	go func() {
		defer close(received)
		payload := make([]byte, 65535)
		for {
			n, err := conn.Read(payload)
			if err != nil {
				return
			}
			if err := reply.Write(payload[:n]); err != nil {
				return
			}
			touch()
		}
	}()
	defer func() { conn.Close(); <-received }()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-received:
			return
		case packet := <-session.packets:
			_, err := conn.Write(packet)
			m.pendingBytes.Add(-int64(len(packet) + 1))
			if err != nil {
				m.failed.Add(1)
				return
			}
			touch()
		}
	}
}
