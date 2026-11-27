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
	queueSize       = 64
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
	ctx            context.Context
	cancel         context.CancelFunc
	resolve        func(netip.AddrPort) (Route, error)
	mu             sync.Mutex
	sessions       map[flow]*association
	directSessions map[directKey]*directAssociation
	opened         map[string]uint64
	pendingBytes   atomic.Int64
	dropped        atomic.Uint64
	failed         atomic.Uint64
	workers        sync.WaitGroup
}

type flow struct {
	listener *capture.PacketListener
	peer     netip.AddrPort
	target   netip.AddrPort
}

type directKey struct {
	listener *capture.PacketListener
	peer     netip.AddrPort
	outbound string
	v6       bool
}

type udpPacket struct {
	buf    *[]byte
	data   []byte
	target netip.AddrPort
}

var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

type association struct {
	packets chan udpPacket
}

type directAssociation struct {
	packets chan udpPacket
}

func NewUDP(resolve func(netip.AddrPort) (Route, error)) *UDP {
	ctx, cancel := context.WithCancel(context.Background())
	return &UDP{
		ctx:            ctx,
		cancel:         cancel,
		resolve:        resolve,
		sessions:       make(map[flow]*association),
		directSessions: make(map[directKey]*directAssociation),
		opened:         make(map[string]uint64),
	}
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
		m.submit(listener, peer, target, payload[:n])
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
	return Stats{Active: len(m.sessions) + len(m.directSessions), Dropped: m.dropped.Load(), Failed: m.failed.Load(), Opened: opened}
}

func (m *UDP) submit(listener *capture.PacketListener, peer, target netip.AddrPort, payload []byte) {
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	route, err := m.resolve(target)
	if err != nil {
		m.dropped.Add(1)
		m.failed.Add(1)
		return
	}
	if route.Outbound.Type == "direct" {
		m.submitDirect(directKey{listener: listener, peer: peer, outbound: route.Name, v6: target.Addr().Is6()}, target, route, payload)
		return
	}

	key := flow{listener: listener, peer: peer, target: target}
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
		if len(m.sessions)+len(m.directSessions) >= route.Network.MaxUDPSessions {
			m.pendingBytes.Add(-size)
			m.dropped.Add(1)
			return
		}
		session = &association{packets: make(chan udpPacket, queueSize)}
		m.sessions[key] = session
		m.workers.Go(func() { m.run(key, session, route) })
	}
	if len(session.packets) >= cap(session.packets) {
		m.pendingBytes.Add(-size)
		m.dropped.Add(1)
		return
	}
	bufPtr := udpBufPool.Get().(*[]byte)
	n := copy(*bufPtr, payload)
	session.packets <- udpPacket{buf: bufPtr, data: (*bufPtr)[:n]}
}

func (m *UDP) submitDirect(key directKey, target netip.AddrPort, route Route, payload []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	size := int64(len(payload) + 1)
	if m.pendingBytes.Add(size) > maxPendingBytes {
		m.pendingBytes.Add(-size)
		m.dropped.Add(1)
		return
	}
	session := m.directSessions[key]
	if session == nil {
		if len(m.sessions)+len(m.directSessions) >= route.Network.MaxUDPSessions {
			m.pendingBytes.Add(-size)
			m.dropped.Add(1)
			return
		}
		session = &directAssociation{packets: make(chan udpPacket, queueSize)}
		m.directSessions[key] = session
		m.workers.Go(func() { m.runDirect(key, session, route) })
	}
	if len(session.packets) >= cap(session.packets) {
		m.pendingBytes.Add(-size)
		m.dropped.Add(1)
		return
	}
	bufPtr := udpBufPool.Get().(*[]byte)
	n := copy(*bufPtr, payload)
	session.packets <- udpPacket{buf: bufPtr, data: (*bufPtr)[:n], target: target}
}

func (m *UDP) runDirect(key directKey, session *directAssociation, route Route) {
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.directSessions, key)
		close(session.packets)
		for pending := range session.packets {
			m.pendingBytes.Add(-int64(len(pending.data) + 1))
			udpBufPool.Put(pending.buf)
			m.dropped.Add(1)
		}
	}()
	conn, err := outbound.ListenDirectUDP(m.ctx, route.Dialer, key.v6)
	if err != nil {
		m.failed.Add(1)
		return
	}
	defer conn.Close()
	m.mu.Lock()
	m.opened[route.Name]++
	m.mu.Unlock()

	throttle := min(time.Second, route.Network.UDPTimeout/4)
	var lastTouch atomic.Int64
	touch := func() {
		now := time.Now()
		nowNano := now.UnixNano()
		prev := lastTouch.Load()
		if prev != 0 && nowNano-prev < int64(throttle) {
			return
		}
		if lastTouch.CompareAndSwap(prev, nowNano) {
			_ = conn.SetDeadline(now.Add(route.Network.UDPTimeout))
		}
	}
	touch()
	stop := context.AfterFunc(m.ctx, func() { conn.Close() })
	defer stop()
	received := make(chan struct{})
	go func() {
		defer close(received)
		bufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufPtr)
		payload := *bufPtr
		var lastRemote netip.AddrPort
		var lastReply capture.Reply
		closeLast := func() {
			if lastReply.Close != nil {
				lastReply.Close()
				lastReply = capture.Reply{}
				lastRemote = netip.AddrPort{}
			}
		}
		defer closeLast()
		for {
			n, remote, err := conn.ReadFromUDPAddrPort(payload)
			if err != nil {
				return
			}
			remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
			if remote != lastRemote || lastReply.Write == nil {
				closeLast()
				reply, err := key.listener.Reply(key.peer, remote)
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					continue
				}
				lastRemote = remote
				lastReply = reply
			}
			if err := lastReply.Write(payload[:n]); err != nil {
				closeLast()
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
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
			_, err := conn.WriteToUDPAddrPort(packet.data, packet.target)
			m.pendingBytes.Add(-int64(len(packet.data) + 1))
			udpBufPool.Put(packet.buf)
			if err != nil {
				m.failed.Add(1)
				if m.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			touch()
		}
	}
}

func (m *UDP) run(key flow, session *association, route Route) {
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.sessions, key)
		close(session.packets)
		for pending := range session.packets {
			m.pendingBytes.Add(-int64(len(pending.data) + 1))
			udpBufPool.Put(pending.buf)
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

	throttle := min(time.Second, route.Network.UDPTimeout/4)
	var lastTouch atomic.Int64
	touch := func() {
		now := time.Now()
		nowNano := now.UnixNano()
		prev := lastTouch.Load()
		if prev != 0 && nowNano-prev < int64(throttle) {
			return
		}
		if lastTouch.CompareAndSwap(prev, nowNano) {
			_ = conn.SetDeadline(now.Add(route.Network.UDPTimeout))
		}
	}
	touch()
	stop := context.AfterFunc(m.ctx, func() { conn.Close() })
	defer stop()
	received := make(chan struct{})
	go func() {
		defer close(received)
		bufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufPtr)
		payload := *bufPtr
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
			_, err := conn.Write(packet.data)
			m.pendingBytes.Add(-int64(len(packet.data) + 1))
			udpBufPool.Put(packet.buf)
			if err != nil {
				m.failed.Add(1)
				return
			}
			touch()
		}
	}
}
