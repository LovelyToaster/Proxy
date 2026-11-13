package capture

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/linuxsocket"
)

func ListenUDP(c config.Capture) ([]*PacketListener, error) {
	if c.Mode == "off" || !c.UDP && !c.DNSHijack {
		return nil, nil
	}
	if err := checkNamespace(c.Namespace, c.Scope == "global"); err != nil {
		return nil, err
	}
	var result []*PacketListener
	for _, family := range enabledFamilies(c) {
		network, addr := "udp4", netip.IPv4Unspecified()
		if family == "-6" {
			network, addr = "udp6", netip.IPv6Unspecified()
		}
		lc := net.ListenConfig{Control: linuxsocket.TransparentControl(true, 0)}
		pc, err := lc.ListenPacket(context.Background(), network, netip.AddrPortFrom(addr, c.Port).String())
		if err != nil {
			for _, l := range result {
				l.Close()
			}
			return nil, err
		}
		conn := pc.(*net.UDPConn)
		control := make([]byte, 128)
		pool := &replyPool{network: network, open: make(map[netip.AddrPort]*replySocket)}
		result = append(result, &PacketListener{
			UDPConn: conn, Transparent: true,
			ReadPacket: func(p []byte) (int, netip.AddrPort, netip.AddrPort, error) {
				n, controlLen, flags, peer, err := conn.ReadMsgUDPAddrPort(p, control)
				if err != nil {
					return 0, peer, netip.AddrPort{}, err
				}
				target, err := linuxsocket.OriginalUDP(control[:controlLen], network == "udp6")
				if err != nil || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || !scopeAllows(c, target, "udp") {
					return 0, peer, target, ErrInvalidDatagram
				}
				return n, peer, target, nil
			},
			Reply: pool.acquire,
		})
	}
	return result, nil
}

type replyPool struct {
	mu      sync.Mutex
	network string
	open    map[netip.AddrPort]*replySocket
}

type replySocket struct {
	conn         *net.UDPConn
	refs         int
	writeMu      sync.Mutex
	lastDeadline atomic.Int64
	idleTimer    *time.Timer
}

func (p *replyPool) acquire(peer, target netip.AddrPort) (Reply, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	socket := p.open[target]
	if socket == nil {
		lc := net.ListenConfig{Control: linuxsocket.TransparentControl(false, bypassMark)}
		pc, err := lc.ListenPacket(context.Background(), p.network, target.String())
		if err != nil {
			return Reply{}, err
		}
		socket = &replySocket{conn: pc.(*net.UDPConn)}
		p.open[target] = socket
	} else if socket.idleTimer != nil {
		socket.idleTimer.Stop()
		socket.idleTimer = nil
	}
	socket.refs++
	return Reply{
		Write: func(packet []byte) error {
			socket.writeMu.Lock()
			defer socket.writeMu.Unlock()
			now := time.Now()
			if now.UnixNano()-socket.lastDeadline.Load() >= int64(250*time.Millisecond) {
				socket.lastDeadline.Store(now.UnixNano())
				_ = socket.conn.SetWriteDeadline(now.Add(time.Second))
			}
			_, err := socket.conn.WriteToUDPAddrPort(packet, peer)
			return err
		},
		Close: func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			socket.refs--
			if socket.refs == 0 {
				if socket.idleTimer != nil {
					socket.idleTimer.Stop()
				}
				socket.idleTimer = time.AfterFunc(2*time.Second, func() {
					p.mu.Lock()
					defer p.mu.Unlock()
					if socket.refs == 0 && p.open[target] == socket {
						delete(p.open, target)
						socket.conn.Close()
					}
				})
			}
		},
	}, nil
}
