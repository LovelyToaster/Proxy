package capture

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/selfsocket"
	"proxy.local/m0/internal/windivert"
)

type Guard struct {
	divert *windivert.Capture
}

func (g *Guard) Close() error {
	if g == nil || g.divert == nil {
		return nil
	}
	return g.divert.Close()
}

func (g *Guard) Done() <-chan struct{} {
	if g == nil || g.divert == nil {
		return nil
	}
	return g.divert.Done()
}

func Listen(c config.Capture) ([]Listener, error) {
	if c.Mode == "off" {
		return nil, nil
	}
	if c.Mode != "windivert" {
		return nil, errors.New("Windows capture requires capture.mode: windivert")
	}
	if err := config.ValidateCapture(c); err != nil {
		return nil, err
	}
	var listeners []Listener
	for _, family := range []struct {
		enabled          bool
		network, address string
	}{
		{c.IPv4, "tcp4", "127.0.0.1"}, {c.IPv6, "tcp6", "::1"},
	} {
		if !family.enabled {
			continue
		}
		if c.Scope == "application" || c.Scope == "global" {
			if family.network == "tcp4" {
				family.address = "0.0.0.0"
			} else {
				family.address = "::"
			}
		}
		listener, err := net.Listen(family.network, net.JoinHostPort(family.address, fmt.Sprint(c.Port)))
		if err != nil {
			for _, previous := range listeners {
				previous.Close()
			}
			return nil, err
		}
		entry := Listener{
			Listener:    listener,
			Transparent: true,
			Destination: func(*net.TCPConn) (netip.AddrPort, error) {
				return netip.AddrPort{}, errors.New("WinDivert capture guard is not bound")
			},
		}
		listeners = append(listeners, entry)
	}
	return listeners, nil
}

func Start(c config.Capture, _ string, upstreams ...map[string]config.Outbound) (*Guard, error) {
	return StartResolved(c, "", nil, upstreams...)
}

func StartResolved(c config.Capture, _ string, resolver *net.Resolver, upstreams ...map[string]config.Outbound) (*Guard, error) {
	if c.Mode == "off" {
		return nil, nil
	}
	if c.Mode != "windivert" {
		return nil, errors.New("Windows capture requires capture.mode: windivert")
	}
	backend, err := windivert.StartCaptureResolved(c, resolver, upstreams...)
	if err != nil {
		return nil, err
	}
	return &Guard{divert: backend}, nil
}

func Dialer(c config.Capture) net.Dialer {
	if c.Mode == "windivert" && c.Scope == "global" {
		// Resolve upstream hostnames in this process, outside Windows DNS service forwarding.
		return selfsocket.Dialer(net.Dialer{Resolver: &net.Resolver{PreferGo: true}})
	}
	return net.Dialer{}
}

func RunGuard(string) error {
	return errors.New("Windows WinDivert guard is managed by the capture handle")
}

func Cleanup(string) error {
	return errors.New("WinDivert capture cleanup is owned by the capture handle")
}

func ListenUDP(config.Capture) ([]*PacketListener, error) {
	return nil, nil
}

func GuardPackets(guard *Guard, c config.Capture) *PacketListener {
	if guard == nil || guard.divert == nil || !c.UDP && !c.DNSHijack {
		return nil
	}
	return &PacketListener{
		Transparent: true, ReadPacket: guard.divert.ReadPacket, CaptureDrops: guard.divert.UDPDrops,
		closePacket: func() error { return nil },
		Reply: func(peer, _ netip.AddrPort) (Reply, error) {
			return Reply{Write: func(payload []byte) error { return guard.divert.ReplyPacket(peer, payload) }, Close: func() {}}, nil
		},
	}
}

func BindGuard(listeners []Listener, guard *Guard) {
	if guard == nil || guard.divert == nil {
		return
	}
	for i := range listeners {
		if listeners[i].Transparent {
			listeners[i].Destination = guard.divert.Destination
			listeners[i].Source = guard.divert.Source
		}
	}
}

func GuardStats(guard *Guard) func() any {
	if guard == nil || guard.divert == nil {
		return nil
	}
	return func() any { return guard.divert.PacketStats() }
}
