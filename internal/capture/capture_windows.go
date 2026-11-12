package capture

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/selfsocket"
	"proxy.local/m0/internal/wfp"
	"proxy.local/m0/internal/windivert"
)

type Guard struct {
	wfp    *wfp.Guard
	divert *windivert.Capture
}

func (g *Guard) Close() error {
	if g.divert != nil {
		return g.divert.Close()
	}
	return g.wfp.Close()
}
func (g *Guard) Done() <-chan struct{} {
	if g.divert != nil {
		return g.divert.Done()
	}
	return g.wfp.Done()
}

func endpoints(c config.Capture) []netip.AddrPort {
	result := make([]netip.AddrPort, 0, len(c.CIDRs))
	var port uint16
	if len(c.Ports) != 0 {
		port = c.Ports[0]
	}
	for _, prefix := range c.CIDRs {
		result = append(result, netip.AddrPortFrom(prefix.Addr(), port))
	}
	return result
}

func Listen(c config.Capture) ([]Listener, error) {
	if c.Mode == "off" {
		return nil, nil
	}
	if c.Mode != "wfp" && c.Mode != "windivert" {
		return nil, errors.New("Windows capture requires capture.mode: wfp or windivert")
	}
	if err := config.ValidateCapture(c); err != nil {
		return nil, err
	}
	targets := endpoints(c)
	if c.DNSHijack {
		for _, prefix := range c.CIDRs {
			targets = append(targets, netip.AddrPortFrom(prefix.Addr(), 53))
		}
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
		if c.Mode == "windivert" && (c.Scope == "application" || c.Scope == "global") {
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
		entry := Listener{Listener: listener, Transparent: true,
			Destination: func(conn *net.TCPConn) (netip.AddrPort, error) {
				target, err := wfp.Destination(conn)
				if err != nil {
					return netip.AddrPort{}, err
				}
				if !slices.Contains(targets, target) {
					return netip.AddrPort{}, errors.New("WFP redirect destination is outside scope")
				}
				return target, nil
			}}
		if c.Mode == "wfp" {
			entry.PrepareDialer = wfp.PrepareDialer
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
	if c.Mode == "windivert" {
		backend, err := windivert.StartCaptureResolved(c, resolver, upstreams...)
		if err != nil {
			return nil, err
		}
		return &Guard{divert: backend}, nil
	}
	if c.Mode != "wfp" {
		return nil, errors.New("Windows capture requires capture.mode: wfp")
	}
	if err := config.ValidateCapture(c); err != nil {
		return nil, err
	}
	backend, err := wfp.Arm(c.WFPApplication, c.Port, endpoints(c), c.UDP, c.DNSHijack)
	if err != nil {
		return nil, err
	}
	return &Guard{wfp: backend}, nil
}
func Dialer(c config.Capture) net.Dialer {
	if c.Mode == "windivert" && c.Scope == "global" {
		// Resolve upstream hostnames in this process, outside Windows DNS service forwarding.
		return selfsocket.Dialer(net.Dialer{Resolver: &net.Resolver{PreferGo: true}})
	}
	return net.Dialer{}
}
func RunGuard(string) error {
	return errors.New("Windows WFP guard is managed through the driver device")
}
func Cleanup(string) error {
	return errors.New("WFP capture cleanup is owned by the driver device handle")
}
func ListenUDP(config.Capture) ([]*PacketListener, error) {
	return nil, nil
}

func GuardPackets(guard *Guard, c config.Capture) *PacketListener {
	if guard == nil || !c.UDP && !c.DNSHijack {
		return nil
	}
	read := guard.wfp
	if guard.divert != nil {
		return &PacketListener{
			Transparent: true, ReadPacket: guard.divert.ReadPacket, CaptureDrops: guard.divert.UDPDrops,
			closePacket: func() error { return nil },
			Reply: func(peer, _ netip.AddrPort) (Reply, error) {
				return Reply{Write: func(payload []byte) error { return guard.divert.ReplyPacket(peer, payload) }, Close: func() {}}, nil
			},
		}
	}
	return &PacketListener{
		Transparent: true,
		ReadPacket:  read.ReadPacket,
		KernelDrops: read.UDPDrops,
		closePacket: func() error { return nil }, // Guard owns the device.
		Reply: func(peer, _ netip.AddrPort) (Reply, error) {
			return Reply{Write: func(payload []byte) error {
				return read.ReplyPacket(peer, payload)
			}, Close: func() {}}, nil
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
		}
	}
}

func GuardStats(guard *Guard) func() any {
	if guard == nil || guard.divert == nil {
		return nil
	}
	return func() any { return guard.divert.PacketStats() }
}
