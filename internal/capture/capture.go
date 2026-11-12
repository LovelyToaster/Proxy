package capture

import (
	"errors"
	"net"
	"net/netip"
)

type Listener struct {
	net.Listener
	Destination   func(*net.TCPConn) (netip.AddrPort, error)
	PrepareDialer func(*net.TCPConn, net.Dialer) (net.Dialer, error)
	Transparent   bool
}

var ErrInvalidDatagram = errors.New("invalid captured UDP datagram")

type Reply struct {
	Write func([]byte) error
	Close func()
}

type PacketListener struct {
	*net.UDPConn
	closePacket  func() error
	Transparent  bool
	ReadPacket   func([]byte) (int, netip.AddrPort, netip.AddrPort, error)
	Reply        func(peer, target netip.AddrPort) (Reply, error)
	KernelDrops  func() (uint64, error)
	CaptureDrops func() (uint64, error)
}

func (p *PacketListener) Close() error {
	if p.closePacket != nil {
		return p.closePacket()
	}
	return p.UDPConn.Close()
}

func ListenExplicitUDP(address, target netip.AddrPort) (*PacketListener, error) {
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(address))
	if err != nil {
		return nil, err
	}
	return &PacketListener{UDPConn: conn, ReadPacket: func(p []byte) (int, netip.AddrPort, netip.AddrPort, error) {
		n, peer, err := conn.ReadFromUDPAddrPort(p)
		return n, peer, target, err
	}, Reply: func(peer, _ netip.AddrPort) (Reply, error) {
		return Reply{Write: func(p []byte) error {
			_, err := conn.WriteToUDPAddrPort(p, peer)
			return err
		}, Close: func() {}}, nil
	}}, nil
}
