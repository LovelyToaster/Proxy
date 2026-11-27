package outbound

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/selfsocket"
)

func socksAuth(conn io.ReadWriter, proxy config.Outbound) error {
	method := byte(0)
	if proxy.Username != "" {
		method = 2
	}
	if _, err := conn.Write([]byte{5, 1, method}); err != nil {
		return err
	}
	var result [2]byte
	if _, err := io.ReadFull(conn, result[:]); err != nil {
		return err
	}
	if result != [2]byte{5, method} {
		return errors.New("SOCKS5 server rejected the configured authentication method")
	}
	if method == 2 {
		request := append([]byte{1, byte(len(proxy.Username))}, proxy.Username...)
		request = append(request, byte(len(proxy.Password)))
		request = append(request, proxy.Password...)
		if _, err := conn.Write(request); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, result[:]); err != nil {
			return err
		}
		if result != [2]byte{1, 0} {
			return errors.New("SOCKS5 authentication failed")
		}
	}
	return nil
}

func socks5(conn io.ReadWriter, proxy config.Outbound, target netip.AddrPort) error {
	if err := socksAuth(conn, proxy); err != nil {
		return err
	}
	_, _, err := socksCommand(conn, 1, target)
	return err
}

func appendSocksAddress(data []byte, target netip.AddrPort) []byte {
	ip := target.Addr().Unmap()
	kind := byte(1)
	if ip.Is6() {
		kind = 4
	}
	data = append(data, kind)
	data = append(data, ip.AsSlice()...)
	return binary.BigEndian.AppendUint16(data, target.Port())
}

func socksCommand(conn io.ReadWriter, command byte, target netip.AddrPort) (string, uint16, error) {
	if _, err := conn.Write(appendSocksAddress([]byte{5, command, 0}, target)); err != nil {
		return "", 0, err
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return "", 0, err
	}
	if reply[0] != 5 || reply[2] != 0 {
		return "", 0, errors.New("invalid SOCKS5 reply")
	}
	if reply[1] != 0 {
		return "", 0, fmt.Errorf("SOCKS5 command %d rejected with code %d", command, reply[1])
	}
	return readSocksAddress(conn, reply[3])
}

func readSocksAddress(reader io.Reader, kind byte) (string, uint16, error) {
	var size int
	switch kind {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return "", 0, err
		}
		if length[0] == 0 {
			return "", 0, errors.New("empty SOCKS5 domain")
		}
		size = int(length[0])
	default:
		return "", 0, errors.New("invalid SOCKS5 address type")
	}
	var encoded [257]byte
	if _, err := io.ReadFull(reader, encoded[:size+2]); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(encoded[size : size+2])
	if kind == 3 {
		return string(encoded[:size]), port, nil
	}
	ip, _ := netip.AddrFromSlice(encoded[:size])
	return ip.Unmap().String(), port, nil
}

func ListenDirectUDP(ctx context.Context, dialer net.Dialer, v6 bool) (*net.UDPConn, error) {
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	return selfsocket.ListenUDP(ctx, dialer, network)
}

func DialUDP(ctx context.Context, dialer net.Dialer, proxy config.Outbound, target netip.AddrPort, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if proxy.Type == "direct" {
		return dialer.DialContext(ctx, "udp", target.String())
	}
	if proxy.Type != "socks5" || !proxy.UDP {
		return nil, errors.New("outbound does not support UDP")
	}
	if target.Addr().Zone() != "" {
		return nil, errors.New("SOCKS5 UDP targets cannot include a local IPv6 zone")
	}
	control, err := dialer.DialContext(ctx, "tcp", proxy.Address)
	if err != nil {
		return nil, err
	}
	conn, err := associateUDP(ctx, dialer, proxy, target, control)
	if err != nil {
		control.Close()
		return nil, err
	}
	go conn.watchControl()
	return conn, nil
}

func associateUDP(ctx context.Context, dialer net.Dialer, proxy config.Outbound, target netip.AddrPort, control net.Conn) (*socksUDP, error) {
	deadline, _ := ctx.Deadline()
	control.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { control.Close() })
	defer stop()
	if err := socksAuth(control, proxy); err != nil {
		return nil, err
	}
	peer := control.RemoteAddr().(*net.TCPAddr).AddrPort()
	unspecified := netip.IPv4Unspecified()
	if peer.Addr().Unmap().Is6() {
		unspecified = netip.IPv6Unspecified()
	}
	host, port, err := socksCommand(control, 3, netip.AddrPortFrom(unspecified, 0))
	if err != nil {
		return nil, err
	}
	if port == 0 || strings.ContainsAny(host, " \t\r\n[]") {
		return nil, errors.New("invalid SOCKS5 UDP relay endpoint")
	}
	if address, err := netip.ParseAddr(host); err == nil && address.IsUnspecified() {
		host = peer.Addr().Unmap().String()
	}
	udp, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil, err
	}
	if !stop() {
		udp.Close()
		return nil, ctx.Err()
	}
	control.SetDeadline(time.Time{})
	return &socksUDP{Conn: udp, control: control, header: appendSocksAddress([]byte{0, 0, 0}, target)}, nil
}

type socksUDP struct {
	net.Conn
	control net.Conn
	header  []byte
}

func (s *socksUDP) watchControl() {
	var unexpected [1]byte
	s.control.Read(unexpected[:])
	s.Close()
}

func (s *socksUDP) Close() error {
	return errors.Join(s.Conn.Close(), s.control.Close())
}

var socksUDPBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

func (s *socksUDP) Write(payload []byte) (int, error) {
	if len(payload)+len(s.header) > 65507 {
		return 0, errors.New("SOCKS5 UDP datagram too large")
	}
	bufPtr := socksUDPBufPool.Get().(*[]byte)
	buf := *bufPtr
	n := copy(buf, s.header)
	n += copy(buf[n:], payload)
	_, err := s.Conn.Write(buf[:n])
	socksUDPBufPool.Put(bufPtr)
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (s *socksUDP) Read(p []byte) (int, error) {
	wire := p
	var bufPtr *[]byte
	if len(wire) < 65535 {
		bufPtr = socksUDPBufPool.Get().(*[]byte)
		wire = *bufPtr
		defer socksUDPBufPool.Put(bufPtr)
	}
	for {
		n, err := s.Conn.Read(wire)
		if err != nil {
			return 0, err
		}
		if n >= len(s.header) && bytes.Equal(wire[:len(s.header)], s.header) {
			return copy(p, wire[len(s.header):n]), nil
		}
	}
}
