//go:build !windows

package selfsocket

import (
	"context"
	"net"
	"net/netip"
	"syscall"
)

func Dialer(d net.Dialer) net.Dialer { return d }
func Owns(netip.AddrPort, byte) bool { return false }

func ListenUDP(ctx context.Context, dialer net.Dialer, network string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: dialer.Control}
	if dialer.ControlContext != nil {
		lc.Control = func(netw, address string, raw syscall.RawConn) error {
			return dialer.ControlContext(ctx, netw, address, raw)
		}
	}
	addr := "0.0.0.0:0"
	if network == "udp6" {
		addr = "[::]:0"
	}
	pc, err := lc.ListenPacket(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
