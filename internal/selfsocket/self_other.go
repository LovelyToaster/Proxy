//go:build !windows

package selfsocket

import (
	"net"
	"net/netip"
)

func Dialer(d net.Dialer) net.Dialer { return d }
func Owns(netip.AddrPort, byte) bool { return false }
