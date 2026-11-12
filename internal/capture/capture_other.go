//go:build !linux && !windows

package capture

import (
	"errors"
	"net"

	"proxy.local/m0/internal/config"
)

var unsupported = errors.New("transparent capture is unavailable on this platform in M1")

type Guard struct{}

func (*Guard) Close() error          { return nil }
func (*Guard) Done() <-chan struct{} { return nil }

func Listen(c config.Capture) ([]Listener, error) {
	if c.Mode == "off" {
		return nil, nil
	}
	return nil, unsupported
}
func Start(c config.Capture, _ string, _ ...map[string]config.Outbound) (*Guard, error) {
	if c.Mode == "off" {
		return nil, nil
	}
	return nil, unsupported
}
func Dialer(config.Capture) net.Dialer { return net.Dialer{} }
func RunGuard(string) error            { return unsupported }
func Cleanup(string) error             { return unsupported }

func ListenUDP(c config.Capture) ([]*PacketListener, error) {
	if c.Mode == "off" || !c.UDP {
		return nil, nil
	}
	return nil, unsupported
}
