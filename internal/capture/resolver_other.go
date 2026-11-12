//go:build !windows && !linux

package capture

import (
	"net"
	"proxy.local/m0/internal/config"
)

func StartResolved(c config.Capture, directory string, _ *net.Resolver, upstreams ...map[string]config.Outbound) (*Guard, error) {
	return Start(c, directory, upstreams...)
}
