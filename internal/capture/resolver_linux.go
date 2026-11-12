package capture

import (
	"net"
	"proxy.local/m0/internal/config"
)

func StartResolved(c config.Capture, directory string, resolver *net.Resolver, upstreams ...map[string]config.Outbound) (*Guard, error) {
	return startLinux(c, directory, resolver, upstreams...)
}
