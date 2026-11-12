//go:build !linux

package capture

import "proxy.local/m0/internal/config"

func ValidateUpstreamReload(config.Capture, map[string]config.Outbound, map[string]config.Outbound) error {
	return nil
}
