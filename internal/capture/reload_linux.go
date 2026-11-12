package capture

import (
	"errors"
	"maps"
	"proxy.local/m0/internal/config"
)

func ValidateUpstreamReload(c config.Capture, before, after map[string]config.Outbound) error {
	if c.Mode != "local" || c.Scope != "global" {
		return nil
	}
	endpoints := func(values map[string]config.Outbound) map[string]bool {
		result := map[string]bool{}
		for _, out := range values {
			if out.Type != "direct" {
				result[out.Address] = true
			}
		}
		return result
	}
	if !maps.Equal(endpoints(before), endpoints(after)) {
		return errors.New("Linux local upstream address changes require a restart to refresh automatic bypass")
	}
	return nil
}
