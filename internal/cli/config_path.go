package cli

import "path/filepath"

// Linux services use a stable system path, independent of sudo's HOME.
func defaultConfigPath(platform, home string, regular func(string) bool) string {
	if platform == "linux" {
		return "/etc/proxy/proxy.yaml"
	}
	if home != "" {
		candidate := filepath.Join(home, ".proxy", "proxy.yaml")
		if regular(candidate) {
			return candidate
		}
	}
	return "proxy.yaml"
}
