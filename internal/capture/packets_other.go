//go:build !windows

package capture

import "proxy.local/m0/internal/config"

func GuardPackets(*Guard, config.Capture) *PacketListener { return nil }

func BindGuard([]Listener, *Guard) {}

func GuardStats(*Guard) func() any { return nil }
