//go:build !windows

package geodata

import "os"

func replaceFile(source, target string) error { return os.Rename(source, target) }
