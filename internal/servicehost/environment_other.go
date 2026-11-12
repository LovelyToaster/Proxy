//go:build !windows

package servicehost

import "errors"

func InstallerPath(string, string) error {
	return errors.New("installer PATH integration requires Windows")
}
