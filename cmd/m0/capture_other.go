//go:build !linux

package main

import "errors"

func capture(_, _, _ string) error {
	return errors.New("kernel capture is unavailable in this build; use the explicit relay for user-mode testing")
}
