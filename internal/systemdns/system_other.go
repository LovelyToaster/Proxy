//go:build !linux && !windows

package systemdns

import (
	"context"
	"errors"
)

func Discover(context.Context) ([]Server, error) {
	return nil, errors.New("system DNS discovery is unavailable")
}
