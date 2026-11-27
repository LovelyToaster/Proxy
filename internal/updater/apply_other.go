//go:build !windows && !linux

package updater

import (
	"context"
	"errors"
)

func PreferDeb(_ string) bool { return false }

func Apply(_ context.Context, _ *StagedUpdate, _ ApplyOptions) (*ApplyResult, error) {
	return nil, errors.New("self-update is only supported on Windows and Linux")
}
