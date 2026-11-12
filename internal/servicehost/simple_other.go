//go:build !windows && !linux

package servicehost

import "context"

func SimpleControl(ctx context.Context, operation, _, _ string) error { return Control(ctx, operation) }
