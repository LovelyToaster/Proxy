//go:build !linux && !windows

package servicehost

import (
	"context"
	"errors"
	"proxy.local/m0/internal/core"
)

func Run(ctx context.Context, config, runtime string) error { return core.Serve(ctx, config, runtime) }
func Control(context.Context, string) error                 { return errors.New("unsupported service manager") }
func Install(string, string, string, bool) error            { return errors.New("unsupported service manager") }
func Uninstall() error                                      { return errors.New("unsupported service manager") }
