//go:build !windows

package windivert

import (
	"context"
	"errors"
)

func Inspect() (Status, error) {
	return Status{Backend: "windivert"}, errors.New("WinDivert requires Windows")
}

func Sniff(context.Context, string, func()) (Counts, error) {
	return Counts{}, errors.New("WinDivert requires Windows")
}
