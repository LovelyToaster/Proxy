package ipc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func pipeName(directory string) string {
	return fmt.Sprintf(`\\.\pipe\proxy-m1-%x`, sha256.Sum256([]byte(strings.ToLower(filepath.Clean(directory)))))
}

func Listen(directory, _ string) (net.Listener, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	descriptor := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + user.User.Sid.String() + ")"
	return winio.ListenPipe(pipeName(directory), &winio.PipeConfig{SecurityDescriptor: descriptor})
}
func dial(ctx context.Context, directory string, readOnly bool) (net.Conn, error) {
	name := pipeName(directory)
	if readOnly {
		name += ".status"
	}
	return winio.DialPipeContext(ctx, name)
}

func ListenStatus(directory, group string) (net.Listener, error) {
	if group == "" {
		return nil, nil
	}
	if group != "interactive" {
		return nil, errors.New("Windows service.status_group must be interactive")
	}
	return winio.ListenPipe(pipeName(directory)+".status", &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)",
	})
}
