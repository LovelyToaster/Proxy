//go:build !windows

package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

const socketName = "proxy.sock"

func Listen(directory, statusGroup string) (net.Listener, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0067 != 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("runtime directory must be private and owned by the current user")
	}
	lock, err := os.OpenFile(filepath.Join(directory, "proxy.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("a proxy instance is already using this runtime directory")
	}
	if statusGroup == "" && info.Mode().Perm()&0010 != 0 {
		if err := os.Chmod(directory, 0700); err != nil {
			lock.Close()
			return nil, err
		}
	}
	listener, err := listenSocket(filepath.Join(directory, socketName))
	if err != nil {
		lock.Close()
		return nil, err
	}
	return &lockedListener{listener, lock}, nil
}

func listenSocket(path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("management path is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

type lockedListener struct {
	net.Listener
	lock *os.File
}

func (l *lockedListener) Close() error { return errors.Join(l.Listener.Close(), l.lock.Close()) }

func dial(ctx context.Context, directory string, readOnly bool) (net.Conn, error) {
	name := socketName
	if readOnly {
		name = "proxy.status.sock"
	}
	return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(directory, name))
}

func ListenStatus(directory, group string) (net.Listener, error) {
	if group == "" {
		return nil, nil
	}
	entry, err := user.LookupGroup(group)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(entry.Gid)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "proxy.status.sock")
	listener, err := listenSocket(path)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(os.Chown(path, -1, gid), os.Chmod(path, 0660)); err != nil {
		listener.Close()
		return nil, err
	}
	if err := errors.Join(os.Chown(directory, -1, gid), os.Chmod(directory, 0710)); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}
