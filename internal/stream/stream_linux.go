//go:build linux

package stream

import (
	"io"
	"net"
	"syscall"
)

const spliceChunk = 1 << 20

func trySplice(dst, src Conn, touch func()) (bool, error) {
	dstTCP, ok1 := dst.(*net.TCPConn)
	srcTCP, ok2 := src.(*net.TCPConn)
	if !ok1 || !ok2 {
		return false, nil
	}
	rawSrc, err := srcTCP.SyscallConn()
	if err != nil {
		return false, nil
	}
	rawDst, err := dstTCP.SyscallConn()
	if err != nil {
		return false, nil
	}
	var pipeFds [2]int
	if err := syscall.Pipe2(pipeFds[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
		return false, nil
	}
	pipeR, pipeW := pipeFds[0], pipeFds[1]
	defer syscall.Close(pipeR)
	defer syscall.Close(pipeW)

	// Expand pipe capacity from default 64 KiB to 1 MiB (or 512 KiB) to cut splice syscalls.
	const fSetPipeSz = 1031
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(pipeW), fSetPipeSz, spliceChunk); errno != 0 {
		_, _, _ = syscall.Syscall(syscall.SYS_FCNTL, uintptr(pipeW), fSetPipeSz, 512<<10)
	}

	const (
		spliceNonBlock = 0x2
		flags          = spliceNonBlock
	)
	first := true
	for {
		var inPipe int
		var readErr error
		var eof bool
		err := rawSrc.Read(func(fd uintptr) bool {
			n, err := syscall.Splice(int(fd), nil, pipeW, nil, spliceChunk, flags)
			if err == syscall.EAGAIN {
				return false
			}
			if err != nil {
				readErr = err
				return true
			}
			if n == 0 {
				eof = true
				return true
			}
			inPipe = int(n)
			return true
		})
		if err != nil {
			return true, err
		}
		if readErr != nil {
			if first && (readErr == syscall.EINVAL || readErr == syscall.ENOSYS) {
				return false, nil
			}
			return true, readErr
		}
		first = false
		if eof {
			return true, nil
		}
		// Drain the entire pipe chunk inside Write so netpoll only parks on true EAGAIN (required by edge-triggered epoll).
		var writeErr error
		err = rawDst.Write(func(fd uintptr) bool {
			for inPipe > 0 {
				n, err := syscall.Splice(pipeR, nil, int(fd), nil, inPipe, flags)
				if err == syscall.EAGAIN {
					return false
				}
				if err != nil {
					writeErr = err
					return true
				}
				if n == 0 {
					writeErr = io.ErrUnexpectedEOF
					return true
				}
				inPipe -= int(n)
			}
			return true
		})
		if err != nil {
			return true, err
		}
		if writeErr != nil {
			return true, writeErr
		}
		if touch != nil {
			touch()
		}
	}
}
