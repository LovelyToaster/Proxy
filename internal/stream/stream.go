package stream

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Conn interface {
	net.Conn
	CloseWrite() error
}

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 256<<10)
		return &b
	},
}

func Relay(client, server Conn, idle time.Duration) error {
	var touch func()
	if idle > 0 {
		throttle := min(time.Second, idle/4)
		var lastTouch atomic.Int64
		touch = func() {
			now := time.Now()
			nowNano := now.UnixNano()
			prev := lastTouch.Load()
			if prev != 0 && nowNano-prev < int64(throttle) {
				return
			}
			if lastTouch.CompareAndSwap(prev, nowNano) {
				deadline := now.Add(idle)
				_ = client.SetDeadline(deadline)
				_ = server.SetDeadline(deadline)
			}
		}
		touch()
	}
	copyHalf := func(dst, src Conn) error {
		handled, err := trySplice(dst, src, touch)
		if !handled {
			var reader io.Reader = src
			if touch != nil {
				reader = activeReader{Reader: src, touch: touch}
			}
			bufPtr := copyBufPool.Get().(*[]byte)
			_, err = io.CopyBuffer(dst, reader, *bufPtr)
			copyBufPool.Put(bufPtr)
		}
		if err != nil {
			dst.Close()
			src.Close()
			return err
		}
		return dst.CloseWrite()
	}
	done := make(chan error, 1)
	go func() { done <- copyHalf(server, client) }()
	err := copyHalf(client, server)
	return errors.Join(err, <-done)
}

type activeReader struct {
	io.Reader
	touch func()
}

func (r activeReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n != 0 {
		r.touch()
	}
	return n, err
}
