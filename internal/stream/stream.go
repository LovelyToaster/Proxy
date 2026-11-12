package stream

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type Conn interface {
	net.Conn
	CloseWrite() error
}

func Relay(client, server Conn, idle time.Duration) error {
	var touch func()
	if idle > 0 {
		var mu sync.Mutex
		touch = func() {
			mu.Lock()
			defer mu.Unlock()
			deadline := time.Now().Add(idle)
			client.SetDeadline(deadline)
			server.SetDeadline(deadline)
		}
		touch()
	}
	copyHalf := func(dst, src Conn) error {
		var reader io.Reader = src
		if touch != nil {
			reader = activeReader{Reader: src, touch: touch}
		}
		_, err := io.Copy(dst, reader)
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
