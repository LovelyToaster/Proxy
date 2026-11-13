package outbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/stream"
)

var httpReaderPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, 32<<10)
	},
}

func Dial(ctx context.Context, dialer net.Dialer, proxy config.Outbound, target netip.AddrPort, timeout time.Duration) (stream.Conn, error) {
	if proxy.Type != "direct" && target.Addr().Zone() != "" {
		return nil, errors.New("proxy targets cannot include a local IPv6 zone")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	address := target.String()
	if proxy.Type != "direct" {
		address = proxy.Address
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	tcp := conn.(*net.TCPConn)
	if proxy.Type == "direct" {
		return tcp, nil
	}

	deadline, _ := ctx.Deadline()
	tcp.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { tcp.Close() })
	var established stream.Conn = tcp
	switch proxy.Type {
	case "socks5":
		err = socks5(tcp, proxy, target)
	case "http":
		established, err = httpConnect(tcp, proxy, target.String())
	default:
		err = errors.New("unsupported outbound type")
	}
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		tcp.Close()
		return nil, err
	}
	tcp.SetDeadline(time.Time{})
	return established, nil
}

func httpConnect(conn *net.TCPConn, proxy config.Outbound, target string) (stream.Conn, error) {
	auth := ""
	if proxy.Username != "" {
		auth = "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(proxy.Username+":"+proxy.Password)) + "\r\n"
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, auth); err != nil {
		return nil, err
	}
	reader := httpReaderPool.Get().(*bufio.Reader)
	reader.Reset(io.LimitReader(conn, 32<<10))
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		reader.Reset(nil)
		httpReaderPool.Put(reader)
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		reader.Reset(nil)
		httpReaderPool.Put(reader)
		return nil, fmt.Errorf("HTTP CONNECT rejected with status %d", response.StatusCode)
	}
	buffered := reader.Buffered()
	if buffered == 0 {
		reader.Reset(nil)
		httpReaderPool.Put(reader)
		return conn, nil
	}
	extra := make([]byte, buffered)
	_, _ = io.ReadFull(reader, extra)
	reader.Reset(nil)
	httpReaderPool.Put(reader)
	return &bufferedConn{TCPConn: conn, reader: io.MultiReader(bytes.NewReader(extra), conn)}, nil
}

type bufferedConn struct {
	*net.TCPConn
	reader io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
