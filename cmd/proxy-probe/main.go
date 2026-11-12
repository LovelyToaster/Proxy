package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	server := flag.String("dns", "127.0.0.1:15353", "proxy DNS endpoint")
	endpoint := flag.String("url", "", "HTTP or HTTPS URL to test")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	flag.Parse()
	if *endpoint == "" {
		fmt.Fprintln(os.Stderr, "--url is required")
		os.Exit(1)
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, *server)
	}}
	dialer := &net.Dialer{Timeout: *timeout, Resolver: resolver}
	transport := &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: *timeout, ResponseHeaderTimeout: *timeout}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: *timeout}
	start := time.Now()
	response, err := client.Get(*endpoint)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer response.Body.Close()
	bytes, err := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"url": response.Request.URL.String(), "status": response.StatusCode, "bytes_read": bytes, "elapsed_ms": time.Since(start).Milliseconds()})
	if response.StatusCode >= 400 {
		os.Exit(1)
	}
}
