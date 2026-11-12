package selfsocket

import (
	"context"
	"net"
	"testing"
)

func TestRegistrationBeforeSendAndClose(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	d := Dialer(net.Dialer{})
	conn, err := d.DialContext(context.Background(), "udp4", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	source := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	if !Owns(source, 17) {
		conn.Close()
		t.Fatal("own socket not registered before first send")
	}
	if Owns(source, 6) {
		conn.Close()
		t.Fatal("protocol mismatch bypassed")
	}
	if _, err := conn.Write([]byte("registered")); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if Owns(source, 17) {
		t.Fatal("closed socket still bypasses")
	}
}
