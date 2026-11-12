package wfp

import (
	"net"
	"os"
	"testing"
	"time"
)

func TestWindowsAppIDAndUnredirectedSocket(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	id, err := applicationID(path)
	if err != nil || len(id) < 2 || len(id)%2 != 0 {
		t.Fatalf("invalid Windows app ID length %d: %v", len(id), err)
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.SetDeadline(time.Now().Add(2 * time.Second))
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if _, err := Destination(accepted); err == nil {
		t.Fatal("accepted a TCP connection without the driver's redirect context")
	}
}
