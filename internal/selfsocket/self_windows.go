package selfsocket

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
)

type socket struct {
	port uint16
	v6   bool
}

var owned = struct {
	sync.Mutex
	sockets map[windows.Handle]socket
	ports   map[uint16]map[windows.Handle]bool
}{sockets: make(map[windows.Handle]socket), ports: make(map[uint16]map[windows.Handle]bool)}

func forget(handle windows.Handle) {
	entry, ok := owned.sockets[handle]
	if !ok {
		return
	}
	delete(owned.sockets, handle)
	delete(owned.ports[entry.port], handle)
	if len(owned.ports[entry.port]) == 0 {
		delete(owned.ports, entry.port)
	}
}

func local(handle windows.Handle) (netip.AddrPort, error) {
	address, err := windows.Getsockname(handle)
	if err != nil {
		return netip.AddrPort{}, err
	}
	switch value := address.(type) {
	case *windows.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(value.Addr), uint16(value.Port)), nil
	case *windows.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(value.Addr), uint16(value.Port)), nil
	}
	return netip.AddrPort{}, fmt.Errorf("unsupported socket family")
}

// Pre-bind an exclusive UDP endpoint before connect can send any packet. Keep
// the real handle, not just a timed port exemption. Closed/reused handles are
// checked against their current endpoint before a packet can bypass capture.
func Dialer(d net.Dialer) net.Dialer {
	previous := d.ControlContext
	control := d.Control
	localAddress := d.LocalAddr
	d.Control = nil
	d.ControlContext = func(ctx context.Context, network, address string, raw syscall.RawConn) error {
		if previous != nil {
			if err := previous(ctx, network, address, raw); err != nil {
				return err
			}
		} else if control != nil {
			if err := control(network, address, raw); err != nil {
				return err
			}
		}
		if !strings.HasPrefix(network, "udp") {
			return nil
		}
		if localAddress != nil {
			return fmt.Errorf("registered UDP dialer requires an automatic local endpoint")
		}
		var result error
		err := raw.Control(func(fd uintptr) {
			handle := windows.Handle(fd)
			// SO_EXCLUSIVEADDRUSE = ~SO_REUSEADDR on Winsock.
			if result = windows.SetsockoptInt(handle, windows.SOL_SOCKET, ^windows.SO_REUSEADDR, 1); result != nil {
				return
			}
			var bind windows.Sockaddr = &windows.SockaddrInet4{}
			if network == "udp6" {
				bind = &windows.SockaddrInet6{}
			}
			if result = windows.Bind(handle, bind); result != nil {
				return
			}
			endpoint, err := local(handle)
			if err != nil {
				result = err
				return
			}
			owned.Lock()
			defer owned.Unlock()
			if len(owned.sockets) >= 512 {
				for socket, entry := range owned.sockets {
					now, err := local(socket)
					if err != nil || now.Port() != entry.port || now.Addr().Is6() != entry.v6 {
						forget(socket)
					}
				}
			}
			if len(owned.sockets) >= 4096 {
				result = fmt.Errorf("own UDP socket registry full")
				return
			}
			forget(handle)
			owned.sockets[handle] = socket{endpoint.Port(), endpoint.Addr().Is6()}
			if owned.ports[endpoint.Port()] == nil {
				owned.ports[endpoint.Port()] = make(map[windows.Handle]bool)
			}
			owned.ports[endpoint.Port()][handle] = true
		})
		if err != nil {
			return err
		}
		return result
	}
	return d
}

func Owns(source netip.AddrPort, protocol byte) bool {
	if protocol != 17 {
		return false
	}
	source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	owned.Lock()
	defer owned.Unlock()
	for handle := range owned.ports[source.Port()] {
		entry := owned.sockets[handle]
		if entry.port != source.Port() || entry.v6 != source.Addr().Is6() {
			continue
		}
		endpoint, err := local(handle)
		if err != nil || endpoint.Port() != entry.port || endpoint.Addr().Is6() != entry.v6 {
			forget(handle)
			continue
		}
		if endpoint.Addr().IsUnspecified() || endpoint.Addr().Unmap() == source.Addr() {
			return true
		}
	}
	return false
}
