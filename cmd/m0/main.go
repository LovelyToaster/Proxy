package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"proxy.local/m0/internal/stream"
)

const deadline = 2 * time.Second

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) < 3 {
		return errors.New("usage: m0 echo|probe|probe-pair|relay|redirect|transparent tcp4|tcp6|udp4|udp6 address [target]")
	}
	mode, network, address := args[0], args[1], args[2]
	switch network {
	case "tcp4", "tcp6", "udp4", "udp6":
	default:
		return fmt.Errorf("unsupported network %q", network)
	}
	if _, err := netip.ParseAddrPort(address); err != nil {
		return err
	}
	switch {
	case mode == "probe" && len(args) == 3:
		return probe(network, address)
	case mode == "probe-pair" && len(args) == 4 && network[:3] == "udp":
		return probeUDP(network, []string{address, args[3], address})
	case mode == "echo" && len(args) == 3:
		return echo(network, address)
	case mode == "relay" && len(args) == 4:
		if _, err := netip.ParseAddrPort(args[3]); err != nil {
			return err
		}
		return relay(network, address, args[3])
	case (mode == "redirect" || mode == "transparent") && len(args) == 3:
		return capture(mode, network, address)
	default:
		return errors.New("invalid mode or arguments")
	}
}

func echo(network, address string) error {
	if network[:3] == "tcp" {
		listener, err := net.Listen(network, address)
		if err != nil {
			return err
		}
		defer listener.Close()
		return serveTCP(listener, func(conn *net.TCPConn) error {
			_, err := io.Copy(conn, conn)
			return err
		})
	}
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		return err
	}
	defer conn.Close()
	return serveUDP(conn.(*net.UDPConn), func(packet []byte, peer netip.AddrPort) error {
		_, err := conn.(*net.UDPConn).WriteToUDPAddrPort(packet, peer)
		return err
	})
}

func relay(network, address, target string) error {
	if network[:3] == "tcp" {
		listener, err := net.Listen(network, address)
		if err != nil {
			return err
		}
		defer listener.Close()
		return serveTCP(listener, func(conn *net.TCPConn) error {
			return relayTCP(conn, network, target, net.Dialer{Timeout: deadline})
		})
	}
	listener, err := net.ListenPacket(network, address)
	if err != nil {
		return err
	}
	defer listener.Close()
	conn := listener.(*net.UDPConn)
	return serveUDP(conn, func(packet []byte, peer netip.AddrPort) error {
		response, err := exchangeUDP(network, target, packet, net.Dialer{Timeout: deadline})
		if err != nil {
			return err
		}
		_, err = conn.WriteToUDPAddrPort(response, peer)
		return err
	})
}

func serveTCP(listener net.Listener, handle func(*net.TCPConn) error) error {
	log.Printf("ready %s", listener.Addr())
	slots := make(chan struct{}, 16)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(deadline))
				if err := handle(conn.(*net.TCPConn)); err != nil {
					log.Print(err)
				}
			}()
		default:
			conn.Close()
		}
	}
}

func relayTCP(client *net.TCPConn, network, target string, dialer net.Dialer) error {
	outbound, err := dialer.DialContext(context.Background(), network, target)
	if err != nil {
		return err
	}
	defer outbound.Close()
	server := outbound.(*net.TCPConn)
	server.SetDeadline(time.Now().Add(deadline))
	return stream.Relay(client, server, 0)
}

func serveUDP(conn *net.UDPConn, handle func([]byte, netip.AddrPort) error) error {
	log.Printf("ready %s", conn.LocalAddr())
	packet := make([]byte, 65535)
	for {
		n, peer, err := conn.ReadFromUDPAddrPort(packet)
		if err != nil {
			return err
		}
		if err := handle(packet[:n], peer); err != nil {
			log.Print(err)
		}
	}
}

func exchangeUDP(network, target string, packet []byte, dialer net.Dialer) ([]byte, error) {
	conn, err := dialer.Dial(network, target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(deadline))
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	n, err := conn.Read(response)
	return response[:n], err
}

func probe(network, address string) error {
	payload := "proxy-m0"
	if network[:3] == "udp" {
		response, err := exchangeUDP(network, address, []byte(payload), net.Dialer{Timeout: deadline})
		if err != nil {
			return err
		}
		if string(response) != payload {
			return fmt.Errorf("unexpected UDP response: %q", response)
		}
		return nil
	}
	conn, err := net.DialTimeout(network, address, deadline)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(deadline))
	if _, err := io.WriteString(conn, payload); err != nil {
		return err
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		return err
	}
	response, err := io.ReadAll(io.LimitReader(conn, int64(len(payload)+1)))
	if err != nil {
		return err
	}
	if string(response) != payload {
		return fmt.Errorf("unexpected TCP response: %q", response)
	}
	return nil
}

func probeUDP(network string, addresses []string) error {
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	response := make([]byte, 64)
	for i, address := range addresses {
		target, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		payload := fmt.Sprintf("proxy-m0-%d", i)
		conn.SetDeadline(time.Now().Add(deadline))
		if _, err := conn.WriteToUDPAddrPort([]byte(payload), target); err != nil {
			return err
		}
		n, peer, err := conn.ReadFromUDPAddrPort(response)
		if err != nil {
			return err
		}
		if peer != target || string(response[:n]) != payload {
			return fmt.Errorf("expected %q from %s, received %q from %s", payload, target, response[:n], peer)
		}
	}
	return nil
}
