package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"proxy.local/m0/internal/linuxsocket"
)

// Values from Linux UAPI in linux/in.h, linux/in6.h and linux/netfilter_ipv4.h.
const (
	bypassMark = 2
)

func capture(mode, network, address string) error {
	namespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil || namespace != os.Getenv("PROXY_M0_NETNS") {
		return errors.New("capture requires the lab network namespace")
	}
	if network[:3] == "udp" {
		if mode != "transparent" {
			return errors.New("UDP capture requires TPROXY")
		}
		return captureUDP(network, address)
	}
	config := net.ListenConfig{}
	if mode == "transparent" {
		config.Control = linuxsocket.TransparentControl(false, 0)
	}
	listener, err := config.Listen(context.Background(), network, address)
	if err != nil {
		return err
	}
	defer listener.Close()
	return serveTCP(listener, func(conn *net.TCPConn) error {
		target := conn.LocalAddr().(*net.TCPAddr).AddrPort()
		if mode == "redirect" {
			target, err := linuxsocket.RedirectTarget(conn, network)
			if err != nil {
				return err
			}
			return forwardCapturedTCP(conn, network, target)
		}
		return forwardCapturedTCP(conn, network, target)
	})
}

func forwardCapturedTCP(conn *net.TCPConn, network string, target netip.AddrPort) error {
	log.Printf("capture %s target=%s", network, target)
	return relayTCP(conn, network, target.String(), markedDialer())
}

func markedDialer() net.Dialer {
	dialer := linuxsocket.MarkedDialer(bypassMark)
	dialer.Timeout = deadline
	return dialer
}

func captureUDP(network, address string) error {
	config := net.ListenConfig{Control: linuxsocket.TransparentControl(true, 0)}
	listener, err := config.ListenPacket(context.Background(), network, address)
	if err != nil {
		return err
	}
	defer listener.Close()
	conn := listener.(*net.UDPConn)
	log.Printf("ready %s", conn.LocalAddr())
	packet, control := make([]byte, 65535), make([]byte, 128)
	for {
		n, oobn, flags, peer, err := conn.ReadMsgUDPAddrPort(packet, control)
		if err != nil {
			return err
		}
		if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
			log.Print("truncated UDP payload or metadata")
			continue
		}
		if err := forwardCapturedUDP(network, packet[:n], control[:oobn], peer); err != nil {
			log.Print(err)
		}
	}
}

func forwardCapturedUDP(network string, packet, control []byte, peer netip.AddrPort) error {
	target, err := linuxsocket.OriginalUDP(control, network == "udp6")
	if err != nil {
		return err
	}
	log.Printf("capture %s target=%s", network, target)
	response, err := exchangeUDP(network, target.String(), packet, markedDialer())
	if err != nil {
		return err
	}
	config := net.ListenConfig{Control: linuxsocket.TransparentControl(false, bypassMark)}
	reply, err := config.ListenPacket(context.Background(), network, target.String())
	if err != nil {
		return err
	}
	defer reply.Close()
	reply.SetWriteDeadline(time.Now().Add(deadline))
	_, err = reply.(*net.UDPConn).WriteToUDPAddrPort(response, peer)
	return err
}
