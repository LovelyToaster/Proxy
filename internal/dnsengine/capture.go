package dnsengine

import (
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var dnsPacketPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4096)
		return &b
	},
}

func (e *Engine) HandleStream(conn net.Conn) {
	channel := &dns.Conn{Conn: conn}
	for range 32 {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		query, err := channel.ReadMsg()
		if err != nil {
			return
		}
		answer := e.handle(query)
		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if channel.WriteMsg(answer) != nil {
			return
		}
	}
}

// SubmitPacket applies backpressure before copying or starting a worker.
func (e *Engine) SubmitPacket(packet []byte, send func([]byte) error) {
	e.queries.Add(1)
	if len(packet) > 4096 {
		e.failed.Add(1)
		return
	}
	select {
	case e.workers <- struct{}{}:
	default:
		e.failed.Add(1)
		return
	}
	bufPtr := dnsPacketPool.Get().(*[]byte)
	n := copy(*bufPtr, packet)
	wire := (*bufPtr)[:n]
	e.packets.Go(func() {
		defer func() { <-e.workers }()
		q := new(dns.Msg)
		err := q.Unpack(wire)
		dnsPacketPool.Put(bufPtr)
		if err != nil || q.Response {
			e.failed.Add(1)
			return
		}
		answer := e.answer(q)
		truncate(q, answer)
		wire, err := answer.Pack()
		if err != nil || send(wire) != nil {
			e.failed.Add(1)
		}
	})
}
