package windivert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/selfsocket"
)

type flowKey struct{ source, target netip.AddrPort }
type tcpFlow struct {
	key         flowKey
	alias       netip.AddrPort
	reservation *net.TCPListener
	seen        time.Time
	sequence    uint32
	address     [10]uint64
}
type udpFlow struct {
	key      flowKey
	cookie   uint64
	template []byte
	address  [10]uint64
	seen     time.Time
}
type datagram struct {
	payload      []byte
	peer, target netip.AddrPort
}

type Capture struct {
	lib                *library
	handle             uintptr
	config             config.Capture
	mu                 sync.Mutex
	io                 sync.RWMutex
	tcp                map[flowKey]*tcpFlow
	reverse            map[netip.AddrPort]*tcpFlow
	udp                map[flowKey]*udpFlow
	tokens             map[uint64]*udpFlow
	next               uint64
	packets            chan datagram
	done, stop, reaped chan struct{}
	closing            atomic.Bool
	drops              atomic.Uint64
	once               sync.Once
	err, closeErr      error
	fragments          fragmentCache
	packetDrops        atomic.Uint64
	unknownHeaders     sync.Map
	exclusions         []string
	upstreamEndpoints  []upstreamEndpoint
	flowLimit          int
	receivedBatches    atomic.Uint64
	receivedPackets    atomic.Uint64
	sentBatches        atomic.Uint64
	sentPackets        atomic.Uint64
}

func StartCapture(c config.Capture, upstreamSets ...map[string]config.Outbound) (*Capture, error) {
	return StartCaptureResolved(c, nil, upstreamSets...)
}

func StartCaptureResolved(c config.Capture, resolver *net.Resolver, upstreamSets ...map[string]config.Outbound) (*Capture, error) {
	if c.Mode != "windivert" {
		return nil, errors.New("invalid WinDivert capture mode")
	}
	if err := config.ValidateCapture(c); err != nil {
		return nil, err
	}
	exclusions := append([]string(nil), c.ExcludeApplications...)
	var endpoints []upstreamEndpoint
	limit := 256
	if c.Scope == "global" {
		limit = 4096
		if len(upstreamSets) > 0 {
			discovered, err := upstreamExclusions(upstreamSets[0], resolver)
			if err != nil {
				return nil, err
			}
			endpoints = discovered
		}
	}
	if c.Scope != "global" {
		app, err := os.Stat(c.WindowsApplication)
		if err != nil {
			return nil, err
		}
		selfPath, err := os.Executable()
		if err != nil {
			return nil, err
		}
		self, err := os.Stat(selfPath)
		if err != nil {
			return nil, err
		}
		if !app.Mode().IsRegular() || os.SameFile(app, self) {
			return nil, errors.New("windows_application must be a separate regular executable")
		}
	}
	lib, _, err := load()
	if err != nil {
		return nil, err
	}
	handle, err := lib.openHandle(captureFilter(c), layerNetwork, 0)
	if err != nil {
		lib.dll.Release()
		return nil, err
	}
	g := &Capture{lib: lib, handle: handle, config: c, tcp: make(map[flowKey]*tcpFlow), reverse: make(map[netip.AddrPort]*tcpFlow),
		udp: make(map[flowKey]*udpFlow), tokens: make(map[uint64]*udpFlow), packets: make(chan datagram, 64),
		done: make(chan struct{}), stop: make(chan struct{}), reaped: make(chan struct{})}
	g.exclusions, g.flowLimit = exclusions, limit
	g.upstreamEndpoints = endpoints
	go g.run()
	go g.reap()
	return g, nil
}

func (g *Capture) Done() <-chan struct{}     { return g.done }
func (g *Capture) UDPDrops() (uint64, error) { return g.drops.Load(), nil }

func (g *Capture) Close() error {
	g.once.Do(func() {
		g.closing.Store(true)
		close(g.stop)
		g.lib.shutdown.Call(g.handle, 1)
		<-g.done
		<-g.reaped
		for _, packet := range g.fragments.Drain() {
			if err := g.send(packet.data, &packet.address, false); err != nil {
				g.err = errors.Join(g.err, err)
			}
		}
		g.mu.Lock()
		for _, flow := range g.tcp {
			flow.reservation.Close()
		}
		g.tcp = nil
		g.reverse = nil
		g.udp = nil
		g.tokens = nil
		g.mu.Unlock()
		g.io.Lock()
		g.closeErr = errors.Join(g.err, g.lib.closeHandle(g.handle), g.lib.dll.Release())
		g.io.Unlock()
	})
	return g.closeErr
}

func (g *Capture) send(data []byte, address *[10]uint64, modified bool) error {
	g.io.RLock()
	defer g.io.RUnlock()
	if modified {
		ok, _, err := g.lib.checksums.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(address)), 0)
		if ok == 0 {
			return fmt.Errorf("WinDivert checksums: %w", err)
		}
	}
	var sent uint32
	ok, _, err := g.lib.send.Call(g.handle, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&sent)), uintptr(unsafe.Pointer(address)))
	if ok == 0 {
		return fmt.Errorf("WinDivertSend: %w", err)
	}
	if sent != uint32(len(data)) {
		return errors.New("short WinDivert send")
	}
	return nil
}

func (g *Capture) run() {
	defer close(g.done)
	defer close(g.packets)
	data := make([]byte, batchBytes)
	var addresses [batchMax][10]uint64
	var storage [batchMax]capturedPacket
	output := newPacketBatch(g.sendBatch)
	emit := func(raw []byte, address *[10]uint64, modified bool) error {
		if modified {
			ok, _, err := g.lib.checksums.Call(uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(address)), 0)
			if ok == 0 {
				return fmt.Errorf("WinDivert checksums: %w", err)
			}
		}
		return output.add(raw, *address)
	}
	for {
		var size uint32
		addressBytes := uint32(len(addresses) * 80)
		ok, _, err := g.lib.recvEx.Call(g.handle, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&size)), 0,
			uintptr(unsafe.Pointer(&addresses[0])), uintptr(unsafe.Pointer(&addressBytes)), 0)
		if ok == 0 {
			if !g.closing.Load() {
				g.err = fmt.Errorf("WinDivertRecvEx: %w", err)
			}
			return
		}
		if size == 0 || size > uint32(len(data)) || addressBytes == 0 || addressBytes%80 != 0 || addressBytes > uint32(len(addresses)*80) {
			g.err = errors.New("invalid captured batch length")
			return
		}
		packets, err := splitBatch(data[:size], addresses[:addressBytes/80], storage[:0])
		if err != nil {
			g.err = err
			return
		}
		g.receivedBatches.Add(1)
		g.receivedPackets.Add(uint64(len(packets)))
		for _, captured := range packets {
			raw, address := captured.data, captured.address
			if g.closing.Load() {
				if err := emit(raw, &address, false); err != nil {
					g.err = err
					return
				}
				continue
			}
			var originals []capturedPacket
			if !g.closing.Load() {
				assembled, held, waiting, err := g.fragments.Add(raw, address, time.Now())
				if err != nil && !errors.Is(err, errProtected) {
					g.packetDrops.Add(1)
					continue
				}
				if waiting {
					continue
				}
				if err == nil {
					raw, originals = assembled, held
					if len(originals) > 0 {
						address = originals[0].address
					}
				}
			}
			p, parseErr := g.lib.parseTransportPacket(raw)
			if parseErr != nil && !errors.Is(parseErr, errProtected) && !errors.Is(parseErr, errOtherProtocol) {
				var unknown unsupportedHeader
				if errors.As(parseErr, &unknown) {
					if g.config.Scope == "global" {
						counter, _ := g.unknownHeaders.LoadOrStore(byte(unknown), new(atomic.Uint64))
						count := counter.(*atomic.Uint64).Add(1)
						if count == 1 || count&(count-1) == 0 {
							log.Printf("WinDivert unsupported IPv6 next-header=%d dropped=%d", unknown, count)
						}
						g.packetDrops.Add(1)
						continue
					}
				} else {
					g.packetDrops.Add(1)
					continue
				}
			}
			modified, consumed := false, false
			if !g.closing.Load() && parseErr == nil {
				if p.protocol == 6 {
					modified, consumed = g.redirectTCP(p, &address)
				} else if g.selected(p) {
					consumed = g.queueUDP(p, address)
				}
			}
			if consumed {
				continue
			}
			if !modified && len(originals) > 0 {
				for _, original := range originals {
					if err := emit(original.data, &original.address, false); err != nil {
						g.err = err
						return
					}
				}
				continue
			}
			if err := emit(raw, &address, modified); err != nil {
				g.err = err
				return
			}
		}
		// Flush even a single packet immediately; do not wait for the next receive.
		if err := output.flush(); err != nil {
			g.err = err
			return
		}
	}
}

func (g *Capture) PacketStats() map[string]any {
	headers := make(map[string]uint64)
	g.unknownHeaders.Range(func(key, value any) bool {
		headers[fmt.Sprint(key)] = value.(*atomic.Uint64).Load()
		return true
	})
	return map[string]any{"scope": g.config.Scope, "packet_dropped": g.packetDrops.Load(), "unknown_ipv6_next_headers": headers,
		"recv_batches": g.receivedBatches.Load(), "recv_packets": g.receivedPackets.Load(),
		"send_batches": g.sentBatches.Load(), "send_packets": g.sentPackets.Load()}
}

func loopback(ip netip.Addr) netip.Addr {
	if ip.Is4() {
		return netip.MustParseAddr("127.0.0.1")
	}
	return netip.IPv6Loopback()
}

func (g *Capture) redirectTCP(p packet, address *[10]uint64) (bool, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if p.source.Port() == g.config.Port {
		flow := g.reverse[p.target]
		if flow == nil {
			return false, false
		}
		flow.seen = time.Now()
		p.rewrite(flow.key.target, flow.key.source)
		*address = returnAddress(flow.address)
		return true, false
	}
	key := flowKey{p.source, p.target}
	flow := g.tcp[key]
	syn := p.data[p.offset+13]&0x12 == 0x02
	sequence := binary.BigEndian.Uint32(p.data[p.offset+4:])
	// Established flows already have an ownership decision. Never enumerate the
	// system connection table for their data/ACK packets or unrelated old flows.
	if flow == nil && !syn {
		return false, false
	}
	if (flow == nil || syn && flow.sequence != sequence) && !g.selected(p) {
		return false, false
	}
	if flow != nil && syn && flow.sequence != sequence {
		delete(g.reverse, flow.alias)
		delete(g.tcp, key)
		flow.reservation.Close()
		flow = nil
	}
	if flow == nil {
		if !syn {
			// A connection established before capture started keeps its original route.
			return false, false
		}
		if len(g.tcp) >= g.flowLimit {
			return false, g.config.Scope == "application" || g.config.Scope == "global"
		}
		network := "tcp4"
		if p.source.Addr().Is6() {
			network = "tcp6"
		}
		local := loopback(p.source.Addr())
		if address[1]&(1<<18) == 0 {
			local = p.source.Addr()
		}
		reservation, err := net.ListenTCP(network, net.TCPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
		if err != nil {
			return false, g.config.Scope == "application" || g.config.Scope == "global"
		}
		alias := reservation.Addr().(*net.TCPAddr).AddrPort()
		if address[1]&(1<<18) == 0 {
			alias = netip.AddrPortFrom(p.target.Addr(), alias.Port())
		}
		flow = &tcpFlow{key: key, alias: alias, reservation: reservation, sequence: sequence, address: *address}
		g.tcp[key], g.reverse[alias] = flow, flow
	}
	flow.seen = time.Now()
	local := loopback(p.target.Addr())
	if flow.address[1]&(1<<18) == 0 {
		local = flow.key.source.Addr()
		*address = returnAddress(flow.address)
	}
	p.rewrite(flow.alias, netip.AddrPortFrom(local, g.config.Port))
	return true, false
}

func (g *Capture) selected(p packet) bool {
	dns := g.config.DNSHijack && p.target.Port() == 53
	usable := usableTarget(p.target.Addr())
	if dns && p.target.Addr().IsLinkLocalUnicast() {
		usable = true
	}
	if !usable {
		return false
	}
	if g.config.Scope != "global" {
		return ownedBy(p, g.config.WindowsApplication)
	}
	// Preserve local services and LAN connections; DNS 53 still goes through the DNS engine.
	if p.target.Port() != 53 && (p.target.Addr().IsPrivate() || p.target.Addr().IsLoopback()) {
		return false
	}
	if selfsocket.Owns(p.source, p.protocol) {
		return false
	}
	return g.selectedPID(p, endpointPID(p))
}

func (g *Capture) selectedPID(p packet, pid uint32) bool {
	if pid == windows.GetCurrentProcessId() {
		return false
	}
	if pid == 0 {
		return g.config.DNSHijack && p.protocol == 17 && p.target.Port() == 53
	}
	for _, endpoint := range g.upstreamEndpoints {
		if endpointPID(packet{source: endpoint.Address, protocol: endpoint.Protocol}) == pid {
			return false
		}
	}
	if len(g.exclusions) > 0 {
		path := processPath(pid)
		for _, excluded := range g.exclusions {
			if strings.EqualFold(path, filepath.Clean(excluded)) {
				return false
			}
		}
	}
	return true
}

func (g *Capture) Destination(conn *net.TCPConn) (netip.AddrPort, error) {
	peer := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
	g.mu.Lock()
	defer g.mu.Unlock()
	flow := g.reverse[peer]
	if flow == nil {
		return netip.AddrPort{}, errors.New("unknown WinDivert TCP alias")
	}
	flow.seen = time.Now()
	return flow.key.target, nil
}

func (g *Capture) Source(conn *net.TCPConn) (netip.AddrPort, error) {
	peer := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
	g.mu.Lock()
	defer g.mu.Unlock()
	flow := g.reverse[peer]
	if flow == nil {
		return netip.AddrPort{}, errors.New("unknown WinDivert TCP alias")
	}
	flow.seen = time.Now()
	return flow.key.source, nil
}

func tokenPeer(cookie uint64) netip.AddrPort {
	addr := [16]byte{0xfd}
	binary.BigEndian.PutUint64(addr[8:], cookie)
	return netip.AddrPortFrom(netip.AddrFrom16(addr), 1)
}

func (g *Capture) queueUDP(p packet, address [10]uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := flowKey{p.source, p.target}
	flow := g.udp[key]
	if flow == nil {
		if len(g.udp) >= g.flowLimit {
			g.drops.Add(1)
			return true
		}
		g.next++
		flow = &udpFlow{key: key, cookie: g.next}
		g.udp[key], g.tokens[flow.cookie] = flow, flow
	}
	flow.seen = time.Now()
	flow.template = append(flow.template[:0], p.data[:p.payload]...)
	flow.address = address
	select {
	case g.packets <- datagram{append([]byte(nil), p.data[p.payload:]...), tokenPeer(flow.cookie), p.target}:
	default:
		g.drops.Add(1)
	}
	return true
}

func (g *Capture) ReadPacket(data []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	p, ok := <-g.packets
	if !ok {
		return 0, netip.AddrPort{}, netip.AddrPort{}, net.ErrClosed
	}
	if len(p.payload) > len(data) {
		return 0, netip.AddrPort{}, netip.AddrPort{}, errors.New("captured UDP payload too large")
	}
	return copy(data, p.payload), p.peer, p.target, nil
}

func (g *Capture) ReplyPacket(peer netip.AddrPort, payload []byte) error {
	if g.closing.Load() {
		return net.ErrClosed
	}
	if len(payload) > 65507 {
		return errors.New("UDP response too large")
	}
	if !peer.Addr().Is6() {
		return errors.New("invalid UDP flow token")
	}
	addr := peer.Addr().As16()
	cookie := binary.BigEndian.Uint64(addr[8:])
	g.mu.Lock()
	flow := g.tokens[cookie]
	if flow == nil {
		g.mu.Unlock()
		return errors.New("expired UDP flow token")
	}
	template := append([]byte(nil), flow.template...)
	address, key := returnAddress(flow.address), flow.key
	flow.seen = time.Now()
	g.mu.Unlock()
	data, err := udpResponse(template, key.target, key.source, payload)
	if err != nil {
		return err
	}
	// Hold the flow lock through send so Close cannot release the DLL concurrently.
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing.Load() {
		return net.ErrClosed
	}
	return g.send(data, &address, true)
}

func usableTarget(ip netip.Addr) bool {
	return !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && ip != netip.MustParseAddr("255.255.255.255")
}

func (g *Capture) reap() {
	defer close(g.reaped)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-g.stop:
			return
		case now := <-ticker.C:
			g.packetDrops.Add(uint64(g.fragments.Expire(now)))
			g.mu.Lock()
			for key, flow := range g.tcp {
				if now.Sub(flow.seen) > 5*time.Minute {
					delete(g.tcp, key)
					delete(g.reverse, flow.alias)
					flow.reservation.Close()
				}
			}
			for key, flow := range g.udp {
				if now.Sub(flow.seen) > time.Minute {
					delete(g.udp, key)
					delete(g.tokens, flow.cookie)
				}
			}
			g.mu.Unlock()
		}
	}
}
