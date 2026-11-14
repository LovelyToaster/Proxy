package windivert

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	"proxy.local/m0/internal/logging"
	"proxy.local/m0/internal/selfsocket"
)

type flowKey struct{ source, target netip.AddrPort }
type tcpFlow struct {
	key         flowKey
	alias       netip.AddrPort
	reservation *net.TCPListener
	seen        atomic.Int64
	sequence    uint32
	address     [10]uint64
}

func (f *tcpFlow) touch(nowUnixNano int64) {
	prev := f.seen.Load()
	if nowUnixNano-prev > int64(time.Second) {
		f.seen.Store(nowUnixNano)
	}
}

type udpFlow struct {
	key      flowKey
	cookie   uint64
	template []byte
	address  [10]uint64
	seen     time.Time
}
type datagram struct {
	buf          *[]byte
	payload      []byte
	peer, target netip.AddrPort
}

var divertUDPPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

type Capture struct {
	lib                *library
	handle             uintptr
	replyHandle        uintptr
	config             config.Capture
	mu                 sync.RWMutex
	io                 sync.RWMutex
	errMu              sync.Mutex
	tcp                map[flowKey]*tcpFlow
	reverse            map[netip.AddrPort]*tcpFlow
	udp                map[flowKey]*udpFlow
	tokens             map[uint64]*udpFlow
	next               uint64
	packets            chan datagram
	done               chan struct{}
	replyDone          chan struct{}
	stop, reaped       chan struct{}
	closing            atomic.Bool
	drops              atomic.Uint64
	once               sync.Once
	err, closeErr      error
	fragments          fragmentCache
	packetDrops        atomic.Uint64
	unknownHeaders     sync.Map
	exclusions         []string
	upstreamEndpoints  []upstreamEndpoint
	upstreamPIDMu      sync.Mutex
	upstreamPIDExpires time.Time
	upstreamPIDs       map[uint32]struct{}
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
	reqFilter, repFilter := splitCaptureFilters(c)
	handle, err := lib.openHandle(reqFilter, layerNetwork, 0)
	if err != nil {
		lib.dll.Release()
		return nil, err
	}
	replyHandle, err := lib.openHandle(repFilter, layerNetwork, 0)
	if err != nil {
		lib.closeHandle(handle)
		lib.dll.Release()
		return nil, err
	}
	lib.tuneHandle(handle)
	lib.tuneHandle(replyHandle)
	g := &Capture{lib: lib, handle: handle, replyHandle: replyHandle, config: c, tcp: make(map[flowKey]*tcpFlow), reverse: make(map[netip.AddrPort]*tcpFlow),
		udp: make(map[flowKey]*udpFlow), tokens: make(map[uint64]*udpFlow), packets: make(chan datagram, 512),
		done: make(chan struct{}), replyDone: make(chan struct{}), stop: make(chan struct{}), reaped: make(chan struct{})}
	g.exclusions, g.flowLimit = exclusions, limit
	g.upstreamEndpoints = endpoints
	go g.runHandle(g.handle, g.done, true)
	go g.runHandle(g.replyHandle, g.replyDone, false)
	go g.reap()
	return g, nil
}

func (g *Capture) Done() <-chan struct{}     { return g.done }
func (g *Capture) UDPDrops() (uint64, error) { return g.drops.Load(), nil }

func (g *Capture) setErr(err error) {
	if err == nil {
		return
	}
	g.errMu.Lock()
	g.err = errors.Join(g.err, err)
	g.errMu.Unlock()
}

func (g *Capture) Close() error {
	g.once.Do(func() {
		g.closing.Store(true)
		close(g.stop)
		g.lib.shutdown.Call(g.handle, 1)
		g.lib.shutdown.Call(g.replyHandle, 1)
		<-g.done
		<-g.replyDone
		<-g.reaped
		for _, packet := range g.fragments.Drain() {
			if err := g.send(packet.data, &packet.address, false); err != nil {
				g.setErr(err)
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
		g.closeErr = errors.Join(g.err, g.lib.closeHandle(g.handle), g.lib.closeHandle(g.replyHandle), g.lib.dll.Release())
		g.io.Unlock()
	})
	return g.closeErr
}

func (g *Capture) send(data []byte, address *[10]uint64, modified bool) error {
	g.io.RLock()
	defer g.io.RUnlock()
	if g.closing.Load() {
		return net.ErrClosed
	}
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

func isNonFragmentPacket(raw []byte) bool {
	if len(raw) < 20 {
		return false
	}
	switch raw[0] >> 4 {
	case 4:
		return binary.BigEndian.Uint16(raw[6:8])&0x3FFF == 0
	case 6:
		if len(raw) < 40 {
			return false
		}
		return raw[6] == 6 || raw[6] == 17
	default:
		return false
	}
}

func (g *Capture) runHandle(handle uintptr, done chan struct{}, closePackets bool) {
	defer close(done)
	if closePackets {
		defer close(g.packets)
	}
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
		ok, _, err := g.lib.recvEx.Call(handle, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&size)), 0,
			uintptr(unsafe.Pointer(&addresses[0])), uintptr(unsafe.Pointer(&addressBytes)), 0)
		if ok == 0 {
			if !g.closing.Load() {
				g.setErr(fmt.Errorf("WinDivertRecvEx: %w", err))
			}
			return
		}
		if size == 0 || size > uint32(len(data)) || addressBytes == 0 || addressBytes%80 != 0 || addressBytes > uint32(len(addresses)*80) {
			g.setErr(errors.New("invalid captured batch length"))
			return
		}
		packets, err := splitBatch(data[:size], addresses[:addressBytes/80], storage[:0])
		if err != nil {
			g.setErr(err)
			return
		}
		g.receivedBatches.Add(1)
		g.receivedPackets.Add(uint64(len(packets)))
		for _, captured := range packets {
			raw, address := captured.data, captured.address
			if g.closing.Load() {
				if err := emit(raw, &address, false); err != nil {
					g.setErr(err)
					return
				}
				continue
			}
			var originals []capturedPacket
			if !g.closing.Load() && !isNonFragmentPacket(raw) {
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
							logging.Warnf("WinDivert unsupported IPv6 next-header=%d dropped=%d", unknown, count)
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
						g.setErr(err)
						return
					}
				}
				continue
			}
			if err := emit(raw, &address, modified); err != nil {
				g.setErr(err)
				return
			}
		}
		// Flush even a single packet immediately; do not wait for the next receive.
		if err := output.flush(); err != nil {
			g.setErr(err)
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
	if p.source.Port() == g.config.Port {
		g.mu.RLock()
		flow := g.reverse[p.target]
		if flow == nil {
			g.mu.RUnlock()
			return false, false
		}
		target, source, addr := flow.key.target, flow.key.source, flow.address
		g.mu.RUnlock()
		flow.touch(time.Now().UnixNano())
		needsCsum := !p.rewriteTCPIncremental(target, source)
		*address = returnAddress(addr)
		return needsCsum, false
	}
	key := flowKey{p.source, p.target}
	syn := p.data[p.offset+13]&0x12 == 0x02
	sequence := binary.BigEndian.Uint32(p.data[p.offset+4:])

	g.mu.RLock()
	flow := g.tcp[key]
	if flow != nil && !(syn && flow.sequence != sequence) {
		alias, addr := flow.alias, flow.address
		g.mu.RUnlock()
		flow.touch(time.Now().UnixNano())
		local := loopback(p.target.Addr())
		if addr[1]&(1<<18) == 0 {
			local = key.source.Addr()
			*address = returnAddress(addr)
		}
		needsCsum := !p.rewriteTCPIncremental(alias, netip.AddrPortFrom(local, g.config.Port))
		return needsCsum, false
	}
	g.mu.RUnlock()

	// Established flows already have an ownership decision. Never enumerate the
	// system connection table for their data/ACK packets or unrelated old flows.
	if flow == nil && !syn {
		return false, false
	}
	if !g.selected(p) {
		return false, false
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	flow = g.tcp[key]
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
		flow.seen.Store(time.Now().UnixNano())
		g.tcp[key], g.reverse[alias] = flow, flow
	}
	flow.touch(time.Now().UnixNano())
	local := loopback(p.target.Addr())
	if flow.address[1]&(1<<18) == 0 {
		local = flow.key.source.Addr()
		*address = returnAddress(flow.address)
	}
	needsCsum := !p.rewriteTCPIncremental(flow.alias, netip.AddrPortFrom(local, g.config.Port))
	return needsCsum, false
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
	return g.selectedPID(p, cachedEndpointPID(p))
}

func (g *Capture) isUpstreamPID(pid uint32) bool {
	if len(g.upstreamEndpoints) == 0 {
		return false
	}
	now := time.Now()
	g.upstreamPIDMu.Lock()
	defer g.upstreamPIDMu.Unlock()
	if g.upstreamPIDs == nil || !now.Before(g.upstreamPIDExpires) {
		pids := make(map[uint32]struct{}, len(g.upstreamEndpoints))
		for _, endpoint := range g.upstreamEndpoints {
			if p := endpointPID(packet{source: endpoint.Address, protocol: endpoint.Protocol}); p != 0 {
				pids[p] = struct{}{}
			}
		}
		g.upstreamPIDs = pids
		g.upstreamPIDExpires = now.Add(500 * time.Millisecond)
	}
	_, ok := g.upstreamPIDs[pid]
	return ok
}

func (g *Capture) selectedPID(p packet, pid uint32) bool {
	if pid == windows.GetCurrentProcessId() {
		return false
	}
	if pid == 0 {
		return g.config.DNSHijack && p.protocol == 17 && p.target.Port() == 53
	}
	if g.isUpstreamPID(pid) {
		return false
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
	g.mu.RLock()
	flow := g.reverse[peer]
	if flow == nil {
		g.mu.RUnlock()
		return netip.AddrPort{}, errors.New("unknown WinDivert TCP alias")
	}
	target := flow.key.target
	g.mu.RUnlock()
	flow.touch(time.Now().UnixNano())
	return target, nil
}

func (g *Capture) Source(conn *net.TCPConn) (netip.AddrPort, error) {
	peer := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
	g.mu.RLock()
	flow := g.reverse[peer]
	if flow == nil {
		g.mu.RUnlock()
		return netip.AddrPort{}, errors.New("unknown WinDivert TCP alias")
	}
	source := flow.key.source
	g.mu.RUnlock()
	flow.touch(time.Now().UnixNano())
	return source, nil
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
	bufPtr := divertUDPPool.Get().(*[]byte)
	n := copy(*bufPtr, p.data[p.payload:])
	select {
	case g.packets <- datagram{buf: bufPtr, payload: (*bufPtr)[:n], peer: tokenPeer(flow.cookie), target: p.target}:
	default:
		divertUDPPool.Put(bufPtr)
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
		if p.buf != nil {
			divertUDPPool.Put(p.buf)
		}
		return 0, netip.AddrPort{}, netip.AddrPort{}, errors.New("captured UDP payload too large")
	}
	copied := copy(data, p.payload)
	if p.buf != nil {
		divertUDPPool.Put(p.buf)
	}
	return copied, p.peer, p.target, nil
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
	tplPtr := divertUDPPool.Get().(*[]byte)
	tn := copy(*tplPtr, flow.template)
	address, key := returnAddress(flow.address), flow.key
	flow.seen = time.Now()
	g.mu.Unlock()
	data, err := udpResponse((*tplPtr)[:tn], key.target, key.source, payload)
	divertUDPPool.Put(tplPtr)
	if err != nil {
		return err
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
				if now.Sub(time.Unix(0, flow.seen.Load())) > 5*time.Minute {
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
