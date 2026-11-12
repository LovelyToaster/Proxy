package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxy.local/m0/internal/capture"
	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/dnsengine"
	"proxy.local/m0/internal/geodata"
	"proxy.local/m0/internal/ipc"
	"proxy.local/m0/internal/logbuffer"
	"proxy.local/m0/internal/outbound"
	"proxy.local/m0/internal/routing"
	"proxy.local/m0/internal/session"
	"proxy.local/m0/internal/stream"
	"proxy.local/m0/internal/web"
)

const Version = "0.1.0-m3"

type connection struct {
	ID          uint64         `json:"id"`
	Source      string         `json:"source"`
	Destination netip.AddrPort `json:"destination"`
	Outbound    string         `json:"outbound"`
	Generation  uint64         `json:"generation"`
	Started     time.Time      `json:"started"`
}

type state struct {
	configPath       string
	applyAutostart   func(bool) error
	runtimeDirectory string
	mu               sync.Mutex
	updates          sync.Mutex
	cfg              config.Config
	routes           *routing.Table
	generation       uint64
	nextID           uint64
	active           map[uint64]connection
	connected        map[string]uint64
	udp              *session.UDP
	kernelUDPDrops   func() (uint64, error)
	captureUDPDrops  func() (uint64, error)
	captureStats     func() any
	dns              *dnsengine.Engine
	store            geodata.Store
	geo              geodata.Manifest
	geoTimer         chan struct{}
}

func Check(path string) error {
	cfg, table, err := load(path)
	if err != nil {
		return err
	}
	defer table.Close()
	engine, err := dnsengine.New(cfg.DNS, net.Dialer{}, cfg.Outbounds)
	if err != nil {
		return err
	}
	return engine.Close()
}

func load(path string) (config.Config, *routing.Table, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return cfg, nil, err
	}
	manifest, err := geodata.ForConfig(path).Read()
	if err != nil {
		return cfg, nil, err
	}
	cfg = geodata.ForConfig(path).Apply(cfg, manifest)
	table, err := routing.Open(cfg.Routing)
	return cfg, table, err
}

func Serve(parent context.Context, path, directory string) error {
	return ServeReady(parent, path, directory, nil)
}

func ServeReady(parent context.Context, path, directory string, ready func()) error {
	return ServeReadyManaged(parent, path, directory, ready, nil)
}

func ServeReadyManaged(parent context.Context, path, directory string, ready func(), apply func(bool) error) error {
	previous := log.Writer()
	if apply != nil {
		log.SetOutput(logbuffer.Default)
	} else {
		log.SetOutput(io.MultiWriter(previous, logbuffer.Default))
	}
	defer log.SetOutput(previous)
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if apply != nil {
		if err := apply(cfg.Service.Autostart); err != nil {
			return err
		}
	}
	store := geodata.ForConfig(path)
	manifest, err := store.Read()
	if err != nil {
		return err
	}
	effective := store.Apply(cfg, manifest)
	routes, err := routing.Open(effective.Routing)
	if err != nil {
		return err
	}
	state := &state{cfg: cfg, routes: routes, generation: 1, active: make(map[uint64]connection), connected: make(map[string]uint64), store: store, geo: manifest, geoTimer: make(chan struct{}, 1)}
	state.runtimeDirectory = directory
	state.configPath = path
	state.applyAutostart = apply
	state.udp = session.NewUDP(state.resolveUDP)
	defer state.udp.Close()
	defer func() { state.routes.Close() }()
	state.dns, err = dnsengine.New(effective.DNS, capture.Dialer(cfg.Capture), effective.Outbounds)
	if err != nil {
		return err
	}
	defer state.dns.Close()

	control, err := ipc.Listen(directory, cfg.Service.StatusGroup)
	if err != nil {
		return err
	}
	store.Prune(manifest)
	status, err := ipc.ListenStatus(directory, cfg.Service.StatusGroup)
	if err != nil {
		control.Close()
		return err
	}
	closeControl := func() {
		if status != nil {
			status.Close()
		}
		control.Close()
	}
	listeners, err := openListeners(cfg)
	if err != nil {
		closeControl()
		return err
	}
	packets, err := openPackets(cfg)
	if err != nil {
		closeListeners(listeners)
		closeControl()
		return err
	}
	if err := parent.Err(); err != nil {
		closeListeners(listeners)
		closePackets(packets)
		closeControl()
		return err
	}

	var webServer *web.Server
	if cfg.Web.Enabled && cfg.Web.Listen != "" {
		var err error
		webServer, err = web.New(cfg.Web.Listen, state)
		if err != nil {
			closeListeners(listeners)
			closePackets(packets)
			closeControl()
			return fmt.Errorf("web dashboard: %w", err)
		}
		log.Printf("web dashboard listening on http://%s", webServer.Addr().String())
		go func() {
			if err := webServer.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("web server error: %v", err)
			}
		}()
		defer webServer.Close()
	}

	dnsServers, err := state.dns.Start()
	if err != nil {
		closeListeners(listeners)
		closePackets(packets)
		closeControl()
		return err
	}
	defer dnsServers.Close()

	guard, err := capture.StartResolved(cfg.Capture, directory, state.dns.Dialer(capture.Dialer(cfg.Capture)).Resolver, cfg.Outbounds)
	if err != nil {
		closeListeners(listeners)
		closePackets(packets)
		closeControl()
		return err
	}
	capture.BindGuard(listeners, guard)
	state.captureStats = capture.GuardStats(guard)
	if packet := capture.GuardPackets(guard, cfg.Capture); packet != nil {
		packets = append(packets, packet)
		state.kernelUDPDrops = packet.KernelDrops
		state.captureUDPDrops = packet.CaptureDrops
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	geoDone := make(chan struct{})
	go func() { defer close(geoDone); state.autoGeo(ctx) }()
	sessions, closeSessions := context.WithCancel(context.Background())
	defer closeSessions()
	var acceptors, connections sync.WaitGroup
	failure := make(chan error, 1)
	for _, listener := range listeners {
		acceptors.Go(func() {
			if err := state.serveTCP(sessions, listener, &connections); !errors.Is(err, net.ErrClosed) {
				select {
				case failure <- err:
				default:
				}
			}
		})
	}
	for _, listener := range packets {
		acceptors.Go(func() {
			if err := state.udp.Serve(listener, state.interceptDNS(listener)); !errors.Is(err, net.ErrClosed) {
				select {
				case failure <- err:
				default:
				}
			}
		})
	}
	var ipcWorkers sync.WaitGroup
	ipcWorkers.Go(func() { state.serveIPC(ctx, control, path, cancel, false) })
	if status != nil {
		ipcWorkers.Go(func() { state.serveIPC(ctx, status, path, cancel, true) })
	}
	log.Printf("proxyd ready (capture=%s)", cfg.Capture.Mode)
	if ready != nil {
		ready()
	}
	var guardDone <-chan struct{}
	if guard != nil {
		guardDone = guard.Done()
	}
	select {
	case <-ctx.Done():
	case err = <-failure:
	case err = <-dnsServers.Failure():
	case <-guardDone:
		err = errors.New("capture guard exited unexpectedly")
	}
	cancel()
	// Remove kernel capture before closing the listeners and draining streams.
	if guard != nil {
		err = errors.Join(err, guard.Close())
	}
	closeListeners(listeners)
	closePackets(packets)
	closeControl()
	acceptors.Wait()
	drained := make(chan struct{})
	go func() { connections.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		closeSessions()
		<-drained
	}
	ipcWorkers.Wait()
	<-geoDone
	return err
}

func openListeners(cfg config.Config) ([]capture.Listener, error) {
	listeners, err := capture.Listen(cfg.Capture)
	if err != nil {
		return nil, err
	}
	for _, item := range cfg.Listeners {
		if item.Network != "tcp" {
			continue
		}
		listener, err := net.Listen("tcp", item.Address.String())
		if err != nil {
			closeListeners(listeners)
			return nil, err
		}
		listeners = append(listeners, capture.Listener{
			Listener:    listener,
			Destination: func(*net.TCPConn) (netip.AddrPort, error) { return item.Target, nil },
		})
	}
	return listeners, nil
}

func openPackets(cfg config.Config) ([]*capture.PacketListener, error) {
	listeners, err := capture.ListenUDP(cfg.Capture)
	if err != nil {
		return nil, err
	}
	for _, item := range cfg.Listeners {
		if item.Network != "udp" {
			continue
		}
		listener, err := capture.ListenExplicitUDP(item.Address, item.Target)
		if err != nil {
			closePackets(listeners)
			return nil, err
		}
		listeners = append(listeners, listener)
	}
	return listeners, nil
}

func closePackets(listeners []*capture.PacketListener) {
	for _, listener := range listeners {
		listener.Close()
	}
}

func (s *state) interceptDNS(listener *capture.PacketListener) func([]byte, netip.AddrPort, netip.AddrPort) bool {
	if s.dns == nil || !listener.Transparent {
		return nil
	}
	return func(packet []byte, peer, target netip.AddrPort) bool {
		if target.Port() != 53 {
			return false
		}
		s.dns.SubmitPacket(packet, func(answer []byte) error {
			reply, err := listener.Reply(peer, target)
			if err != nil {
				return err
			}
			defer reply.Close()
			return reply.Write(answer)
		})
		return true
	}
}

func (s *state) resolveUDP(target netip.AddrPort) (session.Route, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, err := s.routes.Select(target, "udp")
	if err != nil {
		return session.Route{}, err
	}
	proxy := s.cfg.Outbounds[name]
	if proxy.Type == "http" && proxy.UDPFallback != "" {
		name = proxy.UDPFallback
		proxy = s.cfg.Outbounds[name]
	}
	return session.Route{Name: name, Outbound: proxy, Dialer: s.dns.Dialer(capture.Dialer(s.cfg.Capture)), Network: s.cfg.Network}, nil
}

func closeListeners(listeners []capture.Listener) {
	for _, listener := range listeners {
		listener.Close()
	}
}

func (s *state) serveTCP(ctx context.Context, listener capture.Listener, workers *sync.WaitGroup) error {
	for {
		in, err := listener.Accept()
		if err != nil {
			return err
		}
		tcp := in.(*net.TCPConn)
		target, err := listener.Destination(tcp)
		if err != nil {
			tcp.Close()
			log.Printf("TCP destination: %v", err)
			continue
		}

		s.mu.Lock()
		if len(s.active) >= s.cfg.Network.MaxConnections {
			s.mu.Unlock()
			tcp.Close()
			continue
		}
		isDNS := listener.Transparent && target.Port() == 53 && s.dns != nil
		name := "dns"
		if !isDNS {
			name, err = s.routes.Select(target, "tcp")
		}
		if err != nil {
			s.mu.Unlock()
			tcp.Close()
			log.Printf("TCP routing: %v", err)
			continue
		}
		proxy := s.cfg.Outbounds[name]
		network := s.cfg.Network
		dialer := s.dns.Dialer(capture.Dialer(s.cfg.Capture))
		s.nextID++
		id := s.nextID
		source := tcp.RemoteAddr().String()
		if listener.Source != nil {
			if src, err := listener.Source(tcp); err == nil && src.IsValid() {
				source = src.String()
			}
		}
		s.active[id] = connection{id, source, target, name, s.generation, time.Now()}
		s.mu.Unlock()

		workers.Go(func() {
			defer tcp.Close()
			defer func() { s.mu.Lock(); delete(s.active, id); s.mu.Unlock() }()
			stopClient := context.AfterFunc(ctx, func() { tcp.Close() })
			defer stopClient()
			if isDNS {
				s.dns.HandleStream(tcp)
				return
			}
			if listener.PrepareDialer != nil {
				var err error
				dialer, err = listener.PrepareDialer(tcp, dialer)
				if err != nil {
					log.Printf("TCP redirect records: %v", err)
					return
				}
			}
			upstream, err := outbound.Dial(ctx, dialer, proxy, target, network.ConnectTimeout)
			if err != nil {
				log.Printf("TCP dial %s via %s: %v", target, name, err)
				return
			}
			defer upstream.Close()
			stopUpstream := context.AfterFunc(ctx, func() { upstream.Close() })
			defer stopUpstream()
			s.mu.Lock()
			s.connected[name]++
			s.mu.Unlock()
			if err := stream.Relay(tcp, upstream, network.IdleTimeout); err != nil && ctx.Err() == nil {
				log.Printf("TCP relay %s via %s: %v", target, name, err)
			}
		})
	}
}

func (s *state) serveIPC(ctx context.Context, listener net.Listener, path string, stop func(), readOnly bool) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		request, err := ipc.Read(conn)
		var result any
		if err == nil {
			if readOnly && !ipc.ReadOnly(request.Command) {
				err = errors.New("command requires the private management endpoint")
			} else {
				result, err = s.handle(ctx, request.Command, path)
			}
		}
		ipc.Send(conn, result, err)
		conn.Close()
		if request.Command == "stop" && err == nil {
			stop()
			return
		}
	}
}

func (s *state) handle(ctx context.Context, command, path string) (any, error) {
	if strings.HasPrefix(command, "logs:") {
		after, err := strconv.ParseUint(strings.TrimPrefix(command, "logs:"), 10, 64)
		if err != nil {
			return nil, err
		}
		return logbuffer.Default.Read(after), nil
	}
	switch command {
	case "geo-status":
		return s.geoStatus(), nil
	case "geo-update":
		return s.updateGeo(ctx)
	case "dns-status":
		return s.dns.Status(), nil
	case "dns-flush":
		return map[string]bool{"flushed": true}, s.dns.Flush()
	}
	if command == "reload" {
		generation, err := s.reload(path)
		return map[string]uint64{"generation": generation}, err
	}
	var udp session.Stats
	if command == "status" {
		udp = s.udp.Stats()
		if s.kernelUDPDrops != nil {
			if drops, err := s.kernelUDPDrops(); err == nil {
				udp.KernelDropped = &drops
			}
		}
		if s.captureUDPDrops != nil {
			if drops, err := s.captureUDPDrops(); err == nil {
				udp.CaptureDropped = &drops
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch command {
	case "status":
		connected := make(map[string]uint64, len(s.connected))
		for name, count := range s.connected {
			connected[name] = count
		}
		result := map[string]any{"state": "running", "generation": s.generation, "capture": s.cfg.Capture.Mode, "active_tcp": len(s.active), "connected": connected, "udp": udp}
		if s.captureStats != nil {
			result["capture_stats"] = s.captureStats()
		}
		return result, nil
	case "connections":
		items := make([]connection, 0, len(s.active))
		for _, item := range s.active {
			items = append(items, item)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		return items, nil
	case "stop":
		return map[string]string{"state": "stopping"}, nil
	default:
		return nil, fmt.Errorf("unknown IPC command %q", command)
	}
}

func (s *state) Overview() (web.OverviewData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	connected := make(map[string]uint64, len(s.connected))
	for k, v := range s.connected {
		connected[k] = v
	}

	activeConns := make([]web.ActiveConn, 0, len(s.active))
	now := time.Now()
	for _, item := range s.active {
		dur := web.FormatDurationChinese(now.Sub(item.Started))
		activeConns = append(activeConns, web.ActiveConn{
			ID:          item.ID,
			Source:      item.Source,
			Destination: item.Destination.String(),
			Outbound:    item.Outbound,
			Duration:    dur,
		})
	}
	sort.Slice(activeConns, func(i, j int) bool { return activeConns[i].ID < activeConns[j].ID })

	udp := s.udp.Stats()
	if s.kernelUDPDrops != nil {
		if drops, err := s.kernelUDPDrops(); err == nil {
			udp.KernelDropped = &drops
		}
	}
	if s.captureUDPDrops != nil {
		if drops, err := s.captureUDPDrops(); err == nil {
			udp.CaptureDropped = &drops
		}
	}

	driver := s.cfg.Capture.Mode
	if driver == "" || driver == "off" {
		driver = "未启用"
	} else {
		switch strings.ToLower(driver) {
		case "windivert":
			driver = "WinDivert"
		case "tproxy":
			driver = "TPROXY"
		case "redirect":
			driver = "Redirect"
		}
	}

	dnsOverview := web.DNSOverview{Enabled: s.dns != nil}
	if s.dns != nil {
		dnsStat := s.dns.Status()
		dnsOverview.Queries = dnsStat.Queries
		dnsOverview.CacheHits = dnsStat.CacheHits
		dnsOverview.StaleHits = dnsStat.StaleHits
		if dnsStat.CacheHits >= dnsStat.StaleHits {
			dnsOverview.FreshHits = dnsStat.CacheHits - dnsStat.StaleHits
		}
		dnsOverview.Failures = dnsStat.Failures
		dnsOverview.Fallbacks = dnsStat.Fallbacks
		dnsOverview.Cached = dnsStat.Cached
		dnsOverview.MaxEntries = s.cfg.DNS.Cache.MaxEntries
		if dnsOverview.MaxEntries == 0 {
			dnsOverview.MaxEntries = 4096
		}
		totalResolved := dnsStat.CacheHits + dnsStat.Failures
		if dnsStat.Queries > totalResolved {
			dnsOverview.OtherQueries = dnsStat.Queries - totalResolved
		}
		if dnsStat.Queries > 0 {
			hitRate := float64(dnsStat.CacheHits) / float64(dnsStat.Queries) * 100.0
			dnsOverview.HitRate = fmt.Sprintf("%.1f%%", hitRate)
		} else {
			dnsOverview.HitRate = "0%"
		}
		dnsOverview.UpstreamRequests = dnsStat.UpstreamRequests
	}

	return web.OverviewData{
		Driver:      driver,
		Scope:       web.ScopeText(s.cfg.Capture.Scope, s.cfg.Capture.Mode, s.cfg.Capture.IPv4, s.cfg.Capture.IPv6),
		Generation:  s.generation,
		ActiveTCP:   len(s.active),
		MaxTCP:      s.cfg.Network.MaxConnections,
		Connected:   connected,
		ActiveConns: activeConns,
		UDPStats:    udp,
		DNSStats:    dnsOverview,
	}, nil
}

func (s *state) Logs(after uint64) logbuffer.Snapshot {
	return logbuffer.Default.Read(after)
}

func (s *state) FlushDNS() error {
	if s.dns == nil {
		return errors.New("DNS is disabled")
	}
	return s.dns.Flush()
}

func (s *state) Reload() error {
	_, err := s.reload(s.configPath)
	return err
}
