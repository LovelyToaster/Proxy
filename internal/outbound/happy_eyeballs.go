package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/stream"
)

type dialAttemptResult struct {
	target netip.AddrPort
	conn   net.Conn
}

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// DialWithFallback connects to target, and for direct outbounds races validated fallback targets
// after fallbackDelay following RFC 8305 Happy Eyeballs semantics.
func DialWithFallback(
	ctx context.Context,
	dialer net.Dialer,
	proxy config.Outbound,
	target netip.AddrPort,
	fallbacks []netip.AddrPort,
	fallbackDelay time.Duration,
	timeout time.Duration,
) (stream.Conn, netip.AddrPort, error) {
	if proxy.Type != "direct" || fallbackDelay <= 0 || len(fallbacks) == 0 {
		conn, err := Dial(ctx, dialer, proxy, target, timeout)
		return conn, target, err
	}
	conn, dialedTarget, err := dialHappyEyeballs(ctx, dialer.DialContext, target, fallbacks, fallbackDelay, timeout)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	tcp, ok := conn.(stream.Conn)
	if !ok {
		conn.Close()
		return nil, netip.AddrPort{}, errors.New("outbound dial returned non-stream connection")
	}
	return tcp, dialedTarget, nil
}

func dedupeFallbacks(primary netip.AddrPort, fallbacks []netip.AddrPort) []netip.AddrPort {
	if len(fallbacks) == 0 {
		return nil
	}
	seen := make(map[netip.AddrPort]struct{}, len(fallbacks)+1)
	seen[primary] = struct{}{}
	out := make([]netip.AddrPort, 0, len(fallbacks))
	for _, cand := range fallbacks {
		if !cand.IsValid() {
			continue
		}
		if _, exists := seen[cand]; exists {
			continue
		}
		seen[cand] = struct{}{}
		out = append(out, cand)
	}
	return out
}

func dialHappyEyeballs(
	ctx context.Context,
	dialFn dialContextFunc,
	primary netip.AddrPort,
	fallbacks []netip.AddrPort,
	fallbackDelay time.Duration,
	timeout time.Duration,
) (net.Conn, netip.AddrPort, error) {
	candidates := dedupeFallbacks(primary, fallbacks)
	dialCtx, cancelDial := context.WithTimeout(ctx, timeout)
	defer cancelDial()

	if len(candidates) == 0 || fallbackDelay <= 0 {
		conn, err := dialFn(dialCtx, "tcp", primary.String())
		if err != nil {
			return nil, netip.AddrPort{}, err
		}
		return conn, primary, nil
	}

	var (
		mu      sync.Mutex
		settled bool
	)
	winCh := make(chan dialAttemptResult, 1)
	primaryErrCh := make(chan error, 1)
	fallbackErrCh := make(chan error, 1)

	finishSuccess := func(res dialAttemptResult) {
		mu.Lock()
		if settled {
			mu.Unlock()
			res.conn.Close()
			return
		}
		settled = true
		mu.Unlock()
		winCh <- res
	}

	claimPendingWin := func() (dialAttemptResult, bool) {
		mu.Lock()
		alreadySettled := settled
		settled = true
		mu.Unlock()
		if !alreadySettled {
			return dialAttemptResult{}, false
		}
		res := <-winCh
		if ctx.Err() != nil {
			res.conn.Close()
			return dialAttemptResult{}, false
		}
		return res, true
	}

	go func() {
		conn, err := dialFn(dialCtx, "tcp", primary.String())
		if err != nil {
			primaryErrCh <- err
			return
		}
		finishSuccess(dialAttemptResult{target: primary, conn: conn})
	}()

	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()

	fallbackStarted := false
	primaryDone := false
	fallbackDone := false
	var primaryErr, fallbackErr error

	startFallback := func() {
		if fallbackStarted {
			return
		}
		fallbackStarted = true
		timer.Stop()
		go func() {
			var lastErr error
			for _, cand := range candidates {
				if dialCtx.Err() != nil {
					if lastErr == nil {
						lastErr = dialCtx.Err()
					}
					break
				}
				conn, err := dialFn(dialCtx, "tcp", cand.String())
				if err == nil {
					finishSuccess(dialAttemptResult{target: cand, conn: conn})
					return
				}
				lastErr = err
			}
			fallbackErrCh <- lastErr
		}()
	}

	for {
		var timerCh <-chan time.Time
		if !fallbackStarted {
			timerCh = timer.C
		}
		select {
		case win := <-winCh:
			return win.conn, win.target, nil
		case err := <-primaryErrCh:
			primaryDone = true
			primaryErr = err
			if fallbackDone {
				if res, ok := claimPendingWin(); ok {
					return res.conn, res.target, nil
				}
				return nil, netip.AddrPort{}, errors.Join(primaryErr, fallbackErr)
			}
			startFallback()
		case err := <-fallbackErrCh:
			fallbackDone = true
			fallbackErr = err
			if primaryDone {
				if res, ok := claimPendingWin(); ok {
					return res.conn, res.target, nil
				}
				return nil, netip.AddrPort{}, errors.Join(primaryErr, fallbackErr)
			}
		case <-timerCh:
			startFallback()
		case <-dialCtx.Done():
			if res, ok := claimPendingWin(); ok {
				return res.conn, res.target, nil
			}
			return nil, netip.AddrPort{}, dialCtx.Err()
		}
	}
}
