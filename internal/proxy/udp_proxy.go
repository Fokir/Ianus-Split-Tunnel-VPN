package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"awg-split-tunnel/internal/core"
)

// udpBufPool reuses 65535-byte buffers for tunnel read goroutines.
var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

// udpSessionKey is a compact, allocation-free key for the UDP session map.
// Layout: 4 bytes IPv4 address + 2 bytes port (big-endian).
type udpSessionKey [6]byte

func makeUDPSessionKey(addr *net.UDPAddr) udpSessionKey {
	var k udpSessionKey
	if ip4 := addr.IP.To4(); ip4 != nil {
		copy(k[:4], ip4)
	}
	k[4] = byte(addr.Port >> 8)
	k[5] = byte(addr.Port)
	return k
}

// UDPNATLookup resolves a hairpinned client address to its original destination,
// tunnel ID, and fallback context via the UDP NAT table.
type UDPNATLookup func(addrKey string) (core.NATInfo, bool)

// UDPSession tracks a single client-to-tunnel UDP association.
type UDPSession struct {
	lastActive int64 // atomic; Unix seconds
	tunnelConn net.Conn
	clientAddr *net.UDPAddr
	cancel     context.CancelFunc
}

// UDPProxy is a per-tunnel transparent UDP proxy.
// It receives hairpinned datagrams, looks up the original destination from the
// NAT table, and forwards traffic through the VPN provider.
type UDPProxy struct {
	port           uint16
	conn           *net.UDPConn
	natLookup      UDPNATLookup
	providerLookup ProviderLookup
	fallback       *FallbackDialer

	sessionsMu sync.RWMutex
	sessions   map[udpSessionKey]*UDPSession

	// Cached Unix timestamp (seconds), updated every 250ms.
	// Eliminates time.Now() syscall from the per-datagram fast path.
	nowSec atomic.Int64

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// Port returns the proxy listen port.
func (up *UDPProxy) Port() uint16 {
	return up.port
}

// NewUDPProxy creates a UDP proxy that listens on the given port.
// If fallback is non-nil, connection-level fallback is enabled for UDP sessions.
func NewUDPProxy(port uint16, natLookup UDPNATLookup, providerLookup ProviderLookup, fallback *FallbackDialer) *UDPProxy {
	return &UDPProxy{
		port:           port,
		natLookup:      natLookup,
		providerLookup: providerLookup,
		fallback:       fallback,
		sessions:       make(map[udpSessionKey]*UDPSession),
	}
}

// Start begins listening for UDP datagrams.
func (up *UDPProxy) Start(ctx context.Context) error {
	ctx, up.cancel = context.WithCancel(ctx)

	addr := &net.UDPAddr{IP: net.IPv4zero, Port: int(up.port)}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("[Proxy] failed to listen UDP on :%d: %w", up.port, err)
	}
	up.conn = conn
	core.Log.Infof("Proxy", "UDP listening on :%d", up.port)

	// Start cached timestamp updater for fast-path activity tracking.
	up.nowSec.Store(time.Now().Unix())
	up.wg.Add(3)
	go up.timestampUpdater(ctx)
	go up.readLoop(ctx)
	go up.cleanupLoop(ctx)

	return nil
}

// Stop gracefully shuts down the UDP proxy.
func (up *UDPProxy) Stop() {
	if up.cancel != nil {
		up.cancel()
	}
	if up.conn != nil {
		up.conn.Close()
	}

	// Close all active sessions.
	up.sessionsMu.Lock()
	for _, sess := range up.sessions {
		sess.tunnelConn.Close()
		sess.cancel()
	}
	up.sessions = make(map[udpSessionKey]*UDPSession)
	up.sessionsMu.Unlock()

	up.wg.Wait()
	core.Log.Infof("Proxy", "UDP stopped (port %d)", up.port)
}

// readLoop reads datagrams from the listener and dispatches them.
func (up *UDPProxy) readLoop(ctx context.Context) {
	defer up.wg.Done()

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, clientAddr, err := up.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				core.Log.Errorf("Proxy", "UDP read error: %v", err)
				continue
			}
		}

		// Safe: handleDatagram writes buf[:n] synchronously before returning.
		up.handleDatagram(ctx, buf[:n], clientAddr)
	}
}

// handleDatagram processes a single incoming datagram.
func (up *UDPProxy) handleDatagram(ctx context.Context, data []byte, clientAddr *net.UDPAddr) {
	sk := makeUDPSessionKey(clientAddr)

	// Fast path: existing session — zero-alloc binary key lookup.
	up.sessionsMu.RLock()
	sess, exists := up.sessions[sk]
	up.sessionsMu.RUnlock()

	if exists {
		atomic.StoreInt64(&sess.lastActive, up.nowSec.Load())
		if _, err := sess.tunnelConn.Write(data); err != nil {
			core.Log.Errorf("Proxy", "UDP write to tunnel failed for %s: %v", clientAddr, err)
		}
		return
	}

	// Slow path: create new session (string allocation acceptable here).
	addrStr := clientAddr.String()
	info, ok := up.natLookup(addrStr)
	if !ok {
		core.Log.Warnf("Proxy", "UDP no NAT entry for %s, dropping", addrStr)
		return
	}

	// Dial through the tunnel, with connection-level fallback if available.
	var tunnelConn net.Conn
	var err error

	if up.fallback != nil {
		tunnelConn, _, err = up.fallback.DialUDPWithFallback(ctx, info)
	} else {
		prov, provOK := up.providerLookup(info.TunnelID)
		if !provOK {
			core.Log.Errorf("Proxy", "UDP no provider for tunnel %q, dropping", info.TunnelID)
			return
		}
		tunnelConn, err = prov.DialUDP(ctx, info.DialDst())
	}

	if err != nil {
		core.Log.Errorf("Proxy", "UDP failed to dial %s via %s: %v", info.OriginalDst, info.TunnelID, err)
		return
	}

	sessCtx, sessCancel := context.WithCancel(ctx)
	sess = &UDPSession{
		lastActive: up.nowSec.Load(),
		tunnelConn: tunnelConn,
		clientAddr: clientAddr,
		cancel:     sessCancel,
	}

	up.sessionsMu.Lock()
	up.sessions[sk] = sess
	up.sessionsMu.Unlock()

	// Send the first datagram.
	if _, err := tunnelConn.Write(data); err != nil {
		core.Log.Errorf("Proxy", "UDP write to tunnel failed for %s: %v", clientAddr, err)
		up.removeSession(sk)
		return
	}

	// Start reading responses from the tunnel.
	up.wg.Add(1)
	go up.readFromTunnel(sessCtx, sess, sk)
}

// readFromTunnel reads datagrams from the tunnel connection and sends them
// back to the client through the hairpin path.
func (up *UDPProxy) readFromTunnel(ctx context.Context, sess *UDPSession, sk udpSessionKey) {
	defer up.wg.Done()
	defer up.removeSession(sk)

	bp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bp)
	buf := *bp

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := sess.tunnelConn.Read(buf)
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				core.Log.Errorf("Proxy", "UDP tunnel read error for %s: %v", sess.clientAddr, err)
			}
			return
		}

		atomic.StoreInt64(&sess.lastActive, up.nowSec.Load())
		if _, err := up.conn.WriteToUDP(buf[:n], sess.clientAddr); err != nil {
			core.Log.Errorf("Proxy", "UDP write to client %s failed: %v", sess.clientAddr, err)
			return
		}
	}
}

// removeSession closes and removes a session by key.
func (up *UDPProxy) removeSession(sk udpSessionKey) {
	up.sessionsMu.Lock()
	if sess, ok := up.sessions[sk]; ok {
		sess.tunnelConn.Close()
		sess.cancel()
		delete(up.sessions, sk)
	}
	up.sessionsMu.Unlock()
}

// timestampUpdater updates the cached Unix timestamp every 250ms.
func (up *UDPProxy) timestampUpdater(ctx context.Context) {
	defer up.wg.Done()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			up.nowSec.Store(time.Now().Unix())
		}
	}
}

// cleanupLoop periodically removes idle UDP sessions (>2min inactive).
func (up *UDPProxy) cleanupLoop(ctx context.Context) {
	defer up.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := up.nowSec.Load()
			const timeout int64 = 120 // 2 minutes
			var stale []udpSessionKey

			up.sessionsMu.RLock()
			for sk, sess := range up.sessions {
				last := atomic.LoadInt64(&sess.lastActive)
				if now-last > timeout {
					stale = append(stale, sk)
				}
			}
			up.sessionsMu.RUnlock()

			for _, sk := range stale {
				core.Log.Debugf("Proxy", "UDP session timed out, closing")
				up.removeSession(sk)
			}
		}
	}
}
