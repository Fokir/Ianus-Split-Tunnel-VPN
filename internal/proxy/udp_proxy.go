//go:build windows

package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
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

// UDPNATLookup resolves a hairpinned client address to its original destination
// and tunnel ID via the UDP NAT table.
type UDPNATLookup func(addrKey string) (originalDst string, tunnelID string, ok bool)

// UDPSession tracks a single client-to-tunnel UDP association.
type UDPSession struct {
	lastActive int64 // atomic; UnixNano timestamp
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

	sessionsMu sync.RWMutex
	sessions   map[udpSessionKey]*UDPSession

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// NewUDPProxy creates a UDP proxy that listens on the given port.
func NewUDPProxy(port uint16, natLookup UDPNATLookup, providerLookup ProviderLookup) *UDPProxy {
	return &UDPProxy{
		port:           port,
		natLookup:      natLookup,
		providerLookup: providerLookup,
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
	log.Printf("[Proxy] UDP listening on :%d", up.port)

	up.wg.Add(2)
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
	log.Printf("[Proxy] UDP stopped (port %d)", up.port)
}

// Port returns the port this proxy listens on.
func (up *UDPProxy) Port() uint16 {
	return up.port
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
				log.Printf("[Proxy] UDP read error: %v", err)
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
		atomic.StoreInt64(&sess.lastActive, time.Now().UnixNano())
		if _, err := sess.tunnelConn.Write(data); err != nil {
			log.Printf("[Proxy] UDP write to tunnel failed for %s: %v", clientAddr, err)
		}
		return
	}

	// Slow path: create new session (string allocation acceptable here).
	addrStr := clientAddr.String()
	originalDst, tunnelID, ok := up.natLookup(addrStr)
	if !ok {
		log.Printf("[Proxy] UDP no NAT entry for %s, dropping", addrStr)
		return
	}

	prov, ok := up.providerLookup(tunnelID)
	if !ok {
		log.Printf("[Proxy] UDP no provider for tunnel %q, dropping", tunnelID)
		return
	}

	tunnelConn, err := prov.DialUDP(ctx, originalDst)
	if err != nil {
		log.Printf("[Proxy] UDP failed to dial %s via %s: %v", originalDst, tunnelID, err)
		return
	}

	sessCtx, sessCancel := context.WithCancel(ctx)
	sess = &UDPSession{
		lastActive: time.Now().UnixNano(),
		tunnelConn: tunnelConn,
		clientAddr: clientAddr,
		cancel:     sessCancel,
	}

	up.sessionsMu.Lock()
	up.sessions[sk] = sess
	up.sessionsMu.Unlock()

	// Send the first datagram.
	if _, err := tunnelConn.Write(data); err != nil {
		log.Printf("[Proxy] UDP write to tunnel failed for %s: %v", clientAddr, err)
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
				log.Printf("[Proxy] UDP tunnel read error for %s: %v", sess.clientAddr, err)
			}
			return
		}

		atomic.StoreInt64(&sess.lastActive, time.Now().UnixNano())
		if _, err := up.conn.WriteToUDP(buf[:n], sess.clientAddr); err != nil {
			log.Printf("[Proxy] UDP write to client %s failed: %v", sess.clientAddr, err)
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
			now := time.Now()
			var stale []udpSessionKey

			up.sessionsMu.RLock()
			for sk, sess := range up.sessions {
				last := time.Unix(0, atomic.LoadInt64(&sess.lastActive))
				if now.Sub(last) > 2*time.Minute {
					stale = append(stale, sk)
				}
			}
			up.sessionsMu.RUnlock()

			for _, sk := range stale {
				log.Printf("[Proxy] UDP session timed out, closing")
				up.removeSession(sk)
			}
		}
	}
}
