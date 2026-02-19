//go:build windows

package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"awg-split-tunnel/internal/provider"
)

// NATLookup is a function that resolves a client connection to its original
// destination and tunnel ID via the NAT table.
type NATLookup func(clientAddr net.Addr) (originalDst string, tunnelID string, ok bool)

// ProviderLookup is a function that returns the TunnelProvider for a given tunnel ID.
type ProviderLookup func(tunnelID string) (provider.TunnelProvider, bool)

// TunnelProxy is a per-tunnel transparent TCP proxy.
// It accepts redirected connections, looks up the original destination from the
// NAT table, and forwards traffic through the VPN provider.
type TunnelProxy struct {
	port           uint16
	listener       net.Listener
	natLookup      NATLookup
	providerLookup ProviderLookup

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// NewTunnelProxy creates a proxy that listens on the given port.
func NewTunnelProxy(port uint16, natLookup NATLookup, providerLookup ProviderLookup) *TunnelProxy {
	return &TunnelProxy{
		port:           port,
		natLookup:      natLookup,
		providerLookup: providerLookup,
	}
}

// Start begins accepting connections.
func (tp *TunnelProxy) Start(ctx context.Context) error {
	ctx, tp.cancel = context.WithCancel(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", tp.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("[Proxy] failed to listen on %s: %w", addr, err)
	}
	tp.listener = ln
	log.Printf("[Proxy] Listening on %s", addr)

	tp.wg.Add(1)
	go tp.acceptLoop(ctx)

	return nil
}

// Stop gracefully shuts down the proxy.
func (tp *TunnelProxy) Stop() {
	if tp.cancel != nil {
		tp.cancel()
	}
	if tp.listener != nil {
		tp.listener.Close()
	}
	tp.wg.Wait()
	log.Printf("[Proxy] Stopped (port %d)", tp.port)
}

// Port returns the port this proxy listens on.
func (tp *TunnelProxy) Port() uint16 {
	return tp.port
}

func (tp *TunnelProxy) acceptLoop(ctx context.Context) {
	defer tp.wg.Done()

	for {
		conn, err := tp.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[Proxy] Accept error: %v", err)
				continue
			}
		}

		tp.wg.Add(1)
		go tp.handleConnection(ctx, conn)
	}
}

func (tp *TunnelProxy) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer tp.wg.Done()
	defer clientConn.Close()

	// Look up original destination from NAT table.
	originalDst, tunnelID, ok := tp.natLookup(clientConn.RemoteAddr())
	if !ok {
		log.Printf("[Proxy] No NAT entry for %s, closing", clientConn.RemoteAddr())
		return
	}

	// Get the tunnel provider.
	prov, ok := tp.providerLookup(tunnelID)
	if !ok {
		log.Printf("[Proxy] No provider for tunnel %q, closing", tunnelID)
		return
	}

	// Dial through the tunnel.
	remoteConn, err := prov.DialTCP(ctx, originalDst)
	if err != nil {
		log.Printf("[Proxy] Failed to dial %s via %s: %v", originalDst, tunnelID, err)
		return
	}
	defer remoteConn.Close()

	// Bidirectional forwarding.
	var fwg sync.WaitGroup
	fwg.Add(2)
	go forward(clientConn, remoteConn, &fwg)
	go forward(remoteConn, clientConn, &fwg)
	fwg.Wait()
}

// forward copies data from src to dst with buffered I/O.
func forward(dst, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	buf := make([]byte, 32*1024) // 32KB buffer
	io.CopyBuffer(dst, src, buf)

	// Signal half-close.
	if tc, ok := dst.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	if tc, ok := src.(*net.TCPConn); ok {
		tc.CloseRead()
	}
}
