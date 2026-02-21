//go:build windows

package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/provider"
)

// sockBufSize is the socket buffer size for TCP proxy connections.
// 2 MB buffers allow large TCP windows for high throughput, especially
// important for VPN tunneled traffic over high-latency links.
const sockBufSize = 2 * 1024 * 1024

// fwdBufPool reuses 1MB buffers for bidirectional TCP forwarding.
// Larger buffers reduce syscall overhead during bulk transfers.
var fwdBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 1024*1024)
		return &b
	},
}

// NATLookup is a function that resolves a client connection to its original
// destination and tunnel ID via the NAT table.
// addrKey is the string form of the remote address (e.g. "1.2.3.4:5678").
type NATLookup func(addrKey string) (originalDst string, tunnelID string, ok bool)

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

	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
}

// Port returns the proxy listen port.
func (tp *TunnelProxy) Port() uint16 {
	return tp.port
}

// NewTunnelProxy creates a proxy that listens on the given port.
func NewTunnelProxy(port uint16, natLookup NATLookup, providerLookup ProviderLookup) *TunnelProxy {
	return &TunnelProxy{
		port:           port,
		natLookup:      natLookup,
		providerLookup: providerLookup,
		conns:          make(map[net.Conn]struct{}),
	}
}

// Start begins accepting connections.
func (tp *TunnelProxy) Start(ctx context.Context) error {
	ctx, tp.cancel = context.WithCancel(ctx)

	addr := fmt.Sprintf("0.0.0.0:%d", tp.port)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("[Proxy] failed to listen on %s: %w", addr, err)
	}
	tp.listener = ln
	core.Log.Infof("Proxy", "Listening on %s", addr)

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
	// Close all active connections to unblock io.CopyBuffer in forwarders.
	tp.connsMu.Lock()
	for c := range tp.conns {
		c.Close()
	}
	tp.connsMu.Unlock()

	tp.wg.Wait()
	core.Log.Infof("Proxy", "Stopped (port %d)", tp.port)
}

func (tp *TunnelProxy) trackConn(c net.Conn) {
	tp.connsMu.Lock()
	tp.conns[c] = struct{}{}
	tp.connsMu.Unlock()
}

func (tp *TunnelProxy) untrackConn(c net.Conn) {
	tp.connsMu.Lock()
	delete(tp.conns, c)
	tp.connsMu.Unlock()
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
				core.Log.Errorf("Proxy", "Accept error: %v", err)
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

	// Tune client-side loopback socket: disable Nagle, enlarge buffers.
	if tc, ok := clientConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(sockBufSize)
		tc.SetWriteBuffer(sockBufSize)
	}

	tp.trackConn(clientConn)
	defer tp.untrackConn(clientConn)

	// Look up original destination from NAT table.
	originalDst, tunnelID, ok := tp.natLookup(clientConn.RemoteAddr().String())
	if !ok {
		core.Log.Warnf("Proxy", "No NAT entry for %s, closing", clientConn.RemoteAddr())
		return
	}

	// Get the tunnel provider.
	prov, ok := tp.providerLookup(tunnelID)
	if !ok {
		core.Log.Errorf("Proxy", "No provider for tunnel %q, closing", tunnelID)
		return
	}

	// Dial through the tunnel.
	remoteConn, err := prov.DialTCP(ctx, originalDst)
	if err != nil {
		core.Log.Errorf("Proxy", "Failed to dial %s via %s: %v", originalDst, tunnelID, err)
		return
	}
	defer remoteConn.Close()

	// Tune tunnel-side socket: disable Nagle, enlarge buffers.
	if tc, ok := remoteConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(sockBufSize)
		tc.SetWriteBuffer(sockBufSize)
	}

	tp.trackConn(remoteConn)
	defer tp.untrackConn(remoteConn)

	// Bidirectional forwarding.
	var fwg sync.WaitGroup
	fwg.Add(2)
	go forward(clientConn, remoteConn, &fwg)
	go forward(remoteConn, clientConn, &fwg)
	fwg.Wait()
}

// forward copies data from src to dst with pooled buffered I/O.
func forward(dst, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	bp := fwdBufPool.Get().(*[]byte)
	io.CopyBuffer(dst, src, *bp)
	fwdBufPool.Put(bp)

	// Signal half-close.
	if tc, ok := dst.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	if tc, ok := src.(*net.TCPConn); ok {
		tc.CloseRead()
	}
}
