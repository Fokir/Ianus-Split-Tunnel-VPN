package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

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
// destination, tunnel ID, and fallback context via the NAT table.
// addrKey is the string form of the remote address (e.g. "1.2.3.4:5678").
type NATLookup func(addrKey string) (core.NATInfo, bool)

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
	fallback       *FallbackDialer

	// domainMatchFunc is used for SNI-based routing: when a TLS ClientHello
	// is detected, the SNI hostname is matched against domain rules to
	// potentially override the tunnel routing decision.
	domainMatchFunc atomic.Pointer[core.DomainMatchFunc]

	wg     sync.WaitGroup
	cancel context.CancelFunc

	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
}

// Port returns the proxy listen port.
func (tp *TunnelProxy) Port() uint16 {
	return tp.port
}

// SetDomainMatchFunc sets the domain match function for SNI-based routing.
// Safe to call concurrently; uses atomic swap.
func (tp *TunnelProxy) SetDomainMatchFunc(fn *core.DomainMatchFunc) {
	tp.domainMatchFunc.Store(fn)
}

// NewTunnelProxy creates a proxy that listens on the given port.
// If fallback is non-nil, connection-level fallback is enabled: failed dials
// are retried through alternative tunnels according to the rule's fallback policy.
func NewTunnelProxy(port uint16, natLookup NATLookup, providerLookup ProviderLookup, fallback *FallbackDialer) *TunnelProxy {
	return &TunnelProxy{
		port:           port,
		natLookup:      natLookup,
		providerLookup: providerLookup,
		fallback:       fallback,
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

	// Look up original destination and fallback context from NAT table.
	info, ok := tp.natLookup(clientConn.RemoteAddr().String())
	if !ok {
		core.Log.Warnf("Proxy", "No NAT entry for %s, closing", clientConn.RemoteAddr())
		return
	}

	// SNI-based routing: if a domain match function is set, peek at the
	// client's initial data to extract the TLS SNI hostname and potentially
	// override the tunnel routing decision.
	if matchFn := tp.domainMatchFunc.Load(); matchFn != nil {
		buf := make([]byte, 16384) // 16KB — handles modern TLS ClientHello including post-quantum (ML-KEM)
		clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := clientConn.Read(buf)
		clientConn.SetReadDeadline(time.Time{})
		if n > 0 {
			initialData := buf[:n]
			if sni := ExtractSNI(initialData); sni != "" {
				if tid, action, matched := (*matchFn)(sni); matched {
					switch action {
					case core.DomainBlock:
						core.Log.Debugf("Proxy", "SNI %q → block", sni)
						return
					case core.DomainDirect:
						core.Log.Debugf("Proxy", "SNI %q → direct", sni)
						info.TunnelID = "__direct__"
					case core.DomainRoute:
						core.Log.Debugf("Proxy", "SNI %q → tunnel %q", sni, tid)
						info.TunnelID = tid
					}
				}
			}
			// Wrap client connection to replay the already-read bytes.
			clientConn = &prefixConn{Conn: clientConn, prefix: initialData}
		}
	}

	// Dial through the tunnel, with connection-level fallback if available.
	var remoteConn net.Conn
	var err error

	if tp.fallback != nil {
		remoteConn, _, err = tp.fallback.DialTCPWithFallback(ctx, info)
	} else {
		prov, provOK := tp.providerLookup(info.TunnelID)
		if !provOK {
			core.Log.Errorf("Proxy", "No provider for tunnel %q, closing", info.TunnelID)
			return
		}
		remoteConn, err = prov.DialTCP(ctx, info.DialDst())
	}

	if err != nil {
		core.Log.Errorf("Proxy", "Failed to dial %s via %s: %v", info.OriginalDst, info.TunnelID, err)
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

	// Early EOF detection: after a successful dial, the server may still block
	// the connection once it sees the destination (e.g. VLESS/Xray blackhole).
	// DetectEarlyEOF buffers the client's initial data, sends it, and checks
	// if the tunnel responds or immediately closes (0 bytes + EOF).
	if tp.fallback != nil {
		result := tp.fallback.DetectEarlyEOF(ctx, clientConn, remoteConn, info)
		if result.Failed {
			return
		}
		if result.RemoteConn != remoteConn {
			// Fallback produced a new connection — swap it in.
			// The old remoteConn is already closed by DetectEarlyEOF.
			remoteConn = result.RemoteConn
			defer remoteConn.Close()

			// Tune the new connection if it's a raw TCP conn.
			if tc, ok := remoteConn.(*net.TCPConn); ok {
				tc.SetNoDelay(true)
				tc.SetReadBuffer(sockBufSize)
				tc.SetWriteBuffer(sockBufSize)
			}

			tp.trackConn(remoteConn)
			defer tp.untrackConn(remoteConn)
		}
		// If result.RemoteConn == remoteConn (possibly wrapped as prefixConn),
		// the initial exchange already happened — proceed to forwarding.
	}

	// Bidirectional forwarding.
	var fwg sync.WaitGroup
	fwg.Add(2)
	go forward(clientConn, remoteConn, "tunnel→client", info.OriginalDst, &fwg)
	go forward(remoteConn, clientConn, "client→tunnel", info.OriginalDst, &fwg)
	fwg.Wait()
}

// forward copies data from src to dst with pooled buffered I/O.
func forward(dst, src net.Conn, direction, target string, wg *sync.WaitGroup) {
	defer wg.Done()

	bp := fwdBufPool.Get().(*[]byte)
	n, err := io.CopyBuffer(dst, src, *bp)
	fwdBufPool.Put(bp)

	if err != nil {
		core.Log.Warnf("Proxy", "forward %s %s: %d bytes, err=%v (type=%T)", direction, target, n, err, err)
	} else if n == 0 {
		core.Log.Warnf("Proxy", "forward %s %s: 0 bytes (clean EOF — remote closed immediately)", direction, target)
	} else {
		core.Log.Debugf("Proxy", "forward %s %s: %d bytes", direction, target, n)
	}

	// Signal half-close.
	if tc, ok := dst.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	if tc, ok := src.(*net.TCPConn); ok {
		tc.CloseRead()
	}
}
