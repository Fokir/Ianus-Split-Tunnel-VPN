//go:build windows

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"awg-split-tunnel/internal/core"
)

const (
	// maxFallbackHops limits the number of failover rule traversals
	// to prevent infinite loops in misconfigured rule chains.
	maxFallbackHops = 3

	// fallbackDialTimeout is the per-attempt timeout for fallback dials.
	fallbackDialTimeout = 10 * time.Second

	// earlyEOFTimeout is how long to wait for the first response byte from
	// the tunnel after sending initial client data. If the tunnel closes
	// within this window with 0 bytes, it's treated as server-side blocking.
	// 3s is enough to distinguish slow tunnels from server-side blackholes.
	earlyEOFTimeout = 3 * time.Second

	// initialDataReadTimeout is how long to wait for the client's first data
	// (e.g. TLS ClientHello) before giving up on early EOF detection.
	// Client sends immediately after TCP handshake, so 2s is more than enough.
	initialDataReadTimeout = 2 * time.Second
)

// directTunnelID is the special tunnel ID for direct (non-VPN) traffic.
const directTunnelID = "__direct__"

// FallbackDialer handles connection-level fallback when a tunnel provider's
// DialTCP/DialUDP fails. It applies the rule's FallbackPolicy to retry through
// alternative tunnels (failover) or the direct provider (allow_direct).
//
// This addresses cases where the tunnel itself is Up (e.g. VLESS connected)
// but specific connections fail — for example, when the server blocks certain
// domains via Xray routing rules (geosite → blackhole), producing EOF errors.
type FallbackDialer struct {
	providerLookup ProviderLookup
	rules          *core.RuleEngine
}

// NewFallbackDialer creates a FallbackDialer with the given dependencies.
func NewFallbackDialer(providerLookup ProviderLookup, rules *core.RuleEngine) *FallbackDialer {
	return &FallbackDialer{
		providerLookup: providerLookup,
		rules:          rules,
	}
}

// DialTCPWithFallback attempts to dial through the primary tunnel specified
// in info.TunnelID. On connection-level failure, it applies the fallback policy:
//   - PolicyBlock / PolicyDrop: return error (kill switch)
//   - PolicyAllowDirect: retry through __direct__ provider
//   - PolicyFailover: try the next matching rule's tunnel
//
// Returns the established connection and the actual tunnel ID used.
func (fd *FallbackDialer) DialTCPWithFallback(ctx context.Context, info core.NATInfo) (net.Conn, string, error) {
	// Primary attempt through the designated tunnel.
	prov, ok := fd.providerLookup(info.TunnelID)
	if !ok {
		return nil, "", fmt.Errorf("no provider for tunnel %q", info.TunnelID)
	}

	conn, err := prov.DialTCP(ctx, info.OriginalDst)
	if err == nil {
		return conn, info.TunnelID, nil
	}

	// Don't fallback for non-connection errors (context cancelled, no provider, etc.).
	if !shouldFallback(err) {
		return nil, "", err
	}

	core.Log.Warnf("Proxy", "TCP dial %s via %s failed (%v), applying fallback=%s",
		info.OriginalDst, info.TunnelID, err, info.Fallback)

	return fd.applyFallbackTCP(ctx, info, err)
}

// DialUDPWithFallback is the UDP equivalent of DialTCPWithFallback.
func (fd *FallbackDialer) DialUDPWithFallback(ctx context.Context, info core.NATInfo) (net.Conn, string, error) {
	prov, ok := fd.providerLookup(info.TunnelID)
	if !ok {
		return nil, "", fmt.Errorf("no provider for tunnel %q", info.TunnelID)
	}

	conn, err := prov.DialUDP(ctx, info.OriginalDst)
	if err == nil {
		return conn, info.TunnelID, nil
	}

	if !shouldFallback(err) {
		return nil, "", err
	}

	core.Log.Warnf("Proxy", "UDP dial %s via %s failed (%v), applying fallback=%s",
		info.OriginalDst, info.TunnelID, err, info.Fallback)

	return fd.applyFallbackUDP(ctx, info, err)
}

// applyFallbackTCP applies the fallback policy for a failed TCP dial.
func (fd *FallbackDialer) applyFallbackTCP(ctx context.Context, info core.NATInfo, originalErr error) (net.Conn, string, error) {
	switch info.Fallback {
	case core.PolicyBlock, core.PolicyDrop:
		return nil, "", fmt.Errorf("dial failed, fallback=%s: %w", info.Fallback, originalErr)

	case core.PolicyAllowDirect:
		return fd.dialDirectTCP(ctx, info.OriginalDst, originalErr)

	case core.PolicyFailover:
		return fd.failoverDialTCP(ctx, info, originalErr)

	default:
		// Unknown policy — treat as allow_direct for safety.
		return fd.dialDirectTCP(ctx, info.OriginalDst, originalErr)
	}
}

// applyFallbackUDP applies the fallback policy for a failed UDP dial.
func (fd *FallbackDialer) applyFallbackUDP(ctx context.Context, info core.NATInfo, originalErr error) (net.Conn, string, error) {
	switch info.Fallback {
	case core.PolicyBlock, core.PolicyDrop:
		return nil, "", fmt.Errorf("dial failed, fallback=%s: %w", info.Fallback, originalErr)

	case core.PolicyAllowDirect:
		return fd.dialDirectUDP(ctx, info.OriginalDst, originalErr)

	case core.PolicyFailover:
		return fd.failoverDialUDP(ctx, info, originalErr)

	default:
		return fd.dialDirectUDP(ctx, info.OriginalDst, originalErr)
	}
}

// dialDirectTCP attempts to dial through the __direct__ provider.
func (fd *FallbackDialer) dialDirectTCP(ctx context.Context, dst string, originalErr error) (net.Conn, string, error) {
	prov, ok := fd.providerLookup(directTunnelID)
	if !ok {
		return nil, "", fmt.Errorf("direct provider unavailable, original error: %w", originalErr)
	}

	dialCtx, cancel := context.WithTimeout(ctx, fallbackDialTimeout)
	defer cancel()

	conn, err := prov.DialTCP(dialCtx, dst)
	if err != nil {
		return nil, "", fmt.Errorf("direct dial also failed: %v (original: %w)", err, originalErr)
	}

	core.Log.Infof("Proxy", "TCP fallback to direct succeeded for %s", dst)
	return conn, directTunnelID, nil
}

// dialDirectUDP attempts to dial through the __direct__ provider.
func (fd *FallbackDialer) dialDirectUDP(ctx context.Context, dst string, originalErr error) (net.Conn, string, error) {
	prov, ok := fd.providerLookup(directTunnelID)
	if !ok {
		return nil, "", fmt.Errorf("direct provider unavailable, original error: %w", originalErr)
	}

	dialCtx, cancel := context.WithTimeout(ctx, fallbackDialTimeout)
	defer cancel()

	conn, err := prov.DialUDP(dialCtx, dst)
	if err != nil {
		return nil, "", fmt.Errorf("direct dial also failed: %v (original: %w)", err, originalErr)
	}

	core.Log.Infof("Proxy", "UDP fallback to direct succeeded for %s", dst)
	return conn, directTunnelID, nil
}

// failoverDialTCP traverses the rule chain looking for the next matching
// rule and attempts to dial through its tunnel.
func (fd *FallbackDialer) failoverDialTCP(ctx context.Context, info core.NATInfo, originalErr error) (net.Conn, string, error) {
	nextIdx := info.RuleIdx + 1

	for hop := 0; hop < maxFallbackHops; hop++ {
		result, idx := fd.rules.MatchPreLoweredFrom(info.ExeLower, info.BaseLower, nextIdx)
		if !result.Matched {
			break
		}
		nextIdx = idx + 1

		prov, ok := fd.providerLookup(result.TunnelID)
		if !ok {
			continue
		}

		dialCtx, cancel := context.WithTimeout(ctx, fallbackDialTimeout)
		conn, err := prov.DialTCP(dialCtx, info.OriginalDst)
		cancel()

		if err == nil {
			core.Log.Infof("Proxy", "TCP failover to tunnel %s succeeded for %s", result.TunnelID, info.OriginalDst)
			return conn, result.TunnelID, nil
		}

		if !shouldFallback(err) {
			return nil, "", err
		}

		core.Log.Warnf("Proxy", "TCP failover dial %s via %s also failed: %v", info.OriginalDst, result.TunnelID, err)

		// Check this rule's fallback policy.
		switch result.Fallback {
		case core.PolicyBlock, core.PolicyDrop:
			return nil, "", fmt.Errorf("failover dial failed, fallback=%s: %w", result.Fallback, err)
		case core.PolicyAllowDirect:
			return fd.dialDirectTCP(ctx, info.OriginalDst, err)
		case core.PolicyFailover:
			continue // try next rule
		}
	}

	return nil, "", fmt.Errorf("failover chain exhausted, original: %w", originalErr)
}

// failoverDialUDP traverses the rule chain for UDP connections.
func (fd *FallbackDialer) failoverDialUDP(ctx context.Context, info core.NATInfo, originalErr error) (net.Conn, string, error) {
	nextIdx := info.RuleIdx + 1

	for hop := 0; hop < maxFallbackHops; hop++ {
		result, idx := fd.rules.MatchPreLoweredFrom(info.ExeLower, info.BaseLower, nextIdx)
		if !result.Matched {
			break
		}
		nextIdx = idx + 1

		prov, ok := fd.providerLookup(result.TunnelID)
		if !ok {
			continue
		}

		dialCtx, cancel := context.WithTimeout(ctx, fallbackDialTimeout)
		conn, err := prov.DialUDP(dialCtx, info.OriginalDst)
		cancel()

		if err == nil {
			core.Log.Infof("Proxy", "UDP failover to tunnel %s succeeded for %s", result.TunnelID, info.OriginalDst)
			return conn, result.TunnelID, nil
		}

		if !shouldFallback(err) {
			return nil, "", err
		}

		core.Log.Warnf("Proxy", "UDP failover dial %s via %s also failed: %v", info.OriginalDst, result.TunnelID, err)

		switch result.Fallback {
		case core.PolicyBlock, core.PolicyDrop:
			return nil, "", fmt.Errorf("failover dial failed, fallback=%s: %w", result.Fallback, err)
		case core.PolicyAllowDirect:
			return fd.dialDirectUDP(ctx, info.OriginalDst, err)
		case core.PolicyFailover:
			continue
		}
	}

	return nil, "", fmt.Errorf("failover chain exhausted, original: %w", originalErr)
}

// shouldFallback determines whether a dial error should trigger fallback.
// Returns true for connection-level errors (EOF, reset, refused, timeout)
// that suggest the server blocked the destination or it's unreachable through the tunnel.
// Returns false for infrastructure errors (context cancelled) where fallback won't help.
func shouldFallback(err error) bool {
	if err == nil {
		return false
	}

	// Context cancelled — application is shutting down, don't retry.
	if errors.Is(err, context.Canceled) {
		return false
	}

	// Connection-level errors — candidates for fallback.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	if errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Check for net.OpError wrapping connection errors.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}

	// Default: attempt fallback for unknown errors.
	// Better to try and fail than to silently drop traffic.
	return true
}

// ---------------------------------------------------------------------------
// Early EOF detection (server-side blocking after successful dial)
// ---------------------------------------------------------------------------

// prefixConn wraps a net.Conn and prepends buffered data to Read calls.
// Used when we've already read the first response bytes for early EOF detection
// and need to replay them for the bidirectional forwarding phase.
type prefixConn struct {
	net.Conn
	prefix []byte
	offset int
}

func (pc *prefixConn) Read(b []byte) (int, error) {
	if pc.offset < len(pc.prefix) {
		n := copy(b, pc.prefix[pc.offset:])
		pc.offset += n
		return n, nil
	}
	return pc.Conn.Read(b)
}

// EarlyEOFResult is the outcome of DetectEarlyEOF.
type EarlyEOFResult struct {
	// RemoteConn is the connection to use for forwarding.
	// May be the original, a prefixConn wrapper, or a new fallback connection.
	RemoteConn net.Conn
	// ActualTunnel is the tunnel ID actually used (may differ after fallback).
	ActualTunnel string
	// Failed is true if all attempts (including fallback) failed.
	Failed bool
}

// DetectEarlyEOF handles the case where DialTCP succeeds but the server
// closes the connection immediately after receiving client data (e.g. VLESS
// server blocking via Xray routing rules → blackhole → EOF).
//
// Flow:
//  1. Read initial client data (TLS ClientHello, HTTP request, etc.)
//  2. Forward it to the tunnel connection
//  3. Wait for the first response byte with a timeout
//  4. If EOF/error with 0 bytes → server blocked: retry through fallback
//  5. If data received → wrap connection with prefix and return
//
// Returns the connection to use for bidirectional forwarding.
// If fallback is not applicable (PolicyBlock/PolicyDrop) or not available,
// returns the original remoteConn unchanged.
func (fd *FallbackDialer) DetectEarlyEOF(
	ctx context.Context,
	clientConn net.Conn,
	remoteConn net.Conn,
	info core.NATInfo,
) EarlyEOFResult {
	// Only detect early EOF for policies that have a fallback path.
	// Also skip for __direct__ tunnel — no VPN server to block the connection.
	if info.Fallback == core.PolicyBlock || info.Fallback == core.PolicyDrop || info.TunnelID == directTunnelID {
		return EarlyEOFResult{RemoteConn: remoteConn, ActualTunnel: info.TunnelID}
	}

	// Step 1: Read initial data from client.
	// For TLS, this is the ClientHello (~200-500 bytes). For HTTP, the request line.
	// Use a short deadline since the client should send immediately after TCP handshake.
	clientConn.SetReadDeadline(time.Now().Add(initialDataReadTimeout))
	initialBuf := make([]byte, 32768) // 32KB covers any TLS ClientHello
	n, err := clientConn.Read(initialBuf)
	clientConn.SetReadDeadline(time.Time{}) // clear deadline

	if err != nil || n == 0 {
		// Can't read initial data — skip early EOF detection, proceed normally.
		return EarlyEOFResult{RemoteConn: remoteConn, ActualTunnel: info.TunnelID}
	}
	initialData := initialBuf[:n]

	// Step 2: Send initial data to the tunnel.
	if _, err := remoteConn.Write(initialData); err != nil {
		core.Log.Warnf("Proxy", "Early EOF: write to tunnel %s failed for %s: %v",
			info.TunnelID, info.OriginalDst, err)
		remoteConn.Close()
		return fd.retryWithFallbackTCP(ctx, info, initialData)
	}

	// Step 3: Wait for first response from tunnel.
	remoteConn.SetReadDeadline(time.Now().Add(earlyEOFTimeout))
	respBuf := make([]byte, 4096)
	respN, respErr := remoteConn.Read(respBuf)
	remoteConn.SetReadDeadline(time.Time{}) // clear deadline

	if respErr != nil || respN == 0 {
		// Early EOF — server likely blocked the connection.
		core.Log.Warnf("Proxy", "Early EOF detected for %s via %s (err=%v, bytes=%d), trying fallback=%s",
			info.OriginalDst, info.TunnelID, respErr, respN, info.Fallback)
		remoteConn.Close()
		return fd.retryWithFallbackTCP(ctx, info, initialData)
	}

	// Step 4: Got valid response data — connection is alive.
	// Wrap remoteConn so the already-read response bytes are replayed on first Read.
	wrapped := &prefixConn{Conn: remoteConn, prefix: respBuf[:respN]}
	return EarlyEOFResult{RemoteConn: wrapped, ActualTunnel: info.TunnelID}
}

// retryWithFallbackTCP dials through fallback and resends the initial data.
func (fd *FallbackDialer) retryWithFallbackTCP(
	ctx context.Context,
	info core.NATInfo,
	initialData []byte,
) EarlyEOFResult {
	newConn, newTunnel, err := fd.applyFallbackTCP(ctx, info, io.EOF)
	if err != nil {
		core.Log.Errorf("Proxy", "Early EOF fallback failed for %s: %v", info.OriginalDst, err)
		return EarlyEOFResult{Failed: true}
	}

	// Resend initial client data through the fallback connection.
	if _, err := newConn.Write(initialData); err != nil {
		core.Log.Errorf("Proxy", "Early EOF fallback write failed for %s via %s: %v",
			info.OriginalDst, newTunnel, err)
		newConn.Close()
		return EarlyEOFResult{Failed: true}
	}

	core.Log.Infof("Proxy", "Early EOF fallback succeeded for %s → %s", info.OriginalDst, newTunnel)
	return EarlyEOFResult{RemoteConn: newConn, ActualTunnel: newTunnel}
}
