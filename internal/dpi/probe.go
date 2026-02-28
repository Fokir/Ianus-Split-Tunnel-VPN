package dpi

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"syscall"
	"time"

	"awg-split-tunnel/internal/core"
)

const (
	probeTimeout    = 10 * time.Second
	probePort       = "443"
	probeTLSVersion = tls.VersionTLS12
)

// ProbeResult holds the outcome of a connectivity test.
type ProbeResult struct {
	Success bool
	Latency time.Duration
	Error   string
}

// ProbeRunner tests domain accessibility with and without DPI bypass.
type ProbeRunner struct {
	// bindControl binds sockets to the real NIC (bypassing TUN adapter).
	bindControl func(network, address string, c syscall.RawConn) error
	localIP     net.IP
}

// NewProbeRunner creates a probe runner that dials through the real NIC.
func NewProbeRunner(bindControl func(network, address string, c syscall.RawConn) error, localIP net.IP) *ProbeRunner {
	return &ProbeRunner{
		bindControl: bindControl,
		localIP:     localIP,
	}
}

// TestDirect tests if a domain is reachable without any DPI desync.
// A successful TLS handshake means the domain is NOT blocked.
func (pr *ProbeRunner) TestDirect(ctx context.Context, domain string) ProbeResult {
	start := time.Now()

	conn, err := pr.dialTCP(ctx, domain)
	if err != nil {
		return ProbeResult{Error: fmt.Sprintf("tcp dial: %v", err)}
	}
	defer conn.Close()

	err = pr.tlsHandshake(ctx, conn, domain)
	latency := time.Since(start)
	if err != nil {
		return ProbeResult{Error: fmt.Sprintf("tls handshake: %v", err), Latency: latency}
	}

	return ProbeResult{Success: true, Latency: latency}
}

// TestWithStrategy tests if a domain is reachable using a specific DPI bypass strategy.
func (pr *ProbeRunner) TestWithStrategy(ctx context.Context, domain string, strategy *Strategy) ProbeResult {
	start := time.Now()

	conn, err := pr.dialTCP(ctx, domain)
	if err != nil {
		return ProbeResult{Error: fmt.Sprintf("tcp dial: %v", err)}
	}
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return ProbeResult{Error: "not a TCP connection"}
	}

	// Wrap in desync writer that applies the strategy to the first TLS write.
	dw := &desyncWriter{
		conn:     tcpConn,
		strategy: strategy,
	}

	err = pr.tlsHandshakeWithWriter(ctx, tcpConn, dw, domain)
	latency := time.Since(start)
	if err != nil {
		return ProbeResult{Error: fmt.Sprintf("tls handshake with desync: %v", err), Latency: latency}
	}

	return ProbeResult{Success: true, Latency: latency}
}

// dialTCP creates a TCP connection to domain:443 through the real NIC.
func (pr *ProbeRunner) dialTCP(ctx context.Context, domain string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	dialer := &net.Dialer{
		Control: pr.bindControl,
	}
	if pr.localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: pr.localIP}
	}

	return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(domain, probePort))
}

// tlsHandshake performs a TLS handshake on an existing TCP connection.
func (pr *ProbeRunner) tlsHandshake(ctx context.Context, conn net.Conn, domain string) error {
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: domain,
		MinVersion: probeTLSVersion,
	})
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(probeTimeout)
	}
	tlsConn.SetDeadline(deadline)
	return tlsConn.Handshake()
}

// tlsHandshakeWithWriter performs a TLS handshake using a custom writer
// that applies DPI desync on the first write (ClientHello).
func (pr *ProbeRunner) tlsHandshakeWithWriter(ctx context.Context, conn *net.TCPConn, dw *desyncWriter, domain string) error {
	// Enable TCP_NODELAY for split segments.
	conn.SetNoDelay(true)

	tlsConn := tls.Client(&desyncNetConn{
		Conn:   conn,
		writer: dw,
	}, &tls.Config{
		ServerName: domain,
		MinVersion: probeTLSVersion,
	})
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(probeTimeout)
	}
	tlsConn.SetDeadline(deadline)
	return tlsConn.Handshake()
}

// desyncWriter applies DPI desync to the first write (TLS ClientHello).
type desyncWriter struct {
	conn     *net.TCPConn
	strategy *Strategy
	done     bool
}

func (dw *desyncWriter) Write(p []byte) (int, error) {
	if dw.done || !IsTLSClientHello(p) {
		return dw.conn.Write(p)
	}
	dw.done = true
	return applyStrategyToWrite(dw.conn, p, dw.strategy)
}

// desyncNetConn wraps a net.Conn but intercepts Write calls through a desyncWriter.
type desyncNetConn struct {
	net.Conn
	writer *desyncWriter
}

func (c *desyncNetConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

// applyStrategyToWrite applies split/fake operations to a TLS ClientHello write.
// This is a simplified version used by the probe runner (no raw conn TTL manipulation).
func applyStrategyToWrite(conn *net.TCPConn, hello []byte, strategy *Strategy) (int, error) {
	if strategy == nil || len(strategy.Ops) == 0 {
		return conn.Write(hello)
	}

	totalLen := len(hello)
	for _, op := range strategy.Ops {
		if op.FilterProtocol != "" && op.FilterProtocol != "tcp" {
			continue
		}

		switch op.Mode {
		case DesyncMultisplit, DesyncFakedsplit:
			// Apply split at SNI or specified positions.
			positions := resolveSplitPositions(hello, op.SplitPos)
			if len(positions) == 0 {
				return conn.Write(hello)
			}
			chunks := SplitAt(hello, positions)
			for i, chunk := range chunks {
				if _, err := conn.Write(chunk); err != nil {
					return 0, err
				}
				if i < len(chunks)-1 {
					time.Sleep(1 * time.Millisecond)
				}
			}
			return totalLen, nil

		case DesyncFake:
			// In probe mode, we skip fake injection (no raw conn available)
			// and just send the real data.
			core.Log.Debugf("DPI", "Probe: skipping fake injection (no raw conn)")
			return conn.Write(hello)

		case DesyncNone:
			return conn.Write(hello)
		}
	}

	return conn.Write(hello)
}

// resolveSplitPositions resolves split positions for a hello payload.
func resolveSplitPositions(hello []byte, splitPos []int) []int {
	if len(splitPos) == 0 {
		sniOff := FindSNIOffset(hello)
		if sniOff > 0 {
			return []int{sniOff}
		}
		return nil
	}

	var result []int
	for _, pos := range splitPos {
		switch {
		case pos == SplitPosAutoSNI:
			sniOff := FindSNIOffset(hello)
			if sniOff > 0 && sniOff < len(hello) {
				result = append(result, sniOff)
			}
		case pos < 0:
			actual := len(hello) + pos
			if actual > 0 && actual < len(hello) {
				result = append(result, actual)
			}
		default:
			if pos > 0 && pos < len(hello) {
				result = append(result, pos)
			}
		}
	}
	return result
}

// SplitAt splits data into chunks at the given byte offsets.
// Exported for use by the probe runner.
func SplitAt(data []byte, positions []int) [][]byte {
	if len(positions) == 0 {
		return [][]byte{data}
	}

	chunks := make([][]byte, 0, len(positions)+1)
	start := 0
	for _, pos := range positions {
		if pos > start && pos < len(data) {
			chunks = append(chunks, data[start:pos])
			start = pos
		}
	}
	if start < len(data) {
		chunks = append(chunks, data[start:])
	}
	return chunks
}
