//go:build windows

package gateway

import (
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/provider"
)

const (
	probeInterval     = 500 * time.Millisecond
	probeIntervalTCP  = 2 * time.Second // slower for proxy providers to avoid overload
	probeTimeout      = 3 * time.Second
	probeWindow       = 120 // samples
	probeWindowTCP    = 30  // 30 * 2s = 60s window
	reportInterval    = 10 * time.Second
	reconnectCooldown = 5 * time.Second
)

// JitterProbe periodically sends DNS queries through a VPN tunnel
// and measures RTT / jitter to diagnose network quality.
//
// For raw IP tunnels (RawForwarder) it uses UDP DNS queries with a persistent connection.
// For proxy-based tunnels (VLESS, SOCKS5, etc.) it measures TCP dial latency through
// the proxy, which is the reliable and actually-tested code path.
type JitterProbe struct {
	provider provider.TunnelProvider
	tunnelID string
	target   string // "host:port", e.g. "8.8.8.8:53"
	tcpMode  bool   // true for proxy providers without RawForwarder
	window   int    // effective window size

	mu     sync.Mutex
	rtts   [probeWindow]time.Duration // sized to max(probeWindow, probeWindowTCP)
	valid  [probeWindow]bool
	cursor int
	count  int

	// persistent UDP connection (reused across probes, UDP mode only)
	connMu        sync.Mutex
	conn          net.Conn
	lastReconnect time.Time

	// error tracking for debug logging
	consecutiveErrs int
}

// Compile-time check: JitterProbe implements DiagnosticsProvider.
var _ DiagnosticsProvider = (*JitterProbe)(nil)

// NewJitterProbe creates a probe that sends DNS queries to target via the
// given tunnel provider. If tcpMode is true, measures TCP dial latency
// instead of UDP DNS round-trip — required for proxy-based providers where
// UDP may not work reliably.
func NewJitterProbe(prov provider.TunnelProvider, tunnelID, target string, tcpMode bool) *JitterProbe {
	w := probeWindow
	if tcpMode {
		w = probeWindowTCP
	}
	return &JitterProbe{
		provider: prov,
		tunnelID: tunnelID,
		target:   target,
		tcpMode:  tcpMode,
		window:   w,
	}
}

// TunnelID returns the tunnel ID this probe is associated with.
func (p *JitterProbe) TunnelID() string {
	return p.tunnelID
}

// Snapshot computes network quality metrics from the circular buffer.
func (p *JitterProbe) Snapshot() DiagnosticsSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.count == 0 {
		return DiagnosticsSnapshot{}
	}

	n := p.count
	var minRTT, maxRTT, sumRTT time.Duration
	var goodCount, lostCount int
	first := true

	for i := 0; i < n; i++ {
		if !p.valid[i] {
			lostCount++
			continue
		}
		rtt := p.rtts[i]
		sumRTT += rtt
		goodCount++
		if first || rtt < minRTT {
			minRTT = rtt
		}
		if first || rtt > maxRTT {
			maxRTT = rtt
		}
		first = false
	}

	if goodCount == 0 {
		return DiagnosticsSnapshot{
			PacketLoss:  1.0,
			SampleCount: n,
		}
	}

	return DiagnosticsSnapshot{
		PacketLoss:  float64(lostCount) / float64(n),
		AvgRTT:      sumRTT / time.Duration(goodCount),
		Jitter:      maxRTT - minRTT,
		SampleCount: n,
	}
}

// Run starts the probe loop. It blocks until ctx is cancelled.
func (p *JitterProbe) Run(ctx context.Context) {
	mode := "UDP"
	interval := probeInterval
	if p.tcpMode {
		mode = "TCP-dial"
		interval = probeIntervalTCP
	}
	core.Log.Infof("Perf", "Jitter probe started for tunnel %s → %s (%s, every %s)",
		p.tunnelID, p.target, mode, interval)

	probeTicker := time.NewTicker(interval)
	defer probeTicker.Stop()

	reportTicker := time.NewTicker(reportInterval)
	defer reportTicker.Stop()

	defer p.closeConn()

	for {
		select {
		case <-ctx.Done():
			core.Log.Infof("Perf", "Jitter probe stopped for tunnel %s", p.tunnelID)
			return
		case <-probeTicker.C:
			rtt, ok := p.probe(ctx)
			p.record(rtt, ok)
		case <-reportTicker.C:
			p.report()
		}
	}
}

// getOrDialUDP returns the persistent UDP connection, reconnecting if needed.
func (p *JitterProbe) getOrDialUDP(ctx context.Context) (net.Conn, error) {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	if p.conn != nil {
		return p.conn, nil
	}

	if !p.lastReconnect.IsZero() && time.Since(p.lastReconnect) < reconnectCooldown {
		return nil, net.ErrClosed
	}

	dialCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	conn, err := p.provider.DialUDP(dialCtx, p.target)
	if err != nil {
		p.lastReconnect = time.Now()
		return nil, err
	}

	p.conn = conn
	p.lastReconnect = time.Now()
	return conn, nil
}

// invalidateConn closes and clears the persistent UDP connection.
func (p *JitterProbe) invalidateConn() {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
}

// closeConn closes the persistent connection on shutdown.
func (p *JitterProbe) closeConn() {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
}

// probe sends a single probe and returns the RTT.
func (p *JitterProbe) probe(ctx context.Context) (time.Duration, bool) {
	if p.tcpMode {
		return p.probeTCPDial(ctx)
	}
	return p.probeUDPDNS(ctx)
}

// probeTCPDial measures RTT by timing a TCP connection through the proxy.
// The dial time includes the full proxy chain latency (client → proxy → target).
// No DNS protocol needed — just TCP handshake.
func (p *JitterProbe) probeTCPDial(ctx context.Context) (time.Duration, bool) {
	dialCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	start := time.Now()
	conn, err := p.provider.DialTCP(dialCtx, p.target)
	rtt := time.Since(start)

	if err != nil {
		p.consecutiveErrs++
		if p.consecutiveErrs == 1 || p.consecutiveErrs%10 == 0 {
			core.Log.Warnf("Perf", "Jitter %s: TCP dial failed (err #%d): %v",
				p.tunnelID, p.consecutiveErrs, err)
		}
		return 0, false
	}
	conn.Close()

	p.consecutiveErrs = 0
	return rtt, true
}

// probeUDPDNS sends a DNS query via persistent UDP connection and measures RTT.
func (p *JitterProbe) probeUDPDNS(ctx context.Context) (time.Duration, bool) {
	conn, err := p.getOrDialUDP(ctx)
	if err != nil {
		return 0, false
	}

	query := buildDNSQuery()

	_ = conn.SetDeadline(time.Now().Add(probeTimeout))

	start := time.Now()
	if _, err := conn.Write(query); err != nil {
		p.invalidateConn()
		return 0, false
	}

	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err != nil {
		p.invalidateConn()
		return 0, false
	}
	return time.Since(start), true
}

// record stores an RTT sample in the circular buffer.
func (p *JitterProbe) record(rtt time.Duration, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.rtts[p.cursor] = rtt
	p.valid[p.cursor] = ok
	p.cursor = (p.cursor + 1) % p.window
	if p.count < p.window {
		p.count++
	}
}

// report logs aggregated jitter stats for the current window.
func (p *JitterProbe) report() {
	snap := p.Snapshot()
	if snap.SampleCount == 0 {
		return
	}

	if snap.PacketLoss >= 1.0 {
		core.Log.Warnf("Perf", "Jitter %s: all %d probes lost", p.tunnelID, snap.SampleCount)
		return
	}

	lostCount := int(snap.PacketLoss * float64(snap.SampleCount))

	if snap.Jitter > 20*time.Millisecond || lostCount > 0 {
		core.Log.Warnf("Perf", "Jitter %s: avg=%s jitter=%s lost=%d/%d",
			p.tunnelID, snap.AvgRTT, snap.Jitter, lostCount, snap.SampleCount)
	} else {
		core.Log.Infof("Perf", "Jitter %s: avg=%s jitter=%s lost=%d/%d",
			p.tunnelID, snap.AvgRTT, snap.Jitter, lostCount, snap.SampleCount)
	}
}

// buildDNSQuery constructs a minimal DNS A query for "." (root zone).
func buildDNSQuery() []byte {
	buf := make([]byte, 17)
	// Transaction ID (random)
	binary.BigEndian.PutUint16(buf[0:2], uint16(rand.Intn(0xFFFF)))
	// Flags: standard query, recursion desired
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)
	// Questions: 1
	binary.BigEndian.PutUint16(buf[4:6], 1)
	// Answer/Authority/Additional RRs: 0
	// buf[6:12] already zero
	// QNAME: root "." = single 0x00 byte
	buf[12] = 0x00
	// QTYPE: A (1)
	binary.BigEndian.PutUint16(buf[13:15], 1)
	// QCLASS: IN (1)
	binary.BigEndian.PutUint16(buf[15:17], 1)
	return buf
}
