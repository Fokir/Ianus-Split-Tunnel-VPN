//go:build windows

package gateway

import (
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/provider"
)

const (
	probeInterval  = 500 * time.Millisecond
	probeTimeout   = 3 * time.Second
	probeWindow    = 20
	reportInterval = 10 * time.Second
)

// JitterProbe periodically sends UDP DNS queries through a VPN tunnel
// and measures RTT / jitter to diagnose network-level microstutter.
type JitterProbe struct {
	provider provider.TunnelProvider
	tunnelID string
	target   string // "host:port", e.g. "8.8.8.8:53"

	rtts   [probeWindow]time.Duration
	valid  [probeWindow]bool
	cursor int
	count  int
}

// NewJitterProbe creates a probe that sends DNS queries to target via the
// given tunnel provider.
func NewJitterProbe(prov provider.TunnelProvider, tunnelID, target string) *JitterProbe {
	return &JitterProbe{
		provider: prov,
		tunnelID: tunnelID,
		target:   target,
	}
}

// Run starts the probe loop. It blocks until ctx is cancelled.
func (p *JitterProbe) Run(ctx context.Context) {
	core.Log.Infof("Perf", "Jitter probe started for tunnel %s → %s", p.tunnelID, p.target)

	probeTicker := time.NewTicker(probeInterval)
	defer probeTicker.Stop()

	reportTicker := time.NewTicker(reportInterval)
	defer reportTicker.Stop()

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

// probe sends a single DNS query and returns the RTT.
func (p *JitterProbe) probe(ctx context.Context) (time.Duration, bool) {
	dialCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	conn, err := p.provider.DialUDP(dialCtx, p.target)
	if err != nil {
		return 0, false
	}
	defer conn.Close()

	query := buildDNSQuery()

	_ = conn.SetDeadline(time.Now().Add(probeTimeout))

	start := time.Now()
	if _, err := conn.Write(query); err != nil {
		return 0, false
	}

	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err != nil {
		return 0, false
	}
	return time.Since(start), true
}

// record stores an RTT sample in the circular buffer.
func (p *JitterProbe) record(rtt time.Duration, ok bool) {
	p.rtts[p.cursor] = rtt
	p.valid[p.cursor] = ok
	p.cursor = (p.cursor + 1) % probeWindow
	if p.count < probeWindow {
		p.count++
	}
}

// report logs aggregated jitter stats for the current window.
func (p *JitterProbe) report() {
	if p.count == 0 {
		return
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
		core.Log.Warnf("Perf", "Jitter %s: all %d probes lost", p.tunnelID, n)
		return
	}

	avgRTT := sumRTT / time.Duration(goodCount)
	jitter := maxRTT - minRTT

	if jitter > 20*time.Millisecond || lostCount > 0 {
		core.Log.Warnf("Perf", "Jitter %s: min=%s avg=%s max=%s jitter=%s lost=%d/%d",
			p.tunnelID, minRTT, avgRTT, maxRTT, jitter, lostCount, n)
	} else {
		core.Log.Infof("Perf", "Jitter %s: min=%s avg=%s max=%s jitter=%s lost=%d/%d",
			p.tunnelID, minRTT, avgRTT, maxRTT, jitter, lostCount, n)
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

// SetDeadline helper — net.Conn returned by DialUDP should support it.
var _ net.Conn = (*net.UDPConn)(nil)
