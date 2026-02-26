package gateway

import "time"

// DiagnosticsSnapshot holds network quality metrics from a diagnostics probe.
type DiagnosticsSnapshot struct {
	PacketLoss  float64       // 0.0-1.0
	AvgRTT      time.Duration
	Jitter      time.Duration // max-min RTT
	SampleCount int
}

// DiagnosticsProvider exposes network quality data for a single tunnel.
type DiagnosticsProvider interface {
	Snapshot() DiagnosticsSnapshot
	TunnelID() string
}
