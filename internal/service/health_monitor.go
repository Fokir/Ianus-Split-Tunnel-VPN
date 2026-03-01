package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/gateway"
	"awg-split-tunnel/internal/provider"
)

// HealthMonitor periodically checks WireGuard/AWG peer liveness by inspecting
// last_handshake_time via IPC. When all peers of a tunnel are stale beyond the
// threshold, the tunnel is transitioned to Error state, triggering ReconnectManager.
type HealthMonitor struct {
	registry       *core.TunnelRegistry
	providerLookup func(string) (provider.TunnelProvider, bool)
	markUnhealthy  func(string, error) bool
	interval       time.Duration
	staleThreshold time.Duration
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewHealthMonitor creates a health monitor with the given config and callbacks.
// Does not start the monitor — call Start() separately.
func NewHealthMonitor(
	cfg core.HealthCheckConfig,
	registry *core.TunnelRegistry,
	providerLookup func(string) (provider.TunnelProvider, bool),
	markUnhealthy func(string, error) bool,
) *HealthMonitor {
	interval := 30 * time.Second
	if cfg.Interval != "" {
		if d, err := time.ParseDuration(cfg.Interval); err == nil && d > 0 {
			interval = d
		}
	}

	staleThreshold := 3 * time.Minute
	if cfg.StaleThreshold != "" {
		if d, err := time.ParseDuration(cfg.StaleThreshold); err == nil && d > 0 {
			staleThreshold = d
		}
	}

	return &HealthMonitor{
		registry:       registry,
		providerLookup: providerLookup,
		markUnhealthy:  markUnhealthy,
		interval:       interval,
		staleThreshold: staleThreshold,
	}
}

// Start begins the periodic health check loop.
func (hm *HealthMonitor) Start() {
	hm.ctx, hm.cancel = context.WithCancel(context.Background())
	go hm.loop()
	core.Log.Infof("Core", "Health monitor started (interval=%s, stale_threshold=%s)", hm.interval, hm.staleThreshold)
}

// Stop cancels the health check loop.
func (hm *HealthMonitor) Stop() {
	if hm.cancel != nil {
		hm.cancel()
	}
}

func (hm *HealthMonitor) loop() {
	ticker := time.NewTicker(hm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-hm.ctx.Done():
			return
		case <-ticker.C:
			hm.checkAll()
		}
	}
}

func (hm *HealthMonitor) checkAll() {
	entries := hm.registry.All()
	now := time.Now()

	for _, entry := range entries {
		if entry.State != core.TunnelStateUp {
			continue
		}
		if entry.ID == gateway.DirectTunnelID {
			continue
		}

		prov, ok := hm.providerLookup(entry.ID)
		if !ok {
			continue
		}

		hc, ok := prov.(provider.HealthCheckable)
		if !ok {
			continue
		}

		ipcData, err := hc.IpcGet()
		if err != nil {
			core.Log.Warnf("Core", "Health check: IpcGet for %q failed: %v", entry.ID, err)
			continue
		}

		stale, reason := checkPeerHealth(ipcData, now, hm.staleThreshold)
		if !stale {
			continue
		}

		core.Log.Warnf("Core", "Health check: tunnel %q has stale peers (%s), triggering reconnect", entry.ID, reason)
		hm.markUnhealthy(entry.ID, fmt.Errorf("stale peers: %s", reason))
	}
}

// checkPeerHealth parses WireGuard IPC output and determines if all peers are stale.
// Returns (stale, reason). A tunnel with no peers is not considered stale.
func checkPeerHealth(ipcData string, now time.Time, threshold time.Duration) (bool, string) {
	var (
		peerCount  int
		staleCount int
		reason     string
	)

	lines := strings.Split(ipcData, "\n")
	inPeer := false
	var lastHandshakeSec int64

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "public_key=") {
			// Flush previous peer.
			if inPeer {
				peerCount++
				if isPeerStale(lastHandshakeSec, now, threshold) {
					staleCount++
				}
			}
			// Start new peer.
			inPeer = true
			lastHandshakeSec = 0
			continue
		}

		if inPeer && strings.HasPrefix(line, "last_handshake_time_sec=") {
			val := strings.TrimPrefix(line, "last_handshake_time_sec=")
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				lastHandshakeSec = n
			}
		}
	}

	// Flush last peer.
	if inPeer {
		peerCount++
		if isPeerStale(lastHandshakeSec, now, threshold) {
			staleCount++
		}
	}

	if peerCount == 0 {
		return false, ""
	}

	if staleCount == peerCount {
		reason = strconv.Itoa(staleCount) + "/" + strconv.Itoa(peerCount) + " peers stale (threshold " + threshold.String() + ")"
		return true, reason
	}

	return false, ""
}

// isPeerStale returns true if the peer's last handshake is older than threshold.
// A handshake of 0 (never completed) is always stale.
func isPeerStale(handshakeSec int64, now time.Time, threshold time.Duration) bool {
	if handshakeSec == 0 {
		return true
	}
	handshakeTime := time.Unix(handshakeSec, 0)
	return now.Sub(handshakeTime) > threshold
}
