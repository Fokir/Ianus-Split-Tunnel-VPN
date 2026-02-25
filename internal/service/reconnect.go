//go:build windows

package service

import (
	"context"
	"net"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
)

// ReconnectManager watches tunnel state changes and automatically
// reconnects tunnels that fail unexpectedly.
type ReconnectManager struct {
	mu       sync.Mutex
	cfg      core.ReconnectConfig
	ctrl     TunnelController
	registry *core.TunnelRegistry
	bus      *core.EventBus
	resolver *net.Resolver // NIC-bound resolver for connectivity checks

	intentMap map[string]bool              // tunnelID → should be connected
	retrying  map[string]context.CancelFunc // active reconnect goroutines
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewReconnectManager creates a new auto-reconnection manager.
func NewReconnectManager(
	cfg core.ReconnectConfig,
	ctrl TunnelController,
	registry *core.TunnelRegistry,
	bus *core.EventBus,
	resolver *net.Resolver,
) *ReconnectManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ReconnectManager{
		cfg:       cfg,
		ctrl:      ctrl,
		registry:  registry,
		bus:       bus,
		resolver:  resolver,
		intentMap: make(map[string]bool),
		retrying:  make(map[string]context.CancelFunc),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start subscribes to tunnel state events and begins monitoring.
func (rm *ReconnectManager) Start() {
	rm.bus.Subscribe(core.EventTunnelStateChanged, rm.handleStateChange)
	core.Log.Infof("Core", "Reconnect manager started (enabled=%v, interval=%s, max_retries=%d)",
		rm.cfg.Enabled, rm.cfg.Interval, rm.cfg.MaxRetries)
}

// Stop cancels all reconnect goroutines.
func (rm *ReconnectManager) Stop() {
	rm.cancel()
	rm.mu.Lock()
	for id, cancelFn := range rm.retrying {
		cancelFn()
		delete(rm.retrying, id)
	}
	rm.mu.Unlock()
}

// SetEnabled enables or disables auto-reconnection at runtime.
func (rm *ReconnectManager) SetEnabled(enabled bool) {
	rm.mu.Lock()
	rm.cfg.Enabled = enabled
	if !enabled {
		// Cancel all active retry loops.
		for id, cancelFn := range rm.retrying {
			cancelFn()
			delete(rm.retrying, id)
		}
	}
	rm.mu.Unlock()
}

// SetIntent marks a tunnel as intentionally connected or disconnected.
// Called externally when a user connects/disconnects a tunnel.
func (rm *ReconnectManager) SetIntent(tunnelID string, shouldBeConnected bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if shouldBeConnected {
		rm.intentMap[tunnelID] = true
	} else {
		delete(rm.intentMap, tunnelID)
		// Cancel any ongoing reconnect attempt.
		if cancelFn, ok := rm.retrying[tunnelID]; ok {
			cancelFn()
			delete(rm.retrying, tunnelID)
		}
	}
}

// LoadIntents loads persisted active tunnels as reconnect intents.
func (rm *ReconnectManager) LoadIntents(tunnelIDs []string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	for _, id := range tunnelIDs {
		rm.intentMap[id] = true
	}
}

func (rm *ReconnectManager) handleStateChange(e core.Event) {
	payload, ok := e.Payload.(core.TunnelStatePayload)
	if !ok {
		return
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.cfg.Enabled {
		return
	}

	switch payload.NewState {
	case core.TunnelStateUp:
		// Tunnel is up — mark intent and stop any retrying.
		rm.intentMap[payload.TunnelID] = true
		if cancelFn, ok := rm.retrying[payload.TunnelID]; ok {
			cancelFn()
			delete(rm.retrying, payload.TunnelID)
		}

	case core.TunnelStateDown:
		// Explicit user disconnect — clear intent.
		// Note: Down from Error during reconnect is handled by the retry loop.
		if payload.OldState == core.TunnelStateUp {
			delete(rm.intentMap, payload.TunnelID)
			if cancelFn, ok := rm.retrying[payload.TunnelID]; ok {
				cancelFn()
				delete(rm.retrying, payload.TunnelID)
			}
		}

	case core.TunnelStateError:
		// Tunnel failed — start reconnect if intent exists and not already retrying.
		if rm.intentMap[payload.TunnelID] {
			if _, alreadyRetrying := rm.retrying[payload.TunnelID]; !alreadyRetrying {
				retryCtx, retryCancel := context.WithCancel(rm.ctx)
				rm.retrying[payload.TunnelID] = retryCancel
				go rm.reconnectLoop(retryCtx, payload.TunnelID)
			}
		}
	}
}

func (rm *ReconnectManager) reconnectLoop(ctx context.Context, tunnelID string) {
	interval := rm.getInterval()
	maxRetries := rm.cfg.MaxRetries

	core.Log.Infof("Core", "Reconnect: starting retry loop for %q (interval=%s)", tunnelID, interval)

	for attempt := 1; ; attempt++ {
		select {
		case <-ctx.Done():
			core.Log.Infof("Core", "Reconnect: cancelled for %q", tunnelID)
			return
		case <-time.After(interval):
		}

		// Check if intent still exists.
		rm.mu.Lock()
		hasIntent := rm.intentMap[tunnelID]
		rm.mu.Unlock()
		if !hasIntent {
			core.Log.Infof("Core", "Reconnect: intent cleared for %q, stopping", tunnelID)
			return
		}

		// Check if tunnel is already up.
		if entry, ok := rm.registry.Get(tunnelID); ok && entry.State == core.TunnelStateUp {
			core.Log.Infof("Core", "Reconnect: %q is already up, stopping", tunnelID)
			rm.cleanup(tunnelID)
			return
		}

		// Check network connectivity.
		if !rm.hasNetworkConnectivity() {
			core.Log.Debugf("Core", "Reconnect: no network connectivity, skipping attempt for %q", tunnelID)
			continue
		}

		// Max retries check.
		if maxRetries > 0 && attempt > maxRetries {
			core.Log.Warnf("Core", "Reconnect: max retries (%d) reached for %q", maxRetries, tunnelID)
			rm.cleanup(tunnelID)
			return
		}

		core.Log.Infof("Core", "Reconnect: attempt %d for %q", attempt, tunnelID)
		if err := rm.ctrl.ConnectTunnel(ctx, tunnelID); err != nil {
			core.Log.Warnf("Core", "Reconnect: attempt %d failed for %q: %v", attempt, tunnelID, err)
			continue
		}

		core.Log.Infof("Core", "Reconnect: %q reconnected successfully", tunnelID)
		rm.cleanup(tunnelID)
		return
	}
}

func (rm *ReconnectManager) cleanup(tunnelID string) {
	rm.mu.Lock()
	if cancelFn, ok := rm.retrying[tunnelID]; ok {
		cancelFn()
		delete(rm.retrying, tunnelID)
	}
	rm.mu.Unlock()
}

func (rm *ReconnectManager) getInterval() time.Duration {
	if rm.cfg.Interval != "" {
		if d, err := time.ParseDuration(rm.cfg.Interval); err == nil && d > 0 {
			return d
		}
	}
	return 10 * time.Second // default
}

func (rm *ReconnectManager) hasNetworkConnectivity() bool {
	if rm.resolver == nil {
		return true // assume connected if no resolver
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := rm.resolver.LookupHost(ctx, "dns.google")
	return err == nil
}
