//go:build !windows

package service

import (
	"context"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/gateway"
)

// ConnectionMonitor is a stub for non-Windows platforms.
// The real implementation is in connection_monitor.go (windows-only).
type ConnectionMonitor struct{}

// NewConnectionMonitor creates a no-op ConnectionMonitor on non-Windows platforms.
func NewConnectionMonitor(_ *gateway.FlowTable, _ *gateway.DomainTable, _ *gateway.GeoIPResolver) *ConnectionMonitor {
	return &ConnectionMonitor{}
}

// Start is a no-op on non-Windows platforms.
func (cm *ConnectionMonitor) Start(_ context.Context) {}

func (cm *ConnectionMonitor) Subscribe() chan *vpnapi.ConnectionSnapshot {
	ch := make(chan *vpnapi.ConnectionSnapshot)
	close(ch)
	return ch
}

func (cm *ConnectionMonitor) Unsubscribe(_ chan *vpnapi.ConnectionSnapshot) {}
