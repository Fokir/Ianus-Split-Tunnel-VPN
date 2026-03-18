//go:build !windows

package service

import vpnapi "awg-split-tunnel/api/gen"

// ConnectionMonitor is a stub for non-Windows platforms.
// The real implementation is in connection_monitor.go (windows-only).
type ConnectionMonitor struct{}

func (cm *ConnectionMonitor) Subscribe() chan *vpnapi.ConnectionSnapshot {
	ch := make(chan *vpnapi.ConnectionSnapshot)
	close(ch)
	return ch
}

func (cm *ConnectionMonitor) Unsubscribe(_ chan *vpnapi.ConnectionSnapshot) {}
