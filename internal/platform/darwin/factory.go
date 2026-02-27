//go:build darwin

// Package darwin provides macOS-specific platform implementations for daemon mode:
// utun TUN adapter, PF packet filter, route management, sysctl pcblist_n PID lookup,
// IP_BOUND_IF socket binding, Unix domain socket IPC, osascript notifications.
package darwin

import (
	"errors"

	"awg-split-tunnel/internal/platform"
)

var errNotImplemented = errors.New("not implemented on macOS yet")

// NewPlatform creates a Platform configured for macOS (daemon mode):
// utun adapter, PF per-process filtering, PF_ROUTE routes, Unix domain socket IPC.
func NewPlatform() *platform.Platform {
	return &platform.Platform{
		NewTUNAdapter: func() (platform.TUNAdapter, error) {
			return NewTUNAdapter()
		},
		NewProcessFilter: func(tunLUID uint64) (platform.ProcessFilter, error) {
			return NewProcessFilter()
		},
		NewRouteManager: func(tunLUID uint64) platform.RouteManager {
			return NewRouteManager(tunLUID)
		},
		NewProcessID: func() platform.ProcessIdentifier {
			return NewProcessIdentifier()
		},
		IPC:                NewIPCTransport(),
		NewInterfaceBinder: func() platform.InterfaceBinder { return &InterfaceBinder{} },
		Notifier: &Notifier{},

		NewNetworkMonitor: func(onChange func()) (platform.NetworkMonitor, error) {
			return NewNetworkMonitor(onChange)
		},

		PreStartup: func() error {
			// Restore DNS if a previous daemon crash left it pointing at the TUN adapter.
			RestoreDNSFromBackup()
			return nil
		},

		FlushSystemDNS: flushSystemDNS,
	}
}
