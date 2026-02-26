//go:build windows

// Package windows provides Windows-specific platform implementations.
package windows

import (
	"os/exec"
	"syscall"

	"awg-split-tunnel/internal/gateway"
	"awg-split-tunnel/internal/platform"
)

// NewPlatform creates a Platform configured for Windows:
// WinTUN adapter, WFP per-process filtering, iphlpapi routes, Named Pipes IPC.
func NewPlatform() *platform.Platform {
	return &platform.Platform{
		NewTUNAdapter: func() (platform.TUNAdapter, error) {
			return gateway.NewAdapter()
		},
		NewProcessFilter: func(tunLUID uint64) (platform.ProcessFilter, error) {
			return gateway.NewWFPManager(tunLUID)
		},
		NewRouteManager: func(tunLUID uint64) platform.RouteManager {
			return gateway.NewRouteManager(tunLUID)
		},
		NewProcessID: func() platform.ProcessIdentifier {
			return gateway.NewProcessIdentifier()
		},
		IPC:                NewIPCTransport(),
		NewInterfaceBinder: func() platform.InterfaceBinder { return &InterfaceBinder{} },
		Notifier:           &Notifier{},

		PreStartup: func() error {
			return gateway.CleanupConflictingWFP()
		},

		FlushSystemDNS: func() error {
			cmd := exec.Command("ipconfig", "/flushdns")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			return cmd.Run()
		},
	}
}
