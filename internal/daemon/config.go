package daemon

import (
	vpnapi "awg-split-tunnel/api/gen"
)

// RunConfig provides optional hooks for the daemon controller mode (macOS).
// When RegisterService is set, runVPN registers the gRPC service via the
// callback instead of creating its own IPC server.
type RunConfig struct {
	// RegisterService is called after the Service is created.
	// Returns a deregister function to call during shutdown.
	RegisterService func(svc vpnapi.VPNServiceServer) func()
}
