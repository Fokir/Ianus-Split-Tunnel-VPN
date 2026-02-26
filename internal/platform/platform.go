package platform

// Platform aggregates all platform-specific implementations.
// Populated by platform-specific factory (NewPlatform) in platform/windows/ or platform/darwin/.
type Platform struct {
	NewTUNAdapter      func() (TUNAdapter, error)
	NewProcessFilter   func(tunLUID uint64) (ProcessFilter, error)
	NewRouteManager    func(tunLUID uint64) RouteManager
	NewProcessID       func() ProcessIdentifier
	IPC                IPCTransport
	NewInterfaceBinder func() InterfaceBinder
	Notifier           Notifier

	// PreStartup runs platform-specific initialization before the main VPN loop
	// (e.g., cleanup conflicting WFP filters on Windows).
	PreStartup func() error

	// FlushSystemDNS flushes the system DNS cache
	// (ipconfig /flushdns on Windows, dscacheutil on macOS).
	FlushSystemDNS func() error
}
