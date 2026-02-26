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
}
