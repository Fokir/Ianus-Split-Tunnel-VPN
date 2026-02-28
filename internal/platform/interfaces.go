package platform

import (
	"net"
	"net/netip"
	"syscall"
	"time"
)

// RealNIC holds information about the system's real internet-facing NIC.
type RealNIC struct {
	LUID    uint64
	Index   uint32
	Gateway netip.Addr
	LocalIP netip.Addr // NIC's own IPv4 address
}

// TUNAdapter abstracts a TUN adapter (WinTUN on Windows, utun on macOS).
type TUNAdapter interface {
	// Name returns the OS-level interface name (e.g. "utun5" on macOS, "AWG Gateway" on Windows).
	// Used by kill switch to allow traffic on the TUN interface.
	Name() string
	// LUID returns the adapter's locally unique identifier.
	LUID() uint64
	// InterfaceIndex returns the adapter's interface index.
	InterfaceIndex() uint32
	// IP returns the adapter's assigned IP address.
	IP() netip.Addr
	// ReadPacket reads one IP packet into buf and returns the number of bytes read.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes one IP packet to the TUN adapter.
	WritePacket(pkt []byte) error
	// SetDNS configures DNS servers on the TUN adapter.
	SetDNS(servers []netip.Addr) error
	// ClearDNS removes DNS server configuration from the TUN adapter.
	ClearDNS() error
	// Close tears down the adapter.
	Close() error
}

// ProcessFilter abstracts per-process traffic filtering
// (WFP on Windows, PF on macOS).
type ProcessFilter interface {
	// EnsureBlocked lazily adds blocking rules for a process on the real NIC.
	EnsureBlocked(exePath string)
	// BlockProcessOnRealNIC adds WFP/PF rules to block a process on the real NIC.
	BlockProcessOnRealNIC(exePath string) error
	// UnblockProcess removes blocking rules for a process.
	UnblockProcess(exePath string)
	// UnblockAllProcesses removes all per-process blocking rules.
	UnblockAllProcesses()
	// AddBypassPrefixes adds PERMIT rules for the given IP prefixes (local subnets).
	AddBypassPrefixes(prefixes []netip.Prefix) error
	// BlockDNSOnInterface blocks DNS traffic (port 53) on the given interface.
	BlockDNSOnInterface(ifLUID uint64) error
	// UnblockDNSOnInterface removes DNS blocking rules.
	UnblockDNSOnInterface()
	// PermitDNSForSelf allows DNS traffic for the current process on the given interface.
	PermitDNSForSelf(ifLUID uint64) error
	// RemoveDNSPermitForSelf removes DNS self-permit rules.
	RemoveDNSPermitForSelf()
	// BlockAllIPv6 blocks all IPv6 traffic.
	BlockAllIPv6() error
	// EnableKillSwitch blocks all non-VPN traffic except loopback and VPN endpoints.
	// tunIfName is the TUN interface name; vpnEndpoints are the VPN server addresses to exempt.
	EnableKillSwitch(tunIfName string, vpnEndpoints []netip.Addr) error
	// DisableKillSwitch removes the kill switch rules.
	DisableKillSwitch() error
	// Close tears down the filter session (rules auto-removed on Windows).
	Close() error
}

// RouteManager abstracts system routing table management.
type RouteManager interface {
	// DiscoverRealNIC finds the current default gateway (non-TUN) NIC.
	DiscoverRealNIC() (RealNIC, error)
	// RealNICInfo returns the previously discovered real NIC info.
	RealNICInfo() RealNIC
	// SetDefaultRoute adds default routes (0/1 + 128/1) through the TUN adapter.
	SetDefaultRoute() error
	// RemoveDefaultRoute removes the default routes while keeping bypass routes.
	RemoveDefaultRoute() error
	// AddBypassRoute adds a host route for a VPN server through the real NIC.
	AddBypassRoute(dst netip.Addr) error
	// ClearBypassRoutes removes all bypass routes (used before re-adding them on network change).
	ClearBypassRoutes()
	// Cleanup removes all routes added by this manager.
	Cleanup() error
}

// ProcessIdentifier finds the owning PID for network connections.
type ProcessIdentifier interface {
	// FindPIDByPort finds the PID owning a connection with the given local port.
	FindPIDByPort(srcPort uint16, isUDP bool) (uint32, error)
}

// IPCTransport abstracts the IPC transport layer
// (Named Pipes on Windows, Unix Domain Socket on macOS).
type IPCTransport interface {
	// Listener creates a server-side listener.
	Listener() (net.Listener, error)
	// Dial connects to the IPC endpoint with the given timeout.
	Dial(timeout time.Duration) (net.Conn, error)
}

// InterfaceBinder creates socket control functions for binding to specific NICs
// (IP_UNICAST_IF on Windows, IP_BOUND_IF on macOS).
type InterfaceBinder interface {
	// BindControl returns a net.Dialer.Control function that binds sockets
	// to the specified network interface.
	BindControl(ifIndex uint32) func(network, address string, c syscall.RawConn) error
}

// NetworkMonitor detects network changes (interface up/down, default route changes).
type NetworkMonitor interface {
	// Start begins monitoring for network changes.
	Start() error
	// Stop stops the monitor.
	Stop() error
	// Suppress temporarily disables onChange callbacks (e.g. during our own route changes).
	Suppress()
	// Resume re-enables onChange callbacks after Suppress.
	Resume()
}

// Notifier sends system notifications.
type Notifier interface {
	// Show displays a system notification.
	Show(title, message string) error
}
