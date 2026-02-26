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
	// AddBypassPrefixes adds PERMIT rules for the given IP prefixes (local subnets).
	AddBypassPrefixes(prefixes []netip.Prefix) error
	// BlockDNSOnInterface blocks DNS traffic (port 53) on the given interface.
	BlockDNSOnInterface(ifLUID uint64) error
	// PermitDNSForSelf allows DNS traffic for the current process on the given interface.
	PermitDNSForSelf(ifLUID uint64) error
	// BlockAllIPv6 blocks all IPv6 traffic.
	BlockAllIPv6() error
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
	// AddBypassRoute adds a host route for a VPN server through the real NIC.
	AddBypassRoute(dst netip.Addr) error
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

// Notifier sends system notifications.
type Notifier interface {
	// Show displays a system notification.
	Show(title, message string) error
}
