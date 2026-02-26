//go:build darwin

package darwin

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	ipBoundIF   = 25  // IP_BOUND_IF (IPPROTO_IP level on macOS)
	ipv6BoundIF = 125 // IPV6_BOUND_IF (IPPROTO_IPV6 level on macOS)
)

// InterfaceBinder implements platform.InterfaceBinder using IP_BOUND_IF.
type InterfaceBinder struct{}

// BindControl returns a net.Dialer.Control function that forces outgoing
// connections through the NIC identified by ifIndex.
func (b *InterfaceBinder) BindControl(ifIndex uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var setErr error
		err := c.Control(func(fd uintptr) {
			setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, ipBoundIF, int(ifIndex))
		})
		if err != nil {
			return fmt.Errorf("control: %w", err)
		}
		if setErr != nil {
			return fmt.Errorf("IP_BOUND_IF: %w", setErr)
		}
		return nil
	}
}
