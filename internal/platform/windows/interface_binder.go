//go:build windows

package windows

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	ipUnicastIF   = 31 // IP_UNICAST_IF (IPPROTO_IP level)
	ipv6UnicastIF = 31 // IPV6_UNICAST_IF (IPPROTO_IPV6 level)
)

// InterfaceBinder implements platform.InterfaceBinder using IP_UNICAST_IF.
type InterfaceBinder struct{}

// BindControl returns a net.Dialer.Control function that forces outgoing
// connections through the NIC identified by ifIndex.
func (b *InterfaceBinder) BindControl(ifIndex uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var setErr error
		err := c.Control(func(fd uintptr) {
			handle := syscall.Handle(fd)
			// IP_UNICAST_IF needs interface index in network byte order for IPv4.
			var buf [4]byte
			binary.BigEndian.PutUint32(buf[:], ifIndex)
			idx := *(*int32)(unsafe.Pointer(&buf[0]))
			setErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, ipUnicastIF, int(idx))
		})
		if err != nil {
			return fmt.Errorf("control: %w", err)
		}
		if setErr != nil {
			return fmt.Errorf("IP_UNICAST_IF: %w", setErr)
		}
		return nil
	}
}
