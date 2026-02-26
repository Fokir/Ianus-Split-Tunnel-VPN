//go:build darwin

package ipc

import (
	"net"
	"time"
)

// ipcAddress is the Unix Domain Socket path for client connections.
const ipcAddress = "/var/run/awg-split-tunnel.sock"

// ipcDial connects to the VPN service Unix Domain Socket.
func ipcDial(timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", ipcAddress, timeout)
}
