//go:build windows

package ipc

import (
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// ipcAddress is the Named Pipe path for client connections.
const ipcAddress = `\\.\pipe\awg-split-tunnel`

// ipcDial connects to the VPN service Named Pipe.
func ipcDial(timeout time.Duration) (net.Conn, error) {
	return winio.DialPipe(ipcAddress, &timeout)
}
