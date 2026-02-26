//go:build !windows && !darwin

package ipc

import (
	"fmt"
	"net"
	"time"
)

const ipcAddress = "/var/run/awg-split-tunnel.sock"

func ipcDial(timeout time.Duration) (net.Conn, error) {
	return nil, fmt.Errorf("ipc: unsupported platform")
}
