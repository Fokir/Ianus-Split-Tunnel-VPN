//go:build darwin

package darwin

import (
	"net"
	"os"
	"time"
)

const (
	// SocketPath is the Unix domain socket path for the VPN daemon IPC.
	SocketPath = "/var/run/awg-split-tunnel.sock"
)

// IPCTransport implements platform.IPCTransport using Unix domain sockets.
type IPCTransport struct{}

// NewIPCTransport creates a new Unix domain socket IPC transport.
func NewIPCTransport() *IPCTransport {
	return &IPCTransport{}
}

// Listener creates a Unix domain socket listener for the gRPC server.
func (t *IPCTransport) Listener() (net.Listener, error) {
	// Remove stale socket file from previous run.
	os.Remove(SocketPath)
	ln, err := net.Listen("unix", SocketPath)
	if err != nil {
		return nil, err
	}
	// Allow any authenticated user to connect.
	if err := os.Chmod(SocketPath, 0666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Dial connects to the VPN daemon's Unix domain socket.
func (t *IPCTransport) Dial(timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", SocketPath, timeout)
}
