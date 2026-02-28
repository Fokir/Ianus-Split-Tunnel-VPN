//go:build darwin

package darwin

import (
	"log"
	"net"
	"os"
	"time"
)

const (
	// SocketPath is the Unix domain socket path for the VPN daemon IPC.
	SocketPath = "/var/run/awg-split-tunnel.sock"
)

// IPCTransport implements platform.IPCTransport using Unix domain sockets.
type IPCTransport struct {
	inheritedListener net.Listener // set when launchd passes the socket
	launchdActivated  bool
}

// NewIPCTransport creates a new Unix domain socket IPC transport.
// It attempts to inherit a socket from launchd (socket activation).
func NewIPCTransport() *IPCTransport {
	t := &IPCTransport{}

	// Try to inherit a socket from launchd.
	if ln, err := InheritLaunchdSocket(); err == nil {
		log.Printf("[IPC] Inherited launchd socket: %s", ln.Addr())
		t.inheritedListener = ln
		t.launchdActivated = true
	}

	return t
}

// IsLaunchdActivated returns true if the daemon was started via launchd
// socket activation (i.e. a listener was inherited from launchd).
func (t *IPCTransport) IsLaunchdActivated() bool {
	return t.launchdActivated
}

// InheritedListener returns the launchd-inherited listener, or nil.
func (t *IPCTransport) InheritedListener() net.Listener {
	return t.inheritedListener
}

// Listener creates a Unix domain socket listener for the gRPC server.
// If a launchd-inherited listener is available, it is returned (once).
func (t *IPCTransport) Listener() (net.Listener, error) {
	if t.inheritedListener != nil {
		ln := t.inheritedListener
		t.inheritedListener = nil // consume: return only once
		return ln, nil
	}

	// Fallback: create our own socket (dev mode / legacy).
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
