//go:build windows

package windows

import (
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

const (
	// PipeName is the Named Pipe path for the VPN service IPC.
	PipeName = `\\.\pipe\awg-split-tunnel`
)

// IPCTransport implements platform.IPCTransport using Windows Named Pipes.
type IPCTransport struct{}

// NewIPCTransport creates a new Windows Named Pipe IPC transport.
func NewIPCTransport() *IPCTransport {
	return &IPCTransport{}
}

// Listener creates a Named Pipe listener for the gRPC server.
// The pipe allows any authenticated user to connect (SDDL grant).
func (t *IPCTransport) Listener() (net.Listener, error) {
	cfg := &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;AU)",
		MessageMode:        false,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	}
	return winio.ListenPipe(PipeName, cfg)
}

// Dial connects to the VPN service Named Pipe.
func (t *IPCTransport) Dial(timeout time.Duration) (net.Conn, error) {
	return winio.DialPipe(PipeName, &timeout)
}
