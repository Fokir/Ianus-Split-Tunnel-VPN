//go:build windows

// Package ipc provides gRPC transport over Windows Named Pipes
// for communication between the VPN service (elevated) and GUI (user-level).
package ipc

import (
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

const (
	// PipeName is the Named Pipe path for the VPN service.
	PipeName = `\\.\pipe\awg-split-tunnel`
)

// PipeListener creates a Named Pipe listener for the gRPC server.
// The pipe allows any authenticated user to connect (SDDL grant).
func PipeListener() (net.Listener, error) {
	cfg := &winio.PipeConfig{
		// SYSTEM + Administrators: full access; Interactive Users (console/RDP): full access.
		// More restrictive than AU — excludes batch, service, and network logons.
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)",
		MessageMode:        false,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	}
	return winio.ListenPipe(PipeName, cfg)
}

// PipeDial connects to the VPN service Named Pipe.
func PipeDial(timeout time.Duration) (net.Conn, error) {
	return winio.DialPipe(PipeName, &timeout)
}
