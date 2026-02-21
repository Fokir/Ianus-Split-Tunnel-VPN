//go:build windows

package ipc

import (
	"fmt"
	"net"

	"google.golang.org/grpc"

	vpnapi "awg-split-tunnel/api/gen"
)

// Server wraps a gRPC server listening on a Named Pipe.
type Server struct {
	grpc     *grpc.Server
	listener net.Listener
}

// NewServer creates a new IPC server with the given VPNService implementation.
func NewServer(svc vpnapi.VPNServiceServer, opts ...grpc.ServerOption) *Server {
	gs := grpc.NewServer(opts...)
	vpnapi.RegisterVPNServiceServer(gs, svc)
	return &Server{grpc: gs}
}

// Start opens the Named Pipe and begins serving gRPC requests.
// Blocks until Stop is called or an error occurs.
func (s *Server) Start() error {
	ln, err := PipeListener()
	if err != nil {
		return fmt.Errorf("ipc: listen pipe: %w", err)
	}
	s.listener = ln
	return s.grpc.Serve(ln)
}

// Stop gracefully stops the gRPC server and closes the pipe listener.
func (s *Server) Stop() {
	s.grpc.GracefulStop()
}

// ForceStop immediately stops the gRPC server.
func (s *Server) ForceStop() {
	s.grpc.Stop()
}

// GRPCServer returns the underlying grpc.Server for additional configuration.
func (s *Server) GRPCServer() *grpc.Server {
	return s.grpc
}
