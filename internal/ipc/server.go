package ipc

import (
	"net"
	"time"

	"google.golang.org/grpc"

	vpnapi "awg-split-tunnel/api/gen"
)

// Server wraps a gRPC server listening on a platform-specific transport
// (Named Pipes on Windows, Unix domain sockets on macOS).
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

// Start begins serving gRPC requests on the given listener.
// Blocks until Stop is called or an error occurs.
func (s *Server) Start(ln net.Listener) error {
	s.listener = ln
	return s.grpc.Serve(ln)
}

// Stop gracefully stops the gRPC server with a 3-second timeout.
// If active streams don't close in time, falls back to a hard stop
// to prevent hanging on streaming clients that never disconnect.
func (s *Server) Stop() {
	done := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		s.grpc.Stop()
	}
}

// ForceStop immediately stops the gRPC server.
func (s *Server) ForceStop() {
	s.grpc.Stop()
}

// GRPCServer returns the underlying grpc.Server for additional configuration.
func (s *Server) GRPCServer() *grpc.Server {
	return s.grpc
}
