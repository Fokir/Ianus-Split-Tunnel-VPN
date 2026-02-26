package ipc

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	vpnapi "awg-split-tunnel/api/gen"
)

const (
	defaultDialTimeout = 5 * time.Second
)

// Client wraps a gRPC client connected to the VPN service via platform IPC.
type Client struct {
	conn    *grpc.ClientConn
	Service vpnapi.VPNServiceClient
}

// Dial connects to the VPN service using platform-specific IPC transport.
func Dial(ctx context.Context) (*Client, error) {
	return DialWithTimeout(ctx, defaultDialTimeout)
}

// DialWithTimeout connects to the VPN service with a custom timeout.
func DialWithTimeout(ctx context.Context, timeout time.Duration) (*Client, error) {
	conn, err := grpc.NewClient(
		"passthrough:///"+ipcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return ipcDial(timeout)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("ipc: dial: %w", err)
	}

	return &Client{
		conn:    conn,
		Service: vpnapi.NewVPNServiceClient(conn),
	}, nil
}

// Close shuts down the gRPC client connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
