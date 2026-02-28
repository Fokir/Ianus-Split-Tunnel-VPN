//go:build windows || darwin

package main

import (
	"context"
	"runtime"
	"sync"

	"awg-split-tunnel/internal/ipc"

	"google.golang.org/protobuf/types/known/emptypb"
)

// BindingService is exposed to the Svelte frontend via Wails bindings.
// Each public method becomes callable from JavaScript.
type BindingService struct {
	client          *ipc.Client
	ctx             context.Context    // cancelled on GUI shutdown
	cancel          context.CancelFunc // cancels all streaming goroutines
	logStreamOnce   sync.Once
	statsStreamOnce sync.Once
	notifMgr        *NotificationManager
}

// NewBindingService creates a BindingService wrapping the IPC client.
func NewBindingService(client *ipc.Client) *BindingService {
	ctx, cancel := context.WithCancel(context.Background())
	return &BindingService{
		client:   client,
		ctx:      ctx,
		cancel:   cancel,
		notifMgr: NewNotificationManager(),
	}
}

// Shutdown cancels all background streaming goroutines.
func (b *BindingService) Shutdown() {
	b.cancel()
}

// GetPlatform returns the OS identifier ("windows", "darwin", etc.)
// so the frontend can adapt UI hints and examples per platform.
func (b *BindingService) GetPlatform() string {
	return runtime.GOOS
}

// ─── Service status ─────────────────────────────────────────────────

type ServiceStatusResult struct {
	Running       bool   `json:"running"`
	ActiveTunnels int32  `json:"activeTunnels"`
	TotalTunnels  int32  `json:"totalTunnels"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
}

func (b *BindingService) GetStatus() (*ServiceStatusResult, error) {
	resp, err := b.client.Service.GetStatus(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return &ServiceStatusResult{
		Running:       resp.Running,
		ActiveTunnels: resp.ActiveTunnels,
		TotalTunnels:  resp.TotalTunnels,
		Version:       resp.Version,
		UptimeSeconds: resp.UptimeSeconds,
	}, nil
}
