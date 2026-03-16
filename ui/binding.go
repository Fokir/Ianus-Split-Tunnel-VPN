//go:build windows || darwin

package main

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	"awg-split-tunnel/internal/ipc"

	"github.com/wailsapp/wails/v3/pkg/application"
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
	seenBanners     map[string]struct{} // deduplicate banner events

	// windowVisible tracks whether the main window is shown.
	// When false, streaming goroutines skip emitting Wails events
	// to reduce WebView2 activity and memory pressure.
	windowVisible atomic.Bool
}

// NewBindingService creates a BindingService wrapping the IPC client.
func NewBindingService(client *ipc.Client) *BindingService {
	ctx, cancel := context.WithCancel(context.Background())
	bs := &BindingService{
		client:   client,
		ctx:      ctx,
		cancel:   cancel,
		notifMgr: NewNotificationManager(),
	}
	bs.windowVisible.Store(true) // window starts visible
	return bs
}

// OnWindowHidden marks the window as hidden. Streaming goroutines
// will skip emitting Wails events to reduce WebView2 memory pressure.
func (b *BindingService) OnWindowHidden() {
	b.windowVisible.Store(false)
}

// OnWindowShown marks the window as visible. Streaming resumes emitting events.
func (b *BindingService) OnWindowShown() {
	b.windowVisible.Store(true)
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

// PickFile opens a native file dialog and returns the selected file path.
// Returns empty string if the user cancels.
func (b *BindingService) PickFile(title string, filterName string, filterPattern string) (string, error) {
	app := application.Get()
	if app == nil {
		return "", fmt.Errorf("application not initialized")
	}
	dlg := app.Dialog.OpenFile().
		SetTitle(title).
		AddFilter(filterName, filterPattern).
		CanChooseFiles(true).
		CanChooseDirectories(false)
	return dlg.PromptForSingleSelection()
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
