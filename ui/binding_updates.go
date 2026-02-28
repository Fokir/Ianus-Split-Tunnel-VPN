//go:build windows || darwin

package main

import (
	"context"
	"errors"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"google.golang.org/protobuf/types/known/emptypb"
)

// ─── Updates ─────────────────────────────────────────────────────────

type UpdateInfoResult struct {
	Available    bool   `json:"available"`
	Version      string `json:"version"`
	ReleaseNotes string `json:"releaseNotes"`
	AssetSize    int64  `json:"assetSize"`
}

func (b *BindingService) CheckUpdate() (*UpdateInfoResult, error) {
	resp, err := b.client.Service.CheckUpdate(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	result := &UpdateInfoResult{
		Available: resp.Available,
	}
	if resp.Info != nil {
		result.Version = resp.Info.Version
		result.ReleaseNotes = resp.Info.ReleaseNotes
		result.AssetSize = resp.Info.AssetSize
	}
	return result, nil
}

func (b *BindingService) ApplyUpdate() error {
	resp, err := b.client.Service.ApplyUpdate(context.Background(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

// StartUpdateNotifier starts a background goroutine that checks for updates
// shortly after startup and then once per hour. The daemon's Checker.Start()
// also polls GitHub on its own interval and caches the result — this goroutine
// picks up the cached result via gRPC without generating extra API calls in
// most cases.
func (b *BindingService) StartUpdateNotifier() {
	go func() {
		app := application.Get()

		// Initial check after a short delay (daemon Checker needs ~30 s to warm up).
		select {
		case <-time.After(45 * time.Second):
		case <-b.ctx.Done():
			return
		}
		b.emitUpdateIfAvailable(app)

		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-b.ctx.Done():
				return
			case <-ticker.C:
				b.emitUpdateIfAvailable(app)
			}
		}
	}()
}

func (b *BindingService) emitUpdateIfAvailable(app *application.App) {
	result, err := b.CheckUpdate()
	if err != nil || !result.Available {
		return
	}
	b.notifMgr.NotifyUpdateAvailable(result.Version)
	app.Event.Emit("update-available", map[string]interface{}{
		"version":      result.Version,
		"releaseNotes": result.ReleaseNotes,
		"assetSize":    result.AssetSize,
	})
}
