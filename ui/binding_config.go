//go:build windows || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	vpnapi "awg-split-tunnel/api/gen"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ─── Config ─────────────────────────────────────────────────────────

func (b *BindingService) GetConfig() (*vpnapi.AppConfig, error) {
	return b.client.Service.GetConfig(context.Background(), &emptypb.Empty{})
}

func (b *BindingService) SaveConfig(config *vpnapi.AppConfig, restartIfConnected bool) (bool, error) {
	// Re-encode config through protojson to ensure proper protobuf message
	// initialization. Wails creates protobuf structs via encoding/json which
	// leaves internal MessageState uninitialized, causing proto.Marshal to
	// fail with "string field contains invalid UTF-8" during gRPC send.
	jsonBytes, err := json.Marshal(config)
	if err != nil {
		return false, fmt.Errorf("encode config: %w", err)
	}
	cleanConfig := &vpnapi.AppConfig{}
	opts := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := opts.Unmarshal(jsonBytes, cleanConfig); err != nil {
		return false, fmt.Errorf("decode config: %w", err)
	}

	resp, err := b.client.Service.SaveConfig(context.Background(), &vpnapi.SaveConfigRequest{
		Config:             cleanConfig,
		RestartIfConnected: restartIfConnected,
	})
	if err != nil {
		return false, err
	}
	if !resp.Success {
		return false, errors.New(resp.Error)
	}
	return resp.Restarted, nil
}

// ─── DNS ────────────────────────────────────────────────────────────

// FlushDNS clears all DNS caches (internal + domain table + Windows).
func (b *BindingService) FlushDNS() error {
	resp, err := b.client.Service.FlushDNS(context.Background(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

// ─── Autostart ──────────────────────────────────────────────────────

type AutostartInfo struct {
	Enabled            bool `json:"enabled"`
	RestoreConnections bool `json:"restoreConnections"`
}

func (b *BindingService) GetAutostart() (*AutostartInfo, error) {
	resp, err := b.client.Service.GetAutostart(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return &AutostartInfo{
		Enabled:            resp.Enabled,
		RestoreConnections: resp.RestoreConnections,
	}, nil
}

func (b *BindingService) SetAutostart(enabled bool, restoreConnections bool) error {
	// Clean up legacy HKCU\Run entries (from older versions).
	removeLegacyGUIRegistryEntries()

	guiPath, err := guiExePath()
	if err != nil {
		return fmt.Errorf("get GUI path: %w", err)
	}

	// Service handles both SCM start type and GUI scheduled task
	// (runs as SYSTEM — has permission for schtasks /RL HIGHEST).
	resp, err := b.client.Service.SetAutostart(context.Background(), &vpnapi.SetAutostartRequest{
		Config: &vpnapi.AutostartConfig{
			Enabled:            enabled,
			RestoreConnections: restoreConnections,
			GuiExePath:         guiPath,
		},
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

// guiExePath returns the path to the current GUI executable.
func guiExePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Clean(exe), nil
}

func (b *BindingService) RestoreConnections() error {
	resp, err := b.client.Service.RestoreConnections(context.Background(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

// ─── Notifications ──────────────────────────────────────────────────

// SetNotificationPreferences updates notification settings at runtime.
func (b *BindingService) SetNotificationPreferences(enabled, tunnelErrors, updates bool) {
	b.notifMgr.SetPreferences(enabled, tunnelErrors, updates)
}
