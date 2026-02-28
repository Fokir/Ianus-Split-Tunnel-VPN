//go:build darwin

package service

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/protobuf/types/known/emptypb"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/update"
)

// ─── Platform-specific gRPC handlers for macOS ──────────────────────

func (s *Service) ListProcesses(_ context.Context, req *vpnapi.ProcessListRequest) (*vpnapi.ProcessListResponse, error) {
	procs, err := listRunningProcesses(req.NameFilter)
	if err != nil {
		log.Printf("[Service] ListProcesses error: %v", err)
		return nil, err
	}
	log.Printf("[Service] ListProcesses: filter=%q, found %d processes", req.NameFilter, len(procs))
	return &vpnapi.ProcessListResponse{Processes: procs}, nil
}

func (s *Service) GetAutostart(_ context.Context, _ *emptypb.Empty) (*vpnapi.AutostartConfig, error) {
	enabled, _ := isAutostartEnabled()
	return &vpnapi.AutostartConfig{
		Enabled:            enabled,
		RestoreConnections: s.cfg.Get().GUI.RestoreConnections,
	}, nil
}

func (s *Service) SetAutostart(_ context.Context, req *vpnapi.SetAutostartRequest) (*vpnapi.SetAutostartResponse, error) {
	if err := setAutostartEnabled(req.Config.Enabled, req.Config.GuiExePath); err != nil {
		return &vpnapi.SetAutostartResponse{Success: false, Error: err.Error()}, nil
	}

	// Persist restore_connections in config.
	cfg := s.cfg.Get()
	cfg.GUI.RestoreConnections = req.Config.RestoreConnections
	s.cfg.SetFromGUI(cfg)
	if err := s.cfg.Save(); err != nil {
		return &vpnapi.SetAutostartResponse{Success: false, Error: err.Error()}, nil
	}

	return &vpnapi.SetAutostartResponse{Success: true}, nil
}

func (s *Service) ApplyUpdate(ctx context.Context, _ *emptypb.Empty) (*vpnapi.ApplyUpdateResponse, error) {
	if s.updateChecker == nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: "update checker not initialized"}, nil
	}

	info := s.updateChecker.GetLatestInfo()
	if info == nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: "no update available"}, nil
	}

	// Download the tarball.
	extractDir, err := update.DownloadDarwin(ctx, info, s.httpClient, nil)
	if err != nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: fmt.Sprintf("download failed: %v", err)}, nil
	}

	// Apply: replace binary only (no launchctl kickstart).
	// The daemon will exit after this, and launchd will start the new binary
	// on next GUI connect (socket activation) or via KeepAlive (legacy mode).
	if err := update.ApplyDarwinUpdateBinaryOnly(extractDir); err != nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: fmt.Sprintf("apply failed: %v", err)}, nil
	}

	// Signal daemon shutdown so the new binary takes effect.
	go s.bus.Publish(core.Event{Type: core.EventConfigReloaded, Payload: "shutdown"})

	return &vpnapi.ApplyUpdateResponse{Success: true}, nil
}

func (s *Service) CheckConflictingServices(_ context.Context, _ *emptypb.Empty) (*vpnapi.ConflictingServicesResponse, error) {
	// No conflicting service detection on macOS.
	return &vpnapi.ConflictingServicesResponse{}, nil
}

func (s *Service) StopConflictingServices(_ context.Context, _ *vpnapi.StopConflictingServicesRequest) (*vpnapi.StopConflictingServicesResponse, error) {
	return &vpnapi.StopConflictingServicesResponse{Success: true}, nil
}
