//go:build darwin

package service

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	vpnapi "awg-split-tunnel/api/gen"
)

// ─── Platform stubs for macOS ────────────────────────────────────────
// These methods have platform-specific implementations on Windows.
// On macOS they return reasonable defaults or "not supported" errors.

func (s *Service) ListProcesses(_ context.Context, _ *vpnapi.ProcessListRequest) (*vpnapi.ProcessListResponse, error) {
	// TODO: Implement macOS process listing via proc_pidinfo.
	return &vpnapi.ProcessListResponse{}, nil
}

func (s *Service) GetAutostart(_ context.Context, _ *emptypb.Empty) (*vpnapi.AutostartConfig, error) {
	// TODO: Implement macOS autostart via LaunchAgent.
	return &vpnapi.AutostartConfig{
		Enabled:            false,
		RestoreConnections: s.cfg.Get().GUI.RestoreConnections,
	}, nil
}

func (s *Service) SetAutostart(_ context.Context, _ *vpnapi.SetAutostartRequest) (*vpnapi.SetAutostartResponse, error) {
	// TODO: Implement macOS autostart via LaunchAgent.
	return &vpnapi.SetAutostartResponse{Success: false, Error: "autostart not yet supported on macOS"}, nil
}

func (s *Service) ApplyUpdate(_ context.Context, _ *emptypb.Empty) (*vpnapi.ApplyUpdateResponse, error) {
	// TODO: Implement macOS update mechanism.
	return &vpnapi.ApplyUpdateResponse{Success: false, Error: "in-place update not yet supported on macOS"}, nil
}

func (s *Service) CheckConflictingServices(_ context.Context, _ *emptypb.Empty) (*vpnapi.ConflictingServicesResponse, error) {
	// No conflicting service detection on macOS.
	return &vpnapi.ConflictingServicesResponse{}, nil
}

func (s *Service) StopConflictingServices(_ context.Context, _ *vpnapi.StopConflictingServicesRequest) (*vpnapi.StopConflictingServicesResponse, error) {
	return &vpnapi.StopConflictingServicesResponse{Success: true}, nil
}
