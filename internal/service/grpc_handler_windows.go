//go:build windows

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/gateway"
	"awg-split-tunnel/internal/update"
)

// ─── Processes ──────────────────────────────────────────────────────

func (s *Service) ListProcesses(_ context.Context, req *vpnapi.ProcessListRequest) (*vpnapi.ProcessListResponse, error) {
	procs, err := listRunningProcesses(req.NameFilter)
	if err != nil {
		return nil, err
	}
	return &vpnapi.ProcessListResponse{Processes: procs}, nil
}

// ─── Autostart ──────────────────────────────────────────────────────

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

// ─── Updates (Windows-specific) ─────────────────────────────────────

func (s *Service) ApplyUpdate(ctx context.Context, _ *emptypb.Empty) (*vpnapi.ApplyUpdateResponse, error) {
	if s.updateChecker == nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: "update checker not initialized"}, nil
	}

	info := s.updateChecker.GetLatestInfo()
	if info == nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: "no update available"}, nil
	}

	// Download the update.
	extractDir, err := update.Download(ctx, info, s.httpClient, nil)
	if err != nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: fmt.Sprintf("download failed: %v", err)}, nil
	}
	// Clean up temp dir on any error path. On success the updater process
	// is responsible for cleanup (it receives --temp-dir).
	cleanupExtract := true
	defer func() {
		if cleanupExtract {
			os.RemoveAll(filepath.Dir(extractDir))
		}
	}()

	// Find updater binary in the current install directory.
	exe, err := os.Executable()
	if err != nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: fmt.Sprintf("cannot determine install dir: %v", err)}, nil
	}
	installDir := filepath.Dir(exe)
	updaterPath := filepath.Join(installDir, "awg-split-tunnel-updater.exe")

	if _, err := os.Stat(updaterPath); err != nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: "updater binary not found"}, nil
	}

	// Launch updater as a fully detached process.
	core.Log.Infof("Update", "Launching updater: %s", updaterPath)
	cmd := exec.Command(updaterPath,
		"--install-dir", installDir,
		"--temp-dir", extractDir,
		"--start-service",
		"--launch-gui",
	)
	cmd.Dir = installDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // DETACHED_PROCESS
	}
	if err := cmd.Start(); err != nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: fmt.Sprintf("failed to launch updater: %v", err)}, nil
	}

	cleanupExtract = false // updater owns the temp dir now
	return &vpnapi.ApplyUpdateResponse{Success: true}, nil
}

// ─── Conflicting services ──────────────────────────────────────────

func (s *Service) CheckConflictingServices(_ context.Context, _ *emptypb.Empty) (*vpnapi.ConflictingServicesResponse, error) {
	detected := CheckConflictingServices()

	var services []*vpnapi.ConflictingService
	for _, d := range detected {
		services = append(services, &vpnapi.ConflictingService{
			Name:        d.Name,
			DisplayName: d.DisplayName,
			Type:        d.Type,
			Running:     d.Running,
			Description: d.Description,
		})
	}

	return &vpnapi.ConflictingServicesResponse{Services: services}, nil
}

func (s *Service) StopConflictingServices(_ context.Context, req *vpnapi.StopConflictingServicesRequest) (*vpnapi.StopConflictingServicesResponse, error) {
	var stopped, failed []string

	var processes, services []string
	for _, name := range req.Names {
		isService := false
		for _, s := range knownConflictingServices {
			if strings.EqualFold(s.Name, name) {
				isService = true
				break
			}
		}
		if isService {
			services = append(services, name)
		} else {
			processes = append(processes, name)
		}
	}

	// Phase 1: kill user-space processes (releases WinDivert handles).
	for _, name := range processes {
		if err := StopConflictingService(name); err != nil {
			core.Log.Warnf("Core", "Failed to stop conflicting process %q: %v", name, err)
			failed = append(failed, name)
		} else {
			stopped = append(stopped, name)
		}
	}

	// Phase 2: stop and delete driver services.
	if len(processes) > 0 && len(services) > 0 {
		time.Sleep(1 * time.Second)
	}
	for _, name := range services {
		if err := StopConflictingService(name); err != nil {
			core.Log.Warnf("Core", "Failed to stop conflicting service %q: %v", name, err)
			failed = append(failed, name)
		} else {
			stopped = append(stopped, name)
		}
	}

	// Phase 3: clean up orphaned WFP filters.
	if err := gateway.CleanupConflictingWFP(); err != nil {
		core.Log.Warnf("Core", "Conflicting WFP cleanup: %v", err)
	}

	resp := &vpnapi.StopConflictingServicesResponse{
		Success: len(failed) == 0,
		Stopped: stopped,
		Failed:  failed,
	}
	if len(failed) > 0 {
		resp.Error = fmt.Sprintf("failed to stop: %v", failed)
	}
	return resp, nil
}
