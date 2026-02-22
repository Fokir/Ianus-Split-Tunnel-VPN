//go:build windows

package service

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"

	"awg-split-tunnel/internal/winsvc"
)

const (
	// Legacy registry key path (for cleanup only).
	guiAutostartRegKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

	// Legacy schtasks name (for migration/removal).
	legacyTaskName = "AWGSplitTunnel"

	// Legacy registry entry name.
	legacyRegName = "AWGSplitTunnel"

	// Legacy GUI registry entry name.
	legacyGUIRegName = "AWGSplitTunnelGUI"
)

// isAutostartEnabled checks if autostart is enabled.
// Returns true if the service is set to Automatic start.
func isAutostartEnabled() (bool, error) {
	if winsvc.IsServiceInstalled() {
		return isServiceAutomatic()
	}

	// Fallback: check legacy schtasks (for pre-service installations).
	return isLegacyTaskEnabled()
}

// setAutostartEnabled enables or disables the service autostart via SCM.
// GUI autostart (Task Scheduler) is managed by the GUI process itself,
// since the service runs as SYSTEM and cannot access the user's HKCU or
// create per-user scheduled tasks.
//
// When enabled:  Service start type → Automatic (starts at boot)
// When disabled: Service start type → Manual
func setAutostartEnabled(enabled bool) error {
	// Remove legacy schtasks/registry entries regardless.
	removeLegacySchtask()
	removeLegacyRegistryAutostart()

	if winsvc.IsServiceInstalled() {
		var startType uint32 = mgr.StartManual
		if enabled {
			startType = mgr.StartAutomatic
		}
		if err := winsvc.SetStartType(startType); err != nil {
			return fmt.Errorf("set service start type: %w", err)
		}
	}

	return nil
}

// isServiceAutomatic checks if the service start type is Automatic.
func isServiceAutomatic() (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(winsvc.ServiceName)
	if err != nil {
		return false, fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return false, fmt.Errorf("query config: %w", err)
	}

	return cfg.StartType == mgr.StartAutomatic, nil
}

// removeLegacySchtask removes the old scheduled-task-based autostart.
func removeLegacySchtask() {
	_ = exec.Command("schtasks", "/Delete", "/TN", legacyTaskName, "/F").Run()
}

// removeLegacyRegistryAutostart removes old registry-based autostart entries.
func removeLegacyRegistryAutostart() {
	k, err := registry.OpenKey(registry.CURRENT_USER, guiAutostartRegKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue(legacyRegName)
	_ = k.DeleteValue(legacyGUIRegName)
}

// isLegacyTaskEnabled checks the old schtasks autostart (fallback).
func isLegacyTaskEnabled() (bool, error) {
	out, err := exec.Command("schtasks", "/Query", "/TN", legacyTaskName).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "ERROR") || strings.Contains(string(out), "не найдена") {
			return false, nil
		}
		return false, nil
	}
	return true, nil
}
