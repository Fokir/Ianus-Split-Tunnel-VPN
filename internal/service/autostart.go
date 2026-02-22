//go:build windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"

	"awg-split-tunnel/internal/winsvc"
)

const (
	// GUI autostart registry.
	guiAutostartRegKey  = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	guiAutostartRegName = "AWGSplitTunnelGUI"
	guiBinaryName       = "awg-split-tunnel-ui.exe"

	// Legacy schtasks name (for migration/removal).
	legacyTaskName = "AWGSplitTunnel"

	// Legacy registry entry name.
	legacyRegName = "AWGSplitTunnel"
)

// isAutostartEnabled checks if autostart is enabled.
// Autostart means: service start type is Automatic AND GUI registry Run entry exists.
// Returns true if at least the service is set to Automatic.
func isAutostartEnabled() (bool, error) {
	if winsvc.IsServiceInstalled() {
		return isServiceAutomatic()
	}

	// Fallback: check legacy schtasks (for pre-service installations).
	return isLegacyTaskEnabled()
}

// setAutostartEnabled enables or disables autostart for both service and GUI.
// When enabled:
//   - Service start type → Automatic (starts at boot, before user login)
//   - GUI → HKCU\...\Run registry entry (starts at user login, --minimized)
//
// When disabled:
//   - Service start type → Manual
//   - GUI registry entry removed
func setAutostartEnabled(enabled bool) error {
	// Remove legacy schtasks entry regardless.
	removeLegacySchtask()
	removeLegacyRegistryAutostart()

	if winsvc.IsServiceInstalled() {
		// Set service start type.
		var startType uint32 = mgr.StartManual
		if enabled {
			startType = mgr.StartAutomatic
		}
		if err := winsvc.SetStartType(startType); err != nil {
			return fmt.Errorf("set service start type: %w", err)
		}
	}

	// Set GUI autostart via registry.
	if enabled {
		return setGUIAutostart(true)
	}
	return setGUIAutostart(false)
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

// setGUIAutostart adds or removes the GUI from HKCU\...\Run.
func setGUIAutostart(enabled bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, guiAutostartRegKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	if enabled {
		guiPath, err := guiExePath()
		if err != nil {
			return fmt.Errorf("get GUI executable path: %w", err)
		}
		value := fmt.Sprintf(`"%s" --minimized`, guiPath)
		if err := k.SetStringValue(guiAutostartRegName, value); err != nil {
			return fmt.Errorf("set registry value: %w", err)
		}
		return nil
	}

	// Remove the entry.
	err = k.DeleteValue(guiAutostartRegName)
	if err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("delete registry value: %w", err)
	}
	return nil
}

// guiExePath returns the path to the GUI binary, expected next to the service binary.
func guiExePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), guiBinaryName), nil
}

// removeLegacySchtask removes the old scheduled-task-based autostart.
func removeLegacySchtask() {
	_ = exec.Command("schtasks", "/Delete", "/TN", legacyTaskName, "/F").Run()
}

// removeLegacyRegistryAutostart removes the old registry-based autostart entry.
func removeLegacyRegistryAutostart() {
	k, err := registry.OpenKey(registry.CURRENT_USER, guiAutostartRegKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue(legacyRegName)
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
