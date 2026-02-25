//go:build windows

package service

import (
	"fmt"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
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

// setAutostartEnabled enables or disables the service autostart via SCM
// and manages the GUI scheduled task.
//
// When enabled:  Service start type → Automatic, GUI task created
// When disabled: Service start type → Manual, GUI task removed
func setAutostartEnabled(enabled bool, guiExePath string) error {
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

	// Manage GUI scheduled task (runs as SYSTEM — has permission).
	if guiExePath != "" {
		if err := setGUIAutostart(enabled, guiExePath); err != nil {
			return fmt.Errorf("set GUI autostart: %w", err)
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

const guiTaskName = "AWGSplitTunnelGUI"

var (
	modWtsapi32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = modWtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = modWtsapi32.NewProc("WTSFreeMemory")
)

const (
	wtsUserName   = 5
	wtsDomainName = 7
)

// getConsoleUsername returns "DOMAIN\User" for the active console session.
// Works from SYSTEM context (service) via WTS API.
func getConsoleUsername() (string, error) {
	sessionID := windows.WTSGetActiveConsoleSessionId()

	queryString := func(infoClass uint32) (string, error) {
		var buf *uint16
		var bufSize uint32
		ret, _, err := procWTSQuerySessionInformationW.Call(
			0, // WTS_CURRENT_SERVER_HANDLE
			uintptr(sessionID),
			uintptr(infoClass),
			uintptr(unsafe.Pointer(&buf)),
			uintptr(unsafe.Pointer(&bufSize)),
		)
		if ret == 0 {
			return "", fmt.Errorf("WTSQuerySessionInformation(%d): %w", infoClass, err)
		}
		defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
		return windows.UTF16PtrToString(buf), nil
	}

	user, err := queryString(wtsUserName)
	if err != nil {
		return "", err
	}
	if user == "" {
		return "", fmt.Errorf("no user logged in on console session %d", sessionID)
	}

	domain, _ := queryString(wtsDomainName)
	if domain != "" {
		return domain + `\` + user, nil
	}
	return user, nil
}

// setGUIAutostart creates or removes a scheduled task for GUI autostart.
// Runs from the service (SYSTEM) which has permission to manage tasks.
func setGUIAutostart(enabled bool, guiExePath string) error {
	if enabled {
		username, err := getConsoleUsername()
		if err != nil {
			return fmt.Errorf("get console user: %w", err)
		}

		out, err := exec.Command("schtasks", "/Create",
			"/TN", guiTaskName,
			"/TR", fmt.Sprintf(`"%s" --minimized`, guiExePath),
			"/SC", "ONLOGON",
			"/RU", username,
			"/RL", "HIGHEST",
			"/F",
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("schtasks create: %s: %w", strings.TrimSpace(string(out)), err)
		}
		return nil
	}

	// Remove the task (ignore errors if it doesn't exist).
	_ = exec.Command("schtasks", "/Delete", "/TN", guiTaskName, "/F").Run()
	return nil
}

// isGUIAutostartEnabled checks if the GUI scheduled task exists.
func isGUIAutostartEnabled() bool {
	err := exec.Command("schtasks", "/Query", "/TN", guiTaskName).Run()
	return err == nil
}
