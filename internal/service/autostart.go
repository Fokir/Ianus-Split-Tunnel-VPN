//go:build windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	autostartTaskName = "AWGSplitTunnel"

	// Legacy registry key (for migration).
	autostartRegKey  = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	autostartRegName = "AWGSplitTunnel"
)

// isAutostartEnabled checks if the scheduled task exists.
func isAutostartEnabled() (bool, error) {
	out, err := exec.Command("schtasks", "/Query", "/TN", autostartTaskName).CombinedOutput()
	if err != nil {
		// Task not found — not an error, just not enabled.
		if strings.Contains(string(out), "ERROR") || strings.Contains(string(out), "не найдена") {
			return false, nil
		}
		return false, nil
	}
	return true, nil
}

// setAutostartEnabled creates or deletes a scheduled task for autostart with elevated privileges.
func setAutostartEnabled(enabled bool) error {
	if enabled {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("get executable path: %w", err)
		}

		// Delete existing task first (idempotent).
		_ = exec.Command("schtasks", "/Delete", "/TN", autostartTaskName, "/F").Run()

		// Create scheduled task with HIGHEST run level (admin privileges).
		cmd := exec.Command("schtasks", "/Create",
			"/TN", autostartTaskName,
			"/TR", fmt.Sprintf(`"%s" --minimized`, exe),
			"/SC", "ONLOGON",
			"/RL", "HIGHEST",
			"/F",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("create scheduled task: %s: %w", strings.TrimSpace(string(out)), err)
		}

		// Migrate: remove legacy registry entry if present.
		removeLegacyRegistryAutostart()

		return nil
	}

	// Delete the scheduled task.
	out, err := exec.Command("schtasks", "/Delete", "/TN", autostartTaskName, "/F").CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		// Not found is OK — task was already removed.
		if strings.Contains(outStr, "ERROR") && strings.Contains(outStr, "не найдена") {
			return nil
		}
		if strings.Contains(outStr, "does not exist") {
			return nil
		}
		return fmt.Errorf("delete scheduled task: %s: %w", outStr, err)
	}
	return nil
}

// removeLegacyRegistryAutostart removes the old registry-based autostart entry.
func removeLegacyRegistryAutostart() {
	k, err := registry.OpenKey(registry.CURRENT_USER, autostartRegKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue(autostartRegName)
}
