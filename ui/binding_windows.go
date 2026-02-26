//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// removeLegacyGUIRegistryEntries cleans up old HKCU\Run entries from previous versions.
func removeLegacyGUIRegistryEntries() {
	// Best-effort removal using reg.exe (avoid importing x/sys/windows/registry in GUI).
	for _, name := range []string{"AWGSplitTunnelGUI", "AWGSplitTunnel"} {
		cmd := exec.Command("reg", "delete",
			`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			"/v", name, "/f")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = cmd.Run()
	}
}
