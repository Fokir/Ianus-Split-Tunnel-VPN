//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"awg-split-tunnel/internal/winsvc"
)

func main() {
	exeDir := exeDirectory()
	serviceExe := filepath.Join(exeDir, "awg-split-tunnel.exe")
	diagExe := filepath.Join(exeDir, "awg-diag.exe")
	configPath := filepath.Join(exeDir, "config.yaml")

	// Verify required binaries exist.
	for _, path := range []string{serviceExe, diagExe, configPath} {
		if _, err := os.Stat(path); err != nil {
			fmt.Fprintf(os.Stderr, "Error: required file not found: %s\n", path)
			os.Exit(1)
		}
	}

	wasInstalled := winsvc.IsServiceInstalled()
	installedByUs := false
	startedByUs := false

	// Cleanup on exit: stop and uninstall if we set them up.
	defer func() {
		if startedByUs {
			fmt.Println("[awg-test] Stopping service...")
			if err := winsvc.StopService(); err != nil {
				fmt.Fprintf(os.Stderr, "[awg-test] Warning: failed to stop service: %v\n", err)
			}
		}
		if installedByUs {
			fmt.Println("[awg-test] Uninstalling service...")
			if err := winsvc.UninstallService(); err != nil {
				fmt.Fprintf(os.Stderr, "[awg-test] Warning: failed to uninstall service: %v\n", err)
			}
		}
	}()

	// Install service if not already installed.
	if !wasInstalled {
		fmt.Println("[awg-test] Installing service...")
		if err := winsvc.InstallService(serviceExe, configPath); err != nil {
			fmt.Fprintf(os.Stderr, "[awg-test] Failed to install service: %v\n", err)
			os.Exit(1)
		}
		installedByUs = true
	}

	// Start service if not already running.
	if !winsvc.IsServiceRunning() {
		fmt.Println("[awg-test] Starting service...")
		if err := winsvc.StartService(); err != nil {
			fmt.Fprintf(os.Stderr, "[awg-test] Failed to start service: %v\n", err)
			os.Exit(1)
		}
		startedByUs = true

		// Wait for IPC pipe to become available.
		fmt.Println("[awg-test] Waiting for service IPC...")
		if err := waitForIPC(30 * time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "[awg-test] Service not responsive: %v\n", err)
			os.Exit(1)
		}
	}

	// Run: awg-diag.exe test <all forwarded args>
	fmt.Println("[awg-test] Running tests...")
	fmt.Println()

	args := append([]string{"test"}, os.Args[1:]...)
	cmd := exec.Command(diagExe, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "[awg-test] Failed to run diag: %v\n", err)
		os.Exit(1)
	}
}

// waitForIPC polls until the Named Pipe is accessible or timeout expires.
func waitForIPC(timeout time.Duration) error {
	pipePath := `\\.\pipe\awg-split-tunnel`
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if winsvc.IsServiceRunning() {
			f, err := os.Open(pipePath)
			if err == nil {
				f.Close()
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service IPC not ready within %s", timeout)
}

// exeDirectory returns the directory of the current executable.
func exeDirectory() string {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine executable path: %v\n", err)
		os.Exit(1)
	}
	return filepath.Dir(exe)
}
