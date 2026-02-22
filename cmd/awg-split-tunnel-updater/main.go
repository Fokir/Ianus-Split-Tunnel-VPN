//go:build windows

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"awg-split-tunnel/internal/winsvc"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// Files that should be updated (relative to install dir).
var updatableFiles = []string{
	"awg-split-tunnel.exe",
	"awg-split-tunnel-ui.exe",
	"awg-split-tunnel-updater.exe",
	"wintun.dll",
}

func main() {
	installDir := flag.String("install-dir", "", "Installation directory")
	tempDir := flag.String("temp-dir", "", "Directory with extracted update files")
	startService := flag.Bool("start-service", false, "Start Windows Service after update")
	launchGUI := flag.Bool("launch-gui", false, "Launch GUI after update")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("awg-split-tunnel-updater %s (commit=%s, built=%s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	if *installDir == "" || *tempDir == "" {
		fmt.Fprintln(os.Stderr, "Error: --install-dir and --temp-dir are required")
		os.Exit(1)
	}

	// Setup logging to file.
	logFile := filepath.Join(*installDir, "update.log")
	logger := newFileLogger(logFile)
	defer logger.Close()

	logger.Printf("AWG Split Tunnel Updater %s starting", version)
	logger.Printf("Install dir: %s", *installDir)
	logger.Printf("Temp dir: %s", *tempDir)

	// Step 1: Wait for service and GUI to exit.
	logger.Printf("Waiting for service and GUI to exit...")
	if err := waitForProcessExit(*installDir, 30*time.Second); err != nil {
		logger.Printf("Warning: %v (proceeding anyway)", err)
	}

	// Step 2: Backup current files.
	logger.Printf("Backing up current files...")
	backedUp, err := backupFiles(*installDir)
	if err != nil {
		logger.Printf("Error backing up files: %v", err)
		os.Exit(1)
	}
	logger.Printf("Backed up %d files", len(backedUp))

	// Step 3: Copy new files from temp dir.
	logger.Printf("Installing new files...")
	if err := copyNewFiles(*tempDir, *installDir); err != nil {
		logger.Printf("Error copying new files: %v — rolling back", err)
		rollback(*installDir, backedUp, logger)
		os.Exit(1)
	}

	// Step 4: Start service.
	if *startService {
		logger.Printf("Starting Windows Service...")
		if err := winsvc.StartService(); err != nil {
			logger.Printf("Error starting service: %v — rolling back", err)
			rollback(*installDir, backedUp, logger)

			// Try to start old service after rollback.
			logger.Printf("Attempting to start old service...")
			if err := winsvc.StartService(); err != nil {
				logger.Printf("Failed to start old service: %v", err)
			}
			os.Exit(1)
		}

		// Step 5: Verify service is responsive.
		logger.Printf("Verifying service...")
		if err := verifyService(10 * time.Second); err != nil {
			logger.Printf("Service verification failed: %v — rolling back", err)
			_ = winsvc.StopService()
			rollback(*installDir, backedUp, logger)

			logger.Printf("Attempting to start old service...")
			if err := winsvc.StartService(); err != nil {
				logger.Printf("Failed to start old service: %v", err)
			}
			os.Exit(1)
		}
		logger.Printf("Service is running and responsive")
	}

	// Step 6: Launch GUI in user session.
	if *launchGUI {
		guiPath := filepath.Join(*installDir, "awg-split-tunnel-ui.exe")
		if _, err := os.Stat(guiPath); err == nil {
			logger.Printf("Launching GUI: %s", guiPath)
			if err := launchGUIProcess(guiPath); err != nil {
				logger.Printf("Warning: failed to launch GUI: %v", err)
			}
		}
	}

	// Step 7: Cleanup backups and temp dir.
	logger.Printf("Cleaning up...")
	cleanupBackups(*installDir, backedUp)
	os.RemoveAll(*tempDir)

	logger.Printf("Update completed successfully!")
}

// waitForProcessExit waits until service and GUI processes stop.
func waitForProcessExit(installDir string, timeout time.Duration) error {
	// Stop the service gracefully via SCM if running.
	if winsvc.IsServiceRunning() {
		if err := winsvc.StopService(); err != nil {
			return fmt.Errorf("stop service: %w", err)
		}
	}

	// Wait for the GUI process to exit.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !isProcessRunning("awg-split-tunnel-ui.exe") {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for processes to exit")
}

// isProcessRunning checks if a process with the given name is running.
func isProcessRunning(name string) bool {
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", name), "/NH").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), strings.ToLower(name))
}

// backupFiles renames existing files to *.old and returns the list of backed-up files.
func backupFiles(installDir string) ([]string, error) {
	var backedUp []string
	for _, name := range updatableFiles {
		src := filepath.Join(installDir, name)
		if _, err := os.Stat(src); err != nil {
			continue // file doesn't exist, skip
		}
		dst := src + ".old"
		// Remove any previous .old file.
		os.Remove(dst)
		if err := os.Rename(src, dst); err != nil {
			return backedUp, fmt.Errorf("rename %s → %s.old: %w", name, name, err)
		}
		backedUp = append(backedUp, name)
	}
	return backedUp, nil
}

// copyNewFiles copies files from tempDir into installDir.
func copyNewFiles(tempDir, installDir string) error {
	// Walk the temp directory and copy all files.
	return filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(tempDir, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(installDir, relPath)
		destDir := filepath.Dir(destPath)
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return fmt.Errorf("create dir %s: %w", destDir, err)
		}

		return copyFile(path, destPath)
	})
}

// copyFile copies a single file.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// rollback restores backed-up files.
func rollback(installDir string, backedUp []string, logger *fileLogger) {
	logger.Printf("Rolling back %d files...", len(backedUp))
	for _, name := range backedUp {
		src := filepath.Join(installDir, name+".old")
		dst := filepath.Join(installDir, name)
		// Remove the new file if it was copied.
		os.Remove(dst)
		if err := os.Rename(src, dst); err != nil {
			logger.Printf("Rollback failed for %s: %v", name, err)
		}
	}
}

// verifyService checks that the service is running and the Named Pipe is accessible.
func verifyService(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if winsvc.IsServiceRunning() {
			// Try to open the Named Pipe to verify IPC is ready.
			pipePath := `\\.\pipe\awg-split-tunnel`
			f, err := os.Open(pipePath)
			if err == nil {
				f.Close()
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service not responsive within %s", timeout)
}

// launchGUIProcess starts the GUI executable.
// When running as LocalSystem, this creates a scheduled task to run in the user's session.
func launchGUIProcess(guiPath string) error {
	// Use a run-once scheduled task to launch GUI in the active user session.
	taskName := "AWGSplitTunnelGUILaunch"

	// Delete any existing task first.
	_ = exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").Run()

	// Create a run-once task that runs immediately in the interactive session.
	cmd := exec.Command("schtasks", "/Create",
		"/TN", taskName,
		"/TR", fmt.Sprintf(`"%s" --minimized`, guiPath),
		"/SC", "ONCE",
		"/ST", "00:00",
		"/RL", "LIMITED",
		"/IT",
		"/F",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create task: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Run the task immediately.
	cmd = exec.Command("schtasks", "/Run", "/TN", taskName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("run task: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Clean up the task after a delay.
	go func() {
		time.Sleep(5 * time.Second)
		_ = exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").Run()
	}()

	return nil
}

// cleanupBackups removes *.old backup files.
func cleanupBackups(installDir string, backedUp []string) {
	for _, name := range backedUp {
		os.Remove(filepath.Join(installDir, name+".old"))
	}
}

// fileLogger writes log messages to a file and stdout.
type fileLogger struct {
	f *os.File
}

func newFileLogger(path string) *fileLogger {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return &fileLogger{}
	}
	return &fileLogger{f: f}
}

func (l *fileLogger) Printf(format string, args ...any) {
	msg := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	fmt.Print(msg)
	if l.f != nil {
		l.f.WriteString(msg)
	}
}

func (l *fileLogger) Close() {
	if l.f != nil {
		l.f.Close()
	}
}
