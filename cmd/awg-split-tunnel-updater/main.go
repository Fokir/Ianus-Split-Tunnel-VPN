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
	"unsafe"

	"golang.org/x/sys/windows"

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

	// Show progress window (non-closable, topmost).
	pw := NewProgressWindow()
	pw.Show()
	defer pw.Close()

	// Step 1: Wait for service and GUI to exit.
	pw.SetStatus("Stopping service...")
	pw.SetProgress(5)
	logger.Printf("Waiting for service and GUI to exit...")
	if err := waitForProcessExit(*installDir, 30*time.Second); err != nil {
		logger.Printf("Warning: %v (proceeding anyway)", err)
	}
	pw.SetProgress(20)

	// Step 2: Backup current files.
	pw.SetStatus("Creating backup...")
	pw.SetProgress(25)
	logger.Printf("Backing up current files...")
	backedUp, err := backupFiles(*installDir)
	if err != nil {
		logger.Printf("Error backing up files: %v", err)
		pw.SetStatus("Error: backup failed")
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}
	logger.Printf("Backed up %d files", len(backedUp))
	pw.SetProgress(35)

	// Step 3: Copy new files from temp dir.
	pw.SetStatus("Installing new files...")
	pw.SetProgress(40)
	logger.Printf("Installing new files...")
	if err := copyNewFiles(*tempDir, *installDir); err != nil {
		logger.Printf("Error copying new files: %v — rolling back", err)
		pw.SetStatus("Error: install failed, rolling back...")
		rollback(*installDir, backedUp, logger)
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}
	pw.SetProgress(55)

	// Step 4: Start service.
	if *startService {
		pw.SetStatus("Starting service...")
		pw.SetProgress(60)
		logger.Printf("Starting Windows Service...")
		if err := winsvc.StartService(); err != nil {
			logger.Printf("Error starting service: %v — rolling back", err)
			pw.SetStatus("Error: service start failed, rolling back...")
			rollback(*installDir, backedUp, logger)

			// Try to start old service after rollback.
			logger.Printf("Attempting to start old service...")
			if err := winsvc.StartService(); err != nil {
				logger.Printf("Failed to start old service: %v", err)
			}
			time.Sleep(3 * time.Second)
			os.Exit(1)
		}
		pw.SetProgress(75)

		// Step 5: Verify service is responsive.
		pw.SetStatus("Verifying service...")
		pw.SetProgress(80)
		logger.Printf("Verifying service...")
		if err := verifyService(10 * time.Second); err != nil {
			logger.Printf("Service verification failed: %v — rolling back", err)
			pw.SetStatus("Error: service verification failed, rolling back...")
			_ = winsvc.StopService()
			rollback(*installDir, backedUp, logger)

			logger.Printf("Attempting to start old service...")
			if err := winsvc.StartService(); err != nil {
				logger.Printf("Failed to start old service: %v", err)
			}
			time.Sleep(3 * time.Second)
			os.Exit(1)
		}
		logger.Printf("Service is running and responsive")
		pw.SetProgress(90)
	}

	// Step 6: Launch GUI in user session.
	if *launchGUI {
		pw.SetStatus("Starting application...")
		pw.SetProgress(95)
		guiPath := filepath.Join(*installDir, "awg-split-tunnel-ui.exe")
		if _, err := os.Stat(guiPath); err == nil {
			logger.Printf("Launching GUI: %s", guiPath)
			if err := launchGUIProcess(guiPath); err != nil {
				logger.Printf("Warning: failed to launch GUI: %v", err)
			}
		}
	}

	// Step 7: Cleanup backups and temp dir.
	pw.SetStatus("Cleaning up...")
	pw.SetProgress(100)
	logger.Printf("Cleaning up...")
	cleanupBackups(*installDir, backedUp)
	os.RemoveAll(*tempDir)

	logger.Printf("Update completed successfully!")
	pw.SetStatus("Update completed!")
	time.Sleep(1 * time.Second)
}

// waitForProcessExit waits until service and GUI processes stop.
func waitForProcessExit(installDir string, timeout time.Duration) error {
	// Stop the service gracefully via SCM if running.
	if winsvc.IsServiceRunning() {
		if err := winsvc.StopService(); err != nil {
			return fmt.Errorf("stop service: %w", err)
		}
	}

	// Wait for the service process to actually terminate (not just SCM status).
	// StopService returns when SCM reports Stopped, but the process may still
	// be running its shutdown sequence (up to 10s timeout).
	svcDeadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(svcDeadline) {
		if !isProcessRunning("awg-split-tunnel.exe") {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if isProcessRunning("awg-split-tunnel.exe") {
		// Force kill the service process if it's still hanging.
		_ = exec.Command("taskkill", "/F", "/IM", "awg-split-tunnel.exe").Run()
		time.Sleep(1 * time.Second)
	}

	// Give the GUI a few seconds to notice the service is gone and exit on its own.
	gracePeriod := 5 * time.Second
	if gracePeriod > timeout {
		gracePeriod = timeout
	}
	deadline := time.Now().Add(gracePeriod)
	for time.Now().Before(deadline) {
		if !isProcessRunning("awg-split-tunnel-ui.exe") {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	// GUI didn't exit gracefully — force kill it.
	_ = exec.Command("taskkill", "/F", "/IM", "awg-split-tunnel-ui.exe").Run()

	// Wait for the process to actually terminate.
	deadline = time.Now().Add(timeout - gracePeriod)
	for time.Now().Before(deadline) {
		if !isProcessRunning("awg-split-tunnel-ui.exe") {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for GUI to exit after taskkill")
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

var (
	modkernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	procWTSGetActiveConsoleSessionId = modkernel32.NewProc("WTSGetActiveConsoleSessionId")
)

func wtsGetActiveConsoleSessionId() uint32 {
	r, _, _ := procWTSGetActiveConsoleSessionId.Call()
	return uint32(r)
}

// launchGUIProcess starts the GUI executable in the active user's desktop session.
// The updater runs as LocalSystem, so we use CreateProcessAsUser to launch in the user's session.
func launchGUIProcess(guiPath string) error {
	// Find the active console session.
	sessionId := wtsGetActiveConsoleSessionId()
	if sessionId == 0xFFFFFFFF {
		return fmt.Errorf("no active console session")
	}

	// Get the user token for that session.
	var userToken windows.Token
	if err := windows.WTSQueryUserToken(sessionId, &userToken); err != nil {
		return fmt.Errorf("WTSQueryUserToken(session=%d): %w", sessionId, err)
	}
	defer userToken.Close()

	// Create environment block for the user.
	var envBlock *uint16
	if err := windows.CreateEnvironmentBlock(&envBlock, userToken, false); err != nil {
		return fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(envBlock)

	// Prepare command line and startup info.
	exe, _ := windows.UTF16PtrFromString(guiPath)
	cmdLine, _ := windows.UTF16PtrFromString(fmt.Sprintf(`"%s" --minimized`, guiPath))
	workDir, _ := windows.UTF16PtrFromString(filepath.Dir(guiPath))
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)

	si := &windows.StartupInfo{
		Cb:      uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop: desktop,
	}
	pi := &windows.ProcessInformation{}

	// Launch the process in the user's session.
	if err := windows.CreateProcessAsUser(
		userToken,
		exe,
		cmdLine,
		nil, nil,
		false,
		windows.CREATE_DEFAULT_ERROR_MODE|windows.CREATE_UNICODE_ENVIRONMENT,
		envBlock,
		workDir,
		si,
		pi,
	); err != nil {
		return fmt.Errorf("CreateProcessAsUser: %w", err)
	}

	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
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
