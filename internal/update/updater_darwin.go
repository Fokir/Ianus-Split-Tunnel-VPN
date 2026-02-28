//go:build darwin

package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"awg-split-tunnel/internal/core"
)

const (
	darwinDaemonLabel  = "com.awg.split-tunnel"
	darwinDaemonBinary = "/usr/local/bin/awg-split-tunnel"
	darwinGUIAppDir    = "/Applications/AWG Split Tunnel.app"
)

// DownloadDarwin fetches the update tarball, extracts it into a temp directory,
// and returns the path to the extracted files.
func DownloadDarwin(ctx context.Context, info *Info, httpClient *http.Client, progressFn ProgressFunc) (string, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Minute}
	}

	tempDir, err := os.MkdirTemp("", "awg-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}

	tarPath := filepath.Join(tempDir, "update.tar.gz")

	core.Log.Infof("Update", "Downloading %s (%d bytes)...", info.Version, info.AssetSize)
	if err := downloadFile(ctx, httpClient, info.AssetURL, tarPath, info.AssetSize, progressFn); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("download: %w", err)
	}

	extractDir := filepath.Join(tempDir, "files")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("create extract dir: %w", err)
	}

	core.Log.Infof("Update", "Extracting update...")
	if err := extractTarGz(tarPath, extractDir); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("extract: %w", err)
	}

	os.Remove(tarPath)

	core.Log.Infof("Update", "Update downloaded and extracted to %s", extractDir)
	return extractDir, nil
}

// ApplyDarwinUpdate replaces the daemon binary and the GUI app bundle,
// then restarts the daemon via launchctl.
func ApplyDarwinUpdate(extractDir string) error {
	if err := replaceDaemonBinary(extractDir); err != nil {
		return err
	}
	replaceGUIApp(extractDir)

	// Restart daemon via launchctl.
	core.Log.Infof("Update", "Binaries replaced, restarting daemon...")
	out, err := exec.Command("launchctl", "kickstart", "-k", "system/"+darwinDaemonLabel).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl kickstart: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return nil
}

// ApplyDarwinUpdateBinaryOnly replaces the daemon binary and the GUI app
// bundle without restarting. Used with socket activation: the daemon exits
// on its own after binary replacement, and launchd will start the new binary
// on next GUI connect.
func ApplyDarwinUpdateBinaryOnly(extractDir string) error {
	if err := replaceDaemonBinary(extractDir); err != nil {
		return err
	}
	replaceGUIApp(extractDir)

	core.Log.Infof("Update", "Binaries replaced (no restart — daemon will exit for socket activation)")
	return nil
}

// replaceDaemonBinary atomically replaces /usr/local/bin/awg-split-tunnel.
func replaceDaemonBinary(extractDir string) error {
	binaryPath, err := findBinary(extractDir)
	if err != nil {
		return fmt.Errorf("find daemon binary: %w", err)
	}

	tmpBin := darwinDaemonBinary + ".new"
	input, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("read new binary: %w", err)
	}
	if err := os.WriteFile(tmpBin, input, 0755); err != nil {
		return fmt.Errorf("write temp binary: %w", err)
	}
	if err := os.Rename(tmpBin, darwinDaemonBinary); err != nil {
		os.Remove(tmpBin)
		return fmt.Errorf("replace daemon binary: %w", err)
	}

	core.Log.Infof("Update", "Daemon binary replaced: %s", darwinDaemonBinary)
	return nil
}

// replaceGUIApp replaces the .app bundle in /Applications/ if one is found
// in the extracted update. This is best-effort — if the GUI app is not
// present in the update archive or /Applications/ doesn't have the old app,
// the function logs and returns without error.
func replaceGUIApp(extractDir string) {
	newAppDir := findAppBundle(extractDir)
	if newAppDir == "" {
		core.Log.Debugf("Update", "No .app bundle in update archive, skipping GUI update")
		return
	}

	if _, err := os.Stat(darwinGUIAppDir); os.IsNotExist(err) {
		core.Log.Debugf("Update", "No existing GUI app at %s, skipping GUI update", darwinGUIAppDir)
		return
	}

	// Remove old app and replace with new one.
	backupDir := darwinGUIAppDir + ".old"
	os.RemoveAll(backupDir)

	if err := os.Rename(darwinGUIAppDir, backupDir); err != nil {
		core.Log.Warnf("Update", "Failed to backup GUI app: %v", err)
		return
	}

	if err := copyDir(newAppDir, darwinGUIAppDir); err != nil {
		core.Log.Warnf("Update", "Failed to install new GUI app: %v — restoring backup", err)
		os.RemoveAll(darwinGUIAppDir)
		os.Rename(backupDir, darwinGUIAppDir)
		return
	}

	os.RemoveAll(backupDir)
	core.Log.Infof("Update", "GUI app replaced: %s", darwinGUIAppDir)
}

// findAppBundle locates a .app directory within the extract directory.
func findAppBundle(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), ".app") {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

// copyDir recursively copies a directory tree.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(destPath, info.Mode())
		}

		// Handle symlinks.
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(target, destPath)
		}

		return copyFilePreserveMode(path, destPath, info.Mode())
	})
}

// copyFilePreserveMode copies a file preserving the given mode.
func copyFilePreserveMode(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

// findBinary locates the awg-split-tunnel binary in the extract directory.
func findBinary(dir string) (string, error) {
	// Look for exact name first.
	candidate := filepath.Join(dir, "awg-split-tunnel")
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate, nil
	}

	// Walk directory to find any executable.
	var found string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		name := info.Name()
		if name == "awg-split-tunnel" || strings.HasPrefix(name, "awg-split-tunnel-") {
			// Skip .app bundle internals and GUI binaries.
			if strings.Contains(path, ".app/") || strings.Contains(name, "gui") {
				return nil
			}
			if info.Mode()&0111 != 0 {
				found = path
				return filepath.SkipAll
			}
		}
		return nil
	})

	if found == "" {
		return "", fmt.Errorf("daemon binary not found in %s", dir)
	}
	return found, nil
}

// extractTarGz extracts a .tar.gz file to the destination directory.
func extractTarGz(tarGzPath, destDir string) error {
	f, err := os.Open(tarGzPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		destPath := filepath.Join(destDir, header.Name)

		// Prevent tar slip.
		rel, err := filepath.Rel(destDir, destPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("illegal file path in tar: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(destPath, 0755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(destPath), 0755)
			out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		case tar.TypeSymlink:
			os.MkdirAll(filepath.Dir(destPath), 0755)
			os.Remove(destPath)
			if err := os.Symlink(header.Linkname, destPath); err != nil {
				return err
			}
		}
	}
	return nil
}
