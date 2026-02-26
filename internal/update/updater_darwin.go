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

// ApplyDarwinUpdate replaces the daemon binary and restarts the daemon.
// extractDir should contain the new binary (possibly among other files).
func ApplyDarwinUpdate(extractDir string) error {
	// Find the binary in the extract directory.
	binaryPath, err := findBinary(extractDir)
	if err != nil {
		return fmt.Errorf("find binary: %w", err)
	}

	// Atomic replace: write to temp file, then rename.
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
		return fmt.Errorf("replace binary: %w", err)
	}

	// Restart daemon via launchctl.
	core.Log.Infof("Update", "Binary replaced, restarting daemon...")
	out, err := exec.Command("launchctl", "kickstart", "-k", "system/"+darwinDaemonLabel).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl kickstart: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return nil
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
			if info.Mode()&0111 != 0 {
				found = path
				return filepath.SkipAll
			}
		}
		return nil
	})

	if found == "" {
		return "", fmt.Errorf("binary not found in %s", dir)
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
		}
	}
	return nil
}
