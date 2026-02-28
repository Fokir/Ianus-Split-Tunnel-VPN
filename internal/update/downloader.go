package update

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"awg-split-tunnel/internal/core"
)

// ProgressFunc reports download progress: bytesDownloaded, totalBytes.
type ProgressFunc func(downloaded, total int64)

// Download fetches the update zip from info.AssetURL, extracts it into a temp
// directory, and returns the path to the extracted files.
func Download(ctx context.Context, info *Info, httpClient *http.Client, progressFn ProgressFunc) (string, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Minute}
	}

	// Create temp directory for the update.
	tempDir, err := os.MkdirTemp("", "awg-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}

	zipPath := filepath.Join(tempDir, "update.zip")

	// Download the zip.
	core.Log.Infof("Update", "Downloading %s (%d bytes)...", info.Version, info.AssetSize)
	if err := downloadFile(ctx, httpClient, info.AssetURL, zipPath, info.AssetSize, progressFn); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("download: %w", err)
	}

	// Extract the zip.
	extractDir := filepath.Join(tempDir, "files")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("create extract dir: %w", err)
	}

	core.Log.Infof("Update", "Extracting update...")
	if err := extractZip(zipPath, extractDir); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("extract: %w", err)
	}

	// Remove the zip to save space.
	os.Remove(zipPath)

	core.Log.Infof("Update", "Update downloaded and extracted to %s", extractDir)
	return extractDir, nil
}

// downloadFile downloads a URL to a local file with optional progress reporting.
func downloadFile(ctx context.Context, client *http.Client, url, dest string, totalSize int64, progressFn ProgressFunc) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "awg-split-tunnel-updater")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	if progressFn == nil {
		_, err = io.Copy(f, resp.Body)
		return err
	}

	// Copy with progress reporting.
	buf := make([]byte, 32*1024)
	var downloaded int64
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := f.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			downloaded += int64(n)
			progressFn(downloaded, totalSize)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return nil
}

// extractZip extracts a zip archive to the destination directory.
func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		destPath := filepath.Join(destDir, f.Name)

		// Prevent zip slip.
		if !isSubPath(destDir, destPath) {
			return fmt.Errorf("illegal file path in zip: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0755)
			continue
		}

		// Ensure parent directory exists.
		os.MkdirAll(filepath.Dir(destPath), 0755)

		if err := extractSingleFile(f, destPath); err != nil {
			return fmt.Errorf("extract %s: %w", f.Name, err)
		}
	}
	return nil
}

func extractSingleFile(f *zip.File, destPath string) error {
	src, err := f.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

// isSubPath checks if child is under parent directory (zip slip prevention).
func isSubPath(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return !filepath.IsAbs(rel) && !strings.HasPrefix(rel, "..")
}
