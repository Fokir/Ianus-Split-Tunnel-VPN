package dpi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"awg-split-tunnel/internal/core"
)

const (
	// defaultRepo is the GitHub repository for Flowseal's zapret strategies.
	defaultRepo = "Flowseal/zapret-discord-youtube"
	// githubReleasesAPI is the base URL for GitHub Releases API.
	githubReleasesAPI = "https://api.github.com/repos/%s/releases/latest"
	// maxZipSize is the maximum allowed ZIP archive size (50 MB).
	maxZipSize = 50 << 20
)

// StrategyFetcher downloads and parses DPI bypass strategies from GitHub.
type StrategyFetcher struct {
	client *http.Client
	repo   string
}

// NewStrategyFetcher creates a fetcher using the provided HTTP client.
// The client should be bound to the real NIC to avoid routing through the TUN adapter.
func NewStrategyFetcher(client *http.Client) *StrategyFetcher {
	if client == nil {
		client = http.DefaultClient
	}
	return &StrategyFetcher{
		client: client,
		repo:   defaultRepo,
	}
}

// githubRelease represents a GitHub release response.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

// githubAsset represents a single asset in a GitHub release.
type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// FetchAll downloads the latest release ZIP and parses all .bat strategy files.
func (f *StrategyFetcher) FetchAll(ctx context.Context) ([]*Strategy, error) {
	zipURL, err := f.fetchLatestReleaseZipURL(ctx)
	if err != nil {
		return nil, fmt.Errorf("get release ZIP URL: %w", err)
	}

	data, err := f.downloadZip(ctx, zipURL)
	if err != nil {
		return nil, fmt.Errorf("download ZIP: %w", err)
	}

	strategies, err := parseZipStrategies(data)
	if err != nil {
		return nil, fmt.Errorf("parse ZIP strategies: %w", err)
	}

	core.Log.Infof("DPI", "Fetched %d strategies from release ZIP", len(strategies))
	return strategies, nil
}

// fetchLatestReleaseZipURL gets the ZIP archive URL from the latest GitHub release.
func (f *StrategyFetcher) fetchLatestReleaseZipURL(ctx context.Context) (string, error) {
	url := fmt.Sprintf(githubReleasesAPI, f.repo)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := f.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("decode release response: %w", err)
	}

	for _, asset := range release.Assets {
		if strings.HasSuffix(strings.ToLower(asset.Name), ".zip") {
			core.Log.Infof("DPI", "Found release %s, asset: %s", release.TagName, asset.Name)
			return asset.BrowserDownloadURL, nil
		}
	}

	return "", fmt.Errorf("no .zip asset found in release %s", release.TagName)
}

// downloadZip downloads a ZIP archive into memory with size limit check.
func (f *StrategyFetcher) downloadZip(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download ZIP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("download returned %d: %s", resp.StatusCode, string(body))
	}

	if resp.ContentLength > maxZipSize {
		return nil, fmt.Errorf("ZIP too large: %d bytes (limit %d)", resp.ContentLength, maxZipSize)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxZipSize+1))
	if err != nil {
		return nil, fmt.Errorf("read ZIP body: %w", err)
	}
	if len(data) > maxZipSize {
		return nil, fmt.Errorf("ZIP too large: >%d bytes", maxZipSize)
	}

	return data, nil
}

// parseZipStrategies extracts and parses all .bat files from the ZIP archive.
func parseZipStrategies(data []byte) ([]*Strategy, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open ZIP: %w", err)
	}

	var strategies []*Strategy
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		base := filepath.Base(f.Name)
		if !strings.HasSuffix(strings.ToLower(base), ".bat") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			core.Log.Warnf("DPI", "Failed to open ZIP entry %s: %v", f.Name, err)
			continue
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			core.Log.Warnf("DPI", "Failed to read ZIP entry %s: %v", f.Name, err)
			continue
		}

		content := stripBOM(string(raw))
		name := strings.TrimSuffix(base, ".bat")

		s, err := ParseBatFile(content, name)
		if err != nil {
			core.Log.Warnf("DPI", "Failed to parse %s: %v", base, err)
			continue
		}
		if len(s.Ops) > 0 {
			strategies = append(strategies, s)
		}
	}

	return strategies, nil
}

// stripBOM removes UTF-8 BOM prefix if present.
func stripBOM(s string) string {
	return strings.TrimPrefix(s, "\xEF\xBB\xBF")
}
