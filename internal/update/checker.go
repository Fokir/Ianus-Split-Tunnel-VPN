//go:build windows

package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
)

// GitHubRepo is the repository path for update checks.
// TODO: set the real owner before first public release.
const GitHubRepo = "Fokir/Ianus-Split-Tunnel-VPN"

// AssetPattern matches release assets for Windows amd64.
const AssetPattern = "awg-split-tunnel-v"
const AssetSuffix = "-windows-amd64.zip"

// Info holds information about an available update.
type Info struct {
	Version      string
	ReleaseNotes string
	AssetURL     string
	AssetSize    int64
}

// githubRelease maps the relevant fields from the GitHub API response.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Body    string        `json:"body"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// Checker periodically checks GitHub Releases for new versions.
type Checker struct {
	repo           string
	currentVersion string
	httpClient     *http.Client
	interval       time.Duration
	bus            *core.EventBus

	mu     sync.RWMutex
	latest *Info
}

// NewChecker creates a new update checker.
func NewChecker(currentVersion string, interval time.Duration, bus *core.EventBus, httpClient *http.Client) *Checker {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Checker{
		repo:           GitHubRepo,
		currentVersion: currentVersion,
		httpClient:     httpClient,
		interval:       interval,
		bus:            bus,
	}
}

// Start begins periodic update checks. Blocks until ctx is cancelled.
func (c *Checker) Start(ctx context.Context) {
	// Initial check after a short delay.
	select {
	case <-time.After(30 * time.Second):
	case <-ctx.Done():
		return
	}

	c.check(ctx)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.check(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// CheckNow performs an immediate update check and returns the result.
func (c *Checker) CheckNow(ctx context.Context) (*Info, error) {
	info, err := c.fetchLatest(ctx)
	if err != nil {
		return nil, err
	}

	if info == nil {
		return nil, nil // already up to date
	}

	c.mu.Lock()
	c.latest = info
	c.mu.Unlock()

	return info, nil
}

// GetLatestInfo returns the cached result of the last check.
func (c *Checker) GetLatestInfo() *Info {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest
}

// check fetches the latest release and publishes an event if newer.
func (c *Checker) check(ctx context.Context) {
	info, err := c.fetchLatest(ctx)
	if err != nil {
		core.Log.Warnf("Update", "Check failed: %v", err)
		return
	}
	if info == nil {
		return
	}

	c.mu.Lock()
	c.latest = info
	c.mu.Unlock()

	core.Log.Infof("Update", "New version available: %s", info.Version)

	if c.bus != nil {
		c.bus.PublishAsync(core.Event{
			Type: core.EventUpdateAvailable,
			Payload: core.UpdatePayload{
				Version:      info.Version,
				ReleaseNotes: info.ReleaseNotes,
				AssetURL:     info.AssetURL,
				AssetSize:    info.AssetSize,
			},
		})
	}
}

// fetchLatest queries the GitHub API and returns Info if a newer version exists.
// Returns nil, nil if the current version is up to date.
func (c *Checker) fetchLatest(ctx context.Context) (*Info, error) {
	// Skip check for dev builds.
	if c.currentVersion == "dev" || c.currentVersion == "" {
		return nil, nil
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", c.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "awg-split-tunnel/"+c.currentVersion)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // no releases yet
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	releaseVersion := normalizeVersion(release.TagName)
	currentVersion := normalizeVersion(c.currentVersion)

	if !isNewer(releaseVersion, currentVersion) {
		return nil, nil
	}

	// Find the matching asset.
	var asset *githubAsset
	for i := range release.Assets {
		a := &release.Assets[i]
		if strings.HasPrefix(a.Name, AssetPattern) && strings.HasSuffix(a.Name, AssetSuffix) {
			asset = a
			break
		}
	}
	if asset == nil {
		return nil, fmt.Errorf("no matching asset found in release %s", release.TagName)
	}

	return &Info{
		Version:      releaseVersion,
		ReleaseNotes: release.Body,
		AssetURL:     asset.BrowserDownloadURL,
		AssetSize:    asset.Size,
	}, nil
}

// normalizeVersion strips the "v" prefix from a version string.
func normalizeVersion(v string) string {
	return strings.TrimPrefix(v, "v")
}

// isNewer returns true if release > current using simple semver comparison.
func isNewer(release, current string) bool {
	rParts := parseSemver(release)
	cParts := parseSemver(current)

	for i := 0; i < 3; i++ {
		if rParts[i] > cParts[i] {
			return true
		}
		if rParts[i] < cParts[i] {
			return false
		}
	}
	return false
}

// parseSemver extracts major.minor.patch as [3]int. Non-numeric parts are 0.
func parseSemver(v string) [3]int {
	var parts [3]int
	// Remove pre-release suffix (e.g. "1.2.3-beta" → "1.2.3").
	if idx := strings.IndexByte(v, '-'); idx >= 0 {
		v = v[:idx]
	}
	segments := strings.SplitN(v, ".", 3)
	for i, s := range segments {
		if i >= 3 {
			break
		}
		n := 0
		for _, c := range s {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			} else {
				break
			}
		}
		parts[i] = n
	}
	return parts
}
