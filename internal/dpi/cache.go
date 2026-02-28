package dpi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"awg-split-tunnel/internal/core"
)

const cacheFileName = "dpi_strategies.json"

// CacheData is the persistent storage format for DPI strategies.
type CacheData struct {
	// NetworkStrategies maps network ID → active strategy for that network.
	NetworkStrategies map[string]*Strategy `json:"network_strategies,omitempty"`
	// AvailableStrategies are fetched from GitHub (zapret repository).
	AvailableStrategies []*Strategy `json:"available_strategies,omitempty"`
	// SearchResults are strategies found by the parameter searcher.
	SearchResults []*Strategy `json:"search_results,omitempty"`
}

// CacheManager handles persistent storage of DPI strategies.
type CacheManager struct {
	mu       sync.RWMutex
	data     CacheData
	dataDir  string
	filePath string
}

// NewCacheManager creates a cache manager that stores data in the given directory.
func NewCacheManager(dataDir string) *CacheManager {
	return &CacheManager{
		dataDir:  dataDir,
		filePath: filepath.Join(dataDir, cacheFileName),
		data: CacheData{
			NetworkStrategies: make(map[string]*Strategy),
		},
	}
}

// Load reads cached strategies from disk. Returns nil if the file doesn't exist.
func (c *CacheManager) Load() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(c.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			core.Log.Debugf("DPI", "No cache file at %s", c.filePath)
			return nil
		}
		return fmt.Errorf("read cache: %w", err)
	}

	var cached CacheData
	if err := json.Unmarshal(data, &cached); err != nil {
		core.Log.Warnf("DPI", "Corrupt cache file, starting fresh: %v", err)
		return nil
	}

	if cached.NetworkStrategies == nil {
		cached.NetworkStrategies = make(map[string]*Strategy)
	}
	c.data = cached

	core.Log.Infof("DPI", "Loaded cache: %d network strategies, %d available, %d search results",
		len(c.data.NetworkStrategies), len(c.data.AvailableStrategies), len(c.data.SearchResults))
	return nil
}

// Save writes cached strategies to disk atomically (temp + rename).
func (c *CacheManager) Save() error {
	c.mu.RLock()
	data, err := json.MarshalIndent(c.data, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}

	if err := os.MkdirAll(c.dataDir, 0755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	// Atomic write: write to temp file, then rename.
	tmpPath := c.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write cache temp: %w", err)
	}
	if err := os.Rename(tmpPath, c.filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename cache: %w", err)
	}

	return nil
}

// GetNetworkStrategy returns the cached strategy for a specific network ID.
func (c *CacheManager) GetNetworkStrategy(networkID string) *Strategy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data.NetworkStrategies[networkID]
}

// SetNetworkStrategy stores a strategy for a specific network ID and persists to disk.
func (c *CacheManager) SetNetworkStrategy(networkID string, s *Strategy) error {
	c.mu.Lock()
	s.NetworkID = networkID
	c.data.NetworkStrategies[networkID] = s
	c.mu.Unlock()
	return c.Save()
}

// GetAvailableStrategies returns all fetched strategies.
func (c *CacheManager) GetAvailableStrategies() []*Strategy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*Strategy, len(c.data.AvailableStrategies))
	copy(result, c.data.AvailableStrategies)
	return result
}

// SetAvailableStrategies replaces the available strategies list and persists.
func (c *CacheManager) SetAvailableStrategies(strategies []*Strategy) error {
	c.mu.Lock()
	c.data.AvailableStrategies = strategies
	c.mu.Unlock()
	return c.Save()
}

// GetSearchResults returns strategies found by the parameter searcher.
func (c *CacheManager) GetSearchResults() []*Strategy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*Strategy, len(c.data.SearchResults))
	copy(result, c.data.SearchResults)
	return result
}

// AddSearchResult appends a search result and persists.
func (c *CacheManager) AddSearchResult(s *Strategy) error {
	c.mu.Lock()
	c.data.SearchResults = append(c.data.SearchResults, s)
	c.mu.Unlock()
	return c.Save()
}

// GetNetworkID returns a network identifier based on the default gateway IP.
// This is used to associate strategies with specific ISPs/networks.
func GetNetworkID(gatewayIP string) string {
	if gatewayIP == "" {
		return "unknown"
	}
	return "gw:" + gatewayIP
}
