package process

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// cachedPath holds a cached process path with pre-computed lowercase variants.
type cachedPath struct {
	exePath   string // original full path
	exeLower  string // strings.ToLower(exePath)
	baseLower string // filepath.Base(exeLower)
}

// Matcher resolves process IDs to executable paths and matches them against patterns.
type Matcher struct {
	mu    sync.RWMutex
	cache map[uint32]*cachedPath // PID → cached path info
}

// NewMatcher creates a process matcher with an empty cache.
func NewMatcher() *Matcher {
	return &Matcher{
		cache: make(map[uint32]*cachedPath),
	}
}

// GetExePath returns the full executable path for a given PID.
// Results are cached for performance on the hot path.
func (m *Matcher) GetExePath(pid uint32) (string, bool) {
	if cp := m.getCached(pid); cp != nil {
		return cp.exePath, true
	}

	// Query OS for the process path (platform-specific).
	path, err := queryProcessPath(pid)
	if err != nil {
		return "", false
	}

	lower := strings.ToLower(path)
	cp := &cachedPath{
		exePath:   path,
		exeLower:  lower,
		baseLower: filepath.Base(lower),
	}

	m.mu.Lock()
	m.cache[pid] = cp
	m.mu.Unlock()

	return path, true
}

// GetExePathLower returns the full path plus pre-lowered path and base name.
// Zero allocations on cache hit. Used by TUNRouter.resolveFlow() to avoid
// per-flow strings.ToLower allocations.
func (m *Matcher) GetExePathLower(pid uint32) (exePath, exeLower, baseLower string, ok bool) {
	if cp := m.getCached(pid); cp != nil {
		return cp.exePath, cp.exeLower, cp.baseLower, true
	}

	// Query OS for the process path (platform-specific).
	path, err := queryProcessPath(pid)
	if err != nil {
		return "", "", "", false
	}

	lower := strings.ToLower(path)
	base := filepath.Base(lower)
	cp := &cachedPath{
		exePath:   path,
		exeLower:  lower,
		baseLower: base,
	}

	m.mu.Lock()
	m.cache[pid] = cp
	m.mu.Unlock()

	return path, lower, base, true
}

// getCached returns the cached entry for a PID, or nil on miss.
func (m *Matcher) getCached(pid uint32) *cachedPath {
	m.mu.RLock()
	cp := m.cache[pid]
	m.mu.RUnlock()
	return cp
}

// Invalidate removes a PID from the cache (call when process exits).
func (m *Matcher) Invalidate(pid uint32) {
	m.mu.Lock()
	delete(m.cache, pid)
	m.mu.Unlock()
}

// PurgeCache clears the entire PID cache.
func (m *Matcher) PurgeCache() {
	m.mu.Lock()
	m.cache = make(map[uint32]*cachedPath)
	m.mu.Unlock()
}

// StartRevalidation periodically checks cached PIDs and removes entries for
// processes that no longer exist. This prevents stale entries when the OS
// reuses PIDs for different processes.
func (m *Matcher) StartRevalidation(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.revalidateCache()
			}
		}
	}()
}

// revalidateCache removes entries for dead processes and verifies that
// live processes still have the same exe path (catches PID reuse).
func (m *Matcher) revalidateCache() {
	// Snapshot current PIDs under read lock.
	m.mu.RLock()
	pids := make([]uint32, 0, len(m.cache))
	paths := make([]string, 0, len(m.cache))
	for pid, cp := range m.cache {
		pids = append(pids, pid)
		paths = append(paths, cp.exePath)
	}
	m.mu.RUnlock()

	// Check each PID outside the lock.
	var stale []uint32
	for i, pid := range pids {
		currentPath, err := queryProcessPath(pid)
		if err != nil {
			// Process no longer exists.
			stale = append(stale, pid)
			continue
		}
		// Process exists but exe path changed (PID reused).
		if !strings.EqualFold(currentPath, paths[i]) {
			stale = append(stale, pid)
		}
	}

	if len(stale) == 0 {
		return
	}

	m.mu.Lock()
	for _, pid := range stale {
		delete(m.cache, pid)
	}
	m.mu.Unlock()
}

// MatchPattern checks if the given executable path matches a rule pattern.
//
// Pattern types:
//   - "firefox.exe"          → exact exe name match (case-insensitive)
//   - "chrome"               → substring match in exe name (case-insensitive)
//   - "C:\Games\*"           → directory prefix match
//   - "C:\Program Files\*"   → directory prefix match
func MatchPattern(exePath string, pattern string) bool {
	if pattern == "" || exePath == "" {
		return false
	}

	// Regex pattern: "regex:<expr>" matches against full lowercase path.
	if strings.HasPrefix(pattern, "regex:") {
		re, err := regexp.Compile(pattern[6:])
		if err != nil {
			return false
		}
		return re.MatchString(strings.ToLower(exePath))
	}

	// Directory pattern: ends with \* or /*
	if strings.HasSuffix(pattern, `\*`) || strings.HasSuffix(pattern, `/*`) {
		dir := pattern[:len(pattern)-2]
		return strings.HasPrefix(strings.ToLower(exePath), strings.ToLower(dir)+`\`) ||
			strings.HasPrefix(strings.ToLower(exePath), strings.ToLower(dir)+`/`)
	}

	// If pattern contains path separator, treat as full path glob.
	if strings.ContainsAny(pattern, `\/`) {
		matched, _ := filepath.Match(strings.ToLower(pattern), strings.ToLower(exePath))
		return matched
	}

	exeName := filepath.Base(exePath)

	// Exact exe name match (case-insensitive).
	if strings.EqualFold(exeName, pattern) {
		return true
	}

	// Substring match in exe name (case-insensitive).
	if strings.Contains(strings.ToLower(exeName), strings.ToLower(pattern)) {
		return true
	}

	return false
}

// MatchPreprocessed is a fast-path version of MatchPattern.
// It accepts pre-lowercased exePath (exeLower) and base name (baseLower),
// plus the original and pre-lowercased pattern. This avoids repeated
// strings.ToLower allocations when matching against multiple rules.
func MatchPreprocessed(exeLower, baseLower, pattern, patternLower string) bool {
	if patternLower == "" || exeLower == "" {
		return false
	}

	// Regex pattern: "regex:<expr>" matches against full lowercase path.
	// Note: In hot paths (RuleEngine), regex is pre-compiled in regexCache
	// and this branch is never reached. This is a fallback for IPFilter calls.
	if strings.HasPrefix(pattern, "regex:") {
		re, err := regexp.Compile(pattern[6:])
		if err != nil {
			return false
		}
		return re.MatchString(exeLower)
	}

	// Directory pattern: ends with \* or /*
	if strings.HasSuffix(pattern, `\*`) || strings.HasSuffix(pattern, `/*`) {
		dir := patternLower[:len(patternLower)-2]
		if len(exeLower) > len(dir) && strings.HasPrefix(exeLower, dir) {
			c := exeLower[len(dir)]
			return c == '\\' || c == '/'
		}
		return false
	}

	// Full path glob.
	if strings.ContainsAny(pattern, `\/`) {
		matched, _ := filepath.Match(patternLower, exeLower)
		return matched
	}

	// Exact exe name match.
	if baseLower == patternLower {
		return true
	}

	// Substring match in exe name.
	return strings.Contains(baseLower, patternLower)
}
