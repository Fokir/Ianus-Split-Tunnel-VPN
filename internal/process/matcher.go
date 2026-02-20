//go:build windows

package process

import (
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Matcher resolves process IDs to executable paths and matches them against patterns.
type Matcher struct {
	mu    sync.RWMutex
	cache map[uint32]string // PID → exe path cache
}

// NewMatcher creates a process matcher with an empty cache.
func NewMatcher() *Matcher {
	return &Matcher{
		cache: make(map[uint32]string),
	}
}

// GetExePath returns the full executable path for a given PID.
// Results are cached for performance on the hot path.
func (m *Matcher) GetExePath(pid uint32) (string, bool) {
	// Check cache first (fast path, read lock).
	m.mu.RLock()
	path, ok := m.cache[pid]
	m.mu.RUnlock()
	if ok {
		return path, true
	}

	// Query Windows for the process path.
	path, err := queryProcessPath(pid)
	if err != nil {
		return "", false
	}

	// Cache the result.
	m.mu.Lock()
	m.cache[pid] = path
	m.mu.Unlock()

	return path, true
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
	m.cache = make(map[uint32]string)
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

// queryProcessPath uses Windows API to get the executable path from a PID.
func queryProcessPath(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
	if err != nil {
		return "", err
	}

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&buf[0]))), nil
}
