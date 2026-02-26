//go:build darwin

package main

import (
	"sort"
	"strings"
)

// enrichProcessList deduplicates processes by exe name and sorts the list
// alphabetically. On macOS, icon extraction and window detection are not
// implemented yet — they require AppKit/CGO which is out of scope for the
// initial cross-platform build.
func enrichProcessList(procs []ProcessInfo) []ProcessInfo {
	type entry struct {
		proc ProcessInfo
	}
	seen := make(map[string]*entry)
	var order []string

	for i := range procs {
		p := &procs[i]
		key := strings.ToLower(p.Name)

		if existing, ok := seen[key]; ok {
			// Prefer the entry with a non-empty path.
			if p.Path != "" && existing.proc.Path == "" {
				existing.proc.Path = p.Path
			}
		} else {
			seen[key] = &entry{proc: *p}
			order = append(order, key)
		}
	}

	result := make([]ProcessInfo, 0, len(seen))
	for _, key := range order {
		e := seen[key]
		result = append(result, e.proc)
	}

	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})

	return result
}
