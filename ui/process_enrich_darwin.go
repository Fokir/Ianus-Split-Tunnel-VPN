//go:build darwin

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// iconCache caches extracted icons by bundle path (lowercase).
var iconCache sync.Map // string -> string

// extractProcessIcon returns a "data:image/png;base64,..." string for the
// given executable path, or "" if no icon can be extracted.
// Results are cached by .app bundle path.
func extractProcessIcon(exePath string) string {
	if exePath == "" {
		return ""
	}
	bundlePath := appBundleRoot(exePath)
	if bundlePath == "" {
		return ""
	}
	key := strings.ToLower(bundlePath)
	if cached, ok := iconCache.Load(key); ok {
		return cached.(string)
	}
	icon := doExtractIcon(bundlePath)
	iconCache.Store(key, icon)
	return icon
}

// doExtractIcon reads the .app bundle's Info.plist, finds the .icns file,
// extracts a PNG from it, and returns a base64 data URL.
func doExtractIcon(bundlePath string) string {
	iconName := iconFileFromBundle(bundlePath)
	if iconName == "" {
		iconName = "AppIcon" // fallback
	}

	icnsPath := resolveIconPath(bundlePath, iconName)
	if icnsPath == "" {
		return ""
	}

	pngData := extractPNGFromICNS(icnsPath)
	if len(pngData) == 0 {
		return ""
	}

	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngData)
}

// appBundleRoot extracts the .app bundle root from an executable path.
// E.g. "/Applications/Safari.app/Contents/MacOS/Safari" -> "/Applications/Safari.app"
func appBundleRoot(exePath string) string {
	// Normalize to forward slashes (should already be on macOS).
	p := filepath.ToSlash(exePath)
	idx := strings.Index(strings.ToLower(p), ".app/")
	if idx < 0 {
		return ""
	}
	return filepath.FromSlash(p[:idx+4]) // include ".app"
}

// iconFileFromBundle reads Info.plist from the bundle and extracts
// CFBundleIconFile. Handles both XML and binary plist formats.
func iconFileFromBundle(bundlePath string) string {
	plistPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return ""
	}

	// Try XML parsing first.
	if val := plistStringValue(data, "CFBundleIconFile"); val != "" {
		return val
	}

	// If it looks like a binary plist, convert via plutil.
	if bytes.HasPrefix(data, []byte("bplist")) {
		xmlData, err := convertBinaryPlist(plistPath)
		if err != nil {
			return ""
		}
		return plistStringValue(xmlData, "CFBundleIconFile")
	}

	return ""
}

// plistStringValue is a minimal XML plist parser that extracts the string
// value for the given key. It looks for <key>K</key> followed by <string>V</string>.
func plistStringValue(data []byte, key string) string {
	s := string(data)
	keyTag := "<key>" + key + "</key>"
	idx := strings.Index(s, keyTag)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(keyTag):]
	// Skip whitespace between </key> and <string>.
	rest = strings.TrimSpace(rest)
	const open = "<string>"
	const close = "</string>"
	if !strings.HasPrefix(rest, open) {
		return ""
	}
	rest = rest[len(open):]
	end := strings.Index(rest, close)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// convertBinaryPlist converts a binary plist to XML using plutil.
func convertBinaryPlist(filePath string) ([]byte, error) {
	return exec.Command("plutil", "-convert", "xml1", "-o", "-", filePath).Output()
}

// resolveIconPath finds the actual .icns file path inside the bundle's Resources.
// It tries: exact name, name+".icns", and a fallback to "AppIcon.icns".
func resolveIconPath(bundlePath, iconName string) string {
	resDir := filepath.Join(bundlePath, "Contents", "Resources")

	// If iconName already has .icns extension, try it directly.
	if strings.HasSuffix(strings.ToLower(iconName), ".icns") {
		p := filepath.Join(resDir, iconName)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}

	// Try name + ".icns"
	p := filepath.Join(resDir, iconName+".icns")
	if _, err := os.Stat(p); err == nil {
		return p
	}

	// Fallback: AppIcon.icns (common convention)
	if iconName != "AppIcon" {
		p = filepath.Join(resDir, "AppIcon.icns")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// pngSignature is the first 8 bytes of any PNG file.
var pngSignature = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

// icnsTypePriority maps ICNS block types to priority (lower = better).
// We prefer 32×32 for consistency with the Windows implementation.
var icnsTypePriority = map[string]int{
	"icp5": 1,  // 32×32 PNG
	"ic11": 2,  // 32×32@2x PNG
	"icp6": 3,  // 64×64 PNG
	"ic07": 4,  // 128×128 PNG
	"ic08": 5,  // 256×256 PNG
	"ic09": 6,  // 512×512 PNG
	"ic10": 7,  // 1024×1024 PNG
	"ic14": 8,  // 1024×1024@2x PNG
	"ic13": 9,  // 256×256@2x PNG
	"ic12": 10, // 64×64@2x PNG
	"icp4": 11, // 16×16 PNG
}

// extractPNGFromICNS parses an ICNS file and returns the best PNG block.
// ICNS format: 4-byte magic ("icns") + 4-byte total size, then repeated
// blocks of 4-byte type + 4-byte block size + payload.
func extractPNGFromICNS(icnsPath string) []byte {
	data, err := os.ReadFile(icnsPath)
	if err != nil || len(data) < 8 {
		return nil
	}

	// Verify magic.
	if string(data[:4]) != "icns" {
		return nil
	}

	totalSize := int(binary.BigEndian.Uint32(data[4:8]))
	if totalSize > len(data) {
		totalSize = len(data)
	}

	var bestPNG []byte
	bestPriority := 999

	offset := 8
	for offset+8 <= totalSize {
		blockType := string(data[offset : offset+4])
		blockSize := int(binary.BigEndian.Uint32(data[offset+4 : offset+8]))

		if blockSize < 8 || offset+blockSize > totalSize {
			break
		}

		payload := data[offset+8 : offset+blockSize]

		// Check if payload is a PNG.
		if len(payload) > 8 && bytes.HasPrefix(payload, pngSignature) {
			pri, known := icnsTypePriority[blockType]
			if !known {
				pri = 50 // unknown type, low priority
			}
			if pri < bestPriority {
				bestPriority = pri
				bestPNG = payload
			}
		}

		offset += blockSize
	}

	return bestPNG
}

// enrichProcessList deduplicates processes by exe name, extracts icons for
// .app bundles, and sorts the list with GUI apps first.
func enrichProcessList(procs []ProcessInfo) []ProcessInfo {
	type entry struct {
		proc      ProcessInfo
		hasWindow bool
	}
	seen := make(map[string]*entry)
	var order []string

	for i := range procs {
		p := &procs[i]
		key := strings.ToLower(p.Name)
		isApp := strings.Contains(p.Path, ".app/Contents/MacOS/")

		if existing, ok := seen[key]; ok {
			// Prefer the windowed/app entry.
			if isApp && !existing.hasWindow {
				existing.proc = *p
				existing.hasWindow = true
			} else if p.Path != "" && existing.proc.Path == "" {
				existing.proc.Path = p.Path
				if isApp {
					existing.hasWindow = true
				}
			}
		} else {
			seen[key] = &entry{proc: *p, hasWindow: isApp}
			order = append(order, key)
		}
	}

	// Extract icons and build result.
	result := make([]ProcessInfo, 0, len(seen))
	for _, key := range order {
		e := seen[key]
		e.proc.HasWindow = e.hasWindow
		if e.hasWindow && e.proc.Path != "" {
			e.proc.Icon = extractProcessIcon(e.proc.Path)
		}
		result = append(result, e.proc)
	}

	// Sort: GUI apps first, then alphabetically.
	sort.Slice(result, func(i, j int) bool {
		if result[i].HasWindow != result[j].HasWindow {
			return result[i].HasWindow
		}
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})

	return result
}
