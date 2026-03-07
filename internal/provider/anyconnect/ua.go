package anyconnect

import (
	"regexp"
	"strings"
)

// clientID groups identity strings sent to the Cisco server.
type clientID struct {
	UserAgent   string // Full User-Agent header, e.g. "AnyConnect Windows 5.1.15.287"
	Version     string // Version portion, e.g. "5.1.15.287"
	DeviceType  string // "win", "mac-intel", etc.
	PlatformVer string // OS version, e.g. "10.0.26100"
}

// reAnyConnectVer matches "AnyConnect/4.10.08029" or "AnyConnect Darwin 5.1.15.287" patterns.
var reAnyConnectVer = regexp.MustCompile(`(?i)AnyConnect[/ ]\s*(?:Windows|Darwin|Linux)?\s*([0-9][0-9.]+)`)

// resolveClientID returns the effective client identity.
// If customUA is non-empty, the User-Agent and version are derived from it.
// Otherwise the auto-detected values from platform_*.go are used.
func resolveClientID(customUA string) clientID {
	cid := clientID{
		UserAgent:   userAgent,
		Version:     agentVer,
		DeviceType:  deviceType,
		PlatformVer: platformVer,
	}
	if customUA != "" {
		cid.UserAgent = customUA

		// Extract version: prefer "AnyConnect/VERSION" or "AnyConnect PLATFORM VERSION" pattern.
		if m := reAnyConnectVer.FindStringSubmatch(customUA); len(m) > 1 {
			cid.Version = m[1]
		} else if idx := strings.LastIndex(customUA, " "); idx >= 0 {
			cid.Version = customUA[idx+1:]
		}

		// Detect device type and platform version from custom UA so that
		// the XML identity matches the HTTP User-Agent header.
		lower := strings.ToLower(customUA)
		switch {
		case strings.Contains(lower, "macos") || strings.Contains(lower, "darwin") || strings.Contains(lower, "mac"):
			cid.DeviceType = "mac-intel"
			cid.PlatformVer = "15.3.0"
		case strings.Contains(lower, "linux"):
			cid.DeviceType = "linux-64"
			cid.PlatformVer = "6.1.0"
		}
	}
	return cid
}
