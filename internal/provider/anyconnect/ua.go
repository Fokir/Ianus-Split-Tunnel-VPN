package anyconnect

import "strings"

// clientID groups identity strings sent to the Cisco server.
type clientID struct {
	UserAgent   string // Full User-Agent header, e.g. "AnyConnect Windows 5.1.15.287"
	Version     string // Version portion, e.g. "5.1.15.287"
	DeviceType  string // "win", "mac-intel", etc.
	PlatformVer string // OS version, e.g. "10.0.26100"
}

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
		if idx := strings.LastIndex(customUA, " "); idx >= 0 {
			cid.Version = customUA[idx+1:]
		}
	}
	return cid
}
