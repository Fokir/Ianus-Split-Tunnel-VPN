//go:build darwin

package anyconnect

import (
	"os/exec"
	"strings"
)

const (
	fallbackVersion = "5.1.15.287"
	deviceType      = "mac-intel"
	platformVer     = "15.3.0"
)

var (
	agentVer  = detectCiscoVersion()
	userAgent = "AnyConnect Darwin " + agentVer
)

// detectCiscoVersion tries to read the installed Cisco Secure Client / AnyConnect version
// from the macOS application bundle. Falls back to a hardcoded recent version.
func detectCiscoVersion() string {
	// defaults read expects the plist path without the .plist extension.
	plistPaths := []string{
		"/Applications/Cisco/Cisco Secure Client.app/Contents/Info",
		"/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app/Contents/Info",
	}
	for _, p := range plistPaths {
		out, err := exec.Command("defaults", "read", p, "CFBundleShortVersionString").Output()
		if err != nil {
			continue
		}
		if ver := strings.TrimSpace(string(out)); ver != "" {
			return ver
		}
	}

	// Try the vpnagent binary version.
	agentPaths := []string{
		"/opt/cisco/secureclient/bin/vpnagent",
		"/opt/cisco/anyconnect/bin/vpnagent",
	}
	for _, p := range agentPaths {
		out, err := exec.Command(p, "-v").CombinedOutput()
		if err != nil {
			continue
		}
		if ver := parseVPNAgentVersion(string(out)); ver != "" {
			return ver
		}
	}

	return fallbackVersion
}

// parseVPNAgentVersion extracts version from vpnagent output like
// "Cisco AnyConnect Secure Mobility Client 5.1.15.287" or similar.
func parseVPNAgentVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// Look for a version-like token (digits and dots).
		fields := strings.Fields(line)
		for i := len(fields) - 1; i >= 0; i-- {
			f := fields[i]
			if len(f) >= 3 && f[0] >= '0' && f[0] <= '9' && strings.Contains(f, ".") {
				return f
			}
		}
	}
	return ""
}
