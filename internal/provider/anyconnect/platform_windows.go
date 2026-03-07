//go:build windows

package anyconnect

import (
	"golang.org/x/sys/windows/registry"
)

const (
	fallbackVersion = "5.1.15.287"
	deviceType      = "win"
	platformVer     = "10.0.26100"
)

var (
	agentVer  = detectCiscoVersion()
	userAgent = "AnyConnect Windows " + agentVer
)

// detectCiscoVersion tries to read the installed Cisco Secure Client / AnyConnect version
// from the Windows registry. Falls back to a hardcoded recent version.
func detectCiscoVersion() string {
	// Cisco Secure Client 5.x.
	regPaths := []struct {
		key  string
		name string
	}{
		{`SOFTWARE\Cisco\Cisco Secure Client`, "Version"},
		{`SOFTWARE\WOW6432Node\Cisco\Cisco Secure Client`, "Version"},
		{`SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client`, "Version"},
		{`SOFTWARE\WOW6432Node\Cisco\Cisco AnyConnect Secure Mobility Client`, "Version"},
	}

	for _, p := range regPaths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p.key, registry.READ)
		if err != nil {
			continue
		}
		val, _, err := k.GetStringValue(p.name)
		k.Close()
		if err == nil && val != "" {
			return val
		}
	}

	// Try DisplayVersion from Uninstall entries.
	uninstallPaths := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cisco Secure Client - AnyConnect VPN`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Cisco Secure Client - AnyConnect VPN`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cisco AnyConnect Secure Mobility Client`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Cisco AnyConnect Secure Mobility Client`,
	}
	for _, p := range uninstallPaths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
		if err != nil {
			continue
		}
		val, _, err := k.GetStringValue("DisplayVersion")
		k.Close()
		if err == nil && val != "" {
			return val
		}
	}

	return fallbackVersion
}
