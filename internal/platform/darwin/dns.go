//go:build darwin

package darwin

import "os/exec"

// flushSystemDNS flushes the macOS DNS cache.
func flushSystemDNS() error {
	// Flush mDNSResponder cache.
	if err := exec.Command("dscacheutil", "-flushcache").Run(); err != nil {
		return err
	}
	// Signal mDNSResponder to re-read configuration.
	return exec.Command("killall", "-HUP", "mDNSResponder").Run()
}
