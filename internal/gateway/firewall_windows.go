//go:build windows

package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"awg-split-tunnel/internal/core"
)

const firewallRulePrefix = "AWG Split Tunnel"

// EnsureFirewallRules creates Windows Firewall inbound allow rules for AWG
// executables. The hairpin NAT packets (proxy path) arrive on the TUN adapter
// with external source IPs, and Windows Firewall blocks them by default on
// fresh installations — breaking all non-raw-forwarded traffic.
func EnsureFirewallRules() {
	exePath, err := os.Executable()
	if err != nil {
		core.Log.Warnf("WFP", "Cannot get exe path for firewall rules: %v", err)
		return
	}

	dir := filepath.Dir(exePath)

	type fwRule struct {
		suffix string
		path   string
	}

	rules := []fwRule{
		{"Service", exePath},
	}

	for _, name := range []string{"awg-split-tunnel-ui.exe", "awg-split-tunnel-updater.exe"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			var suffix string
			switch name {
			case "awg-split-tunnel-ui.exe":
				suffix = "UI"
			case "awg-split-tunnel-updater.exe":
				suffix = "Updater"
			}
			rules = append(rules, fwRule{suffix, p})
		}
	}

	for _, r := range rules {
		name := firewallRulePrefix + " " + r.suffix
		ensureFirewallRule(name, r.path)
	}
}

func ensureFirewallRule(name, exePath string) {
	// Check if rule already exists (exit code 0 = found).
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+name)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if cmd.Run() == nil {
		return
	}

	// Add inbound allow rule for the executable.
	add := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name,
		"dir=in",
		"action=allow",
		"program="+exePath,
		"enable=yes",
		"profile=any",
	)
	add.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := add.Run(); err != nil {
		core.Log.Warnf("WFP", "Failed to add firewall rule %q: %v", name, err)
		return
	}
	core.Log.Infof("WFP", "Added Windows Firewall rule: %s (%s)", name, exePath)
}
