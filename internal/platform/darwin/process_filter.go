//go:build darwin

package darwin

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"

	"awg-split-tunnel/internal/core"
)

const (
	pfAnchorRoot       = "com.awg"
	pfAnchorDNS        = "com.awg/dns"
	pfAnchorIPv6       = "com.awg/ipv6"
	pfAnchorKillSwitch = "com.awg/killswitch"
)

// ProcessFilter implements platform.ProcessFilter using macOS PF (Packet Filter).
//
// Per-process blocking is advisory on macOS — PF cannot filter by process,
// so routing through utun provides the actual traffic enforcement.
// DNS leak protection and IPv6 blocking use PF anchor rules.
type ProcessFilter struct {
	mu sync.Mutex

	pfToken string // PF reference counting token from pfctl -E
	pfSetup bool   // whether PF anchor is registered in running config

	// DNS leak protection state.
	dnsBlockedIf  string // interface name where DNS is blocked (e.g. "en0")
	dnsPermitSelf bool   // whether self-permit is active

	// IPv6 blocking state.
	ipv6Blocked bool

	// Kill switch state.
	killSwitchActive bool

	// Per-process tracking (advisory — routing does actual enforcement).
	blocked map[string]bool
}

// NewProcessFilter creates a macOS PF-based process filter.
// Enables PF with reference counting and registers our anchor.
func NewProcessFilter() (*ProcessFilter, error) {
	f := &ProcessFilter{
		blocked: make(map[string]bool),
	}

	// Enable PF with reference counting.
	token, err := pfctlEnable()
	if err != nil {
		core.Log.Warnf("PF", "Could not enable PF: %v (continuing without PF rules)", err)
		return f, nil // non-fatal: routing still provides traffic capture
	}
	f.pfToken = token

	// Register our anchor in the running PF config.
	if err := f.ensureAnchorReference(); err != nil {
		core.Log.Warnf("PF", "Could not register PF anchor: %v", err)
	} else {
		f.pfSetup = true
	}

	core.Log.Infof("PF", "Packet filter initialized (token=%s)", f.pfToken)
	return f, nil
}

// ensureAnchorReference loads a temporary PF config that includes
// our anchor reference alongside the original /etc/pf.conf rules.
// Does not modify /etc/pf.conf on disk — only the running config.
// The anchor is inserted among filtering rules (before the first "anchor" line)
// to respect PF rule ordering: options, normalization, queueing, translation, filtering.
func (f *ProcessFilter) ensureAnchorReference() error {
	orig, err := os.ReadFile("/etc/pf.conf")
	if err != nil {
		return fmt.Errorf("read pf.conf: %w", err)
	}

	content := string(orig)

	// Skip if already referenced (e.g. from a previous un-cleaned run).
	if strings.Contains(content, pfAnchorRoot) {
		return nil
	}

	// Insert our anchor before the first plain "anchor" line (filtering section),
	// preserving PF rule ordering (scrub-anchor etc. come before filtering anchors).
	anchorLine := fmt.Sprintf("anchor \"%s/*\"", pfAnchorRoot)
	lines := strings.Split(content, "\n")
	var result []string
	inserted := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Insert before the first plain "anchor" line (filtering section).
		if !inserted && strings.HasPrefix(trimmed, "anchor ") {
			result = append(result, anchorLine)
			inserted = true
		}
		result = append(result, line)
	}
	if !inserted {
		result = append(result, anchorLine)
	}

	combined := strings.Join(result, "\n")
	cmd := exec.Command("pfctl", "-f", "-")
	cmd.Stdin = strings.NewReader(combined)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl load: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return nil
}

// --- Per-process tracking (advisory on macOS) ---

// EnsureBlocked tracks the process as blocked. On macOS, routing through utun
// enforces per-process traffic capture; PF cannot filter by process.
func (f *ProcessFilter) EnsureBlocked(exePath string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked[strings.ToLower(exePath)] = true
}

// BlockProcessOnRealNIC tracks the process as blocked.
func (f *ProcessFilter) BlockProcessOnRealNIC(exePath string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked[strings.ToLower(exePath)] = true
	return nil
}

// UnblockProcess removes process from blocked tracking.
func (f *ProcessFilter) UnblockProcess(exePath string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.blocked, strings.ToLower(exePath))
}

// UnblockAllProcesses clears all per-process tracking.
func (f *ProcessFilter) UnblockAllProcesses() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked = make(map[string]bool)
}

// --- Bypass prefixes ---

// AddBypassPrefixes is a no-op on macOS. Bypass prefixes are handled by routing
// (bypass routes via real NIC), and PF per-process blocking is not used.
func (f *ProcessFilter) AddBypassPrefixes(prefixes []netip.Prefix) error {
	return nil
}

// --- DNS leak protection ---

// BlockDNSOnInterface adds PF rules to block DNS (port 53 TCP+UDP) on the
// specified interface (typically the physical NIC). Prevents ISP DNS interception.
func (f *ProcessFilter) BlockDNSOnInterface(ifLUID uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.pfSetup {
		return fmt.Errorf("PF not initialized")
	}

	ifName, err := interfaceNameByIndex(ifLUID)
	if err != nil {
		return fmt.Errorf("resolve interface %d: %w", ifLUID, err)
	}

	f.dnsBlockedIf = ifName
	if err := f.rebuildDNSAnchor(); err != nil {
		return err
	}

	core.Log.Infof("PF", "DNS blocked on %s (port 53 TCP+UDP)", ifName)
	return nil
}

// UnblockDNSOnInterface removes DNS blocking rules.
func (f *ProcessFilter) UnblockDNSOnInterface() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.dnsBlockedIf = ""
	f.dnsPermitSelf = false

	if f.pfSetup {
		if err := pfctlFlushAnchor(pfAnchorDNS); err != nil {
			core.Log.Warnf("PF", "Flush DNS anchor: %v", err)
		}
	}
	core.Log.Infof("PF", "DNS block rules removed")
}

// PermitDNSForSelf allows our daemon process (running as root) to send DNS
// queries on the physical NIC. Weight overrides BlockDNSOnInterface via PF
// rule ordering (pass before block, both with "quick").
func (f *ProcessFilter) PermitDNSForSelf(ifLUID uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.pfSetup {
		return fmt.Errorf("PF not initialized")
	}

	f.dnsPermitSelf = true
	if err := f.rebuildDNSAnchor(); err != nil {
		return err
	}

	core.Log.Infof("PF", "DNS self-permit enabled for root on physical NIC")
	return nil
}

// RemoveDNSPermitForSelf removes DNS self-permit rules.
func (f *ProcessFilter) RemoveDNSPermitForSelf() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.dnsPermitSelf = false
	if f.pfSetup && f.dnsBlockedIf != "" {
		if err := f.rebuildDNSAnchor(); err != nil {
			core.Log.Warnf("PF", "Rebuild DNS anchor: %v", err)
		}
	}
}

// rebuildDNSAnchor regenerates the com.awg/dns anchor rules.
// Self-permit (pass) rules come before block rules — with "quick",
// the first match wins: root can send DNS, others are blocked.
// Must be called with f.mu held.
func (f *ProcessFilter) rebuildDNSAnchor() error {
	var rules strings.Builder

	// Self-permit rules FIRST (quick = first match wins).
	if f.dnsPermitSelf && f.dnsBlockedIf != "" {
		fmt.Fprintf(&rules, "pass out quick on %s proto tcp from any to any port 53 user root\n", f.dnsBlockedIf)
		fmt.Fprintf(&rules, "pass out quick on %s proto udp from any to any port 53 user root\n", f.dnsBlockedIf)
	}

	// Block DNS on physical NIC for everyone else.
	if f.dnsBlockedIf != "" {
		fmt.Fprintf(&rules, "block return out quick on %s proto tcp from any to any port 53\n", f.dnsBlockedIf)
		fmt.Fprintf(&rules, "block return out quick on %s proto udp from any to any port 53\n", f.dnsBlockedIf)
	}

	if rules.Len() == 0 {
		return pfctlFlushAnchor(pfAnchorDNS)
	}
	return pfctlLoadAnchor(pfAnchorDNS, rules.String())
}

// --- IPv6 blocking ---

// BlockAllIPv6 adds PF rules to block all IPv6 traffic (except loopback).
func (f *ProcessFilter) BlockAllIPv6() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.pfSetup {
		return fmt.Errorf("PF not initialized")
	}

	if f.ipv6Blocked {
		return nil
	}

	rules := "pass quick on lo0 inet6 all\nblock return quick inet6 all\n"
	if err := pfctlLoadAnchor(pfAnchorIPv6, rules); err != nil {
		return err
	}

	f.ipv6Blocked = true
	core.Log.Infof("PF", "IPv6 traffic blocked (loopback excepted)")
	return nil
}

// --- Kill Switch ---

// EnableKillSwitch blocks all non-VPN traffic except loopback and VPN endpoints.
// Uses PF anchor com.awg/killswitch with "quick" rules.
func (f *ProcessFilter) EnableKillSwitch(tunIfName string, vpnEndpoints []netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.pfSetup {
		return fmt.Errorf("PF not initialized")
	}

	var rules strings.Builder
	// Allow loopback.
	rules.WriteString("pass out quick on lo0 all\n")
	rules.WriteString("pass in quick on lo0 all\n")
	// Allow all traffic on TUN interface.
	fmt.Fprintf(&rules, "pass out quick on %s all\n", tunIfName)
	fmt.Fprintf(&rules, "pass in quick on %s all\n", tunIfName)
	// Allow traffic to VPN endpoints (needed for the tunnel itself).
	for _, ep := range vpnEndpoints {
		fmt.Fprintf(&rules, "pass out quick proto udp to %s\n", ep.String())
		fmt.Fprintf(&rules, "pass out quick proto tcp to %s\n", ep.String())
	}
	// Block everything else.
	rules.WriteString("block drop out quick all\n")
	rules.WriteString("block drop in quick all\n")

	if err := pfctlLoadAnchor(pfAnchorKillSwitch, rules.String()); err != nil {
		return err
	}

	f.killSwitchActive = true
	core.Log.Infof("PF", "Kill switch enabled (TUN=%s, %d VPN endpoints)", tunIfName, len(vpnEndpoints))
	return nil
}

// DisableKillSwitch removes the kill switch rules.
func (f *ProcessFilter) DisableKillSwitch() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.killSwitchActive {
		return nil
	}

	if f.pfSetup {
		if err := pfctlFlushAnchor(pfAnchorKillSwitch); err != nil {
			return err
		}
	}

	f.killSwitchActive = false
	core.Log.Infof("PF", "Kill switch disabled")
	return nil
}

// PermitDirectIPs is a no-op on macOS (routing handles direct bypass).
func (f *ProcessFilter) PermitDirectIPs(ips []netip.Addr) error {
	return nil
}

// RemoveDirectIPs is a no-op on macOS.
func (f *ProcessFilter) RemoveDirectIPs(ips []netip.Addr) {}

// --- Cleanup ---

// Close flushes all PF anchor rules, restores original pf.conf config,
// and releases the PF reference counting token.
func (f *ProcessFilter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.pfSetup {
		pfctlFlushAnchor(pfAnchorDNS)
		pfctlFlushAnchor(pfAnchorIPv6)
		pfctlFlushAnchor(pfAnchorKillSwitch)

		// Restore original pf.conf (removes our anchor reference from running config).
		if out, err := exec.Command("pfctl", "-f", "/etc/pf.conf").CombinedOutput(); err != nil {
			core.Log.Warnf("PF", "Restore pf.conf: %s: %v", strings.TrimSpace(string(out)), err)
		}
		f.pfSetup = false
	}

	if f.pfToken != "" {
		exec.Command("pfctl", "-X", f.pfToken).Run()
		f.pfToken = ""
	}

	core.Log.Infof("PF", "Packet filter closed")
	return nil
}

// --- PF command helpers ---

// pfctlEnable enables PF with reference counting and returns the token.
func pfctlEnable() (string, error) {
	// pfctl -E may return non-zero if PF is already enabled; we still get a token.
	out, _ := exec.Command("pfctl", "-E").CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Token") {
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	return "", fmt.Errorf("no PF token in output: %s", strings.TrimSpace(string(out)))
}

// pfctlLoadAnchor loads rules into the specified PF anchor.
func pfctlLoadAnchor(anchor, rules string) error {
	cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -a %s: %s: %w", anchor, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// pfctlFlushAnchor removes all rules from the specified PF anchor.
func pfctlFlushAnchor(anchor string) error {
	out, err := exec.Command("pfctl", "-a", anchor, "-F", "all").CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl flush %s: %s: %w", anchor, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// interfaceNameByIndex resolves an interface index to its name (e.g. 4 → "en0").
func interfaceNameByIndex(index uint64) (string, error) {
	iface, err := net.InterfaceByIndex(int(index))
	if err != nil {
		return "", err
	}
	return iface.Name, nil
}
