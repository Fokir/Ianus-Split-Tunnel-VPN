//go:build windows

package gateway

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"awg-split-tunnel/internal/core"

	"golang.org/x/sys/windows"

	"github.com/tailscale/wf"
)

// WFP GUIDs for our provider and sublayer.
var (
	awgProviderID = wf.ProviderID{
		Data1: 0xABCD0001,
		Data2: 0x0001,
		Data3: 0x0001,
		Data4: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
	awgSublayerID = wf.SublayerID{
		Data1: 0xABCD0002,
		Data2: 0x0002,
		Data3: 0x0002,
		Data4: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
)

// WFPManager manages WFP per-process interface blocking rules.
// Uses Dynamic=true session so all rules auto-cleanup on process exit.
type WFPManager struct {
	session  *wf.Session
	tunLUID  uint64

	mu      sync.Mutex
	rules   map[string][]wf.RuleID // exePath (lowered) → rule IDs
	nextSeq uint32

	// directIPs tracks WFP PERMIT rules for direct-routed IPs (bypass TUN).
	directIPs map[[4]byte][]wf.RuleID
}

// NewWFPManager creates a WFP session with dynamic rules.
func NewWFPManager(tunLUID uint64) (*WFPManager, error) {
	sess, err := wf.New(&wf.Options{
		Name:        "AWG Split Tunnel",
		Description: "Per-process interface blocking for split tunneling",
		Dynamic:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("[WFP] open session: %w", err)
	}

	// Register our provider.
	if err := sess.AddProvider(&wf.Provider{
		ID:          awgProviderID,
		Name:        "AWG Split Tunnel",
		Description: "AWG Split Tunnel WFP Provider",
	}); err != nil {
		sess.Close()
		return nil, fmt.Errorf("[WFP] add provider: %w", err)
	}

	// Register our sublayer with maximum weight to ensure our rules take
	// precedence over third-party WFP filters (antivirus, firewalls, etc.).
	// Callout drivers bypass weight-based arbitration, so they must be
	// detected and stopped separately.
	if err := sess.AddSublayer(&wf.Sublayer{
		ID:       awgSublayerID,
		Name:     "AWG Split Tunnel Rules",
		Provider: awgProviderID,
		Weight:   0xFFFF, // maximum priority
	}); err != nil {
		sess.Close()
		return nil, fmt.Errorf("[WFP] add sublayer: %w", err)
	}

	core.Log.Infof("WFP", "Session opened (Dynamic=true, TUN LUID=0x%x)", tunLUID)

	return &WFPManager{
		session:   sess,
		tunLUID:   tunLUID,
		rules:     make(map[string][]wf.RuleID),
		directIPs: make(map[[4]byte][]wf.RuleID),
	}, nil
}

// EnsureBlocked idempotently ensures the process at exePath can only connect
// through the TUN adapter. If rules already exist for this path, this is a no-op.
func (w *WFPManager) EnsureBlocked(exePath string) {
	key := strings.ToLower(exePath)

	w.mu.Lock()
	if _, exists := w.rules[key]; exists {
		w.mu.Unlock()
		return
	}
	w.mu.Unlock()

	if err := w.BlockProcessOnRealNIC(exePath); err != nil {
		core.Log.Errorf("WFP", "Failed to block %s on real NIC: %v", exePath, err)
	}
}

// BlockProcessOnRealNIC adds WFP rules that block the given process on any
// interface except the TUN adapter.
//
// Rules:
// 1. ALE_AUTH_CONNECT_V4: Block if AppID matches AND LocalInterface != TUN LUID
// 2. ALE_AUTH_RECV_ACCEPT_V4: Block inbound (e.g. STUN responses) on non-TUN interface
func (w *WFPManager) BlockProcessOnRealNIC(exePath string) error {
	key := strings.ToLower(exePath)

	// Compute AppID outside the lock — this involves filesystem I/O
	// and can take milliseconds. We don't want to hold the mutex during this.
	appID, err := wf.AppID(exePath)
	if err != nil {
		return fmt.Errorf("[WFP] AppID(%s): %w", exePath, err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.rules[key]; exists {
		return nil // already blocked
	}

	var ruleIDs []wf.RuleID

	// Rule 1: Block outbound connections on non-TUN interfaces.
	// Exclude loopback traffic so localhost (127.0.0.1) remains reachable.
	connectRuleID := w.nextRuleID()
	if err := w.session.AddRule(&wf.Rule{
		ID:       connectRuleID,
		Name:     fmt.Sprintf("AWG block connect: %s", key),
		Layer:    wf.LayerALEAuthConnectV4,
		Sublayer: awgSublayerID,
		Weight:   1000,
		Conditions: []*wf.Match{
			{
				Field: wf.FieldALEAppID,
				Op:    wf.MatchTypeEqual,
				Value: appID,
			},
			{
				Field: wf.FieldIPLocalInterface,
				Op:    wf.MatchTypeNotEqual,
				Value: uint64(w.tunLUID),
			},
			{
				Field: wf.FieldFlags,
				Op:    wf.MatchTypeFlagsNoneSet,
				Value: wf.ConditionFlagIsLoopback,
			},
		},
		Action: wf.ActionBlock,
	}); err != nil {
		return fmt.Errorf("[WFP] add connect rule: %w", err)
	}
	ruleIDs = append(ruleIDs, connectRuleID)

	// Rule 2: Block inbound accept (STUN responses) on non-TUN interfaces.
	// Exclude loopback traffic so localhost (127.0.0.1) remains reachable.
	recvRuleID := w.nextRuleID()
	if err := w.session.AddRule(&wf.Rule{
		ID:       recvRuleID,
		Name:     fmt.Sprintf("AWG block recv: %s", key),
		Layer:    wf.LayerALEAuthRecvAcceptV4,
		Sublayer: awgSublayerID,
		Weight:   1000,
		Conditions: []*wf.Match{
			{
				Field: wf.FieldALEAppID,
				Op:    wf.MatchTypeEqual,
				Value: appID,
			},
			{
				Field: wf.FieldIPLocalInterface,
				Op:    wf.MatchTypeNotEqual,
				Value: uint64(w.tunLUID),
			},
			{
				Field: wf.FieldFlags,
				Op:    wf.MatchTypeFlagsNoneSet,
				Value: wf.ConditionFlagIsLoopback,
			},
		},
		Action: wf.ActionBlock,
	}); err != nil {
		// Rollback the first rule.
		w.session.DeleteRule(connectRuleID)
		return fmt.Errorf("[WFP] add recv rule: %w", err)
	}
	ruleIDs = append(ruleIDs, recvRuleID)

	w.rules[key] = ruleIDs
	core.Log.Debugf("WFP", "Blocked %s on real NIC (%d rules)", key, len(ruleIDs))
	return nil
}

// UnblockProcess removes WFP rules for the given process.
func (w *WFPManager) UnblockProcess(exePath string) {
	key := strings.ToLower(exePath)

	w.mu.Lock()
	ruleIDs, exists := w.rules[key]
	if exists {
		delete(w.rules, key)
	}
	w.mu.Unlock()

	for _, id := range ruleIDs {
		w.session.DeleteRule(id)
	}
}

// AddBypassPrefixes creates WFP PERMIT rules for bypass CIDRs.
// These rules have higher weight (2000) than per-process BLOCK rules (1000),
// ensuring traffic to bypass IPs is allowed on the real NIC even for
// WFP-blocked processes.
//
// This is needed because connected subnet routes (e.g. 192.168.1.0/24) are
// more specific than TUN's /1 split routes, so local traffic goes through
// the real NIC where per-process BLOCK rules would drop it.
func (w *WFPManager) AddBypassPrefixes(prefixes []netip.Prefix) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, prefix := range prefixes {
		if !prefix.Addr().Is4() {
			continue
		}

		// Permit outbound connections to bypass CIDRs on any interface.
		connectID := w.nextRuleID()
		if err := w.session.AddRule(&wf.Rule{
			ID:       connectID,
			Name:     fmt.Sprintf("AWG bypass permit connect: %s", prefix),
			Layer:    wf.LayerALEAuthConnectV4,
			Sublayer: awgSublayerID,
			Weight:   2000,
			Conditions: []*wf.Match{
				{
					Field: wf.FieldIPRemoteAddress,
					Op:    wf.MatchTypeEqual,
					Value: prefix,
				},
			},
			Action: wf.ActionPermit,
		}); err != nil {
			return fmt.Errorf("[WFP] add bypass permit connect %s: %w", prefix, err)
		}

		// Permit inbound responses from bypass CIDRs on any interface.
		recvID := w.nextRuleID()
		if err := w.session.AddRule(&wf.Rule{
			ID:       recvID,
			Name:     fmt.Sprintf("AWG bypass permit recv: %s", prefix),
			Layer:    wf.LayerALEAuthRecvAcceptV4,
			Sublayer: awgSublayerID,
			Weight:   2000,
			Conditions: []*wf.Match{
				{
					Field: wf.FieldIPRemoteAddress,
					Op:    wf.MatchTypeEqual,
					Value: prefix,
				},
			},
			Action: wf.ActionPermit,
		}); err != nil {
			return fmt.Errorf("[WFP] add bypass permit recv %s: %w", prefix, err)
		}
	}

	core.Log.Infof("WFP", "Added bypass permits for %d prefixes", len(prefixes))
	return nil
}

// PermitDirectIPs adds WFP PERMIT rules for specific destination IPs, allowing
// blocked processes to reach these IPs directly on the real NIC (bypassing TUN).
// Weight 2000 overrides per-process BLOCK (1000), same as bypass prefixes.
// Idempotent: skips IPs that already have permit rules.
func (w *WFPManager) PermitDirectIPs(ips []netip.Addr) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	added := 0
	for _, ip := range ips {
		if !ip.Is4() {
			continue
		}
		key := ip.As4()
		if _, exists := w.directIPs[key]; exists {
			continue
		}

		prefix := netip.PrefixFrom(ip, 32)

		connectID := w.nextRuleID()
		if err := w.session.AddRule(&wf.Rule{
			ID:       connectID,
			Name:     fmt.Sprintf("AWG direct permit connect: %s", ip),
			Layer:    wf.LayerALEAuthConnectV4,
			Sublayer: awgSublayerID,
			Weight:   2000,
			Conditions: []*wf.Match{
				{
					Field: wf.FieldIPRemoteAddress,
					Op:    wf.MatchTypeEqual,
					Value: prefix,
				},
			},
			Action: wf.ActionPermit,
		}); err != nil {
			return fmt.Errorf("[WFP] add direct permit connect %s: %w", ip, err)
		}

		recvID := w.nextRuleID()
		if err := w.session.AddRule(&wf.Rule{
			ID:       recvID,
			Name:     fmt.Sprintf("AWG direct permit recv: %s", ip),
			Layer:    wf.LayerALEAuthRecvAcceptV4,
			Sublayer: awgSublayerID,
			Weight:   2000,
			Conditions: []*wf.Match{
				{
					Field: wf.FieldIPRemoteAddress,
					Op:    wf.MatchTypeEqual,
					Value: prefix,
				},
			},
			Action: wf.ActionPermit,
		}); err != nil {
			_ = w.session.DeleteRule(connectID)
			return fmt.Errorf("[WFP] add direct permit recv %s: %w", ip, err)
		}

		w.directIPs[key] = []wf.RuleID{connectID, recvID}
		added++
	}

	if added > 0 {
		core.Log.Debugf("WFP", "Added direct permits for %d IPs (total tracked: %d)", added, len(w.directIPs))
	}
	return nil
}

// RemoveDirectIPs removes WFP PERMIT rules for the given destination IPs.
func (w *WFPManager) RemoveDirectIPs(ips []netip.Addr) {
	w.mu.Lock()
	defer w.mu.Unlock()

	removed := 0
	for _, ip := range ips {
		if !ip.Is4() {
			continue
		}
		key := ip.As4()
		ruleIDs, exists := w.directIPs[key]
		if !exists {
			continue
		}
		for _, id := range ruleIDs {
			_ = w.session.DeleteRule(id)
		}
		delete(w.directIPs, key)
		removed++
	}

	if removed > 0 {
		core.Log.Debugf("WFP", "Removed direct permits for %d IPs (total tracked: %d)", removed, len(w.directIPs))
	}
}

// Special keys for DNS-related WFP rules.
const (
	wfpDNSBlockKey      = "__dns_block__"
	wfpDNSPermitSelfKey = "__dns_self_permit__"
)

// BlockDNSOnInterface adds WFP rules to block DNS (UDP/TCP port 53) on a
// specific interface (typically the physical NIC). This prevents ISP DPI from
// intercepting DNS queries while keeping DNS available on other adapters
// (e.g. VMware, Hyper-V work subnets).
// Idempotent: no-op if already blocked.
func (w *WFPManager) BlockDNSOnInterface(ifLUID uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.rules[wfpDNSBlockKey]; exists {
		return nil // already blocked
	}

	var ruleIDs []wf.RuleID

	for _, proto := range []uint8{17, 6} {
		protoName := "UDP"
		if proto == 6 {
			protoName = "TCP"
		}

		ruleID := w.nextRuleID()
		if err := w.session.AddRule(&wf.Rule{
			ID:       ruleID,
			Name:     fmt.Sprintf("AWG block DNS leak: %s:53 on LUID 0x%x", protoName, ifLUID),
			Layer:    wf.LayerALEAuthConnectV4,
			Sublayer: awgSublayerID,
			Weight:   3000,
			Conditions: []*wf.Match{
				{
					Field: wf.FieldIPProtocol,
					Op:    wf.MatchTypeEqual,
					Value: proto,
				},
				{
					Field: wf.FieldIPRemotePort,
					Op:    wf.MatchTypeEqual,
					Value: uint16(53),
				},
				{
					Field: wf.FieldIPLocalInterface,
					Op:    wf.MatchTypeEqual,
					Value: ifLUID,
				},
			},
			Action: wf.ActionBlock,
		}); err != nil {
			return fmt.Errorf("[WFP] block DNS leak %s: %w", protoName, err)
		}
		ruleIDs = append(ruleIDs, ruleID)
	}

	w.rules[wfpDNSBlockKey] = ruleIDs
	core.Log.Infof("WFP", "DNS blocked on interface LUID 0x%x (port 53 UDP+TCP)", ifLUID)
	return nil
}

// UnblockDNSOnInterface removes the DNS blocking rules added by BlockDNSOnInterface.
func (w *WFPManager) UnblockDNSOnInterface() {
	w.removeRulesByKey(wfpDNSBlockKey)
	core.Log.Infof("WFP", "DNS block rules removed")
}

// PermitDNSForSelf adds WFP PERMIT rules allowing our own process to send DNS
// queries on the specified interface. This is needed so the DNS resolver can
// fall back to the direct provider (real NIC) when VPN tunnels are down.
// Weight 4000 overrides BlockDNSOnInterface (weight 3000).
// Idempotent: no-op if already permitted.
func (w *WFPManager) PermitDNSForSelf(ifLUID uint64) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("[WFP] get executable path: %w", err)
	}

	appID, err := wf.AppID(exePath)
	if err != nil {
		return fmt.Errorf("[WFP] AppID(%s): %w", exePath, err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.rules[wfpDNSPermitSelfKey]; exists {
		return nil // already permitted
	}

	var ruleIDs []wf.RuleID

	for _, proto := range []uint8{17, 6} {
		protoName := "UDP"
		if proto == 6 {
			protoName = "TCP"
		}

		ruleID := w.nextRuleID()
		if err := w.session.AddRule(&wf.Rule{
			ID:       ruleID,
			Name:     fmt.Sprintf("AWG permit DNS self: %s:53 on LUID 0x%x", protoName, ifLUID),
			Layer:    wf.LayerALEAuthConnectV4,
			Sublayer: awgSublayerID,
			Weight:   4000,
			Conditions: []*wf.Match{
				{
					Field: wf.FieldALEAppID,
					Op:    wf.MatchTypeEqual,
					Value: appID,
				},
				{
					Field: wf.FieldIPProtocol,
					Op:    wf.MatchTypeEqual,
					Value: proto,
				},
				{
					Field: wf.FieldIPRemotePort,
					Op:    wf.MatchTypeEqual,
					Value: uint16(53),
				},
				{
					Field: wf.FieldIPLocalInterface,
					Op:    wf.MatchTypeEqual,
					Value: ifLUID,
				},
			},
			Action: wf.ActionPermit,
		}); err != nil {
			return fmt.Errorf("[WFP] permit DNS self %s: %w", protoName, err)
		}
		ruleIDs = append(ruleIDs, ruleID)
	}

	w.rules[wfpDNSPermitSelfKey] = ruleIDs
	core.Log.Infof("WFP", "DNS self-permit on interface LUID 0x%x (port 53 UDP+TCP)", ifLUID)
	return nil
}

// RemoveDNSPermitForSelf removes the DNS self-permit rules added by PermitDNSForSelf.
func (w *WFPManager) RemoveDNSPermitForSelf() {
	w.removeRulesByKey(wfpDNSPermitSelfKey)
}

// UnblockAllProcesses removes all per-process WFP rules (but not IPv6, DNS, or
// bypass rules). Used when deactivating the gateway so that previously blocked
// apps can reach the real NIC directly.
func (w *WFPManager) UnblockAllProcesses() {
	w.mu.Lock()
	var toDelete []wf.RuleID
	for key, ids := range w.rules {
		switch key {
		case "__ipv6_block__", wfpDNSBlockKey, wfpDNSPermitSelfKey:
			continue // keep these
		}
		toDelete = append(toDelete, ids...)
		delete(w.rules, key)
	}
	w.mu.Unlock()

	for _, id := range toDelete {
		w.session.DeleteRule(id)
	}
	if len(toDelete) > 0 {
		core.Log.Infof("WFP", "Removed all per-process blocking rules (%d rules)", len(toDelete))
	}
}

// removeRulesByKey removes all WFP rules stored under the given key.
func (w *WFPManager) removeRulesByKey(key string) {
	w.mu.Lock()
	ruleIDs, exists := w.rules[key]
	if exists {
		delete(w.rules, key)
	}
	w.mu.Unlock()

	for _, id := range ruleIDs {
		w.session.DeleteRule(id)
	}
}

// BlockAllIPv6 adds WFP rules that block all IPv6 traffic (except loopback)
// while the VPN session is active. This prevents IPv6 leaks since the project
// is IPv4-only. Rules are stored under "__ipv6_block__" key and auto-removed
// when the Dynamic=true session closes.
func (w *WFPManager) BlockAllIPv6() error {
	const key = "__ipv6_block__"

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.rules[key]; exists {
		return nil
	}

	var ruleIDs []wf.RuleID

	// Rule 1: Block all outbound IPv6 connections (except loopback).
	connectRuleID := w.nextRuleID()
	if err := w.session.AddRule(&wf.Rule{
		ID:       connectRuleID,
		Name:     "AWG block IPv6 connect",
		Layer:    wf.LayerALEAuthConnectV6,
		Sublayer: awgSublayerID,
		Weight:   500,
		Conditions: []*wf.Match{
			{
				Field: wf.FieldFlags,
				Op:    wf.MatchTypeFlagsNoneSet,
				Value: wf.ConditionFlagIsLoopback,
			},
		},
		Action: wf.ActionBlock,
	}); err != nil {
		return fmt.Errorf("[WFP] add IPv6 connect block: %w", err)
	}
	ruleIDs = append(ruleIDs, connectRuleID)

	// Rule 2: Block all inbound IPv6 traffic (except loopback).
	recvRuleID := w.nextRuleID()
	if err := w.session.AddRule(&wf.Rule{
		ID:       recvRuleID,
		Name:     "AWG block IPv6 recv",
		Layer:    wf.LayerALEAuthRecvAcceptV6,
		Sublayer: awgSublayerID,
		Weight:   500,
		Conditions: []*wf.Match{
			{
				Field: wf.FieldFlags,
				Op:    wf.MatchTypeFlagsNoneSet,
				Value: wf.ConditionFlagIsLoopback,
			},
		},
		Action: wf.ActionBlock,
	}); err != nil {
		w.session.DeleteRule(connectRuleID)
		return fmt.Errorf("[WFP] add IPv6 recv block: %w", err)
	}
	ruleIDs = append(ruleIDs, recvRuleID)

	w.rules[key] = ruleIDs
	core.Log.Infof("WFP", "IPv6 traffic blocked (%d rules)", len(ruleIDs))
	return nil
}

// EnableKillSwitch is a no-op on Windows. WFP per-process blocking rules
// already enforce traffic through the TUN adapter, providing equivalent protection.
func (w *WFPManager) EnableKillSwitch(tunIfName string, vpnEndpoints []netip.Addr) error {
	return nil
}

// DisableKillSwitch is a no-op on Windows.
func (w *WFPManager) DisableKillSwitch() error {
	return nil
}

// Close closes the WFP session. Dynamic=true means all rules are auto-removed.
func (w *WFPManager) Close() error {
	if w.session != nil {
		err := w.session.Close()
		core.Log.Infof("WFP", "Session closed")
		return err
	}
	return nil
}

// CleanupConflictingWFP removes orphaned WFP providers, sublayers, and filters
// created by conflicting software (WinDivert, GearUP Booster, etc.). These
// programs register kernel callout drivers that create WFP objects; after the
// driver is stopped these may linger if the driver didn't unload cleanly.
// This function opens a temporary non-dynamic session, enumerates all WFP state,
// and removes anything matching known conflicting patterns.
//
// Safe to call even if no conflicting artifacts exist.
func CleanupConflictingWFP() error {
	sess, err := wf.New(&wf.Options{
		Name:        "AWG Conflicting WFP Cleanup",
		Description: "Temporary session for removing conflicting WFP artifacts",
		Dynamic:     false, // deletions must persist after session closes
	})
	if err != nil {
		return fmt.Errorf("[WFP] open cleanup session: %w", err)
	}
	defer sess.Close()

	// Step 1: find conflicting providers.
	providers, err := sess.Providers()
	if err != nil {
		return fmt.Errorf("[WFP] enumerate providers: %w", err)
	}

	var conflictingProviders []wf.ProviderID
	for _, p := range providers {
		if isConflictingWFPName(p.Name) || isConflictingWFPName(p.Description) {
			conflictingProviders = append(conflictingProviders, p.ID)
			core.Log.Infof("WFP", "Found conflicting provider %q (%v)", p.Name, p.ID)
		}
	}

	if len(conflictingProviders) == 0 {
		core.Log.Infof("WFP", "No conflicting WFP artifacts found")
		return nil
	}

	// Step 2: delete filters that belong to conflicting providers.
	rules, err := sess.Rules()
	if err != nil {
		core.Log.Warnf("WFP", "Enumerate rules for cleanup: %v", err)
	} else {
		var deleted int
		for _, r := range rules {
			if providerIn(r.Provider, conflictingProviders) || isConflictingWFPName(r.Name) {
				if err := sess.DeleteRule(r.ID); err != nil {
					core.Log.Warnf("WFP", "Delete conflicting rule %v: %v", r.ID, err)
				} else {
					deleted++
				}
			}
		}
		if deleted > 0 {
			core.Log.Infof("WFP", "Deleted %d conflicting WFP filters", deleted)
		}
	}

	// Step 3: delete sublayers that belong to conflicting providers.
	for _, pid := range conflictingProviders {
		sublayers, err := sess.Sublayers(pid)
		if err != nil {
			core.Log.Warnf("WFP", "Enumerate sublayers for provider %v: %v", pid, err)
			continue
		}
		for _, sl := range sublayers {
			if err := sess.DeleteSublayer(sl.ID); err != nil {
				core.Log.Warnf("WFP", "Delete conflicting sublayer %v: %v", sl.ID, err)
			} else {
				core.Log.Infof("WFP", "Deleted conflicting sublayer %q", sl.Name)
			}
		}
	}

	// Step 4: delete the conflicting providers themselves.
	for _, pid := range conflictingProviders {
		if err := sess.DeleteProvider(pid); err != nil {
			core.Log.Warnf("WFP", "Delete conflicting provider %v: %v", pid, err)
		} else {
			core.Log.Infof("WFP", "Deleted conflicting provider %v", pid)
		}
	}

	return nil
}

// isConflictingWFPName checks whether a WFP object name/description belongs to
// known conflicting software (WinDivert, GearUP Booster, etc.).
func isConflictingWFPName(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "windivert") ||
		strings.Contains(lower, "gearup") ||
		strings.Contains(lower, "gunetfilter") ||
		strings.Contains(lower, "hostpacket")
}

// providerIn checks whether pid is in the list.
func providerIn(pid wf.ProviderID, list []wf.ProviderID) bool {
	for _, p := range list {
		if p == pid {
			return true
		}
	}
	return false
}

// ConflictingWFPProvider describes a third-party WFP provider that has callout
// rules which may conflict with our TUN routing.
type ConflictingWFPProvider struct {
	Name         string // provider name (e.g. "WinDivert")
	Description  string // provider description
	CalloutRules int    // number of callout-based rules
	TotalRules   int    // total rules from this provider
}

// DetectConflictingWFPCallouts opens a temporary WFP session and enumerates all
// rules looking for third-party callout-based filters. Callout drivers (like
// WinDivert, GearUP, npcap) intercept packets at the kernel level and bypass
// normal WFP weight-based arbitration — they are the primary source of routing
// conflicts that cannot be resolved by simply increasing our sublayer weight.
//
// Returns a list of conflicting providers with callout rules. Returns nil if
// no conflicts are found.
func DetectConflictingWFPCallouts() ([]ConflictingWFPProvider, error) {
	sess, err := wf.New(&wf.Options{
		Name:        "AWG WFP Conflict Detection",
		Description: "Temporary session for detecting conflicting WFP callouts",
		Dynamic:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("[WFP] open detection session: %w", err)
	}
	defer sess.Close()

	// Build a set of known safe provider IDs to exclude from conflict detection.
	// We exclude our own provider and zero (unowned system rules).
	safeProviders := map[wf.ProviderID]bool{
		awgProviderID:    true,
		wf.ProviderID{}: true, // unowned / system rules
	}

	// Enumerate providers to build a name map and identify Microsoft/system providers.
	providers, err := sess.Providers()
	if err != nil {
		return nil, fmt.Errorf("[WFP] enumerate providers: %w", err)
	}
	providerNames := make(map[wf.ProviderID]string)
	providerDescs := make(map[wf.ProviderID]string)
	for _, p := range providers {
		providerNames[p.ID] = p.Name
		providerDescs[p.ID] = p.Description
		// Mark Microsoft/system providers as safe — they don't conflict with
		// VPN routing (Windows Firewall, IPsec, etc.).
		lower := strings.ToLower(p.Name + " " + p.Description)
		if strings.Contains(lower, "microsoft") ||
			strings.Contains(lower, "windows") ||
			p.Name == "" {
			safeProviders[p.ID] = true
		}
	}

	// Enumerate all rules and find callout-based ones from third-party providers.
	rules, err := sess.Rules()
	if err != nil {
		return nil, fmt.Errorf("[WFP] enumerate rules: %w", err)
	}

	type providerStats struct {
		calloutRules int
		totalRules   int
	}
	stats := make(map[wf.ProviderID]*providerStats)

	for _, r := range rules {
		if safeProviders[r.Provider] {
			continue
		}
		if stats[r.Provider] == nil {
			stats[r.Provider] = &providerStats{}
		}
		stats[r.Provider].totalRules++
		if r.Action == wf.ActionCalloutTerminating ||
			r.Action == wf.ActionCalloutInspection ||
			r.Action == wf.ActionCalloutUnknown {
			stats[r.Provider].calloutRules++
		}
	}

	// Build result — only include providers with callout rules.
	var result []ConflictingWFPProvider
	for pid, s := range stats {
		if s.calloutRules > 0 {
			result = append(result, ConflictingWFPProvider{
				Name:         providerNames[pid],
				Description:  providerDescs[pid],
				CalloutRules: s.calloutRules,
				TotalRules:   s.totalRules,
			})
		}
	}

	return result, nil
}

func (w *WFPManager) nextRuleID() wf.RuleID {
	w.nextSeq++
	guid, err := windows.GenerateGUID()
	if err != nil {
		// Fallback to sequential GUIDs.
		return wf.RuleID{
			Data1: 0xABCD0100 + w.nextSeq,
			Data2: 0x0001,
			Data3: 0x0001,
			Data4: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		}
	}
	return wf.RuleID(guid)
}
