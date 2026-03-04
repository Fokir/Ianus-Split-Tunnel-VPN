//go:build windows

package gateway

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"awg-split-tunnel/internal/core"

	"golang.org/x/sys/windows"

	"github.com/tailscale/wf"
)

const (
	// wfpTxnTimeout is the WFP session transaction timeout.
	// If BFE (Base Filtering Engine) is busy, WFP operations wait up to this
	// duration to acquire the global transaction lock before returning an error.
	// Default WFP timeout is 15s; we use 5s for faster failure detection.
	wfpTxnTimeout = 5 * time.Second

	// wfpRetryDelay is the delay before retrying a failed WFP operation.
	wfpRetryDelay = 100 * time.Millisecond

	// wfpMaxRetries is the number of retry attempts for transient WFP failures.
	wfpMaxRetries = 2
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

// dualStackLayers pairs IPv4 and IPv6 ALE layers for dual-stack rule creation.
// Every per-process or interface-scoped rule must be applied on both stacks to
// prevent traffic leaks through IPv6 dual-stack sockets.
var dualStackLayers = []struct {
	connect wf.LayerID
	recv    wf.LayerID
	tag     string // suffix for rule names
}{
	{wf.LayerALEAuthConnectV4, wf.LayerALEAuthRecvAcceptV4, ""},
	{wf.LayerALEAuthConnectV6, wf.LayerALEAuthRecvAcceptV6, " V6"},
}

// isWin11_24H2OrLater detects Windows 11 24H2 (build 26100+) where WFP
// ActionBlock on UDP at ALE layers causes system-wide DNS hang.
func isWin11_24H2OrLater() (bool, uint32) {
	info := windows.RtlGetVersion()
	return info.BuildNumber >= 26100, info.BuildNumber
}

// WFPManager manages WFP per-process interface blocking rules.
// Uses Dynamic=true session so all rules auto-cleanup on process exit.
type WFPManager struct {
	session  *wf.Session
	tunLUID  uint64

	// skipUDPBlock is true on Win11 24H2+ to avoid kernel UDP hang.
	// When set, BLOCK rules only match TCP (protocol 6), and UDP DNS
	// block rules are skipped entirely.
	skipUDPBlock bool

	mu      sync.Mutex
	rules   map[string][]wf.RuleID // exePath (lowered) → rule IDs
	nextSeq uint32

	// directIPs tracks WFP PERMIT rules for direct-routed IPs (bypass TUN).
	directIPs map[[4]byte][]wf.RuleID
}

// CleanupOrphanedOwnFilters removes WFP rules, sublayers, and provider left
// behind by a previous instance that did not shut down cleanly (BSOD, power
// loss, taskkill /F). Opens a temporary non-dynamic session, enumerates all
// WFP objects belonging to awgProviderID, and deletes them.
// Safe to call even if no orphaned artifacts exist.
func CleanupOrphanedOwnFilters() {
	sess, err := wf.New(&wf.Options{
		Name:                    "AWG Orphan Cleanup",
		Description:             "Temporary session for removing orphaned AWG WFP artifacts",
		Dynamic:                 false, // deletions must persist after session closes
		TransactionStartTimeout: wfpTxnTimeout,
	})
	if err != nil {
		core.Log.Warnf("WFP", "Open orphan cleanup session: %v", err)
		return
	}
	defer sess.Close()

	// Step 1: delete orphaned rules belonging to our provider.
	rules, err := sess.Rules()
	if err != nil {
		core.Log.Warnf("WFP", "Enumerate rules for orphan cleanup: %v", err)
	} else {
		var deleted int
		for _, r := range rules {
			if r.Provider == awgProviderID {
				if err := sess.DeleteRule(r.ID); err != nil {
					core.Log.Warnf("WFP", "Delete orphaned rule %v: %v", r.ID, err)
				} else {
					deleted++
				}
			}
		}
		if deleted > 0 {
			core.Log.Infof("WFP", "Removed %d orphaned WFP filters from previous session", deleted)
		}
	}

	// Step 2: delete orphaned sublayers.
	sublayers, err := sess.Sublayers(awgProviderID)
	if err != nil {
		core.Log.Warnf("WFP", "Enumerate sublayers for orphan cleanup: %v", err)
	} else {
		for _, sl := range sublayers {
			if err := sess.DeleteSublayer(sl.ID); err != nil {
				core.Log.Warnf("WFP", "Delete orphaned sublayer %v: %v", sl.ID, err)
			} else {
				core.Log.Infof("WFP", "Removed orphaned sublayer %q", sl.Name)
			}
		}
	}

	// Step 3: delete the orphaned provider itself.
	if err := sess.DeleteProvider(awgProviderID); err != nil {
		// Expected if no orphaned provider exists — not an error.
	} else {
		core.Log.Infof("WFP", "Removed orphaned provider")
	}
}

// NewWFPManager creates a WFP session with dynamic rules.
func NewWFPManager(tunLUID uint64) (*WFPManager, error) {
	// Clean up any orphaned WFP artifacts from a previous unclean shutdown.
	CleanupOrphanedOwnFilters()
	sess, err := wf.New(&wf.Options{
		Name:                    "AWG Split Tunnel",
		Description:             "Per-process interface blocking for split tunneling",
		Dynamic:                 true,
		TransactionStartTimeout: wfpTxnTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("[WFP] open session: %w", err)
	}

	// Register our provider. If it already exists (e.g. another instance's
	// dynamic session is still alive), delete it and retry once.
	provider := &wf.Provider{
		ID:          awgProviderID,
		Name:        "AWG Split Tunnel",
		Description: "AWG Split Tunnel WFP Provider",
	}
	if err := sess.AddProvider(provider); err != nil {
		core.Log.Warnf("WFP", "Provider already exists, deleting and retrying: %v", err)
		_ = sess.DeleteProvider(awgProviderID)
		if err := sess.AddProvider(provider); err != nil {
			sess.Close()
			return nil, fmt.Errorf("[WFP] add provider (retry): %w", err)
		}
	}

	// Register our sublayer with maximum weight to ensure our rules take
	// precedence over third-party WFP filters (antivirus, firewalls, etc.).
	// Callout drivers bypass weight-based arbitration, so they must be
	// detected and stopped separately.
	// If the sublayer already exists (e.g. stale dynamic session from a crashed
	// instance that BFE hasn't cleaned up yet), delete and retry once.
	sublayer := &wf.Sublayer{
		ID:       awgSublayerID,
		Name:     "AWG Split Tunnel Rules",
		Provider: awgProviderID,
		Weight:   0xFFFF, // maximum priority
	}
	if err := sess.AddSublayer(sublayer); err != nil {
		core.Log.Warnf("WFP", "Sublayer already exists, deleting and retrying: %v", err)
		_ = sess.DeleteSublayer(awgSublayerID)
		if err := sess.AddSublayer(sublayer); err != nil {
			sess.Close()
			return nil, fmt.Errorf("[WFP] add sublayer (retry): %w — another instance may be running", err)
		}
	}

	skipUDP, buildNum := isWin11_24H2OrLater()
	if skipUDP {
		core.Log.Warnf("WFP", "Win11 24H2+ detected (build %d): UDP BLOCK rules disabled to prevent kernel hang", buildNum)
	}
	core.Log.Infof("WFP", "Session opened (Dynamic=true, TUN LUID=0x%x, build=%d)", tunLUID, buildNum)

	return &WFPManager{
		session:      sess,
		tunLUID:      tunLUID,
		skipUDPBlock: skipUDP,
		rules:        make(map[string][]wf.RuleID),
		directIPs:    make(map[[4]byte][]wf.RuleID),
	}, nil
}

// addRuleWithRetry attempts to add a WFP rule, retrying on transient BFE
// failures (e.g. lock contention). Returns the error from the last attempt.
func (w *WFPManager) addRuleWithRetry(rule *wf.Rule) error {
	var err error
	for attempt := 0; attempt <= wfpMaxRetries; attempt++ {
		if err = w.session.AddRule(rule); err == nil {
			return nil
		}
		if attempt < wfpMaxRetries {
			core.Log.Warnf("WFP", "AddRule %q attempt %d failed (retrying in %v): %v",
				rule.Name, attempt+1, wfpRetryDelay, err)
			time.Sleep(wfpRetryDelay)
		}
	}
	return err
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
// interface except the TUN adapter. Rules are applied on both V4 and V6 ALE
// layers to prevent traffic leaks through IPv6 dual-stack sockets.
//
// Rules (per IP version):
// 1. ALE_AUTH_CONNECT: Block if AppID matches AND LocalInterface != TUN LUID
// 2. ALE_AUTH_RECV_ACCEPT: Block inbound (e.g. STUN responses) on non-TUN interface
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

	// Block outbound connections and inbound accept on non-TUN interfaces.
	// Applied on both V4 and V6 ALE layers to prevent dual-stack socket bypass.
	// Exclude loopback traffic so localhost remains reachable.
	// On Win11 24H2+, only block TCP to avoid kernel UDP hang.
	for _, ds := range dualStackLayers {
		conditions := []*wf.Match{
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
		}
		if w.skipUDPBlock {
			conditions = append(conditions, &wf.Match{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: uint8(6), // TCP only
			})
		}

		connectRuleID := w.nextRuleID()
		if err := w.addRuleWithRetry(&wf.Rule{
			ID:         connectRuleID,
			Name:       fmt.Sprintf("AWG block connect%s: %s", ds.tag, key),
			Layer:      ds.connect,
			Sublayer:   awgSublayerID,
			Weight:     1000,
			Conditions: conditions,
			Action:     wf.ActionBlock,
		}); err != nil {
			for _, id := range ruleIDs {
				w.session.DeleteRule(id)
			}
			return fmt.Errorf("[WFP] add connect%s rule: %w", ds.tag, err)
		}
		ruleIDs = append(ruleIDs, connectRuleID)

		recvRuleID := w.nextRuleID()
		if err := w.addRuleWithRetry(&wf.Rule{
			ID:         recvRuleID,
			Name:       fmt.Sprintf("AWG block recv%s: %s", ds.tag, key),
			Layer:      ds.recv,
			Sublayer:   awgSublayerID,
			Weight:     1000,
			Conditions: conditions,
			Action:     wf.ActionBlock,
		}); err != nil {
			for _, id := range ruleIDs {
				w.session.DeleteRule(id)
			}
			return fmt.Errorf("[WFP] add recv%s rule: %w", ds.tag, err)
		}
		ruleIDs = append(ruleIDs, recvRuleID)
	}

	w.rules[key] = ruleIDs
	core.Log.Debugf("WFP", "Blocked %s on real NIC (%d rules, dual-stack)", key, len(ruleIDs))
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

// Special keys for WFP rules.
const (
	wfpDNSBlockKey            = "__dns_block__"
	wfpDoHDoTBlockKey         = "__doh_dot_block__"
	wfpDNSPermitSelfKey       = "__dns_self_permit__"
	wfpDefaultBlockKey        = "__default_block__"
	wfpVirtualAdapterKey      = "__virtual_adapter__"
)

// knownDoHDoTServers contains well-known public DNS resolver IPs that support
// DNS-over-HTTPS (port 443) and DNS-over-TLS (port 853). Blocking these on
// the physical NIC prevents DNS leaks via encrypted DNS protocols.
var knownDoHDoTServers = []netip.Addr{
	// Google Public DNS
	netip.MustParseAddr("8.8.8.8"),
	netip.MustParseAddr("8.8.4.4"),
	netip.MustParseAddr("2001:4860:4860::8888"),
	netip.MustParseAddr("2001:4860:4860::8844"),
	// Cloudflare DNS
	netip.MustParseAddr("1.1.1.1"),
	netip.MustParseAddr("1.0.0.1"),
	netip.MustParseAddr("2606:4700:4700::1111"),
	netip.MustParseAddr("2606:4700:4700::1001"),
	// Quad9
	netip.MustParseAddr("9.9.9.9"),
	netip.MustParseAddr("149.112.112.112"),
	netip.MustParseAddr("2620:fe::fe"),
	netip.MustParseAddr("2620:fe::9"),
	// OpenDNS (Cisco)
	netip.MustParseAddr("208.67.222.222"),
	netip.MustParseAddr("208.67.220.220"),
	netip.MustParseAddr("2620:119:35::35"),
	netip.MustParseAddr("2620:119:53::53"),
	// NextDNS
	netip.MustParseAddr("45.90.28.0"),
	netip.MustParseAddr("45.90.30.0"),
	netip.MustParseAddr("2a07:a8c0::"),
	netip.MustParseAddr("2a07:a8c1::"),
	// AdGuard DNS
	netip.MustParseAddr("94.140.14.14"),
	netip.MustParseAddr("94.140.15.15"),
	netip.MustParseAddr("2a10:50c0::ad1:ff"),
	netip.MustParseAddr("2a10:50c0::ad2:ff"),
	// CleanBrowsing
	netip.MustParseAddr("185.228.168.9"),
	netip.MustParseAddr("185.228.169.9"),
}

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

	// Block DNS on both V4 and V6 ALE layers to prevent dual-stack DNS leaks.
	// On Win11 24H2+, skip UDP DNS block to avoid kernel hang.
	for _, ds := range dualStackLayers {
		for _, proto := range []uint8{17, 6} {
			if proto == 17 && w.skipUDPBlock {
				continue // skip UDP DNS block on 24H2+
			}

			protoName := "UDP"
			if proto == 6 {
				protoName = "TCP"
			}

			ruleID := w.nextRuleID()
			if err := w.addRuleWithRetry(&wf.Rule{
				ID:       ruleID,
				Name:     fmt.Sprintf("AWG block DNS leak%s: %s:53 on LUID 0x%x", ds.tag, protoName, ifLUID),
				Layer:    ds.connect,
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
				return fmt.Errorf("[WFP] block DNS leak%s %s: %w", ds.tag, protoName, err)
			}
			ruleIDs = append(ruleIDs, ruleID)
		}
	}

	w.rules[wfpDNSBlockKey] = ruleIDs
	if w.skipUDPBlock {
		core.Log.Infof("WFP", "DNS blocked on interface LUID 0x%x (port 53 TCP-only, dual-stack, UDP skipped for 24H2+)", ifLUID)
	} else {
		core.Log.Infof("WFP", "DNS blocked on interface LUID 0x%x (port 53 UDP+TCP, dual-stack)", ifLUID)
	}
	return nil
}

// UnblockDNSOnInterface removes the DNS blocking rules added by BlockDNSOnInterface.
func (w *WFPManager) UnblockDNSOnInterface() {
	w.removeRulesByKey(wfpDNSBlockKey)
	core.Log.Infof("WFP", "DNS block rules removed")
}

// BlockDoHDoTOnInterface adds WFP rules to block DNS-over-HTTPS (port 443) and
// DNS-over-TLS (port 853) to well-known public DNS resolvers on the specified
// interface. This prevents DNS leaks via encrypted DNS protocols that bypass
// the standard port-53 block.
// Idempotent: no-op if already blocked.
func (w *WFPManager) BlockDoHDoTOnInterface(ifLUID uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.rules[wfpDoHDoTBlockKey]; exists {
		return nil // already blocked
	}

	var ruleIDs []wf.RuleID

	// Ports to block: 443 (DoH) and 853 (DoT).
	dohDotPorts := []uint16{443, 853}

	for _, ds := range dualStackLayers {
		for _, ip := range knownDoHDoTServers {
			// Match IP version to layer: skip IPv6 addrs on V4 layer and vice versa.
			if ip.Is4() && ds.tag == " V6" {
				continue
			}
			if ip.Is6() && ds.tag == "" {
				continue
			}

			prefix := netip.PrefixFrom(ip, ip.BitLen())

			for _, port := range dohDotPorts {
				// TCP only — DoH uses HTTPS (TCP:443), DoT uses TLS (TCP:853).
				ruleID := w.nextRuleID()
				if err := w.addRuleWithRetry(&wf.Rule{
					ID:       ruleID,
					Name:     fmt.Sprintf("AWG block DoH/DoT%s: TCP:%d to %s on LUID 0x%x", ds.tag, port, ip, ifLUID),
					Layer:    ds.connect,
					Sublayer: awgSublayerID,
					Weight:   3000,
					Conditions: []*wf.Match{
						{
							Field: wf.FieldIPProtocol,
							Op:    wf.MatchTypeEqual,
							Value: uint8(6), // TCP
						},
						{
							Field: wf.FieldIPRemotePort,
							Op:    wf.MatchTypeEqual,
							Value: port,
						},
						{
							Field: wf.FieldIPRemoteAddress,
							Op:    wf.MatchTypeEqual,
							Value: prefix,
						},
						{
							Field: wf.FieldIPLocalInterface,
							Op:    wf.MatchTypeEqual,
							Value: ifLUID,
						},
					},
					Action: wf.ActionBlock,
				}); err != nil {
					return fmt.Errorf("[WFP] block DoH/DoT%s TCP:%d to %s: %w", ds.tag, port, ip, err)
				}
				ruleIDs = append(ruleIDs, ruleID)
			}
		}
	}

	w.rules[wfpDoHDoTBlockKey] = ruleIDs
	core.Log.Infof("WFP", "DoH/DoT blocked on interface LUID 0x%x (%d rules for %d resolvers, ports 443+853)",
		ifLUID, len(ruleIDs), len(knownDoHDoTServers))
	return nil
}

// UnblockDoHDoTOnInterface removes DoH/DoT blocking rules added by BlockDoHDoTOnInterface.
func (w *WFPManager) UnblockDoHDoTOnInterface() {
	w.removeRulesByKey(wfpDoHDoTBlockKey)
	core.Log.Infof("WFP", "DoH/DoT block rules removed")
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

	// Permit DNS on both V4 and V6 ALE layers (dual-stack).
	for _, ds := range dualStackLayers {
		for _, proto := range []uint8{17, 6} {
			protoName := "UDP"
			if proto == 6 {
				protoName = "TCP"
			}

			ruleID := w.nextRuleID()
			if err := w.session.AddRule(&wf.Rule{
				ID:       ruleID,
				Name:     fmt.Sprintf("AWG permit DNS self%s: %s:53 on LUID 0x%x", ds.tag, protoName, ifLUID),
				Layer:    ds.connect,
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
				return fmt.Errorf("[WFP] permit DNS self%s %s: %w", ds.tag, protoName, err)
			}
			ruleIDs = append(ruleIDs, ruleID)
		}
	}

	w.rules[wfpDNSPermitSelfKey] = ruleIDs
	core.Log.Infof("WFP", "DNS self-permit on interface LUID 0x%x (port 53 UDP+TCP, dual-stack)", ifLUID)
	return nil
}

// RemoveDNSPermitForSelf removes the DNS self-permit rules added by PermitDNSForSelf.
func (w *WFPManager) RemoveDNSPermitForSelf() {
	w.removeRulesByKey(wfpDNSPermitSelfKey)
}

// EnableDefaultBlock adds low-priority WFP BLOCK rules (weight 100) that block
// ALL processes on non-TUN, non-loopback interfaces. This forces all traffic
// through TUN when the gateway is active — fixing Windows 10 where some processes
// bypass TUN /1 split routes and send traffic directly through the physical NIC.
//
// A PERMIT rule (weight 200) is added for our own process so the direct proxy
// and DNS resolver can still dial out on the real NIC.
//
// Higher-weight rules override this: bypass PERMIT (2000), DNS BLOCK (3000), etc.
// Idempotent: no-op if already enabled.
func (w *WFPManager) EnableDefaultBlock() error {
	w.mu.Lock()
	if _, exists := w.rules[wfpDefaultBlockKey]; exists {
		w.mu.Unlock()
		return nil
	}
	w.mu.Unlock()

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

	// Double-check after re-acquiring lock.
	if _, exists := w.rules[wfpDefaultBlockKey]; exists {
		return nil
	}

	var ruleIDs []wf.RuleID

	// Block ALL traffic and permit self on both V4 and V6 ALE layers (dual-stack).
	// On Win11 24H2+, only block TCP to avoid kernel UDP hang.
	for _, ds := range dualStackLayers {
		blockConditions := []*wf.Match{
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
		}
		if w.skipUDPBlock {
			blockConditions = append(blockConditions, &wf.Match{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: uint8(6), // TCP only
			})
		}

		// Block outbound connections on non-TUN, non-loopback interfaces.
		blockConnectID := w.nextRuleID()
		if err := w.session.AddRule(&wf.Rule{
			ID:         blockConnectID,
			Name:       fmt.Sprintf("AWG default block connect%s", ds.tag),
			Layer:      ds.connect,
			Sublayer:   awgSublayerID,
			Weight:     100,
			Conditions: blockConditions,
			Action:     wf.ActionBlock,
		}); err != nil {
			for _, id := range ruleIDs {
				w.session.DeleteRule(id)
			}
			return fmt.Errorf("[WFP] add default block connect%s: %w", ds.tag, err)
		}
		ruleIDs = append(ruleIDs, blockConnectID)

		// Block inbound on non-TUN, non-loopback interfaces.
		blockRecvID := w.nextRuleID()
		if err := w.session.AddRule(&wf.Rule{
			ID:         blockRecvID,
			Name:       fmt.Sprintf("AWG default block recv%s", ds.tag),
			Layer:      ds.recv,
			Sublayer:   awgSublayerID,
			Weight:     100,
			Conditions: blockConditions,
			Action:     wf.ActionBlock,
		}); err != nil {
			for _, id := range ruleIDs {
				w.session.DeleteRule(id)
			}
			return fmt.Errorf("[WFP] add default block recv%s: %w", ds.tag, err)
		}
		ruleIDs = append(ruleIDs, blockRecvID)

		// PERMIT our own process outbound on non-TUN (for direct proxy, DNS).
		selfConnectID := w.nextRuleID()
		if err := w.session.AddRule(&wf.Rule{
			ID:       selfConnectID,
			Name:     fmt.Sprintf("AWG default self permit connect%s", ds.tag),
			Layer:    ds.connect,
			Sublayer: awgSublayerID,
			Weight:   200,
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
			},
			Action: wf.ActionPermit,
		}); err != nil {
			for _, id := range ruleIDs {
				w.session.DeleteRule(id)
			}
			return fmt.Errorf("[WFP] add default self permit connect%s: %w", ds.tag, err)
		}
		ruleIDs = append(ruleIDs, selfConnectID)

		// PERMIT our own process inbound on non-TUN.
		selfRecvID := w.nextRuleID()
		if err := w.session.AddRule(&wf.Rule{
			ID:       selfRecvID,
			Name:     fmt.Sprintf("AWG default self permit recv%s", ds.tag),
			Layer:    ds.recv,
			Sublayer: awgSublayerID,
			Weight:   200,
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
			},
			Action: wf.ActionPermit,
		}); err != nil {
			for _, id := range ruleIDs {
				w.session.DeleteRule(id)
			}
			return fmt.Errorf("[WFP] add default self permit recv%s: %w", ds.tag, err)
		}
		ruleIDs = append(ruleIDs, selfRecvID)
	}

	w.rules[wfpDefaultBlockKey] = ruleIDs
	core.Log.Infof("WFP", "Default block enabled (%d rules, dual-stack, self-permit for %s)", len(ruleIDs), exePath)
	return nil
}

// DisableDefaultBlock removes the default block rules added by EnableDefaultBlock.
func (w *WFPManager) DisableDefaultBlock() {
	w.removeRulesByKey(wfpDefaultBlockKey)
	core.Log.Debugf("WFP", "Default block disabled")
}

// PermitVirtualAdapters discovers Hyper-V, WSL2, and Docker virtual network
// adapters and adds WFP PERMIT rules (weight 1500) so their traffic bypasses
// the default block and per-process BLOCK rules. This prevents the VPN from
// breaking containerized networking.
//
// Call after EnableDefaultBlock and on network changes (NetworkMonitor callback).
func (w *WFPManager) PermitVirtualAdapters() error {
	luids, names := discoverVirtualAdapters(w.tunLUID)
	if len(luids) == 0 {
		return nil
	}

	// Remove stale rules before re-adding.
	w.removeRulesByKey(wfpVirtualAdapterKey)

	w.mu.Lock()
	defer w.mu.Unlock()

	var ruleIDs []wf.RuleID

	for i, luid := range luids {
		for _, ds := range dualStackLayers {
			// Permit outbound on virtual adapter.
			connectID := w.nextRuleID()
			if err := w.session.AddRule(&wf.Rule{
				ID:       connectID,
				Name:     fmt.Sprintf("AWG permit vAdapter connect: %s%s", names[i], ds.tag),
				Layer:    ds.connect,
				Sublayer: awgSublayerID,
				Weight:   1500,
				Conditions: []*wf.Match{
					{
						Field: wf.FieldIPLocalInterface,
						Op:    wf.MatchTypeEqual,
						Value: luid,
					},
				},
				Action: wf.ActionPermit,
			}); err != nil {
				for _, id := range ruleIDs {
					w.session.DeleteRule(id)
				}
				return fmt.Errorf("[WFP] permit vAdapter connect %s%s: %w", names[i], ds.tag, err)
			}
			ruleIDs = append(ruleIDs, connectID)

			// Permit inbound on virtual adapter.
			recvID := w.nextRuleID()
			if err := w.session.AddRule(&wf.Rule{
				ID:       recvID,
				Name:     fmt.Sprintf("AWG permit vAdapter recv: %s%s", names[i], ds.tag),
				Layer:    ds.recv,
				Sublayer: awgSublayerID,
				Weight:   1500,
				Conditions: []*wf.Match{
					{
						Field: wf.FieldIPLocalInterface,
						Op:    wf.MatchTypeEqual,
						Value: luid,
					},
				},
				Action: wf.ActionPermit,
			}); err != nil {
				for _, id := range ruleIDs {
					w.session.DeleteRule(id)
				}
				return fmt.Errorf("[WFP] permit vAdapter recv %s%s: %w", names[i], ds.tag, err)
			}
			ruleIDs = append(ruleIDs, recvID)
		}
	}

	w.rules[wfpVirtualAdapterKey] = ruleIDs
	core.Log.Infof("WFP", "Permitted %d virtual adapters (%d rules): %v", len(luids), len(ruleIDs), names)
	return nil
}

// RemoveVirtualAdapterPermits removes WFP rules for virtual adapters.
func (w *WFPManager) RemoveVirtualAdapterPermits() {
	w.removeRulesByKey(wfpVirtualAdapterKey)
}

// discoverVirtualAdapters enumerates network interfaces and returns LUIDs and
// names of Hyper-V, WSL2, Docker, and VMware virtual adapters. The TUN adapter
// LUID is excluded.
func discoverVirtualAdapters(tunLUID uint64) (luids []uint64, names []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		core.Log.Warnf("WFP", "Failed to enumerate interfaces for virtual adapter detection: %v", err)
		return nil, nil
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // skip down interfaces
		}

		name := iface.Name
		nameLower := strings.ToLower(name)

		if !isVirtualAdapterName(nameLower) {
			continue
		}

		luid, err := convertInterfaceIndexToLuid(uint32(iface.Index))
		if err != nil {
			core.Log.Warnf("WFP", "Failed to get LUID for %s (index %d): %v", name, iface.Index, err)
			continue
		}

		if luid == tunLUID {
			continue // skip our own TUN adapter
		}

		luids = append(luids, luid)
		names = append(names, name)
	}
	return
}

// isVirtualAdapterName returns true if the interface name matches known
// virtualization adapter patterns (Hyper-V, Docker, WSL2, VMware).
func isVirtualAdapterName(nameLower string) bool {
	// Hyper-V / WSL2 / Docker Desktop virtual switches.
	if strings.Contains(nameLower, "vethernet") {
		return true
	}
	// Docker internal networks.
	if strings.Contains(nameLower, "docker") {
		return true
	}
	// VMware virtual adapters.
	if strings.Contains(nameLower, "vmnet") || strings.Contains(nameLower, "vmware") {
		return true
	}
	// VirtualBox host-only / bridged adapters.
	if strings.Contains(nameLower, "virtualbox") || strings.Contains(nameLower, "vboxnet") {
		return true
	}
	return false
}

// convertInterfaceIndexToLuid converts a network interface index to its LUID.
func convertInterfaceIndexToLuid(ifIndex uint32) (uint64, error) {
	var luid uint64
	r, _, _ := procConvertInterfaceIndexToLuid.Call(
		uintptr(ifIndex),
		uintptr(unsafe.Pointer(&luid)),
	)
	if r != 0 {
		return 0, fmt.Errorf("ConvertInterfaceIndexToLuid: error %d", r)
	}
	return luid, nil
}

// UnblockAllProcesses removes all per-process WFP rules (but not IPv6, DNS,
// default block, or bypass rules). Used when deactivating the gateway so that
// previously blocked apps can reach the real NIC directly.
func (w *WFPManager) UnblockAllProcesses() {
	w.mu.Lock()
	var toDelete []wf.RuleID
	for key, ids := range w.rules {
		switch key {
		case "__ipv6_block__", wfpDNSBlockKey, wfpDNSPermitSelfKey, wfpDefaultBlockKey, wfpVirtualAdapterKey:
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
		Name:                    "AWG Conflicting WFP Cleanup",
		Description:             "Temporary session for removing conflicting WFP artifacts",
		Dynamic:                 false, // deletions must persist after session closes
		TransactionStartTimeout: wfpTxnTimeout,
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
// known conflicting software that installs WFP callout drivers or packet filters.
func isConflictingWFPName(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "windivert") ||
		strings.Contains(lower, "gearup") ||
		strings.Contains(lower, "gunetfilter") ||
		strings.Contains(lower, "hostpacket") ||
		strings.Contains(lower, "netlimiter") ||
		strings.Contains(lower, "glasswire") ||
		strings.Contains(lower, "simplewall") ||
		strings.Contains(lower, "fort firewall") ||
		strings.Contains(lower, "proxifier")
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
		Name:                    "AWG WFP Conflict Detection",
		Description:             "Temporary session for detecting conflicting WFP callouts",
		Dynamic:                 true,
		TransactionStartTimeout: wfpTxnTimeout,
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
