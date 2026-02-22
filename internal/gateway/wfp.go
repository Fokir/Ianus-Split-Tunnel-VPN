//go:build windows

package gateway

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

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

	// Register our sublayer.
	if err := sess.AddSublayer(&wf.Sublayer{
		ID:       awgSublayerID,
		Name:     "AWG Split Tunnel Rules",
		Provider: awgProviderID,
		Weight:   0x0F, // high priority
	}); err != nil {
		sess.Close()
		return nil, fmt.Errorf("[WFP] add sublayer: %w", err)
	}

	core.Log.Infof("WFP", "Session opened (Dynamic=true, TUN LUID=0x%x)", tunLUID)

	return &WFPManager{
		session: sess,
		tunLUID: tunLUID,
		rules:   make(map[string][]wf.RuleID),
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
	blockStart := time.Now()
	defer func() {
		if elapsed := time.Since(blockStart); elapsed > time.Millisecond {
			core.Log.Warnf("Perf", "BlockProcessOnRealNIC took %s (%s)", elapsed, exePath)
		}
	}()

	key := strings.ToLower(exePath)

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

// BlockDNSOnInterface adds WFP rules to block DNS (UDP/TCP port 53) on a
// specific interface (typically the physical NIC). This prevents ISP DPI from
// intercepting DNS queries while keeping DNS available on other adapters
// (e.g. VMware, Hyper-V work subnets).
func (w *WFPManager) BlockDNSOnInterface(ifLUID uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

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
	}

	core.Log.Infof("WFP", "DNS blocked on interface LUID 0x%x (port 53 UDP+TCP)", ifLUID)
	return nil
}

// PermitDNSForSelf adds WFP PERMIT rules allowing our own process to send DNS
// queries on the specified interface. This is needed so the DNS resolver can
// fall back to the direct provider (real NIC) when VPN tunnels are down.
// Weight 4000 overrides BlockDNSOnInterface (weight 3000).
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
	}

	core.Log.Infof("WFP", "DNS self-permit on interface LUID 0x%x (port 53 UDP+TCP)", ifLUID)
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
