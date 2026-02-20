//go:build windows

package gateway

import (
	"fmt"
	"log"
	"strings"
	"sync"

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

	log.Printf("[WFP] Session opened (Dynamic=true, TUN LUID=0x%x)", tunLUID)

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
		log.Printf("[WFP] Failed to block %s on real NIC: %v", exePath, err)
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
		},
		Action: wf.ActionBlock,
	}); err != nil {
		return fmt.Errorf("[WFP] add connect rule: %w", err)
	}
	ruleIDs = append(ruleIDs, connectRuleID)

	// Rule 2: Block inbound accept (STUN responses) on non-TUN interfaces.
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
		},
		Action: wf.ActionBlock,
	}); err != nil {
		// Rollback the first rule.
		w.session.DeleteRule(connectRuleID)
		return fmt.Errorf("[WFP] add recv rule: %w", err)
	}
	ruleIDs = append(ruleIDs, recvRuleID)

	w.rules[key] = ruleIDs
	log.Printf("[WFP] Blocked %s on real NIC (%d rules)", key, len(ruleIDs))
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

// Close closes the WFP session. Dynamic=true means all rules are auto-removed.
func (w *WFPManager) Close() error {
	if w.session != nil {
		err := w.session.Close()
		log.Printf("[WFP] Session closed")
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
