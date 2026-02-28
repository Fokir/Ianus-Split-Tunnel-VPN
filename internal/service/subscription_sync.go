package service

import (
	"context"
	"fmt"
	"strings"

	"awg-split-tunnel/internal/core"
)

// syncSubscriptionTunnels reconciles the running tunnels for a single
// subscription with the freshly-fetched list. New tunnels are added via
// TunnelController; stale ones are removed.
func (s *Service) syncSubscriptionTunnels(ctx context.Context, subName string, wanted []core.TunnelConfig) {
	wantedIDs := make(map[string]struct{}, len(wanted))
	for _, tc := range wanted {
		wantedIDs[tc.ID] = struct{}{}
	}

	// Remove tunnels that no longer appear in the subscription.
	for _, entry := range s.registry.All() {
		sub, ok := entry.Config.Settings["_subscription"]
		if !ok {
			continue
		}
		if subStr, _ := sub.(string); subStr == subName {
			if _, keep := wantedIDs[entry.ID]; !keep {
				if err := s.ctrl.RemoveTunnel(entry.ID); err != nil {
					core.Log.Warnf("Core", "Failed to remove stale subscription tunnel %q: %v", entry.ID, err)
				}
			}
		}
	}

	// Add tunnels that are not yet registered.
	for _, tc := range wanted {
		if _, exists := s.registry.Get(tc.ID); exists {
			continue
		}
		if err := s.ctrl.AddTunnel(ctx, tc, nil); err != nil {
			core.Log.Warnf("Core", "Failed to add subscription tunnel %q: %v", tc.ID, err)
		}
	}

	// Restore custom display names from gui.tunnel_names.
	customNames := s.cfg.GetAllTunnelNames()
	if len(customNames) > 0 {
		for _, tc := range wanted {
			if name, ok := customNames[tc.ID]; ok && name != "" {
				s.registry.SetName(tc.ID, name)
			}
		}
	}
}

// syncAllSubscriptionTunnels refreshes tunnels for every configured
// subscription using the current cache.
func (s *Service) syncAllSubscriptionTunnels(ctx context.Context) {
	subs := s.cfg.GetSubscriptions()
	for name := range subs {
		cached := s.subMgr.GetCached(name)
		s.syncSubscriptionTunnels(ctx, name, cached)
	}
}

// getSubscriptionTunnelIDs returns the IDs of all tunnels belonging to
// the given subscription.
func (s *Service) getSubscriptionTunnelIDs(subName string) []string {
	var ids []string
	for _, entry := range s.registry.All() {
		sub, ok := entry.Config.Settings["_subscription"]
		if !ok {
			continue
		}
		if subStr, _ := sub.(string); subStr == subName {
			ids = append(ids, entry.ID)
		}
	}
	return ids
}

// getActiveSubscriptionTunnelIDs returns the IDs of active (Up/Connecting)
// tunnels belonging to the given subscription.
func (s *Service) getActiveSubscriptionTunnelIDs(subName string) []string {
	var ids []string
	for _, entry := range s.registry.All() {
		sub, ok := entry.Config.Settings["_subscription"]
		if !ok {
			continue
		}
		if subStr, _ := sub.(string); subStr == subName {
			st := s.registry.GetState(entry.ID)
			if st == core.TunnelStateUp || st == core.TunnelStateConnecting {
				ids = append(ids, entry.ID)
			}
		}
	}
	return ids
}

// disconnectSubscriptionTunnels disconnects all active tunnels belonging to
// the subscription and returns the list of tunnel IDs that were active.
func (s *Service) disconnectSubscriptionTunnels(subName string) []string {
	active := s.getActiveSubscriptionTunnelIDs(subName)
	for _, id := range active {
		if err := s.ctrl.DisconnectTunnel(id); err != nil {
			core.Log.Warnf("Sub", "Failed to disconnect subscription tunnel %q before refresh: %v", id, err)
		}
	}
	return active
}

// reconnectTunnels reconnects tunnels by their IDs. If a tunnel ID no longer
// exists (was removed during sync), it is skipped.
func (s *Service) reconnectTunnels(ctx context.Context, tunnelIDs []string) {
	for _, id := range tunnelIDs {
		if _, exists := s.registry.Get(id); !exists {
			core.Log.Debugf("Sub", "Skipping reconnect for removed tunnel %q", id)
			continue
		}
		if err := s.ctrl.ConnectTunnel(ctx, id); err != nil {
			core.Log.Warnf("Sub", "Failed to reconnect subscription tunnel %q: %v", id, err)
		}
	}
}

// refreshSubscriptionSafe performs a safe subscription refresh cycle:
// 1. Disconnect active tunnels of the subscription
// 2. Flush DNS caches
// 3. Fetch new subscription data
// 4. Sync tunnels (remove stale, add new)
// 5. Reconnect previously-active tunnels (by ID if still present)
// 6. Flush DNS caches again
func (s *Service) refreshSubscriptionSafe(ctx context.Context, name string, sub core.SubscriptionConfig) ([]core.TunnelConfig, error) {
	// Step 1: Remember and disconnect active tunnels.
	wasActive := s.disconnectSubscriptionTunnels(name)
	core.Log.Infof("Sub", "Disconnected %d active tunnel(s) for subscription %q before refresh", len(wasActive), name)

	// Step 2: Flush DNS before fetch so the HTTP request goes through the real NIC.
	s.flushDNSQuiet()

	// Step 3: Fetch and parse subscription.
	tunnels, fetchErr := s.subMgr.Refresh(ctx, name, sub)

	// Step 4: Sync tunnels regardless of fetch error (partial results may exist).
	if fetchErr == nil {
		s.syncSubscriptionTunnels(ctx, name, tunnels)
	}

	// Step 5: Reconnect tunnels that were active before.
	if len(wasActive) > 0 {
		s.reconnectTunnels(ctx, wasActive)
	}

	// Step 6: Flush DNS after reconnection to clear stale entries.
	s.flushDNSQuiet()

	return tunnels, fetchErr
}

// refreshAllSubscriptionsSafe performs a safe refresh for all subscriptions.
func (s *Service) refreshAllSubscriptionsSafe(ctx context.Context) ([]core.TunnelConfig, error) {
	cfg := s.cfg.Get()
	var allTunnels []core.TunnelConfig
	var errs []string

	for name, sub := range cfg.Subscriptions {
		tunnels, err := s.refreshSubscriptionSafe(ctx, name, sub)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		allTunnels = append(allTunnels, tunnels...)
	}

	if len(errs) > 0 {
		return allTunnels, fmt.Errorf("subscription errors: %s", strings.Join(errs, "; "))
	}
	return allTunnels, nil
}

// flushDNSQuiet flushes DNS caches, logging any error but not returning it.
func (s *Service) flushDNSQuiet() {
	if s.dnsFlush == nil {
		return
	}
	if err := s.dnsFlush(); err != nil {
		core.Log.Warnf("Sub", "DNS flush failed: %v", err)
	}
}

// removeSubscriptionTunnels removes all running tunnels that belong to
// the given subscription.
func (s *Service) removeSubscriptionTunnels(subName string) {
	for _, entry := range s.registry.All() {
		sub, ok := entry.Config.Settings["_subscription"]
		if !ok {
			continue
		}
		if subStr, _ := sub.(string); subStr == subName {
			if err := s.ctrl.RemoveTunnel(entry.ID); err != nil {
				core.Log.Warnf("Core", "Failed to remove subscription tunnel %q: %v", entry.ID, err)
			}
		}
	}
}
