package service

import (
	"context"

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
