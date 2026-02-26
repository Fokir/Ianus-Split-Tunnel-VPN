package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SubscriptionManager fetches and parses VLESS subscription URLs,
// converting them into TunnelConfig entries.
type SubscriptionManager struct {
	mu         sync.RWMutex
	cfgMgr     *ConfigManager
	bus        *EventBus
	httpClient *http.Client
	stopChs    map[string]chan struct{}
	// cache stores the last fetched tunnels per subscription name.
	cache map[string][]TunnelConfig
	// parseURI is the function used to parse vless:// URIs into TunnelConfig.
	// Injected to avoid circular dependency with the vless package.
	parseURI func(uri string) (TunnelConfig, error)
}

// NewSubscriptionManager creates a new subscription manager.
// parseURI converts a single vless:// URI string into a TunnelConfig.
func NewSubscriptionManager(
	cfgMgr *ConfigManager,
	bus *EventBus,
	httpClient *http.Client,
	parseURI func(uri string) (TunnelConfig, error),
) *SubscriptionManager {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &SubscriptionManager{
		cfgMgr:     cfgMgr,
		bus:        bus,
		httpClient: httpClient,
		stopChs:    make(map[string]chan struct{}),
		cache:      make(map[string][]TunnelConfig),
		parseURI:   parseURI,
	}
}

// Start begins auto-refresh goroutines for all subscriptions with a refresh interval.
func (sm *SubscriptionManager) Start(ctx context.Context) {
	cfg := sm.cfgMgr.Get()
	for name, sub := range cfg.Subscriptions {
		if sub.RefreshInterval == "" {
			continue
		}
		interval, err := time.ParseDuration(sub.RefreshInterval)
		if err != nil || interval <= 0 {
			Log.Warnf("Sub", "Invalid refresh_interval %q for subscription %q", sub.RefreshInterval, name)
			continue
		}
		sm.startRefreshLoop(ctx, name, sub, interval)
	}
}

// Stop halts all refresh goroutines.
func (sm *SubscriptionManager) Stop() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for name, ch := range sm.stopChs {
		close(ch)
		delete(sm.stopChs, name)
	}
}

// RefreshAll fetches and parses all subscriptions. Returns combined tunnel configs.
func (sm *SubscriptionManager) RefreshAll(ctx context.Context) ([]TunnelConfig, error) {
	cfg := sm.cfgMgr.Get()
	var allTunnels []TunnelConfig
	var errs []string

	for name, sub := range cfg.Subscriptions {
		tunnels, err := sm.Refresh(ctx, name, sub)
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

// Refresh fetches and parses a single subscription, returning tunnel configs.
func (sm *SubscriptionManager) Refresh(ctx context.Context, name string, sub SubscriptionConfig) ([]TunnelConfig, error) {
	Log.Infof("Sub", "Refreshing subscription %q from %s", name, sub.URL)

	data, err := sm.fetch(ctx, sub)
	if err != nil {
		sm.publishUpdate(name, nil, err)
		return nil, fmt.Errorf("fetch %q: %w", name, err)
	}

	tunnels, err := sm.parse(name, sub, data)
	if err != nil {
		sm.publishUpdate(name, nil, err)
		return nil, fmt.Errorf("parse %q: %w", name, err)
	}

	sm.mu.Lock()
	sm.cache[name] = tunnels
	sm.mu.Unlock()

	sm.publishUpdate(name, tunnels, nil)
	Log.Infof("Sub", "Subscription %q: got %d tunnels", name, len(tunnels))
	return tunnels, nil
}

// GetCached returns the last fetched tunnels for a subscription.
func (sm *SubscriptionManager) GetCached(name string) []TunnelConfig {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.cache[name]
}

// fetch downloads subscription content from URL.
func (sm *SubscriptionManager) fetch(ctx context.Context, sub SubscriptionConfig) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sub.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	ua := sub.UserAgent
	if ua == "" {
		ua = "AWGSplitTunnel/1.0"
	}
	req.Header.Set("User-Agent", ua)

	resp, err := sm.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, sub.URL)
	}

	// Limit body to 2 MB to prevent abuse.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return body, nil
}

// parse decodes subscription content and converts URIs to TunnelConfigs.
func (sm *SubscriptionManager) parse(name string, sub SubscriptionConfig, data []byte) ([]TunnelConfig, error) {
	// Try base64 decode (standard, then URL-safe).
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			// Maybe it's already plaintext URIs.
			decoded = data
		}
	}

	lines := strings.Split(strings.TrimSpace(string(decoded)), "\n")
	prefix := sub.Prefix
	if prefix == "" {
		prefix = name
	}

	var tunnels []TunnelConfig
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Only support vless:// URIs for now.
		if !strings.HasPrefix(line, "vless://") {
			Log.Debugf("Sub", "Skipping non-vless URI in subscription %q: %.40s...", name, line)
			continue
		}

		tc, err := sm.parseURI(line)
		if err != nil {
			Log.Warnf("Sub", "Subscription %q: failed to parse URI #%d: %v", name, i+1, err)
			continue
		}

		// Set tunnel ID and mark as subscription-sourced.
		if tc.ID == "" {
			tc.ID = fmt.Sprintf("%s_%d", prefix, i+1)
		} else {
			tc.ID = fmt.Sprintf("%s_%s", prefix, tc.ID)
		}

		tc.Settings["_subscription"] = name

		tunnels = append(tunnels, tc)
	}

	if len(tunnels) == 0 {
		return nil, fmt.Errorf("no valid vless:// URIs found in subscription %q", name)
	}

	return tunnels, nil
}

func (sm *SubscriptionManager) startRefreshLoop(ctx context.Context, name string, sub SubscriptionConfig, interval time.Duration) {
	sm.mu.Lock()
	stopCh := make(chan struct{})
	sm.stopChs[name] = stopCh
	sm.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case <-ticker.C:
				if _, err := sm.Refresh(ctx, name, sub); err != nil {
					Log.Warnf("Sub", "Auto-refresh failed for %q: %v", name, err)
				}
			}
		}
	}()

	Log.Infof("Sub", "Auto-refresh for %q every %s", name, interval)
}

func (sm *SubscriptionManager) publishUpdate(name string, tunnels []TunnelConfig, err error) {
	if sm.bus != nil {
		sm.bus.Publish(Event{
			Type: EventSubscriptionUpdated,
			Payload: SubscriptionPayload{
				Name:    name,
				Tunnels: tunnels,
				Error:   err,
			},
		})
	}
}
