package dpi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"awg-split-tunnel/internal/core"
)

// StrategyManager orchestrates the DPI bypass subsystem:
// strategy fetching, caching, probing, parameter search, and provider binding.
type StrategyManager struct {
	cfg     core.DPIBypassConfig
	bus     *core.EventBus
	cache   *CacheManager
	fetcher *StrategyFetcher
	probe   *ProbeRunner
	search  *ParameterSearcher

	// setStrategy is called when a new strategy is activated.
	// It updates the DPIBypassProvider with the new strategy.
	setStrategy func(s *Strategy)

	networkID string
}

// ManagerDeps holds dependencies for creating a StrategyManager.
type ManagerDeps struct {
	Config      core.DPIBypassConfig
	Bus         *core.EventBus
	DataDir     string
	BindControl func(network, address string, c syscall.RawConn) error
	LocalIP     net.IP
	GatewayIP   string
}

// NewStrategyManager creates and initializes the DPI strategy manager.
func NewStrategyManager(deps ManagerDeps) *StrategyManager {
	cache := NewCacheManager(deps.DataDir)

	// Create NIC-bound HTTP client for fetching strategies via the real NIC.
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout: 10 * time.Second,
					Control: deps.BindControl,
				}
				if deps.LocalIP != nil {
					dialer.LocalAddr = &net.TCPAddr{IP: deps.LocalIP}
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}

	fetcher := NewStrategyFetcher(httpClient)
	probe := NewProbeRunner(deps.BindControl, deps.LocalIP)
	searcher := NewParameterSearcher(probe, deps.Bus, cache)

	return &StrategyManager{
		cfg:       deps.Config,
		bus:       deps.Bus,
		cache:     cache,
		fetcher:   fetcher,
		probe:     probe,
		search:    searcher,
		networkID: GetNetworkID(deps.GatewayIP),
	}
}

// SetStrategyCallback sets the function called when a new strategy is activated.
func (m *StrategyManager) SetStrategyCallback(fn func(s *Strategy)) {
	m.setStrategy = fn
}

// Init loads the cache and optionally runs a startup connectivity check.
func (m *StrategyManager) Init(ctx context.Context) error {
	if err := m.cache.Load(); err != nil {
		core.Log.Warnf("DPI", "Cache load failed: %v", err)
	}

	// Try to restore cached strategy for current network.
	cached := m.cache.GetNetworkStrategy(m.networkID)
	if cached != nil {
		core.Log.Infof("DPI", "Restored cached strategy %q for network %s", cached.Name, m.networkID)
		m.activateStrategy(cached)
	}

	if m.cfg.StartupCheck {
		go m.startupCheck(ctx)
	}

	return nil
}

// startupCheck tests connectivity in the background at startup.
func (m *StrategyManager) startupCheck(ctx context.Context) {
	domains := m.cfg.TestDomains
	if len(domains) == 0 {
		return
	}

	domain := domains[0]

	// Test direct access first.
	result := m.probe.TestDirect(ctx, domain)
	if result.Success {
		core.Log.Infof("DPI", "Startup check: %s is accessible directly (%v)", domain, result.Latency)
		return
	}

	core.Log.Infof("DPI", "Startup check: %s blocked (%s), testing cached strategy...", domain, result.Error)

	// Try cached strategy.
	cached := m.cache.GetNetworkStrategy(m.networkID)
	if cached != nil {
		result = m.probe.TestWithStrategy(ctx, domain, cached)
		if result.Success {
			core.Log.Infof("DPI", "Startup check: cached strategy works (%v)", result.Latency)
			m.activateStrategy(cached)
			return
		}
		core.Log.Warnf("DPI", "Startup check: cached strategy failed: %s", result.Error)
	}

	core.Log.Warnf("DPI", "Startup check: no working strategy. Run DPI search to find one.")
}

// FetchStrategies downloads strategies from the zapret GitHub repository.
func (m *StrategyManager) FetchStrategies(ctx context.Context) ([]*Strategy, error) {
	strategies, err := m.fetcher.FetchAll(ctx)
	if err != nil {
		return nil, err
	}
	if err := m.cache.SetAvailableStrategies(strategies); err != nil {
		core.Log.Warnf("DPI", "Failed to cache fetched strategies: %v", err)
	}
	return strategies, nil
}

// ListStrategies returns all known strategies (cached + fetched + search results).
func (m *StrategyManager) ListStrategies() []*Strategy {
	var all []*Strategy
	all = append(all, m.cache.GetAvailableStrategies()...)
	all = append(all, m.cache.GetSearchResults()...)
	return all
}

// SelectStrategy activates a strategy by name.
func (m *StrategyManager) SelectStrategy(name string) error {
	for _, s := range m.ListStrategies() {
		if s.Name == name {
			m.activateStrategy(s)
			if err := m.cache.SetNetworkStrategy(m.networkID, s); err != nil {
				core.Log.Warnf("DPI", "Failed to cache selected strategy: %v", err)
			}
			return nil
		}
	}
	return fmt.Errorf("strategy %q not found", name)
}

// StartSearch starts the parameter search process.
func (m *StrategyManager) StartSearch(ctx context.Context, baseName string) error {
	var base *Strategy
	if baseName != "" {
		for _, s := range m.ListStrategies() {
			if s.Name == baseName {
				base = s
				break
			}
		}
	}

	// If no base strategy, use a sensible default.
	if base == nil {
		base = &Strategy{
			Name:   "default_base",
			Source: "search",
			Ops: []DesyncOp{{
				Mode:           DesyncMultisplit,
				FilterProtocol: "tcp",
				FilterPorts:    []int{443},
				FakeTTL:        1,
				Repeats:        1,
				SplitPos:       []int{SplitPosAutoSNI},
			}},
		}
	}

	return m.search.Start(ctx, base, m.cfg.TestDomains, m.networkID)
}

// StopSearch stops the running parameter search.
func (m *StrategyManager) StopSearch() {
	m.search.Stop()
}

// SearchState returns the current search state.
func (m *StrategyManager) SearchState() SearchState {
	return m.search.State()
}

// Probe tests a specific domain with a specific strategy.
func (m *StrategyManager) Probe(ctx context.Context, domain string, strategyName string) ProbeResult {
	if strategyName == "" {
		return m.probe.TestDirect(ctx, domain)
	}
	for _, s := range m.ListStrategies() {
		if s.Name == strategyName {
			return m.probe.TestWithStrategy(ctx, domain, s)
		}
	}
	return ProbeResult{Error: fmt.Sprintf("strategy %q not found", strategyName)}
}

func (m *StrategyManager) activateStrategy(s *Strategy) {
	if m.setStrategy != nil {
		m.setStrategy(s)
	}
	if m.bus != nil {
		m.bus.PublishAsync(core.Event{
			Type: core.EventDPIStrategyChanged,
			Payload: core.DPIStrategyChangedPayload{
				StrategyName: s.Name,
				Source:       s.Source,
			},
		})
	}
}
