// Package service provides the gRPC service layer for the VPN daemon.
// It wraps core components (ConfigManager, TunnelRegistry, RuleEngine)
// and exposes them via the VPNService gRPC interface for GUI communication.
package service

import (
	"context"
	"net/http"
	"net/netip"
	"sync"
	"time"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/gateway"
	"awg-split-tunnel/internal/update"
)

// TunnelController abstracts tunnel lifecycle operations
// so the service layer doesn't depend on concrete provider types.
type TunnelController interface {
	// ConnectTunnel starts a tunnel by ID. Returns error if already connected or not found.
	ConnectTunnel(ctx context.Context, tunnelID string) error
	// DisconnectTunnel stops a tunnel by ID. Returns error if not connected or not found.
	DisconnectTunnel(tunnelID string) error
	// RestartTunnel disconnects and reconnects a tunnel.
	RestartTunnel(ctx context.Context, tunnelID string) error
	// ConnectAll connects all configured tunnels.
	ConnectAll(ctx context.Context) error
	// DisconnectAll disconnects all active tunnels.
	DisconnectAll() error
	// AddTunnel adds a new tunnel config and optionally starts it.
	AddTunnel(ctx context.Context, cfg core.TunnelConfig, confFileData []byte) error
	// RemoveTunnel removes a tunnel (disconnects first if active).
	RemoveTunnel(tunnelID string) error
	// GetAdapterIP returns the VPN adapter IP for a tunnel.
	GetAdapterIP(tunnelID string) string
	// GetServerEndpoints returns the remote server endpoint addresses for a tunnel.
	GetServerEndpoints(tunnelID string) []netip.AddrPort
}

// Service is the central orchestrator that implements VPNServiceServer.
// It bridges the gRPC API with the core VPN components.
type Service struct {
	vpnapi.UnimplementedVPNServiceServer

	cfg       *core.ConfigManager
	registry  *core.TunnelRegistry
	rules     *core.RuleEngine
	bus       *core.EventBus
	ctrl      TunnelController
	logs      *LogStreamer
	stats     *StatsCollector
	version   string
	startTime time.Time

	domainReloader  func(rules []core.DomainRule) error
	dnsFlush        func() error
	geositeFilePath string
	geoipFilePath   string
	httpClient      *http.Client
	geoResolver     *gateway.GeoIPResolver

	subMgr         *core.SubscriptionManager
	updateChecker  *update.Checker
	reconnectMgr   *ReconnectManager

	mu sync.RWMutex
}

// Config holds parameters for creating a new Service.
type Config struct {
	ConfigManager  *core.ConfigManager
	TunnelRegistry *core.TunnelRegistry
	RuleEngine     *core.RuleEngine
	EventBus       *core.EventBus
	TunnelCtrl     TunnelController
	LogStreamer    *LogStreamer
	StatsCollector *StatsCollector // optional: use externally-created collector
	Version        string

	// DomainReloader rebuilds the domain matcher from updated rules.
	// Called by SaveDomainRules and UpdateGeosite handlers.
	DomainReloader func(rules []core.DomainRule) error
	// DNSFlush clears the DNS cache, domain table, and Windows DNS cache.
	DNSFlush func() error
	// GeositeFilePath is the path to geosite.dat for listing categories and updating.
	GeositeFilePath string
	// GeoIPFilePath is the path to geoip.dat for listing categories and updating.
	GeoIPFilePath string
	// HTTPClient is bound to the real NIC to bypass TUN for outbound HTTP (geosite downloads).
	HTTPClient *http.Client
	// SubscriptionManager manages subscription URL fetching and refresh.
	SubscriptionManager *core.SubscriptionManager
	// UpdateChecker is an optional auto-update checker instance.
	UpdateChecker *update.Checker
	// ReconnectManager handles auto-reconnection on tunnel failures.
	ReconnectManager *ReconnectManager
}

// New creates a new Service instance.
func New(c Config) *Service {
	s := &Service{
		cfg:             c.ConfigManager,
		registry:        c.TunnelRegistry,
		rules:           c.RuleEngine,
		bus:             c.EventBus,
		ctrl:            c.TunnelCtrl,
		version:         c.Version,
		startTime:       time.Now(),
		domainReloader:  c.DomainReloader,
		dnsFlush:        c.DNSFlush,
		geositeFilePath: c.GeositeFilePath,
		geoipFilePath:   c.GeoIPFilePath,
		httpClient:      c.HTTPClient,
	}
	if c.LogStreamer != nil {
		s.logs = c.LogStreamer
	} else {
		s.logs = NewLogStreamer(c.EventBus)
	}
	if c.StatsCollector != nil {
		s.stats = c.StatsCollector
	} else {
		s.stats = NewStatsCollector(c.TunnelRegistry, c.EventBus)
	}
	s.subMgr = c.SubscriptionManager
	s.updateChecker = c.UpdateChecker
	s.reconnectMgr = c.ReconnectManager

	// Initialize GeoIP resolver for IP→country lookup (best-effort).
	if c.GeoIPFilePath != "" {
		if resolver, err := gateway.NewGeoIPResolver(c.GeoIPFilePath); err == nil {
			s.geoResolver = resolver
		}
	}

	return s
}

// Start initializes background workers (stats collection, log capture)
// and subscribes to events for subscription tunnel hot-reload.
func (s *Service) Start(ctx context.Context) {
	s.stats.Start(ctx)
	s.logs.Start()

	// When subscriptions auto-refresh via timer, the event carries the
	// already-fetched tunnels. We flush DNS before and after sync so stale
	// records don't linger, but do NOT disconnect tunnels — that would
	// interrupt the user every N hours. Full stop/start cycle is only
	// used for explicit (user-triggered) refreshes via refreshSubscriptionSafe.
	if s.subMgr != nil {
		s.bus.Subscribe(core.EventSubscriptionUpdated, func(e core.Event) {
			payload, ok := e.Payload.(core.SubscriptionPayload)
			if !ok || payload.Error != nil {
				return
			}
			s.flushDNSQuiet()
			s.syncSubscriptionTunnels(ctx, payload.Name, payload.Tunnels)
			s.flushDNSQuiet()
		})
	}

	// Start auto-reconnection manager.
	if s.reconnectMgr != nil {
		s.reconnectMgr.Start()
	}
}

// Stop shuts down background workers.
func (s *Service) Stop() {
	if s.reconnectMgr != nil {
		s.reconnectMgr.Stop()
	}
	s.logs.Stop()
	s.stats.Stop()
}

// ReconnectManager returns the reconnect manager for external use.
func (s *Service) ReconnectManager() *ReconnectManager {
	return s.reconnectMgr
}
