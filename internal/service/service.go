//go:build windows

// Package service provides the gRPC service layer for the VPN daemon.
// It wraps core components (ConfigManager, TunnelRegistry, RuleEngine)
// and exposes them via the VPNService gRPC interface for GUI communication.
package service

import (
	"context"
	"sync"
	"time"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/core"
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
}

// New creates a new Service instance.
func New(c Config) *Service {
	s := &Service{
		cfg:       c.ConfigManager,
		registry:  c.TunnelRegistry,
		rules:     c.RuleEngine,
		bus:       c.EventBus,
		ctrl:      c.TunnelCtrl,
		version:   c.Version,
		startTime: time.Now(),
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
	return s
}

// Start initializes background workers (stats collection, log capture).
func (s *Service) Start(ctx context.Context) {
	s.stats.Start(ctx)
	s.logs.Start()
}

// Stop shuts down background workers.
func (s *Service) Stop() {
	s.logs.Stop()
	s.stats.Stop()
}
