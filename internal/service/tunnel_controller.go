//go:build windows

package service

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/gateway"
	"awg-split-tunnel/internal/provider"
	"awg-split-tunnel/internal/provider/amneziawg"
	"awg-split-tunnel/internal/proxy"
)

// tunnelInstance tracks a running tunnel and its associated resources.
type tunnelInstance struct {
	provider     provider.TunnelProvider
	tcpProxy     *proxy.TunnelProxy
	udpProxy     *proxy.UDPProxy
	proxyPort    uint16
	udpProxyPort uint16
	config       core.TunnelConfig
}

// ControllerDeps holds all dependencies needed by the TunnelControllerImpl.
type ControllerDeps struct {
	Registry  *core.TunnelRegistry
	Bus       *core.EventBus
	Flows     *gateway.FlowTable
	TUNRouter *gateway.TUNRouter
	RouteMgr  *gateway.RouteManager
	WFPMgr    *gateway.WFPManager
	Adapter   *gateway.Adapter
	DNSRouter *gateway.DNSRouter

	// RealNIC info for direct provider and bypass routes.
	RealNICIndex   uint32
	RealNICLocalIP netip.Addr
	RealNICLUID    uint64

	// Providers is a shared map for provider lookup (used by proxies).
	// The controller manages this map's contents.
	Providers map[string]provider.TunnelProvider
}

// TunnelControllerImpl manages tunnel lifecycle: create, connect, disconnect, remove.
type TunnelControllerImpl struct {
	mu   sync.Mutex
	deps ControllerDeps

	instances     map[string]*tunnelInstance
	nextProxyPort uint16
	ctx           context.Context

	// For proxy provider lookups.
	providerLookup func(tunnelID string) (provider.TunnelProvider, bool)
}

// NewTunnelController creates a new TunnelControllerImpl.
// initialPort is the first proxy port to use (e.g. 30002 after direct provider gets 30000/30001).
func NewTunnelController(ctx context.Context, deps ControllerDeps, initialPort uint16) *TunnelControllerImpl {
	tc := &TunnelControllerImpl{
		deps:          deps,
		instances:     make(map[string]*tunnelInstance),
		nextProxyPort: initialPort,
		ctx:           ctx,
	}
	tc.providerLookup = func(tunnelID string) (provider.TunnelProvider, bool) {
		p, ok := deps.Providers[tunnelID]
		return p, ok
	}
	return tc
}

// ─── TunnelController interface implementation ──────────────────────

func (tc *TunnelControllerImpl) ConnectTunnel(ctx context.Context, tunnelID string) error {
	tc.mu.Lock()
	inst, ok := tc.instances[tunnelID]
	tc.mu.Unlock()

	if !ok {
		return fmt.Errorf("tunnel %q not found", tunnelID)
	}

	state := tc.deps.Registry.GetState(tunnelID)
	if state == core.TunnelStateUp {
		return fmt.Errorf("tunnel %q already connected", tunnelID)
	}

	tc.deps.Registry.SetState(tunnelID, core.TunnelStateConnecting, nil)

	if err := inst.provider.Connect(ctx); err != nil {
		tc.deps.Registry.SetState(tunnelID, core.TunnelStateError, err)
		return fmt.Errorf("connect tunnel %q: %w", tunnelID, err)
	}

	tc.deps.Registry.SetState(tunnelID, core.TunnelStateUp, nil)
	tc.registerRawForwarder(tunnelID, inst.provider)
	tc.addBypassRoutes(inst.provider)

	return nil
}

func (tc *TunnelControllerImpl) DisconnectTunnel(tunnelID string) error {
	tc.mu.Lock()
	inst, ok := tc.instances[tunnelID]
	tc.mu.Unlock()

	if !ok {
		return fmt.Errorf("tunnel %q not found", tunnelID)
	}

	if err := inst.provider.Disconnect(); err != nil {
		return fmt.Errorf("disconnect tunnel %q: %w", tunnelID, err)
	}

	tc.deps.Registry.SetState(tunnelID, core.TunnelStateDown, nil)
	return nil
}

func (tc *TunnelControllerImpl) RestartTunnel(ctx context.Context, tunnelID string) error {
	if err := tc.DisconnectTunnel(tunnelID); err != nil {
		core.Log.Warnf("Core", "Restart disconnect %q: %v", tunnelID, err)
	}
	// Brief pause to allow cleanup.
	time.Sleep(500 * time.Millisecond)
	return tc.ConnectTunnel(ctx, tunnelID)
}

func (tc *TunnelControllerImpl) ConnectAll(ctx context.Context) error {
	tc.mu.Lock()
	ids := make([]string, 0, len(tc.instances))
	for id := range tc.instances {
		ids = append(ids, id)
	}
	tc.mu.Unlock()

	var lastErr error
	for _, id := range ids {
		state := tc.deps.Registry.GetState(id)
		if state == core.TunnelStateUp {
			continue
		}
		if err := tc.ConnectTunnel(ctx, id); err != nil {
			core.Log.Errorf("Core", "ConnectAll: %v", err)
			lastErr = err
		}
	}
	return lastErr
}

func (tc *TunnelControllerImpl) DisconnectAll() error {
	tc.mu.Lock()
	ids := make([]string, 0, len(tc.instances))
	for id := range tc.instances {
		ids = append(ids, id)
	}
	tc.mu.Unlock()

	var lastErr error
	for _, id := range ids {
		state := tc.deps.Registry.GetState(id)
		if state != core.TunnelStateUp && state != core.TunnelStateConnecting {
			continue
		}
		if err := tc.DisconnectTunnel(id); err != nil {
			core.Log.Errorf("Core", "DisconnectAll: %v", err)
			lastErr = err
		}
	}
	return lastErr
}

func (tc *TunnelControllerImpl) AddTunnel(ctx context.Context, cfg core.TunnelConfig, confFileData []byte) error {
	tc.mu.Lock()
	if _, exists := tc.instances[cfg.ID]; exists {
		tc.mu.Unlock()
		return fmt.Errorf("tunnel %q already exists", cfg.ID)
	}

	proxyPort := tc.nextProxyPort
	udpProxyPort := tc.nextProxyPort + 1
	tc.nextProxyPort += 2
	tc.mu.Unlock()

	// If conf file data provided, write it next to the executable.
	if len(confFileData) > 0 {
		confFileName := getStringSetting(cfg.Settings, "config_file", cfg.ID+".conf")
		confPath := resolveRelativeToExe(confFileName)
		if err := os.WriteFile(confPath, confFileData, 0600); err != nil {
			return fmt.Errorf("write config file %q: %w", confPath, err)
		}
		if cfg.Settings == nil {
			cfg.Settings = make(map[string]any)
		}
		cfg.Settings["config_file"] = confFileName
	}

	// Create provider.
	prov, err := tc.createProvider(cfg)
	if err != nil {
		return err
	}

	// Register in registry.
	if err := tc.deps.Registry.Register(cfg, proxyPort, udpProxyPort); err != nil {
		return fmt.Errorf("register tunnel %q: %w", cfg.ID, err)
	}

	tc.deps.Providers[cfg.ID] = prov
	tc.deps.Flows.RegisterProxyPort(proxyPort)
	tc.deps.Flows.RegisterUDPProxyPort(udpProxyPort)

	// Start proxies.
	tp := proxy.NewTunnelProxy(proxyPort, tc.deps.Flows.LookupNAT, tc.providerLookup)
	if err := tp.Start(tc.ctx); err != nil {
		return fmt.Errorf("start TCP proxy for %q: %w", cfg.ID, err)
	}

	up := proxy.NewUDPProxy(udpProxyPort, tc.deps.Flows.LookupUDPNAT, tc.providerLookup)
	if err := up.Start(tc.ctx); err != nil {
		tp.Stop()
		return fmt.Errorf("start UDP proxy for %q: %w", cfg.ID, err)
	}

	tc.mu.Lock()
	tc.instances[cfg.ID] = &tunnelInstance{
		provider:     prov,
		tcpProxy:     tp,
		udpProxy:     up,
		proxyPort:    proxyPort,
		udpProxyPort: udpProxyPort,
		config:       cfg,
	}
	tc.mu.Unlock()

	return nil
}

func (tc *TunnelControllerImpl) RemoveTunnel(tunnelID string) error {
	tc.mu.Lock()
	inst, ok := tc.instances[tunnelID]
	if !ok {
		tc.mu.Unlock()
		return fmt.Errorf("tunnel %q not found", tunnelID)
	}
	delete(tc.instances, tunnelID)
	tc.mu.Unlock()

	// Disconnect if active.
	state := tc.deps.Registry.GetState(tunnelID)
	if state == core.TunnelStateUp || state == core.TunnelStateConnecting {
		_ = inst.provider.Disconnect()
	}

	// Stop proxies.
	inst.tcpProxy.Stop()
	inst.udpProxy.Stop()

	// Remove from shared provider map and registry.
	delete(tc.deps.Providers, tunnelID)
	tc.deps.Registry.Unregister(tunnelID)

	return nil
}

func (tc *TunnelControllerImpl) GetAdapterIP(tunnelID string) string {
	tc.mu.Lock()
	inst, ok := tc.instances[tunnelID]
	tc.mu.Unlock()
	if !ok {
		return ""
	}
	ip := inst.provider.GetAdapterIP()
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

// ─── Helpers ────────────────────────────────────────────────────────

func (tc *TunnelControllerImpl) createProvider(cfg core.TunnelConfig) (provider.TunnelProvider, error) {
	switch cfg.Protocol {
	case "amneziawg":
		configFile := getStringSetting(cfg.Settings, "config_file", "")
		if configFile != "" {
			configFile = resolveRelativeToExe(configFile)
		}
		awgCfg := amneziawg.Config{
			ConfigFile: configFile,
			AdapterIP:  getStringSetting(cfg.Settings, "adapter_ip", ""),
		}
		return amneziawg.New(cfg.Name, awgCfg)
	default:
		return nil, fmt.Errorf("unknown protocol %q for tunnel %q", cfg.Protocol, cfg.ID)
	}
}

func (tc *TunnelControllerImpl) registerRawForwarder(tunnelID string, prov provider.TunnelProvider) {
	if rf, ok := prov.(provider.RawForwarder); ok {
		vpnIP := prov.GetAdapterIP()
		if vpnIP.IsValid() && vpnIP.Is4() {
			tc.deps.TUNRouter.RegisterRawForwarder(tunnelID, rf, vpnIP.As4())
		}
	}
}

func (tc *TunnelControllerImpl) addBypassRoutes(prov provider.TunnelProvider) {
	if awgProv, ok := prov.(*amneziawg.Provider); ok {
		for _, ep := range awgProv.GetPeerEndpoints() {
			if err := tc.deps.RouteMgr.AddBypassRoute(ep.Addr()); err != nil {
				core.Log.Warnf("Core", "Failed to add bypass route for %s: %v", ep, err)
			}
		}
	}
}

// RegisterExistingTunnel registers a tunnel that was already created during startup.
// Used to migrate existing tunnels from main.go's startup sequence to the controller.
func (tc *TunnelControllerImpl) RegisterExistingTunnel(
	tunnelID string,
	prov provider.TunnelProvider,
	tp *proxy.TunnelProxy,
	up *proxy.UDPProxy,
	proxyPort, udpProxyPort uint16,
	cfg core.TunnelConfig,
) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.instances[tunnelID] = &tunnelInstance{
		provider:     prov,
		tcpProxy:     tp,
		udpProxy:     up,
		proxyPort:    proxyPort,
		udpProxyPort: udpProxyPort,
		config:       cfg,
	}
}

// ─── Utility functions (shared with main.go) ────────────────────────

func getStringSetting(settings map[string]any, key, defaultVal string) string {
	if v, ok := settings[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultVal
}

func resolveRelativeToExe(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	exe, err := os.Executable()
	if err != nil {
		return path
	}
	return filepath.Join(filepath.Dir(exe), path)
}
