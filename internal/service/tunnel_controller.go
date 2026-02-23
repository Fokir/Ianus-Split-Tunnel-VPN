//go:build windows

package service

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/gateway"
	"awg-split-tunnel/internal/provider"
	"awg-split-tunnel/internal/provider/amneziawg"
	"awg-split-tunnel/internal/provider/httpproxy"
	"awg-split-tunnel/internal/provider/socks5"
	"awg-split-tunnel/internal/provider/vless"
	"awg-split-tunnel/internal/provider/wireguard"
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

	// RuleEngine for updating active tunnel set on connect/disconnect.
	Rules *core.RuleEngine
	// ConfigManager for persisting active tunnels list.
	Cfg *core.ConfigManager
	Context   context.Context
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
	deps.Context = ctx // Set the context in deps
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

	// Initialize the Direct tunnel.
	directCfg := core.TunnelConfig{
		ID:       gateway.DirectTunnelID,
		Protocol: "direct",
		Name:     "Direct",
	}
	if err := tc.AddTunnel(ctx, directCfg, nil); err != nil {
		core.Log.Errorf("Core", "Failed to add direct tunnel during controller init: %v", err)
	}

	return tc
}

// Shutdown disconnects all tunnels and stops all proxies.
func (tc *TunnelControllerImpl) Shutdown() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	core.Log.Infof("Core", "Shutting down TunnelController...")

	for id, inst := range tc.instances {
		// Disconnect if active.
		state := tc.deps.Registry.GetState(id)
		if state == core.TunnelStateUp || state == core.TunnelStateConnecting {
			if err := inst.provider.Disconnect(); err != nil {
				core.Log.Errorf("Core", "Error disconnecting %s during shutdown: %v", id, err)
			}
		}

		// Stop proxies.
		inst.tcpProxy.Stop()
		inst.udpProxy.Stop()

		// Remove from shared provider map and registry.
		delete(tc.deps.Providers, id)
		tc.deps.Registry.Unregister(id)
	}

	// Clear all instances.
	tc.instances = make(map[string]*tunnelInstance)
	core.Log.Infof("Core", "TunnelController shutdown complete.")
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

	// Pass real NIC index to VLESS providers so they can resolve hostnames
	// through the real NIC, bypassing TUN DNS (10.255.0.1).
	if vp, ok := inst.provider.(*vless.Provider); ok && tc.deps.RealNICIndex > 0 {
		vp.SetRealNICIndex(tc.deps.RealNICIndex)
	}

	if err := inst.provider.Connect(tc.deps.Context); err != nil {
		tc.deps.Registry.SetState(tunnelID, core.TunnelStateError, err)
		return fmt.Errorf("connect tunnel %q: %w", tunnelID, err)
	}

	tc.deps.Registry.SetState(tunnelID, core.TunnelStateUp, nil)
	tc.registerRawForwarder(tunnelID, inst.provider)
	tc.addBypassRoutes(inst.provider)

	// Mark tunnel as active in rule engine and persist.
	if tc.deps.Rules != nil {
		tc.deps.Rules.SetTunnelActive(tunnelID, true)
	}
	tc.saveActiveTunnels()

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

	// Mark tunnel as inactive in rule engine and persist.
	if tc.deps.Rules != nil {
		tc.deps.Rules.SetTunnelActive(tunnelID, false)
	}
	tc.saveActiveTunnels()

	return nil
}

func (tc *TunnelControllerImpl) RestartTunnel(ctx context.Context, tunnelID string) error {
	if err := tc.DisconnectTunnel(tunnelID); err != nil {
		core.Log.Warnf("Core", "Restart disconnect %q: %v", tunnelID, err)
	}
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

	// Generate unique ID if not provided.
	if cfg.ID == "" {
		cfg.ID = tc.generateTunnelID(cfg.Name, cfg.Protocol)
	}

	if _, exists := tc.instances[cfg.ID]; exists {
		tc.mu.Unlock()
		return fmt.Errorf("tunnel %q already exists", cfg.ID)
	}

	proxyPort := tc.nextProxyPort
	udpProxyPort := tc.nextProxyPort + 1
	tc.nextProxyPort += 2
	tc.mu.Unlock()

	// If conf file data provided, handle per protocol.
	if len(confFileData) > 0 {
		if cfg.Protocol == core.ProtocolVLESS {
			// Detect format: vless:// URI or JSON.
			raw := strings.TrimSpace(string(confFileData))
			var vlessCfg vless.Config
			if strings.HasPrefix(raw, "vless://") {
				var uriName string
				var err error
				vlessCfg, uriName, err = vless.ParseVLESSURI(raw)
				if err != nil {
					return fmt.Errorf("parse VLESS URI: %w", err)
				}
				if cfg.Name == "" && uriName != "" {
					cfg.Name = uriName
				}
			} else {
				var err error
				vlessCfg, err = vless.ParseXrayJSON(confFileData)
				if err != nil {
					return fmt.Errorf("parse VLESS JSON config: %w", err)
				}
			}
			applyVLESSSettings(&cfg, vlessCfg)
		} else {
			// AWG / WireGuard: write .conf file next to executable.
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
	if err := tp.Start(tc.deps.Context); err != nil {
		return fmt.Errorf("start TCP proxy for %q: %w", cfg.ID, err)
	}

	up := proxy.NewUDPProxy(udpProxyPort, tc.deps.Flows.LookupUDPNAT, tc.providerLookup)
	if err := up.Start(tc.deps.Context); err != nil {
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

	// Persist new tunnel to config file (skip subscription-sourced tunnels).
	if _, isSub := cfg.Settings["_subscription"]; !isSub {
		tc.persistTunnelConfig(cfg)
	}

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

	// Remove tunnel from persisted config (skip subscription-sourced tunnels).
	if _, isSub := inst.config.Settings["_subscription"]; !isSub {
		tc.removeTunnelConfig(tunnelID)
	}

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
	return CreateProvider(cfg)
}

// CreateProvider creates a TunnelProvider from a TunnelConfig.
// Supports all protocols: amneziawg, wireguard, socks5, httpproxy, vless.
func CreateProvider(cfg core.TunnelConfig) (provider.TunnelProvider, error) {
	switch cfg.Protocol {
	case core.ProtocolAmneziaWG:
		configFile := getStringSetting(cfg.Settings, "config_file", "")
		if configFile != "" {
			configFile = resolveRelativeToExe(configFile)
		}
		awgCfg := amneziawg.Config{
			ConfigFile: configFile,
			AdapterIP:  getStringSetting(cfg.Settings, "adapter_ip", ""),
		}
		return amneziawg.New(cfg.Name, awgCfg)
	case core.ProtocolWireGuard:
		configFile := getStringSetting(cfg.Settings, "config_file", "")
		if configFile != "" {
			configFile = resolveRelativeToExe(configFile)
		}
		wgCfg := wireguard.Config{
			ConfigFile: configFile,
			AdapterIP:  getStringSetting(cfg.Settings, "adapter_ip", ""),
		}
		return wireguard.New(cfg.Name, wgCfg)
	case core.ProtocolSOCKS5:
		socksCfg := socks5.Config{
			Server:     getStringSetting(cfg.Settings, "server", ""),
			Port:       getIntSetting(cfg.Settings, "port", 1080),
			Username:   getStringSetting(cfg.Settings, "username", ""),
			Password:   getStringSetting(cfg.Settings, "password", ""),
			UDPEnabled: getBoolSetting(cfg.Settings, "udp_enabled", true),
		}
		return socks5.New(cfg.Name, socksCfg)
	case core.ProtocolHTTPProxy:
		httpCfg := httpproxy.Config{
			Server:        getStringSetting(cfg.Settings, "server", ""),
			Port:          getIntSetting(cfg.Settings, "port", 8080),
			Username:      getStringSetting(cfg.Settings, "username", ""),
			Password:      getStringSetting(cfg.Settings, "password", ""),
			TLS:           getBoolSetting(cfg.Settings, "tls", false),
			TLSSkipVerify: getBoolSetting(cfg.Settings, "tls_skip_verify", false),
		}
		return httpproxy.New(cfg.Name, httpCfg)
	case core.ProtocolVLESS:
		vlessCfg := vless.Config{
			Address:    getStringSetting(cfg.Settings, "address", ""),
			Port:       getIntSetting(cfg.Settings, "port", 443),
			UUID:       getStringSetting(cfg.Settings, "uuid", ""),
			Flow:       getStringSetting(cfg.Settings, "flow", ""),
			Encryption: getStringSetting(cfg.Settings, "encryption", "none"),
			Network:    getStringSetting(cfg.Settings, "network", "tcp"),
			Security:   getStringSetting(cfg.Settings, "security", "reality"),
		}
		// Parse nested reality settings.
		if reality := getMapSetting(cfg.Settings, "reality"); reality != nil {
			vlessCfg.Reality = vless.RealityConfig{
				PublicKey:   getStringSetting(reality, "public_key", ""),
				ShortID:     getStringSetting(reality, "short_id", ""),
				ServerName:  getStringSetting(reality, "server_name", ""),
				Fingerprint: getStringSetting(reality, "fingerprint", "chrome"),
				SpiderX:     getStringSetting(reality, "spider_x", ""),
			}
		}
		// Parse nested TLS settings.
		if tlsCfg := getMapSetting(cfg.Settings, "tls"); tlsCfg != nil {
			vlessCfg.TLS = vless.TLSConfig{
				ServerName:    getStringSetting(tlsCfg, "server_name", ""),
				Fingerprint:   getStringSetting(tlsCfg, "fingerprint", ""),
				AllowInsecure: getBoolSetting(tlsCfg, "allow_insecure", false),
			}
		}
		// Parse nested WebSocket settings.
		if wsCfg := getMapSetting(cfg.Settings, "ws"); wsCfg != nil {
			vlessCfg.WebSocket = vless.WSConfig{
				Path: getStringSetting(wsCfg, "path", ""),
			}
			if hdrs := getMapSetting(wsCfg, "headers"); hdrs != nil {
				vlessCfg.WebSocket.Headers = make(map[string]string)
				for k, v := range hdrs {
					if s, ok := v.(string); ok {
						vlessCfg.WebSocket.Headers[k] = s
					}
				}
			}
		}
		// Parse nested gRPC settings.
		if grpcCfg := getMapSetting(cfg.Settings, "grpc"); grpcCfg != nil {
			vlessCfg.GRPC = vless.GRPCConfig{
				ServiceName: getStringSetting(grpcCfg, "service_name", ""),
			}
		}
		// Parse nested XHTTP settings.
		if xhttpCfg := getMapSetting(cfg.Settings, "xhttp"); xhttpCfg != nil {
			vlessCfg.XHTTP = vless.XHTTPConfig{
				Path: getStringSetting(xhttpCfg, "path", ""),
				Host: getStringSetting(xhttpCfg, "host", ""),
				Mode: getStringSetting(xhttpCfg, "mode", ""),
			}
			if extra := getMapSetting(xhttpCfg, "extra"); extra != nil {
				vlessCfg.XHTTP.Extra = extra
			}
		}
		return vless.New(cfg.Name, vlessCfg)
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
	if ep, ok := prov.(provider.EndpointProvider); ok {
		for _, addr := range ep.GetServerEndpoints() {
			if err := tc.deps.RouteMgr.AddBypassRoute(addr.Addr()); err != nil {
				core.Log.Warnf("Core", "Failed to add bypass route for %s: %v", addr, err)
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

// ─── VLESS settings helper ───────────────────────────────────────────

// applyVLESSSettings populates cfg.Settings from a parsed vless.Config.
func applyVLESSSettings(cfg *core.TunnelConfig, vc vless.Config) {
	if cfg.Settings == nil {
		cfg.Settings = make(map[string]any)
	}
	cfg.Settings["address"] = vc.Address
	cfg.Settings["port"] = fmt.Sprintf("%d", vc.Port)
	cfg.Settings["uuid"] = vc.UUID
	cfg.Settings["flow"] = vc.Flow
	cfg.Settings["encryption"] = vc.Encryption
	cfg.Settings["network"] = vc.Network
	cfg.Settings["security"] = vc.Security

	if vc.Security == "reality" {
		cfg.Settings["reality"] = map[string]any{
			"public_key":  vc.Reality.PublicKey,
			"short_id":    vc.Reality.ShortID,
			"server_name": vc.Reality.ServerName,
			"fingerprint": vc.Reality.Fingerprint,
			"spider_x":    vc.Reality.SpiderX,
		}
	}
	if vc.Security == "tls" {
		cfg.Settings["tls"] = map[string]any{
			"server_name":    vc.TLS.ServerName,
			"fingerprint":    vc.TLS.Fingerprint,
			"allow_insecure": vc.TLS.AllowInsecure,
		}
	}
	if vc.Network == "ws" {
		ws := map[string]any{"path": vc.WebSocket.Path}
		if len(vc.WebSocket.Headers) > 0 {
			ws["headers"] = vc.WebSocket.Headers
		}
		cfg.Settings["ws"] = ws
	}
	if vc.Network == "grpc" {
		cfg.Settings["grpc"] = map[string]any{
			"service_name": vc.GRPC.ServiceName,
		}
	}
	if vc.Network == "xhttp" || vc.Network == "splithttp" {
		xhttp := map[string]any{}
		if vc.XHTTP.Path != "" {
			xhttp["path"] = vc.XHTTP.Path
		}
		if vc.XHTTP.Host != "" {
			xhttp["host"] = vc.XHTTP.Host
		}
		if vc.XHTTP.Mode != "" {
			xhttp["mode"] = vc.XHTTP.Mode
		}
		if len(vc.XHTTP.Extra) > 0 {
			xhttp["extra"] = vc.XHTTP.Extra
		}
		if len(xhttp) > 0 {
			cfg.Settings["xhttp"] = xhttp
		}
	}
}

// ─── ID generation & config persistence ─────────────────────────────

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// generateTunnelID creates a unique tunnel ID from name and protocol.
// Must be called with tc.mu held.
func (tc *TunnelControllerImpl) generateTunnelID(name, protocol string) string {
	base := name
	if base == "" {
		base = protocol
	}
	// Slugify: lowercase, replace non-alnum with dash, trim dashes.
	slug := strings.ToLower(base)
	slug = slugRe.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "tunnel"
	}

	// Ensure uniqueness.
	candidate := slug
	for i := 2; ; i++ {
		if _, exists := tc.instances[candidate]; !exists {
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", slug, i)
	}
}

// persistTunnelConfig adds the tunnel config to ConfigManager and saves.
func (tc *TunnelControllerImpl) persistTunnelConfig(tunnelCfg core.TunnelConfig) {
	if tc.deps.Cfg == nil {
		return
	}
	cfg := tc.deps.Cfg.Get()
	cfg.Tunnels = append(cfg.Tunnels, tunnelCfg)
	tc.deps.Cfg.SetFromGUI(cfg)
	if err := tc.deps.Cfg.Save(); err != nil {
		core.Log.Warnf("Core", "Failed to persist tunnel %q config: %v", tunnelCfg.ID, err)
	}
}

// removeTunnelConfig removes the tunnel from ConfigManager and saves.
func (tc *TunnelControllerImpl) removeTunnelConfig(tunnelID string) {
	if tc.deps.Cfg == nil {
		return
	}
	cfg := tc.deps.Cfg.Get()
	filtered := cfg.Tunnels[:0]
	for _, t := range cfg.Tunnels {
		if t.ID != tunnelID {
			filtered = append(filtered, t)
		}
	}
	cfg.Tunnels = filtered
	tc.deps.Cfg.SetFromGUI(cfg)
	if err := tc.deps.Cfg.Save(); err != nil {
		core.Log.Warnf("Core", "Failed to remove tunnel %q from config: %v", tunnelID, err)
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

func getIntSetting(settings map[string]any, key string, defaultVal int) int {
	if v, ok := settings[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case float64:
			return int(n)
		case string:
			var i int
			if _, err := fmt.Sscanf(n, "%d", &i); err == nil {
				return i
			}
		}
	}
	return defaultVal
}

func getBoolSetting(settings map[string]any, key string, defaultVal bool) bool {
	if v, ok := settings[key]; ok {
		switch b := v.(type) {
		case bool:
			return b
		case string:
			return b == "true" || b == "1" || b == "yes"
		}
	}
	return defaultVal
}

func getMapSetting(settings map[string]any, key string) map[string]any {
	if v, ok := settings[key]; ok {
		if m, ok := v.(map[string]any); ok {
			return m
		}
	}
	return nil
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

// saveActiveTunnels persists the list of currently connected tunnel IDs to config.
func (tc *TunnelControllerImpl) saveActiveTunnels() {
	if tc.deps.Cfg == nil {
		return
	}

	var active []string
	for id := range tc.instances {
		if tc.deps.Registry.GetState(id) == core.TunnelStateUp {
			active = append(active, id)
		}
	}

	cfg := tc.deps.Cfg.Get()
	cfg.GUI.ActiveTunnels = active
	tc.deps.Cfg.SetQuiet(cfg)
	if err := tc.deps.Cfg.Save(); err != nil {
		core.Log.Warnf("Core", "Failed to save active tunnels: %v", err)
	}
}
