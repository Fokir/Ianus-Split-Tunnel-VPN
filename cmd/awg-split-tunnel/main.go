//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/gateway"
	"awg-split-tunnel/internal/process"
	"awg-split-tunnel/internal/provider"
	"awg-split-tunnel/internal/provider/amneziawg"
	"awg-split-tunnel/internal/provider/direct"
	"awg-split-tunnel/internal/proxy"
)

// Build info — injected via ldflags at compile time.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("awg-split-tunnel %s (commit=%s, built=%s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("[Core] AWG Split Tunnel %s starting...", version)

	// === 1. Core components ===
	bus := core.NewEventBus()

	resolvedConfigPath := resolveRelativeToExe(*configPath)
	cfgManager := core.NewConfigManager(resolvedConfigPath, bus)
	if err := cfgManager.Load(); err != nil {
		log.Fatalf("[Core] Failed to load config: %v", err)
	}
	cfg := cfgManager.Get()

	registry := core.NewTunnelRegistry(bus)
	matcher := process.NewMatcher()
	ruleEngine := core.NewRuleEngine(cfg.Rules, bus, matcher)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// === 2. Gateway Adapter (WinTUN) ===
	adapter, err := gateway.NewAdapter()
	if err != nil {
		log.Fatalf("[Core] Failed to create gateway adapter: %v", err)
	}

	// === 3. Discover Real NIC ===
	routeMgr := gateway.NewRouteManager(adapter.LUID())
	realNIC, err := routeMgr.DiscoverRealNIC()
	if err != nil {
		adapter.Close()
		log.Fatalf("[Core] Failed to discover real NIC: %v", err)
	}

	// === 4. WFP Manager ===
	wfpMgr, err := gateway.NewWFPManager(adapter.LUID())
	if err != nil {
		adapter.Close()
		log.Fatalf("[Core] Failed to create WFP manager: %v", err)
	}

	// === 5. Flow Table + Process Identifier ===
	flows := gateway.NewFlowTable()
	procID := gateway.NewProcessIdentifier()

	// === 6. DNS Router ===
	dnsConfig := gateway.DNSConfig{
		FallbackTunnelID: cfg.DNS.FallbackTunnelID,
	}
	for _, s := range cfg.DNS.Servers {
		if ip, err := netip.ParseAddr(s); err == nil {
			dnsConfig.FallbackServers = append(dnsConfig.FallbackServers, ip)
		} else {
			log.Printf("[Core] Invalid DNS server %q in config: %v", s, err)
		}
	}
	dnsRouter := gateway.NewDNSRouter(dnsConfig, registry)

	// === 7. TUN Router (not started yet) ===
	tunRouter := gateway.NewTUNRouter(
		adapter, flows, procID, matcher, ruleEngine, registry, wfpMgr, dnsRouter,
	)

	// === 8. Direct Provider + proxies ===
	providers := make(map[string]provider.TunnelProvider)
	proxies := make([]*proxy.TunnelProxy, 0)
	udpProxies := make([]*proxy.UDPProxy, 0)

	// Provider lookup function for proxies.
	providerLookup := func(tunnelID string) (provider.TunnelProvider, bool) {
		p, ok := providers[tunnelID]
		return p, ok
	}

	var nextProxyPort uint16 = 30000

	// Register Direct Provider.
	directProv := direct.New(realNIC.Index)
	directProxyPort := nextProxyPort
	directUDPProxyPort := nextProxyPort + 1
	nextProxyPort += 2

	directCfg := core.TunnelConfig{
		ID:       gateway.DirectTunnelID,
		Protocol: "direct",
		Name:     "Direct",
	}
	if err := registry.Register(directCfg, directProxyPort, directUDPProxyPort); err != nil {
		log.Fatalf("[Core] Failed to register direct provider: %v", err)
	}
	registry.SetState(gateway.DirectTunnelID, core.TunnelStateUp, nil)
	providers[gateway.DirectTunnelID] = directProv

	flows.RegisterProxyPort(directProxyPort)
	flows.RegisterUDPProxyPort(directUDPProxyPort)

	tp := proxy.NewTunnelProxy(directProxyPort, flows.LookupNAT, providerLookup)
	proxies = append(proxies, tp)
	if err := tp.Start(ctx); err != nil {
		log.Fatalf("[Core] Failed to start direct TCP proxy: %v", err)
	}

	up := proxy.NewUDPProxy(directUDPProxyPort, flows.LookupUDPNAT, providerLookup)
	udpProxies = append(udpProxies, up)
	if err := up.Start(ctx); err != nil {
		log.Fatalf("[Core] Failed to start direct UDP proxy: %v", err)
	}

	// === 9. VPN Providers + proxies ===
	for _, tcfg := range cfg.Tunnels {
		proxyPort := nextProxyPort
		udpProxyPort := nextProxyPort + 1
		nextProxyPort += 2

		var prov provider.TunnelProvider

		switch tcfg.Protocol {
		case "amneziawg":
			configFile := getStringSetting(tcfg.Settings, "config_file", "")
			if configFile != "" {
				configFile = resolveRelativeToExe(configFile)
			}
			awgCfg := amneziawg.Config{
				ConfigFile: configFile,
				AdapterIP:  getStringSetting(tcfg.Settings, "adapter_ip", ""),
			}
			p, err := amneziawg.New(tcfg.Name, awgCfg)
			if err != nil {
				log.Printf("[Core] Failed to create AWG provider %q: %v", tcfg.ID, err)
				continue
			}
			prov = p

		default:
			log.Printf("[Core] Unknown protocol %q for tunnel %q, skipping", tcfg.Protocol, tcfg.ID)
			continue
		}

		// Register tunnel.
		if err := registry.Register(tcfg, proxyPort, udpProxyPort); err != nil {
			log.Printf("[Core] Failed to register tunnel %q: %v", tcfg.ID, err)
			continue
		}

		providers[tcfg.ID] = prov
		flows.RegisterProxyPort(proxyPort)
		flows.RegisterUDPProxyPort(udpProxyPort)

		// TCP proxy.
		tp := proxy.NewTunnelProxy(proxyPort, flows.LookupNAT, providerLookup)
		proxies = append(proxies, tp)
		if err := tp.Start(ctx); err != nil {
			log.Printf("[Core] Failed to start TCP proxy for tunnel %q: %v", tcfg.ID, err)
			continue
		}

		// UDP proxy.
		up := proxy.NewUDPProxy(udpProxyPort, flows.LookupUDPNAT, providerLookup)
		udpProxies = append(udpProxies, up)
		if err := up.Start(ctx); err != nil {
			log.Printf("[Core] Failed to start UDP proxy for tunnel %q: %v", tcfg.ID, err)
			continue
		}

		// Connect the provider.
		if err := prov.Connect(ctx); err != nil {
			log.Printf("[Core] Failed to connect tunnel %q: %v", tcfg.ID, err)
			registry.SetState(tcfg.ID, core.TunnelStateError, err)
			continue
		}
		registry.SetState(tcfg.ID, core.TunnelStateUp, nil)

		// Register raw forwarder if the provider supports it.
		if rf, ok := prov.(provider.RawForwarder); ok {
			vpnIP := prov.GetAdapterIP()
			if vpnIP.IsValid() && vpnIP.Is4() {
				tunRouter.RegisterRawForwarder(tcfg.ID, rf, vpnIP.As4())
			}
		}

		// === 10. Add bypass route for VPN server endpoints ===
		if awgProv, ok := prov.(*amneziawg.Provider); ok {
			for _, ep := range awgProv.GetPeerEndpoints() {
				if err := routeMgr.AddBypassRoute(ep.Addr()); err != nil {
					log.Printf("[Core] Failed to add bypass route for %s: %v", ep, err)
				}
			}
		}
	}

	// === 11. Set default route via TUN (LAST — after all bypass routes) ===
	if err := routeMgr.SetDefaultRoute(); err != nil {
		log.Fatalf("[Core] Failed to set default route: %v", err)
	}

	// === 12. Start TUN Router ===
	if err := tunRouter.Start(ctx); err != nil {
		log.Fatalf("[Core] Failed to start TUN router: %v", err)
	}

	// --- Log active rules ---
	rules := ruleEngine.GetRules()
	log.Printf("[Core] Active rules: %d", len(rules))
	for _, r := range rules {
		log.Printf("[Rule]   %s → tunnel=%q fallback=%s", r.Pattern, r.TunnelID, r.Fallback)
	}

	// --- Wait for shutdown signal ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	log.Println("[Core] Running. Press Ctrl+C to stop.")
	<-sig

	// === Graceful shutdown (reverse order) ===
	log.Println("[Core] Shutting down...")
	cancel()

	done := make(chan struct{})
	go func() {
		// 1. Stop TUN Router
		tunRouter.Stop()

		// 2. Stop all proxies
		for _, tp := range proxies {
			tp.Stop()
		}
		for _, up := range udpProxies {
			up.Stop()
		}

		// 3. Disconnect all providers
		for id, prov := range providers {
			if err := prov.Disconnect(); err != nil {
				log.Printf("[Core] Error disconnecting %s: %v", id, err)
			}
		}

		// 4. WFP Manager Close (Dynamic=true auto-cleans)
		wfpMgr.Close()

		// 5. Route Manager Cleanup (restore default route)
		routeMgr.Cleanup()

		// 6. Gateway Adapter Close (remove TUN)
		adapter.Close()

		close(done)
	}()

	select {
	case <-done:
		log.Println("[Core] Shutdown complete.")
	case <-time.After(10 * time.Second):
		log.Println("[Core] Shutdown timed out, forcing exit.")
		os.Exit(1)
	}
}

func getStringSetting(settings map[string]any, key, defaultVal string) string {
	if v, ok := settings[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultVal
}

// resolveRelativeToExe resolves a relative path against the directory containing
// the running executable. Absolute paths are returned unchanged.
func resolveRelativeToExe(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	exe, err := os.Executable()
	if err != nil {
		log.Printf("[Core] Cannot determine executable path, using %q as-is: %v", path, err)
		return path
	}
	return filepath.Join(filepath.Dir(exe), path)
}
