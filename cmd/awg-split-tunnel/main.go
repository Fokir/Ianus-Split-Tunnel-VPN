//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/gateway"
	"awg-split-tunnel/internal/ipc"
	"awg-split-tunnel/internal/process"
	"awg-split-tunnel/internal/provider"
	"awg-split-tunnel/internal/provider/direct"
	"awg-split-tunnel/internal/provider/vless"
	"awg-split-tunnel/internal/proxy"
	"awg-split-tunnel/internal/service"
	"awg-split-tunnel/internal/update"
	"awg-split-tunnel/internal/winsvc"
)

// Build info — injected via ldflags at compile time.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// stopCh is used to signal shutdown from SCM or OS signals.
var stopCh = make(chan struct{}, 1)

func main() {
	// Handle subcommands first (install, uninstall, start, stop).
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			handleInstall()
			return
		case "uninstall":
			handleUninstall()
			return
		case "start":
			handleStart()
			return
		case "stop":
			handleStop()
			return
		}
	}

	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Print version and exit")
	serviceMode := flag.Bool("service", false, "Run as Windows Service (used by SCM)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("awg-split-tunnel %s (commit=%s, built=%s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	resolvedConfig := resolveRelativeToExe(*configPath)

	// Determine if running as a Windows Service.
	if *serviceMode || winsvc.IsWindowsService() {
		runFunc := func() error {
			return runVPN(resolvedConfig)
		}
		stopFunc := func() {
			close(stopCh)
		}
		if err := winsvc.RunService(runFunc, stopFunc); err != nil {
			log.Fatalf("[Core] Service failed: %v", err)
		}
		return
	}

	// Console mode (development / direct launch).
	if err := runVPN(resolvedConfig); err != nil {
		log.Fatalf("[Core] Fatal: %v", err)
	}
}

// runVPN contains the full VPN lifecycle. It blocks until shutdown is signalled.
func runVPN(configPath string) error {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// === 1. Core components ===
	bus := core.NewEventBus()

	cfgManager := core.NewConfigManager(configPath, bus)
	if err := cfgManager.Load(); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	cfg := cfgManager.Get()

	// Initialize logger from config.
	core.Log = core.NewLogger(cfg.Logging)

	// Start log streamer early so it captures ALL log messages from the start.
	logStreamer := service.NewLogStreamer(bus)
	logStreamer.Start()

	core.Log.Infof("Core", "AWG Split Tunnel %s starting...", version)

	registry := core.NewTunnelRegistry(bus)
	matcher := process.NewMatcher()
	ruleEngine := core.NewRuleEngine(cfg.Rules, bus, matcher)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// === 2. Gateway Adapter (WinTUN) ===
	adapter, err := gateway.NewAdapter()
	if err != nil {
		return fmt.Errorf("failed to create gateway adapter: %w", err)
	}

	// === 3. Discover Real NIC ===
	routeMgr := gateway.NewRouteManager(adapter.LUID())
	realNIC, err := routeMgr.DiscoverRealNIC()
	if err != nil {
		adapter.Close()
		return fmt.Errorf("failed to discover real NIC: %w", err)
	}

	// === 4. WFP Manager ===
	wfpMgr, err := gateway.NewWFPManager(adapter.LUID())
	if err != nil {
		adapter.Close()
		return fmt.Errorf("failed to create WFP manager: %w", err)
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
			core.Log.Warnf("Core", "Invalid DNS server %q in config: %v", s, err)
		}
	}
	dnsRouter := gateway.NewDNSRouter(dnsConfig, registry)

	// === 7. TUN Router (not started yet) ===
	tunRouter := gateway.NewTUNRouter(
		adapter, flows, procID, matcher, ruleEngine, registry, wfpMgr, dnsRouter,
	)

	// === 7a. IP/App Filter ===
	ipFilter := gateway.NewIPFilter(cfg.Global, cfg.Tunnels)
	tunRouter.SetIPFilter(ipFilter)
	if ipFilter.HasFilters() {
		core.Log.Infof("Gateway", "IP/App filter active: global disallowed_ips=%d, global allowed_ips=%d, global disallowed_apps=%d",
			len(cfg.Global.DisallowedIPs), len(cfg.Global.AllowedIPs), len(cfg.Global.DisallowedApps))
	}

	// === 7b. WFP bypass permits for local/disallowed CIDRs ===
	bypassPrefixes := gateway.GetBypassPrefixes(cfg.Global)
	if len(bypassPrefixes) > 0 {
		if err := wfpMgr.AddBypassPrefixes(bypassPrefixes); err != nil {
			core.Log.Warnf("Core", "Failed to add WFP bypass permits: %v", err)
		}
	}

	// === 8. Direct Provider + proxies ===
	providers := make(map[string]provider.TunnelProvider)
	proxies := make([]*proxy.TunnelProxy, 0)
	udpProxies := make([]*proxy.UDPProxy, 0)

	providerLookup := func(tunnelID string) (provider.TunnelProvider, bool) {
		p, ok := providers[tunnelID]
		return p, ok
	}

	var nextProxyPort uint16 = 30000

	// Register Direct Provider.
	directProv := direct.New(realNIC.Index, realNIC.LocalIP)
	directProxyPort := nextProxyPort
	directUDPProxyPort := nextProxyPort + 1
	nextProxyPort += 2

	directCfg := core.TunnelConfig{
		ID:       gateway.DirectTunnelID,
		Protocol: "direct",
		Name:     "Direct",
	}
	if err := registry.Register(directCfg, directProxyPort, directUDPProxyPort); err != nil {
		return fmt.Errorf("failed to register direct provider: %w", err)
	}
	registry.SetState(gateway.DirectTunnelID, core.TunnelStateUp, nil)
	providers[gateway.DirectTunnelID] = directProv

	flows.RegisterProxyPort(directProxyPort)
	flows.RegisterUDPProxyPort(directUDPProxyPort)

	tp := proxy.NewTunnelProxy(directProxyPort, flows.LookupNAT, providerLookup)
	proxies = append(proxies, tp)
	if err := tp.Start(ctx); err != nil {
		return fmt.Errorf("failed to start direct TCP proxy: %w", err)
	}

	up := proxy.NewUDPProxy(directUDPProxyPort, flows.LookupUDPNAT, providerLookup)
	udpProxies = append(udpProxies, up)
	if err := up.Start(ctx); err != nil {
		return fmt.Errorf("failed to start direct UDP proxy: %w", err)
	}

	// === 8a. Subscriptions: fetch and merge into tunnel list ===
	subMgr := core.NewSubscriptionManager(cfgManager, bus, nil, vless.ParseURIToTunnelConfig)
	if len(cfg.Subscriptions) > 0 {
		subTunnels, err := subMgr.RefreshAll(ctx)
		if err != nil {
			core.Log.Warnf("Core", "Subscription errors: %v", err)
		}
		if len(subTunnels) > 0 {
			cfg.Tunnels = append(cfg.Tunnels, subTunnels...)
			core.Log.Infof("Core", "Added %d tunnels from subscriptions", len(subTunnels))
		}
	}

	// === 9. VPN Providers + proxies ===
	var jitterProbes []*gateway.JitterProbe
	for _, tcfg := range cfg.Tunnels {
		proxyPort := nextProxyPort
		udpProxyPort := nextProxyPort + 1
		nextProxyPort += 2

		prov, err := service.CreateProvider(tcfg)
		if err != nil {
			core.Log.Errorf("Core", "Failed to create provider for tunnel %q: %v", tcfg.ID, err)
			continue
		}

		if err := registry.Register(tcfg, proxyPort, udpProxyPort); err != nil {
			core.Log.Errorf("Core", "Failed to register tunnel %q: %v", tcfg.ID, err)
			continue
		}

		providers[tcfg.ID] = prov
		flows.RegisterProxyPort(proxyPort)
		flows.RegisterUDPProxyPort(udpProxyPort)

		tp := proxy.NewTunnelProxy(proxyPort, flows.LookupNAT, providerLookup)
		proxies = append(proxies, tp)
		if err := tp.Start(ctx); err != nil {
			core.Log.Errorf("Core", "Failed to start TCP proxy for tunnel %q: %v", tcfg.ID, err)
			continue
		}

		up := proxy.NewUDPProxy(udpProxyPort, flows.LookupUDPNAT, providerLookup)
		udpProxies = append(udpProxies, up)
		if err := up.Start(ctx); err != nil {
			core.Log.Errorf("Core", "Failed to start UDP proxy for tunnel %q: %v", tcfg.ID, err)
			continue
		}

		if err := prov.Connect(ctx); err != nil {
			core.Log.Errorf("Core", "Failed to connect tunnel %q: %v", tcfg.ID, err)
			registry.SetState(tcfg.ID, core.TunnelStateError, err)
			continue
		}
		registry.SetState(tcfg.ID, core.TunnelStateUp, nil)
		ruleEngine.SetTunnelActive(tcfg.ID, true)

		if rf, ok := prov.(provider.RawForwarder); ok {
			vpnIP := prov.GetAdapterIP()
			if vpnIP.IsValid() && vpnIP.Is4() {
				tunRouter.RegisterRawForwarder(tcfg.ID, rf, vpnIP.As4())
			}
		}

		_, isRaw := prov.(provider.RawForwarder)
		probe := gateway.NewJitterProbe(prov, tcfg.ID, "8.8.8.8:53", !isRaw)
		jitterProbes = append(jitterProbes, probe)
		go probe.Run(ctx)

		// === 10. Add bypass route for VPN server endpoints ===
		if ep, ok := prov.(provider.EndpointProvider); ok {
			for _, addr := range ep.GetServerEndpoints() {
				if err := routeMgr.AddBypassRoute(addr.Addr()); err != nil {
					core.Log.Warnf("Core", "Failed to add bypass route for %s: %v", addr, err)
				}
			}
		}
	}

	// === 10a. Create TunnelController and register existing tunnels ===
	tunnelCtrl := service.NewTunnelController(ctx, service.ControllerDeps{
		Registry:       registry,
		Bus:            bus,
		Flows:          flows,
		TUNRouter:      tunRouter,
		RouteMgr:       routeMgr,
		WFPMgr:         wfpMgr,
		Adapter:        adapter,
		DNSRouter:      dnsRouter,
		RealNICIndex:   realNIC.Index,
		RealNICLocalIP: realNIC.LocalIP,
		RealNICLUID:    realNIC.LUID,
		Providers:      providers,
		Rules:          ruleEngine,
		Cfg:            cfgManager,
	}, nextProxyPort)

	for _, tcfg := range cfg.Tunnels {
		if prov, ok := providers[tcfg.ID]; ok {
			entry, entryOk := registry.Get(tcfg.ID)
			if !entryOk {
				continue
			}
			var tunnelTP *proxy.TunnelProxy
			var tunnelUP *proxy.UDPProxy
			for _, p := range proxies {
				if p.Port() == entry.ProxyPort {
					tunnelTP = p
					break
				}
			}
			for _, p := range udpProxies {
				if p.Port() == entry.UDPProxyPort {
					tunnelUP = p
					break
				}
			}
			if tunnelTP != nil && tunnelUP != nil {
				tunnelCtrl.RegisterExistingTunnel(
					tcfg.ID, prov, tunnelTP, tunnelUP,
					entry.ProxyPort, entry.UDPProxyPort, tcfg,
				)
			}
		}
	}

	// === 10b. Start subscription auto-refresh ===
	if subMgr != nil {
		subMgr.Start(ctx)
	}

	// === 11. Set default route via TUN (LAST — after all bypass routes) ===
	if err := routeMgr.SetDefaultRoute(); err != nil {
		return fmt.Errorf("failed to set default route: %w", err)
	}

	// === 11a. DNS Resolver (local DNS forwarder through VPN) ===
	var dnsResolver *gateway.DNSResolver
	if dnsConfig.FallbackTunnelID != "" && len(dnsConfig.FallbackServers) > 0 {
		resolverCfg := gateway.DNSResolverConfig{
			ListenAddr:     adapter.IP().String() + ":53",
			Servers:        dnsConfig.FallbackServers,
			TunnelID:       dnsConfig.FallbackTunnelID,
			FallbackDirect: true,
			Cache:          buildDNSCacheConfig(cfg.DNS.Cache),
		}
		dnsResolver = gateway.NewDNSResolver(resolverCfg, registry, providers)
		if err := dnsResolver.Start(ctx); err != nil {
			core.Log.Warnf("DNS", "Failed to start DNS resolver: %v", err)
		} else {
			resolverIP := []netip.Addr{adapter.IP()}
			if err := adapter.SetDNS(resolverIP); err != nil {
				core.Log.Warnf("DNS", "Failed to set DNS on TUN adapter: %v", err)
			} else {
				core.Log.Infof("DNS", "TUN adapter DNS → %s (local resolver)", adapter.IP())
			}

			if err := wfpMgr.BlockDNSOnInterface(realNIC.LUID); err != nil {
				core.Log.Warnf("DNS", "Failed to add DNS leak protection: %v", err)
			}
		}
	}

	// === 11c. Domain-based routing ===
	geositeFilePath := resolveRelativeToExe("geosite.dat")
	nicHTTPClient := gateway.NewNICBoundHTTPClient(realNIC.Index, realNIC.LocalIP)
	domainTable := gateway.NewDomainTable()
	domainTable.StartCleanup(ctx)
	domainMatcher := buildDomainMatcher(cfg.DomainRules, geositeFilePath, nicHTTPClient)
	if dnsResolver != nil {
		dnsResolver.SetDomainMatcher(domainMatcher)
		dnsResolver.SetDomainTable(domainTable)
	}
	tunRouter.SetDomainTable(domainTable)
	if domainMatcher != nil && !domainMatcher.IsEmpty() {
		core.Log.Infof("DNS", "Domain matcher active: %d rules", len(cfg.DomainRules))
	}

	domainReloader := func(rules []core.DomainRule) error {
		m := buildDomainMatcher(rules, geositeFilePath, nicHTTPClient)
		if dnsResolver != nil {
			dnsResolver.SetDomainMatcher(m)
		}
		domainTable.Flush()
		core.Log.Infof("DNS", "Domain rules reloaded: %d rules", len(rules))
		return nil
	}

	// === 11b. Stats Collector ===
	statsCollector := service.NewStatsCollector(registry, bus)
	tunRouter.SetBytesReporter(statsCollector.AddBytes)
	for _, probe := range jitterProbes {
		statsCollector.RegisterDiagnostics(probe)
	}

	// === 12. Start TUN Router ===
	if err := tunRouter.Start(ctx); err != nil {
		return fmt.Errorf("failed to start TUN router: %w", err)
	}

	rules := ruleEngine.GetRules()
	core.Log.Infof("Core", "Active rules: %d", len(rules))
	for _, r := range rules {
		core.Log.Infof("Rule", "  %s → tunnel=%q fallback=%s", r.Pattern, r.TunnelID, r.Fallback)
	}

	// === 12a. Update Checker ===
	var updateChecker *update.Checker
	if cfg.Update.IsEnabled() {
		interval := 24 * time.Hour
		if cfg.Update.CheckInterval != "" {
			if d, err := time.ParseDuration(cfg.Update.CheckInterval); err == nil && d > 0 {
				interval = d
			}
		}
		updateChecker = update.NewChecker(version, interval, bus, nicHTTPClient)
		go updateChecker.Start(ctx)
		core.Log.Infof("Update", "Auto-update checker started (interval=%s)", interval)
	}

	// === 13. Start gRPC IPC server for GUI communication ===
	svc := service.New(service.Config{
		ConfigManager:       cfgManager,
		TunnelRegistry:      registry,
		RuleEngine:          ruleEngine,
		EventBus:            bus,
		TunnelCtrl:          tunnelCtrl,
		LogStreamer:         logStreamer,
		StatsCollector:      statsCollector,
		Version:             version,
		DomainReloader:      domainReloader,
		GeositeFilePath:     geositeFilePath,
		HTTPClient:          nicHTTPClient,
		SubscriptionManager: subMgr,
		UpdateChecker:       updateChecker,
	})
	svc.Start(ctx)

	ipcServer := ipc.NewServer(svc)
	go func() {
		core.Log.Infof("Core", "IPC server starting on %s", ipc.PipeName)
		if err := ipcServer.Start(); err != nil {
			core.Log.Errorf("Core", "IPC server error: %v", err)
		}
	}()

	// --- Wait for shutdown signal ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Listen for RPC-initiated shutdown (Shutdown RPC publishes this event).
	bus.Subscribe(core.EventConfigReloaded, func(e core.Event) {
		if e.Payload == "shutdown" {
			sig <- syscall.SIGTERM
		}
	})

	core.Log.Infof("Core", "Running. Press Ctrl+C to stop.")

	// Wait for either OS signal or SCM stop (via stopCh).
	select {
	case <-sig:
	case <-stopCh:
	}

	// === Graceful shutdown (reverse order) ===
	core.Log.Infof("Core", "Shutting down...")
	cancel()

	done := make(chan struct{})
	go func() {
		ipcServer.Stop()
		svc.Stop()

		if subMgr != nil {
			subMgr.Stop()
		}

		if dnsResolver != nil {
			dnsResolver.Stop()
		}

		tunRouter.Stop()

		for _, tp := range proxies {
			tp.Stop()
		}
		for _, up := range udpProxies {
			up.Stop()
		}

		for id, prov := range providers {
			if err := prov.Disconnect(); err != nil {
				core.Log.Errorf("Core", "Error disconnecting %s: %v", id, err)
			}
		}

		wfpMgr.Close()
		routeMgr.Cleanup()
		adapter.Close()

		close(done)
	}()

	select {
	case <-done:
		core.Log.Infof("Core", "Shutdown complete.")
	case <-time.After(10 * time.Second):
		core.Log.Errorf("Core", "Shutdown timed out, forcing exit.")
		os.Exit(1)
	}

	return nil
}

// handleInstall registers the service with the Windows SCM.
func handleInstall() {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to configuration file (optional)")
	fs.Parse(os.Args[2:])

	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine executable path: %v\n", err)
		os.Exit(1)
	}

	if err := winsvc.InstallService(exePath, *configPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service installed successfully.")
}

// handleUninstall removes the service from the Windows SCM.
func handleUninstall() {
	if err := winsvc.UninstallService(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service uninstalled successfully.")
}

// handleStart starts the service via SCM.
func handleStart() {
	if err := winsvc.StartService(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service started successfully.")
}

// handleStop stops the service via SCM.
func handleStop() {
	if err := winsvc.StopService(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service stopped successfully.")
}

func getStringSetting(settings map[string]any, key, defaultVal string) string {
	if v, ok := settings[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultVal
}

func buildDNSCacheConfig(yamlCfg core.DNSCacheYAMLConfig) *gateway.DNSCacheConfig {
	if yamlCfg.Enabled != nil && !*yamlCfg.Enabled {
		return nil
	}
	cfg := &gateway.DNSCacheConfig{
		MaxSize: yamlCfg.MaxSize,
	}
	if yamlCfg.MinTTL != "" {
		if d, err := time.ParseDuration(yamlCfg.MinTTL); err == nil {
			cfg.MinTTL = d
		}
	}
	if yamlCfg.MaxTTL != "" {
		if d, err := time.ParseDuration(yamlCfg.MaxTTL); err == nil {
			cfg.MaxTTL = d
		}
	}
	if yamlCfg.NegTTL != "" {
		if d, err := time.ParseDuration(yamlCfg.NegTTL); err == nil {
			cfg.NegTTL = d
		}
	}
	return cfg
}

func buildDomainMatcher(rules []core.DomainRule, geositeFilePath string, httpClient *http.Client) *gateway.DomainMatcher {
	if len(rules) == 0 {
		return nil
	}

	var regularRules []core.DomainRule
	geositeCategories := make(map[string]core.DomainRule)

	for _, r := range rules {
		prefix, value := splitDomainPattern(r.Pattern)
		if prefix == "geosite" && value != "" {
			geositeCategories[value] = r
		} else {
			regularRules = append(regularRules, r)
		}
	}

	var geositeEntries []gateway.GeositeExpanded
	if len(geositeCategories) > 0 {
		if err := gateway.EnsureGeositeFile(geositeFilePath, httpClient); err != nil {
			core.Log.Warnf("DNS", "Failed to ensure geosite.dat: %v", err)
		} else {
			entries, err := gateway.LoadGeosite(geositeFilePath, geositeCategories)
			if err != nil {
				core.Log.Warnf("DNS", "Failed to load geosite data: %v", err)
			} else {
				geositeEntries = entries
			}
		}
	}

	return gateway.NewDomainMatcher(regularRules, geositeEntries)
}

func splitDomainPattern(pattern string) (string, string) {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == ':' {
			prefix := pattern[:i]
			switch prefix {
			case "domain", "full", "keyword", "geosite":
				return prefix, pattern[i+1:]
			}
			break
		}
	}
	return "domain", pattern
}

func resolveRelativeToExe(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	exe, err := os.Executable()
	if err != nil {
		core.Log.Warnf("Core", "Cannot determine executable path, using %q as-is: %v", path, err)
		return path
	}
	return filepath.Join(filepath.Dir(exe), path)
}
