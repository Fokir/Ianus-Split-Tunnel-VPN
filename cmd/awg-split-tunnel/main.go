//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/gateway"
	"awg-split-tunnel/internal/ipc"
	"awg-split-tunnel/internal/process"
	"awg-split-tunnel/internal/provider"
	"awg-split-tunnel/internal/provider/vless"
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

	// Start periodic PID cache revalidation (detects PID reuse, evicts dead entries).
	matcher.StartRevalidation(ctx)

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

	// === 4a. Block all IPv6 traffic ===
	if err := wfpMgr.BlockAllIPv6(); err != nil {
		core.Log.Warnf("WFP", "Failed to block IPv6: %v", err)
	}

	// === 5. Flow Table + Process Identifier ===
	flows := gateway.NewFlowTable()
	procID := gateway.NewProcessIdentifier()

	// === 6. DNS Router ===
	dnsConfig := gateway.DNSConfig{
		TunnelIDs: cfg.DNS.TunnelIDs,
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
	var nextProxyPort uint16 = 30000

	// NIC-bound HTTP client — created early so subscriptions can use it too.
	nicHTTPClient := gateway.NewNICBoundHTTPClient(realNIC.Index, realNIC.LocalIP)

	// === 8a. Subscriptions: fetch and merge into tunnel list ===
	subMgr := core.NewSubscriptionManager(cfgManager, bus, nicHTTPClient, vless.ParseURIToTunnelConfig)
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

	// === 9. VPN Providers + proxies (managed by TunnelController) ===
	// === 10a. Create TunnelController and register existing tunnels ===
	providers := make(map[string]provider.TunnelProvider)
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
		if err := tunnelCtrl.AddTunnel(ctx, tcfg, nil); err != nil {
			core.Log.Errorf("Core", "Failed to add tunnel %q during startup: %v", tcfg.ID, err)
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
	if len(dnsConfig.TunnelIDs) > 0 && len(dnsConfig.FallbackServers) > 0 {
		resolverCfg := gateway.DNSResolverConfig{
			ListenAddr:     adapter.IP().String() + ":53",
			Servers:        dnsConfig.FallbackServers,
			TunnelIDs:      dnsConfig.TunnelIDs,
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

			// Allow our own process to send DNS through the real NIC,
			// so the DNS resolver can fall back to direct when VPN tunnels are down.
			if err := wfpMgr.PermitDNSForSelf(realNIC.LUID); err != nil {
				core.Log.Warnf("DNS", "Failed to add DNS self-permit: %v", err)
			}
		}
	}

	// === 11c. Domain-based routing ===
	geositeFilePath := resolveRelativeToExe("geosite.dat")
	geoipFilePath := resolveRelativeToExe("geoip.dat")
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

	// GeoIP routing.
	geoipMatcher := buildGeoIPMatcher(cfg.DomainRules, geoipFilePath, nicHTTPClient)
	if geoipMatcher != nil && !geoipMatcher.IsEmpty() {
		tunRouter.SetGeoIPMatcher(geoipMatcher)
		core.Log.Infof("DNS", "GeoIP matcher active")
	}

	// Set initial SNI-based domain match function on tunnel proxies.
	if domainMatcher != nil && !domainMatcher.IsEmpty() {
		fn := domainMatchFuncFrom(domainMatcher)
		tunnelCtrl.SetDomainMatchFunc(&fn)
	}

	dnsFlush := func() error {
		if dnsResolver != nil {
			dnsResolver.FlushCache()
		}
		domainTable.Flush()
		// Flush Windows DNS cache.
		cmd := exec.Command("ipconfig", "/flushdns")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err != nil {
			core.Log.Warnf("DNS", "ipconfig /flushdns failed: %v", err)
		}
		core.Log.Infof("DNS", "All DNS caches flushed")
		return nil
	}

	domainReloader := func(rules []core.DomainRule) error {
		m := buildDomainMatcher(rules, geositeFilePath, nicHTTPClient)
		if dnsResolver != nil {
			dnsResolver.SetDomainMatcher(m)
		}
		domainTable.Flush()

		// Rebuild GeoIP matcher.
		gm := buildGeoIPMatcher(rules, geoipFilePath, nicHTTPClient)
		tunRouter.SetGeoIPMatcher(gm)

		// Update SNI-based routing on all proxies.
		if m != nil && !m.IsEmpty() {
			fn := domainMatchFuncFrom(m)
			tunnelCtrl.SetDomainMatchFunc(&fn)
		} else {
			tunnelCtrl.SetDomainMatchFunc(nil)
		}

		core.Log.Infof("DNS", "Domain rules reloaded: %d rules", len(rules))
		return nil
	}

	// === 11b. Stats Collector ===
	statsCollector := service.NewStatsCollector(registry, bus)
	tunRouter.SetBytesReporter(statsCollector.AddBytes)


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

	// === 12b. Reconnect Manager ===
	var reconnectMgr *service.ReconnectManager
	{
		rcfg := cfg.GUI.Reconnect
		// NIC-bound resolver for connectivity checks (bypass TUN).
		nicResolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp", "8.8.8.8:53")
			},
		}
		reconnectMgr = service.NewReconnectManager(rcfg, tunnelCtrl, registry, bus, nicResolver)
		if rcfg.Enabled && cfg.GUI.RestoreConnections {
			reconnectMgr.LoadIntents(cfg.GUI.ActiveTunnels)
		}
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
		DNSFlush:            dnsFlush,
		GeositeFilePath:     geositeFilePath,
		GeoIPFilePath:       geoipFilePath,
		HTTPClient:          nicHTTPClient,
		SubscriptionManager: subMgr,
		UpdateChecker:       updateChecker,
		ReconnectManager:    reconnectMgr,
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
	reloadCh := make(chan struct{}, 1)
	bus.Subscribe(core.EventConfigReloaded, func(e core.Event) {
		if e.Payload == "shutdown" {
			sig <- syscall.SIGTERM
		} else {
			// Signal that config needs to be reloaded.
			select {
			case reloadCh <- struct{}{}:
			default:
				core.Log.Warnf("Core", "Skipping config reload signal, channel full.")
			}
		}
	})

	core.Log.Infof("Core", "Running. Press Ctrl+C to stop, or modify config file for hot-reload.")

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

mainLoop:
	for {
		select {
		case <-sig:
			core.Log.Infof("Core", "OS signal received. Shutting down...")
			break mainLoop
		case <-stopCh:
			core.Log.Infof("Core", "SCM stop signal received. Shutting down...")
			break mainLoop
		case <-reloadCh:
			core.Log.Infof("Core", "Config reload signal received. Applying configuration...")
			// Read directly from in-memory config — it is already updated by the
			// setter that published EventConfigReloaded.  Re-reading from disk
			// (Load) would race with Save and could overwrite the new config.
			newCfg := cfgManager.Get()
			// TODO: Implement actual diffing and applying changes to tunnels.
			// For now, a simple re-initialization of IP filter and rules.
			ipFilter = gateway.NewIPFilter(newCfg.Global, newCfg.Tunnels)
			tunRouter.SetIPFilter(ipFilter)
			ruleEngine.SetRules(newCfg.Rules)
			// Rebuild domain matcher if rules changed
			if dnsResolver != nil {
				domainReloader(newCfg.DomainRules)
			}
			core.Log.Infof("Core", "Configuration reloaded.")
		case <-runCtx.Done():
			core.Log.Infof("Core", "Run context cancelled. Exiting main loop.")
			break mainLoop
		}
	}

	// === Graceful shutdown (reverse order) ===
	core.Log.Infof("Core", "Shutting down...")
	cancel() // Cancel the main context
	runCancel() // Cancel the run context

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

		// Use tunnel controller for graceful shutdown of all tunnels
		tunnelCtrl.Shutdown()

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
		core.Log.Close()
		os.Exit(1)
	}

	core.Log.Close()
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
		switch prefix {
		case "geosite":
			if value != "" {
				geositeCategories[value] = r
			}
		case "geoip":
			// GeoIP rules are handled separately via buildGeoIPMatcher; skip here.
			continue
		default:
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

func buildGeoIPMatcher(rules []core.DomainRule, geoipFilePath string, httpClient *http.Client) *gateway.GeoIPMatcher {
	geoipCategories := make(map[string]core.DomainRule)
	for _, r := range rules {
		prefix, value := splitDomainPattern(r.Pattern)
		if prefix == "geoip" && value != "" {
			geoipCategories[value] = r
		}
	}

	if len(geoipCategories) == 0 {
		return nil
	}

	if err := gateway.EnsureGeoIPFile(geoipFilePath, httpClient); err != nil {
		core.Log.Warnf("DNS", "Failed to ensure geoip.dat: %v", err)
		return nil
	}

	matcher, err := gateway.NewGeoIPMatcher(geoipFilePath, geoipCategories)
	if err != nil {
		core.Log.Warnf("DNS", "Failed to build GeoIP matcher: %v", err)
		return nil
	}
	return matcher
}

func splitDomainPattern(pattern string) (string, string) {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == ':' {
			prefix := pattern[:i]
			switch prefix {
			case "domain", "full", "keyword", "geosite", "geoip":
				return prefix, pattern[i+1:]
			}
			break
		}
	}
	return "domain", pattern
}

// domainMatchFuncFrom wraps a DomainMatcher into a core.DomainMatchFunc
// for use in the proxy layer's SNI-based routing.
func domainMatchFuncFrom(dm *gateway.DomainMatcher) core.DomainMatchFunc {
	return func(domain string) (string, core.DomainAction, bool) {
		r := dm.Match(domain)
		return r.TunnelID, r.Action, r.Matched
	}
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
