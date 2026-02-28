package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/daemon"
	"awg-split-tunnel/internal/dpi"
	"awg-split-tunnel/internal/gateway"
	"awg-split-tunnel/internal/ipc"
	"awg-split-tunnel/internal/platform"
	"awg-split-tunnel/internal/process"
	"awg-split-tunnel/internal/provider"
	"awg-split-tunnel/internal/provider/dpibypass"
	"awg-split-tunnel/internal/provider/vless"
	"awg-split-tunnel/internal/service"
	"awg-split-tunnel/internal/update"
)

// Build info — injected via ldflags at compile time.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// runVPN contains the full VPN lifecycle. It blocks until shutdown is signalled.
func runVPN(configPath string, plat *platform.Platform, stopCh <-chan struct{}, opts ...daemon.RunConfig) error {
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
	defer logStreamer.Stop() // safe to call multiple times; ensures cleanup on early init errors

	core.Log.Infof("Core", "AWG Split Tunnel %s starting...", version)

	// Clean up any orphaned routes from previous crashes.
	if err := gateway.CleanupOrphanedRoutes(); err != nil {
		core.Log.Warnf("Core", "Orphaned route cleanup failed: %v", err)
	}

	registry := core.NewTunnelRegistry(bus)
	matcher := process.NewMatcher()
	ruleEngine := core.NewRuleEngine(cfg.Rules, bus, matcher)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start periodic PID cache revalidation (detects PID reuse, evicts dead entries).
	matcher.StartRevalidation(ctx)

	// === 2. Gateway Adapter (TUN) ===
	adapter, err := plat.NewTUNAdapter()
	if err != nil {
		return fmt.Errorf("failed to create gateway adapter: %w", err)
	}

	// === 3. Discover Real NIC ===
	routeMgr := plat.NewRouteManager(adapter.LUID())
	realNIC, err := routeMgr.DiscoverRealNIC()
	if err != nil {
		adapter.Close()
		return fmt.Errorf("failed to discover real NIC: %w", err)
	}

	// === 4. Process Filter (WFP/PF) ===
	procFilter, err := plat.NewProcessFilter(adapter.LUID())
	if err != nil {
		adapter.Close()
		return fmt.Errorf("failed to create process filter: %w", err)
	}

	// Deferred cleanup for resources created before the main shutdown handler.
	// On normal path, initCleanup is set to nil after TUN router starts successfully.
	initCleanup := func() {
		procFilter.Close()
		routeMgr.Cleanup()
		adapter.Close()
	}
	defer func() {
		if initCleanup != nil {
			initCleanup()
		}
	}()

	// === 4a. Platform-specific pre-startup (e.g., cleanup conflicting WFP filters) ===
	if plat.PreStartup != nil {
		if err := plat.PreStartup(); err != nil {
			core.Log.Warnf("Core", "Pre-startup cleanup: %v", err)
		}
	}

	// === 4b. Block all IPv6 traffic ===
	if err := procFilter.BlockAllIPv6(); err != nil {
		core.Log.Warnf("Core", "Failed to block IPv6: %v", err)
	}

	// === 5. Flow Table + Process Identifier ===
	flows := gateway.NewFlowTable()
	procID := plat.NewProcessID()

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
		adapter, flows, procID, matcher, ruleEngine, registry, procFilter, dnsRouter,
	)

	// === 7a. IP/App Filter ===
	ipFilter := gateway.NewIPFilter(cfg.Global, cfg.Tunnels)
	tunRouter.SetIPFilter(ipFilter)
	if ipFilter.HasFilters() {
		core.Log.Infof("Gateway", "IP/App filter active: global disallowed_ips=%d, global allowed_ips=%d, global disallowed_apps=%d",
			len(cfg.Global.DisallowedIPs), len(cfg.Global.AllowedIPs), len(cfg.Global.DisallowedApps))
	}

	// === 7b. Process filter bypass permits for local/disallowed CIDRs ===
	bypassPrefixes := gateway.GetBypassPrefixes(cfg.Global)
	if len(bypassPrefixes) > 0 {
		if err := procFilter.AddBypassPrefixes(bypassPrefixes); err != nil {
			core.Log.Warnf("Core", "Failed to add bypass permits: %v", err)
		}
	}

	// === 8. Direct Provider + proxies ===
	var nextProxyPort uint16 = 30000

	// Create InterfaceBinder for binding sockets to real NIC (direct provider, HTTP client).
	ifBinder := plat.NewInterfaceBinder()

	// NIC-bound HTTP client — created early so subscriptions can use it too.
	nicHTTPClient := gateway.NewNICBoundHTTPClient(realNIC.Index, realNIC.LocalIP, ifBinder)

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
		Registry:        registry,
		Bus:             bus,
		Flows:           flows,
		TUNRouter:       tunRouter,
		RouteMgr:        routeMgr,
		WFPMgr:          procFilter,
		Adapter:         adapter,
		DNSRouter:       dnsRouter,
		RealNICIndex:    realNIC.Index,
		RealNICLocalIP:  realNIC.LocalIP,
		RealNICLUID:     realNIC.LUID,
		InterfaceBinder: ifBinder,
		Providers:       providers,
		Rules:           ruleEngine,
		Cfg:             cfgManager,
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

	// === 11. DNS Resolver (local DNS forwarder — created and started now, ===
	// === but routes and DNS interception are activated only when VPN tunnels connect) ===
	var dnsResolver *gateway.DNSResolver
	hasDNSResolver := false
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
			hasDNSResolver = true
		}
		// Enable in-band DNS hijack in the TUN router. On macOS, packets to
		// the TUN IP (10.255.0.1:53) go through the TUN device instead of
		// being delivered to the socket-based resolver. The TUN router
		// intercepts these and calls Resolve() directly.
		tunRouter.SetDNSResolver(dnsResolver)
	}

	// === 11a. Gateway activation controller ===
	// Routes, DNS interception, and per-process blocking are ONLY active
	// when at least one VPN tunnel (excluding __direct__) is UP.
	// This ensures unmatched traffic always flows through the real NIC normally.
	var (
		gwMu     sync.Mutex
		gwActive bool
	)

	activateGateway := func() {
		gwMu.Lock()
		defer gwMu.Unlock()
		if gwActive {
			return
		}

		// Platform-specific pre-activation cleanup (e.g., conflicting WFP filters).
		if plat.PreStartup != nil {
			if err := plat.PreStartup(); err != nil {
				core.Log.Warnf("Core", "Pre-activation cleanup: %v", err)
			}
		}

		if err := routeMgr.SetDefaultRoute(); err != nil {
			core.Log.Errorf("Core", "Failed to set default route on activation: %v", err)
			return
		}

		if hasDNSResolver {
			if err := adapter.SetDNS([]netip.Addr{adapter.IP()}); err != nil {
				core.Log.Warnf("DNS", "Failed to set DNS on TUN adapter: %v", err)
			}
			if err := procFilter.BlockDNSOnInterface(realNIC.LUID); err != nil {
				core.Log.Warnf("DNS", "Failed to add DNS leak protection: %v", err)
			}
			if err := procFilter.PermitDNSForSelf(realNIC.LUID); err != nil {
				core.Log.Warnf("DNS", "Failed to add DNS self-permit: %v", err)
			}
		}

		// === Kill Switch ===
		if cfgManager.Get().Global.KillSwitch {
			var vpnEndpoints []netip.Addr
			for _, entry := range registry.All() {
				if entry.ID == gateway.DirectTunnelID || entry.State != core.TunnelStateUp {
					continue
				}
				for _, ep := range tunnelCtrl.GetServerEndpoints(entry.ID) {
					vpnEndpoints = append(vpnEndpoints, ep.Addr())
				}
			}
			if err := procFilter.EnableKillSwitch(adapter.Name(), vpnEndpoints); err != nil {
				core.Log.Warnf("Core", "Failed to enable kill switch: %v", err)
			}
		}

		gwActive = true
		core.Log.Infof("Core", "Gateway activated (VPN tunnel available)")
	}

	deactivateGateway := func() {
		gwMu.Lock()
		defer gwMu.Unlock()
		if !gwActive {
			return
		}

		// Disable kill switch before removing other rules.
		if err := procFilter.DisableKillSwitch(); err != nil {
			core.Log.Warnf("Core", "Failed to disable kill switch: %v", err)
		}

		// Remove per-process blocking rules first — they block apps on real NIC.
		procFilter.UnblockAllProcesses()

		if err := routeMgr.RemoveDefaultRoute(); err != nil {
			core.Log.Warnf("Route", "Failed to remove default route: %v", err)
		}

		if hasDNSResolver {
			procFilter.UnblockDNSOnInterface()
			procFilter.RemoveDNSPermitForSelf()
			if err := adapter.ClearDNS(); err != nil {
				core.Log.Warnf("DNS", "Failed to clear TUN DNS: %v", err)
			}
		}

		gwActive = false
		core.Log.Infof("Core", "Gateway deactivated (no VPN tunnels)")
	}

	// Declared early so event handler closure can reference it (assigned below).
	var netMon platform.NetworkMonitor

	// Timer for delayed netMon.Resume() calls — tracked to prevent accumulation
	// on rapid state changes.
	var netMonTimer *time.Timer
	var netMonTimerMu sync.Mutex

	// Subscribe to tunnel state changes — activate/deactivate gateway dynamically.
	bus.Subscribe(core.EventTunnelStateChanged, func(e core.Event) {
		payload, ok := e.Payload.(core.TunnelStatePayload)
		if !ok {
			return
		}
		// Ignore the direct tunnel — it's always up.
		if payload.TunnelID == gateway.DirectTunnelID {
			return
		}

		// Count active VPN tunnels (excluding __direct__).
		vpnUp := 0
		for _, entry := range registry.All() {
			if entry.ID != gateway.DirectTunnelID && entry.State == core.TunnelStateUp {
				vpnUp++
			}
		}

		gwMu.Lock()
		wasActive := gwActive
		gwMu.Unlock()

		if vpnUp > 0 && !wasActive {
			// Suppress network monitor during activation to prevent feedback loop
			// from our own route modifications generating PF_ROUTE events.
			if netMon != nil {
				netMon.Suppress()
			}
			// Add bypass routes BEFORE default routes to prevent a window
			// where VPN encrypted traffic gets misrouted through TUN.
			for _, entry := range registry.All() {
				if entry.ID == gateway.DirectTunnelID || entry.State != core.TunnelStateUp {
					continue
				}
				for _, ep := range tunnelCtrl.GetServerEndpoints(entry.ID) {
					if err := routeMgr.AddBypassRoute(ep.Addr()); err != nil {
						core.Log.Warnf("Route", "Pre-activation bypass route for %s: %v", ep.Addr(), err)
					}
				}
			}
			activateGateway()
			// Resume after delay to absorb the cascade of PF_ROUTE events.
			if netMon != nil {
				netMonTimerMu.Lock()
				if netMonTimer != nil {
					netMonTimer.Stop()
				}
				netMonTimer = time.AfterFunc(3*time.Second, func() {
					if netMon != nil {
						netMon.Resume()
					}
				})
				netMonTimerMu.Unlock()
			}
		} else if vpnUp == 0 && wasActive {
			if netMon != nil {
				netMon.Suppress()
			}
			deactivateGateway()
			if netMon != nil {
				netMonTimerMu.Lock()
				if netMonTimer != nil {
					netMonTimer.Stop()
				}
				netMonTimer = time.AfterFunc(3*time.Second, func() {
					if netMon != nil {
						netMon.Resume()
					}
				})
				netMonTimerMu.Unlock()
			}
		} else if vpnUp > 0 && wasActive && cfgManager.Get().Global.KillSwitch {
			// VPN endpoint list may have changed — refresh kill switch rules.
			var vpnEndpoints []netip.Addr
			for _, entry := range registry.All() {
				if entry.ID == gateway.DirectTunnelID || entry.State != core.TunnelStateUp {
					continue
				}
				for _, ep := range tunnelCtrl.GetServerEndpoints(entry.ID) {
					vpnEndpoints = append(vpnEndpoints, ep.Addr())
				}
			}
			if err := procFilter.EnableKillSwitch(adapter.Name(), vpnEndpoints); err != nil {
				core.Log.Warnf("Core", "Failed to refresh kill switch: %v", err)
			}
		}
	})

	// === 11d. Network Monitor (detect network changes — macOS) ===
	if plat.NewNetworkMonitor != nil {
		onChange := func() {
			core.Log.Infof("Core", "Network change detected")

			// Re-discover real NIC (gateway may have changed).
			// DiscoverRealNIC updates routeMgr's internal copy atomically.
			newNIC, err := routeMgr.DiscoverRealNIC()
			if err != nil {
				core.Log.Warnf("Route", "Failed to re-discover NIC after network change: %v", err)
				return
			}

			gwMu.Lock()
			isActive := gwActive
			oldGW := realNIC.Gateway
			oldIdx := realNIC.Index
			oldIP := realNIC.LocalIP
			if isActive {
				realNIC = newNIC
			}
			gwMu.Unlock()

			if !isActive {
				return
			}

			// Skip if NIC hasn't actually changed — prevents feedback loop
			// where our own route modifications trigger PF_ROUTE events.
			if newNIC.Gateway == oldGW && newNIC.Index == oldIdx && newNIC.LocalIP == oldIP {
				core.Log.Debugf("Core", "Network event ignored (NIC unchanged)")
				return
			}

			// NIC actually changed — proceed with full re-application.
			core.Log.Infof("Core", "NIC changed: gw=%s→%s idx=%d→%d ip=%s→%s",
				oldGW, newNIC.Gateway, oldIdx, newNIC.Index, oldIP, newNIC.LocalIP)

			// Re-apply default routes (including interface-scoped routes for real NIC).
			// Scoped routes reference the real gateway and may become stale on network change.
			routeMgr.RemoveDefaultRoute()
			if err := routeMgr.SetDefaultRoute(); err != nil {
				core.Log.Warnf("Route", "Re-apply default routes: %v", err)
			}

			// Clear old bypass routes (they reference the old gateway) and re-add.
			routeMgr.ClearBypassRoutes()
			for _, entry := range registry.All() {
				if entry.ID == gateway.DirectTunnelID || entry.State != core.TunnelStateUp {
					continue
				}
				for _, ep := range tunnelCtrl.GetServerEndpoints(entry.ID) {
					if err := routeMgr.AddBypassRoute(ep.Addr()); err != nil {
						core.Log.Warnf("Route", "Re-apply bypass route for %s: %v", ep.Addr(), err)
					}
				}
			}

			// Re-apply DNS configuration and leak protection for the new NIC.
			if hasDNSResolver {
				if err := adapter.SetDNS([]netip.Addr{adapter.IP()}); err != nil {
					core.Log.Warnf("DNS", "Re-set DNS: %v", err)
				}
				// Remove stale DNS leak protection rules (old NIC LUID) and re-add for new NIC.
				procFilter.UnblockDNSOnInterface()
				procFilter.RemoveDNSPermitForSelf()
				if err := procFilter.BlockDNSOnInterface(newNIC.LUID); err != nil {
					core.Log.Warnf("DNS", "Re-apply DNS leak protection: %v", err)
				}
				if err := procFilter.PermitDNSForSelf(newNIC.LUID); err != nil {
					core.Log.Warnf("DNS", "Re-apply DNS self-permit: %v", err)
				}
			}
			// Flush system DNS cache so stale entries from old NIC are purged.
			if plat.FlushSystemDNS != nil {
				if err := plat.FlushSystemDNS(); err != nil {
					core.Log.Warnf("DNS", "System DNS flush after network change: %v", err)
				}
			}

			core.Log.Infof("Core", "Network change handled (new gateway: %s)", newNIC.Gateway)
		}

		nm, err := plat.NewNetworkMonitor(onChange)
		if err != nil {
			core.Log.Warnf("Core", "Failed to create network monitor: %v", err)
		} else {
			netMon = nm
			if err := netMon.Start(); err != nil {
				core.Log.Warnf("Core", "Failed to start network monitor: %v", err)
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

	// FakeIP pool: synthetic IPs for domain-based routing (prevents browser DNS cache issues).
	var fakeIPPool *gateway.FakeIPPool
	if cfg.DNS.FakeIP.Enabled == nil || *cfg.DNS.FakeIP.Enabled {
		cidr := cfg.DNS.FakeIP.CIDR
		if cidr == "" {
			cidr = "198.18.0.0/15"
		}
		var err error
		fakeIPPool, err = gateway.NewFakeIPPool(cidr)
		if err != nil {
			core.Log.Errorf("DNS", "Failed to create FakeIP pool: %v", err)
		} else {
			if dnsResolver != nil {
				dnsResolver.SetFakeIPPool(fakeIPPool)
			}
			tunRouter.SetFakeIPPool(fakeIPPool)
			core.Log.Infof("DNS", "FakeIP pool active: %s", cidr)
		}
	}
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
		if fakeIPPool != nil {
			fakeIPPool.Flush()
		}
		if dnsResolver != nil {
			dnsResolver.FlushCache()
		}
		domainTable.Flush()
		// Flush system DNS cache (platform-specific).
		if plat.FlushSystemDNS != nil {
			if err := plat.FlushSystemDNS(); err != nil {
				core.Log.Warnf("DNS", "System DNS flush failed: %v", err)
			}
		}
		core.Log.Infof("DNS", "All DNS caches flushed")
		return nil
	}

	domainReloader := func(rules []core.DomainRule) error {
		m := buildDomainMatcher(rules, geositeFilePath, nicHTTPClient)
		if dnsResolver != nil {
			dnsResolver.SetDomainMatcher(m)
		}
		if fakeIPPool != nil {
			fakeIPPool.Flush()
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
	// TUN router started — the main shutdown handler takes over cleanup.
	initCleanup = nil

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

	// === 12c. DPI Bypass Manager ===
	dpiDataDir := filepath.Dir(configPath)
	dpiBindControl := ifBinder.BindControl(realNIC.Index)
	dpiLocalIP := realNIC.LocalIP.AsSlice()
	dpiGatewayIP := realNIC.Gateway.String()

	// createDPIManager is a factory that creates and initializes a DPI manager.
	createDPIManager := func() (*dpi.StrategyManager, error) {
		dpicfg := cfgManager.Get().DPIBypass
		mgr := dpi.NewStrategyManager(dpi.ManagerDeps{
			Config:      dpicfg,
			Bus:         bus,
			DataDir:     dpiDataDir,
			BindControl: dpiBindControl,
			LocalIP:     dpiLocalIP,
			GatewayIP:   dpiGatewayIP,
		})
		mgr.SetStrategyCallback(func(s *dpi.Strategy) {
			for _, p := range providers {
				if dp, ok := p.(*dpibypass.Provider); ok {
					dp.SetStrategy(s)
				}
			}
		})
		if err := mgr.Init(ctx); err != nil {
			return mgr, fmt.Errorf("DPI manager init: %w", err)
		}
		core.Log.Infof("DPI", "DPI bypass manager initialized")
		return mgr, nil
	}

	var dpiMgr *dpi.StrategyManager
	if cfg.DPIBypass.Enabled {
		var err error
		dpiMgr, err = createDPIManager()
		if err != nil {
			core.Log.Warnf("DPI", "Manager init failed: %v", err)
		}
		// Add ephemeral DPI bypass tunnel (not persisted to config).
		dpiCfg := core.TunnelConfig{
			ID:       "dpi-bypass",
			Protocol: core.ProtocolDPIBypass,
			Name:     "DPI Bypass",
		}
		if err := tunnelCtrl.AddTunnel(ctx, dpiCfg, nil); err != nil {
			core.Log.Warnf("DPI", "Failed to add DPI tunnel: %v", err)
		} else if err := tunnelCtrl.ConnectTunnel(ctx, "dpi-bypass"); err != nil {
			core.Log.Warnf("DPI", "Failed to connect DPI tunnel: %v", err)
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
		DPIManager:          dpiMgr,
		DPIManagerFactory:   createDPIManager,
	})
	svc.Start(ctx)

	// Register service via controller callback (daemon mode) or create own IPC server.
	var ipcServer *ipc.Server
	var deregisterSvc func()
	if len(opts) > 0 && opts[0].RegisterService != nil {
		deregisterSvc = opts[0].RegisterService(svc)
	} else {
		ipcServer = ipc.NewServer(svc)
		go func() {
			ln, err := plat.IPC.Listener()
			if err != nil {
				core.Log.Errorf("Core", "IPC listen error: %v", err)
				return
			}
			core.Log.Infof("Core", "IPC server starting on %s", ln.Addr())
			if err := ipcServer.Start(ln); err != nil {
				core.Log.Errorf("Core", "IPC server error: %v", err)
			}
		}()
	}

	// --- Wait for shutdown signal ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

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
			core.Log.Infof("Core", "Service stop signal received. Shutting down...")
			break mainLoop
		case <-reloadCh:
			core.Log.Infof("Core", "Config reload signal received. Applying configuration...")
			newCfg := cfgManager.Get()
			ipFilter = gateway.NewIPFilter(newCfg.Global, newCfg.Tunnels)
			tunRouter.SetIPFilter(ipFilter)
			ruleEngine.SetRules(newCfg.Rules)
			// Rebuild domain matcher if rules changed
			if dnsResolver != nil {
				domainReloader(newCfg.DomainRules)
			}
			// Check if kill switch setting changed.
			gwMu.Lock()
			active := gwActive
			gwMu.Unlock()
			if active {
				if newCfg.Global.KillSwitch {
					var vpnEndpoints []netip.Addr
					for _, entry := range registry.All() {
						if entry.ID == gateway.DirectTunnelID || entry.State != core.TunnelStateUp {
							continue
						}
						for _, ep := range tunnelCtrl.GetServerEndpoints(entry.ID) {
							vpnEndpoints = append(vpnEndpoints, ep.Addr())
						}
					}
					if err := procFilter.EnableKillSwitch(adapter.Name(), vpnEndpoints); err != nil {
						core.Log.Warnf("Core", "Failed to enable kill switch on reload: %v", err)
					}
				} else {
					if err := procFilter.DisableKillSwitch(); err != nil {
						core.Log.Warnf("Core", "Failed to disable kill switch on reload: %v", err)
					}
				}
			}
			core.Log.Infof("Core", "Configuration reloaded.")
		case <-runCtx.Done():
			core.Log.Infof("Core", "Run context cancelled. Exiting main loop.")
			break mainLoop
		}
	}

	// === Graceful shutdown (reverse order) ===
	core.Log.Infof("Core", "Shutting down...")
	cancel()    // Cancel the main context
	runCancel() // Cancel the run context

	done := make(chan struct{})
	go func() {
		if deregisterSvc != nil {
			deregisterSvc()
		}
		if ipcServer != nil {
			ipcServer.Stop()
		}
		svc.Stop()

		if dpiMgr != nil {
			dpiMgr.Stop()
		}

		if subMgr != nil {
			subMgr.Stop()
		}

		if dnsResolver != nil {
			dnsResolver.Stop()
		}

		// Stop network monitor.
		if netMon != nil {
			netMon.Stop()
		}

		// Use tunnel controller for graceful shutdown of all tunnels
		tunnelCtrl.Shutdown()

		// Explicitly deactivate gateway (restore DNS, routes, kill switch)
		// before closing the adapter. Don't rely on async event propagation
		// from tunnelCtrl.Shutdown — it may race with adapter.Close.
		deactivateGateway()

		procFilter.Close()
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
