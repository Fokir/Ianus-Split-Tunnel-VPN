//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/process"
	"awg-split-tunnel/internal/provider"
	"awg-split-tunnel/internal/provider/amneziawg"
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

	// --- Initialize core components ---
	bus := core.NewEventBus()

	// Resolve config path relative to executable location if not absolute.
	resolvedConfigPath := resolveRelativeToExe(*configPath)
	cfgManager := core.NewConfigManager(resolvedConfigPath, bus)
	if err := cfgManager.Load(); err != nil {
		log.Fatalf("[Core] Failed to load config: %v", err)
	}
	cfg := cfgManager.Get()

	registry := core.NewTunnelRegistry(bus)
	matcher := process.NewMatcher()
	ruleEngine := core.NewRuleEngine(cfg.Rules, bus, matcher)

	// --- Create providers and proxies for each tunnel ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	providers := make(map[string]provider.TunnelProvider)
	proxies := make([]*proxy.TunnelProxy, 0)
	udpProxies := make([]*proxy.UDPProxy, 0)

	// Create the packet router first (needed for NAT lookup).
	router, err := core.NewPacketRouter(registry, ruleEngine, bus, cfg.AdapterIndex)
	if err != nil {
		log.Fatalf("[Core] Failed to create packet router: %v", err)
	}

	// Provider lookup function for proxies.
	providerLookup := func(tunnelID string) (provider.TunnelProvider, bool) {
		p, ok := providers[tunnelID]
		return p, ok
	}

	var nextProxyPort uint16 = 30000

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

		// Register tunnel in the registry.
		if err := registry.Register(tcfg, proxyPort, udpProxyPort); err != nil {
			log.Printf("[Core] Failed to register tunnel %q: %v", tcfg.ID, err)
			continue
		}

		providers[tcfg.ID] = prov

		// Register proxy ports for O(1) hot-path lookup.
		router.RegisterProxyPort(proxyPort)
		router.RegisterUDPProxyPort(udpProxyPort)

		// Create and start TCP transparent proxy.
		tp := proxy.NewTunnelProxy(proxyPort, router.LookupNAT, providerLookup)
		proxies = append(proxies, tp)

		if err := tp.Start(ctx); err != nil {
			log.Printf("[Core] Failed to start TCP proxy for tunnel %q: %v", tcfg.ID, err)
			continue
		}

		// Create and start UDP transparent proxy.
		up := proxy.NewUDPProxy(udpProxyPort, router.LookupUDPNAT, providerLookup)
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
	}

	// --- Start packet router ---
	if err := router.Start(ctx); err != nil {
		log.Fatalf("[Core] Failed to start packet router: %v", err)
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

	// --- Graceful shutdown ---
	log.Println("[Core] Shutting down...")
	cancel()

	done := make(chan struct{})
	go func() {
		router.Stop()
		for _, tp := range proxies {
			tp.Stop()
		}
		for _, up := range udpProxies {
			up.Stop()
		}
		for id, prov := range providers {
			if err := prov.Disconnect(); err != nil {
				log.Printf("[Core] Error disconnecting %s: %v", id, err)
			}
		}
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
