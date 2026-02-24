//go:build windows

package gateway

import (
	"net/netip"

	"awg-split-tunnel/internal/core"
)

// DNSConfig configures per-process DNS routing and fallback behavior.
type DNSConfig struct {
	// TunnelIDs are the tunnels used for DNS resolution.
	// Queries are sent through all tunnels simultaneously, first response wins.
	// Empty means DNS resolver is disabled.
	TunnelIDs []string

	// FallbackServers are DNS servers to use for fallback queries.
	FallbackServers []netip.Addr
}

// DNSRoute is the resolved DNS routing decision for a packet.
type DNSRoute struct {
	TunnelIDs []string   // target tunnels for this DNS query
	DNSServer netip.Addr // specific DNS server to forward to
}

// DNSRouter determines per-process DNS routing.
type DNSRouter struct {
	config   DNSConfig
	registry *core.TunnelRegistry
}

// NewDNSRouter creates a DNS router with the given configuration.
func NewDNSRouter(config DNSConfig, registry *core.TunnelRegistry) *DNSRouter {
	core.Log.Infof("DNS", "Router created (tunnels=%v, fallback_servers=%v)",
		config.TunnelIDs, config.FallbackServers)
	return &DNSRouter{
		config:   config,
		registry: registry,
	}
}

// ResolveDNSRoute determines which tunnel and DNS server to use for a DNS query.
//
// Decision logic:
// 1. Process matched to a tunnel → use that tunnel's DNS servers
// 2. Process is unmatched → use DNSConfig.TunnelIDs (or direct)
// 3. Direct tunnel → use system DNS via real NIC
func (dr *DNSRouter) ResolveDNSRoute(tunnelID string) DNSRoute {
	// If process matched to a specific tunnel, use that tunnel.
	if tunnelID != "" && tunnelID != DirectTunnelID {
		entry, ok := dr.registry.Get(tunnelID)
		if ok && entry.State == core.TunnelStateUp {
			return DNSRoute{
				TunnelIDs: []string{tunnelID},
				// DNS server will be the original destination (the app's configured DNS).
				// The proxy will route it through the tunnel's netstack,
				// which already has DNS servers configured from the WG config.
			}
		}
	}

	// Fallback: use all configured DNS tunnels.
	if len(dr.config.TunnelIDs) > 0 {
		route := DNSRoute{TunnelIDs: dr.config.TunnelIDs}
		if len(dr.config.FallbackServers) > 0 {
			route.DNSServer = dr.config.FallbackServers[0]
		}
		return route
	}

	// No fallback configured: route through direct provider.
	return DNSRoute{TunnelIDs: []string{DirectTunnelID}}
}
