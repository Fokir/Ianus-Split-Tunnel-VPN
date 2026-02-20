//go:build windows

package gateway

import (
	"net/netip"

	"awg-split-tunnel/internal/core"
)

// DNSConfig configures per-process DNS routing and fallback behavior.
type DNSConfig struct {
	// FallbackTunnelID is the tunnel used for system/svchost DNS queries.
	// Empty means use direct (no tunnel).
	FallbackTunnelID string

	// FallbackServers are DNS servers to use for fallback queries.
	FallbackServers []netip.Addr
}

// DNSRoute is the resolved DNS routing decision for a packet.
type DNSRoute struct {
	TunnelID  string     // target tunnel for this DNS query
	DNSServer netip.Addr // specific DNS server to forward to
}

// DNSRouter determines per-process DNS routing.
type DNSRouter struct {
	config   DNSConfig
	registry *core.TunnelRegistry
}

// NewDNSRouter creates a DNS router with the given configuration.
func NewDNSRouter(config DNSConfig, registry *core.TunnelRegistry) *DNSRouter {
	core.Log.Infof("DNS", "Router created (fallback_tunnel=%q, fallback_servers=%v)",
		config.FallbackTunnelID, config.FallbackServers)
	return &DNSRouter{
		config:   config,
		registry: registry,
	}
}

// ResolveDNSRoute determines which tunnel and DNS server to use for a DNS query.
//
// Decision logic:
// 1. Process matched to a tunnel → use that tunnel's DNS servers
// 2. Process is unmatched → use DNSConfig.FallbackTunnelID (or direct)
// 3. Direct tunnel → use system DNS via real NIC
func (dr *DNSRouter) ResolveDNSRoute(tunnelID string) DNSRoute {
	// If process matched to a specific tunnel, use that tunnel.
	if tunnelID != "" && tunnelID != DirectTunnelID {
		entry, ok := dr.registry.Get(tunnelID)
		if ok && entry.State == core.TunnelStateUp {
			return DNSRoute{
				TunnelID: tunnelID,
				// DNS server will be the original destination (the app's configured DNS).
				// The proxy will route it through the tunnel's netstack,
				// which already has DNS servers configured from the WG config.
			}
		}
	}

	// Fallback: use configured fallback tunnel and servers.
	if dr.config.FallbackTunnelID != "" {
		route := DNSRoute{TunnelID: dr.config.FallbackTunnelID}
		if len(dr.config.FallbackServers) > 0 {
			route.DNSServer = dr.config.FallbackServers[0]
		}
		return route
	}

	// No fallback configured: route through direct provider.
	return DNSRoute{TunnelID: DirectTunnelID}
}
