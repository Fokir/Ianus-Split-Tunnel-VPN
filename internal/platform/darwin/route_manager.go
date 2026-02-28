//go:build darwin

package darwin

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/platform"
)

// defaultSubRanges covers the full IPv4 address space using 8 specific prefixes
// instead of the traditional 0/1 + 128/1 split. This avoids replacing the macOS
// system default route (0/0), which preserves scoped-route semantics and service
// ordering used by system apps (Safari, App Store, etc.). More-specific routes
// always win via longest-prefix match, so all traffic still flows through utun.
// This is the same approach used by sing-tun on Darwin.
var defaultSubRanges = []string{
	"1.0.0.0/8",
	"2.0.0.0/7",
	"4.0.0.0/6",
	"8.0.0.0/5",
	"16.0.0.0/4",
	"32.0.0.0/3",
	"64.0.0.0/2",
	"128.0.0.0/1",
}

// RouteManager implements platform.RouteManager using macOS route(8) commands.
// Uses sub-range routes through utun for traffic capture (sing-tun approach),
// and /32 bypass routes via real NIC gateway for VPN server endpoints.
type RouteManager struct {
	tunIfIndex uint32
	tunIfName  string // e.g. "utun5"
	realNIC    platform.RealNIC
	realIfName string // e.g. "en0"

	mu            sync.Mutex
	defaultRoutes [][]string // delete args for each default route
	bypassRoutes  [][]string // delete args for each bypass route
}

// NewRouteManager creates a macOS route manager.
// tunLUID is the utun interface index (cast to uint64 on macOS).
func NewRouteManager(tunLUID uint64) *RouteManager {
	tunIfIndex := uint32(tunLUID)
	var tunIfName string
	if iface, err := net.InterfaceByIndex(int(tunIfIndex)); err == nil {
		tunIfName = iface.Name
	}
	return &RouteManager{
		tunIfIndex: tunIfIndex,
		tunIfName:  tunIfName,
	}
}

// DiscoverRealNIC finds the current default gateway (non-TUN) NIC
// by parsing `route -n get default` and resolving interface details.
func (rm *RouteManager) DiscoverRealNIC() (platform.RealNIC, error) {
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return platform.RealNIC{}, fmt.Errorf("route get default: %w", err)
	}

	var gateway, ifName string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			gateway = strings.TrimSpace(line[len("gateway:"):])
		} else if strings.HasPrefix(line, "interface:") {
			ifName = strings.TrimSpace(line[len("interface:"):])
		}
	}

	if gateway == "" || ifName == "" {
		return platform.RealNIC{}, fmt.Errorf("no default gateway found in route output")
	}

	gwAddr, err := netip.ParseAddr(gateway)
	if err != nil {
		return platform.RealNIC{}, fmt.Errorf("parse gateway %q: %w", gateway, err)
	}

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return platform.RealNIC{}, fmt.Errorf("interface %s: %w", ifName, err)
	}

	nic := platform.RealNIC{
		LUID:    uint64(iface.Index), // macOS uses interface index as LUID
		Index:   uint32(iface.Index),
		Gateway: gwAddr,
	}

	// Resolve the NIC's own IPv4 address.
	if addrs, err := iface.Addrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					nic.LocalIP, _ = netip.AddrFromSlice(ip4)
					break
				}
			}
		}
	}

	rm.realNIC = nic
	rm.realIfName = ifName
	core.Log.Infof("Route", "Real NIC: %s (Index=%d, Gateway=%s, LocalIP=%s)",
		ifName, nic.Index, nic.Gateway, nic.LocalIP)
	return nic, nil
}

// RealNICInfo returns the previously discovered real NIC information.
func (rm *RouteManager) RealNICInfo() platform.RealNIC { return rm.realNIC }

// SetDefaultRoute adds sub-range routes covering the full IPv4 space through utun.
// Uses 8 specific prefixes instead of 0/1+128/1 to avoid replacing the system
// default route, which preserves macOS scoped-route semantics for system apps.
// Additionally adds interface-scoped routes for the real NIC so that sockets
// bound via IP_BOUND_IF (DirectProvider) can still route through the physical interface.
func (rm *RouteManager) SetDefaultRoute() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(rm.defaultRoutes) > 0 {
		return nil // already set
	}

	if rm.tunIfName == "" {
		return fmt.Errorf("[Route] TUN interface name unknown")
	}

	for _, prefix := range defaultSubRanges {
		addArgs := []string{"-n", "add", "-net", prefix, "-interface", rm.tunIfName}
		delArgs := []string{"-n", "delete", "-net", prefix, "-interface", rm.tunIfName}

		if err := routeExec(addArgs, true); err != nil {
			return fmt.Errorf("[Route] add %s: %w", prefix, err)
		}
		rm.defaultRoutes = append(rm.defaultRoutes, delArgs)
	}

	// Add interface-scoped routes for the real NIC so that sockets bound
	// to the physical interface via IP_BOUND_IF can still route traffic.
	// Without these, macOS kernel returns EHOSTUNREACH for bound sockets
	// because the unscoped sub-range routes point to utun, not en0.
	if rm.realNIC.Gateway.IsValid() && rm.realIfName != "" {
		gw := rm.realNIC.Gateway.String()
		for _, prefix := range defaultSubRanges {
			addArgs := []string{"-n", "add", "-net", prefix, gw, "-ifscope", rm.realIfName}
			delArgs := []string{"-n", "delete", "-net", prefix, "-ifscope", rm.realIfName}

			if err := routeExec(addArgs, true); err != nil {
				core.Log.Warnf("Route", "scoped route %s via %s: %v", prefix, rm.realIfName, err)
			} else {
				rm.defaultRoutes = append(rm.defaultRoutes, delArgs)
			}
		}
	}

	core.Log.Infof("Route", "Default routes set via %s (%d sub-ranges)", rm.tunIfName, len(defaultSubRanges))
	return nil
}

// RemoveDefaultRoute removes the sub-range default routes, keeping bypass routes intact.
func (rm *RouteManager) RemoveDefaultRoute() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(rm.defaultRoutes) == 0 {
		return nil
	}

	var lastErr error
	for _, delArgs := range rm.defaultRoutes {
		if err := routeExec(delArgs, false); err != nil {
			lastErr = err
		}
	}
	rm.defaultRoutes = nil

	if lastErr != nil {
		core.Log.Warnf("Route", "RemoveDefaultRoute completed with errors: %v", lastErr)
		return lastErr
	}
	core.Log.Infof("Route", "Default routes removed")
	return nil
}

// AddBypassRoute adds a /32 host route for a VPN server endpoint via the real NIC gateway.
// This prevents routing loops: VPN traffic reaches the server directly, not through the TUN.
func (rm *RouteManager) AddBypassRoute(dst netip.Addr) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.realNIC.Gateway.IsValid() {
		return fmt.Errorf("[Route] no real NIC gateway for bypass route")
	}

	addArgs := []string{"-n", "add", "-host", dst.String(), rm.realNIC.Gateway.String()}
	delArgs := []string{"-n", "delete", "-host", dst.String()}

	if err := routeExec(addArgs, true); err != nil {
		return fmt.Errorf("[Route] bypass %s: %w", dst, err)
	}
	rm.bypassRoutes = append(rm.bypassRoutes, delArgs)

	core.Log.Infof("Route", "Added bypass route: %s via %s", dst, rm.realNIC.Gateway)
	return nil
}

// ClearBypassRoutes removes all bypass routes. Used before re-adding them
// after a network change (new gateway).
func (rm *RouteManager) ClearBypassRoutes() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for _, delArgs := range rm.bypassRoutes {
		routeExec(delArgs, false)
	}
	rm.bypassRoutes = nil
}

// Cleanup removes all routes added by this manager (both default and bypass).
func (rm *RouteManager) Cleanup() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	var lastErr error
	for _, delArgs := range rm.defaultRoutes {
		if err := routeExec(delArgs, false); err != nil {
			lastErr = err
		}
	}
	rm.defaultRoutes = nil

	for _, delArgs := range rm.bypassRoutes {
		if err := routeExec(delArgs, false); err != nil {
			lastErr = err
		}
	}
	rm.bypassRoutes = nil

	if lastErr != nil {
		core.Log.Warnf("Route", "Cleanup completed with errors: %v", lastErr)
		return lastErr
	}
	core.Log.Infof("Route", "Cleanup completed")
	return nil
}

// routeExec runs a `route` command. If tolerateExists is true,
// "File exists" errors are silently ignored (route already present).
// "not in table" errors are always tolerated on delete.
func routeExec(args []string, tolerateExists bool) error {
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		if tolerateExists && strings.Contains(outStr, "File exists") {
			return nil
		}
		if strings.Contains(outStr, "not in table") {
			return nil
		}
		return fmt.Errorf("route %s: %s", strings.Join(args, " "), outStr)
	}
	return nil
}
