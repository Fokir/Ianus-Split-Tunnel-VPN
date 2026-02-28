//go:build windows

package gateway

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/platform"

	"golang.org/x/sys/windows"
)

// RealNIC is an alias for platform.RealNIC so gateway code continues to compile
// while the RouteManager satisfies the platform.RouteManager interface.
type RealNIC = platform.RealNIC

// RouteManager manages system routing table entries for the TUN gateway.
type RouteManager struct {
	tunLUID  uint64
	realNIC  RealNIC

	mu            sync.Mutex
	routes        []mibIPForwardRow2 // bypass routes we've added (for cleanup)
	defaultRoutes []mibIPForwardRow2 // default split routes (0/1 + 128/1), managed separately
}

// NewRouteManager creates a route manager for the given TUN adapter.
func NewRouteManager(tunLUID uint64) *RouteManager {
	return &RouteManager{tunLUID: tunLUID}
}

// DiscoverRealNIC finds the current default gateway (non-TUN) NIC.
// Must be called before SetDefaultRoute.
func (rm *RouteManager) DiscoverRealNIC() (RealNIC, error) {
	nic, err := discoverRealNIC(rm.tunLUID)
	if err != nil {
		return RealNIC{}, err
	}

	// Resolve the NIC's own IPv4 address for direct provider LocalAddr binding.
	if iface, err := net.InterfaceByIndex(int(nic.Index)); err == nil {
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
	}

	rm.realNIC = nic
	core.Log.Infof("Route", "Real NIC: LUID=0x%x Index=%d Gateway=%s LocalIP=%s", nic.LUID, nic.Index, nic.Gateway, nic.LocalIP)
	return nic, nil
}

// RealNICInfo returns the discovered real NIC information.
func (rm *RouteManager) RealNICInfo() RealNIC { return rm.realNIC }

// SetDefaultRoute adds split default routes (0.0.0.0/1 + 128.0.0.0/1) via TUN.
// This captures all traffic without replacing the actual 0.0.0.0/0 entry.
// Also adds backup split routes via real NIC (high metric) so that the direct
// provider's IP_UNICAST_IF can find matching routes on the real NIC interface.
//
// These routes are tracked separately so they can be removed via RemoveDefaultRoute
// without affecting bypass routes.
func (rm *RouteManager) SetDefaultRoute() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(rm.defaultRoutes) > 0 {
		return nil // already set
	}

	// Backup split routes via real NIC (high metric, used by IP_UNICAST_IF).
	// Without these, IP_UNICAST_IF has no /1 route on the real NIC and TCP
	// connections from the direct proxy fall through to TUN's /1 routes.
	const backupMetric = 9999
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		p := netip.MustParsePrefix(prefix)
		row, err := rm.createRoute(p, rm.realNIC.LUID, rm.realNIC.Gateway, backupMetric)
		if err != nil {
			core.Log.Warnf("Route", "Backup route %s via real NIC: %v", prefix, err)
			continue
		}
		rm.defaultRoutes = append(rm.defaultRoutes, row)
	}

	// Primary split routes via TUN (metric 0, captures all traffic).
	row, err := rm.createRoute(netip.MustParsePrefix("0.0.0.0/1"), rm.tunLUID, netip.Addr{}, 0)
	if err != nil {
		return fmt.Errorf("[Route] add 0.0.0.0/1: %w", err)
	}
	rm.defaultRoutes = append(rm.defaultRoutes, row)

	row, err = rm.createRoute(netip.MustParsePrefix("128.0.0.0/1"), rm.tunLUID, netip.Addr{}, 0)
	if err != nil {
		return fmt.Errorf("[Route] add 128.0.0.0/1: %w", err)
	}
	rm.defaultRoutes = append(rm.defaultRoutes, row)

	core.Log.Infof("Route", "Default routes set via TUN")
	return nil
}

// RemoveDefaultRoute removes the default split routes (0.0.0.0/1 + 128.0.0.0/1)
// while keeping bypass routes intact. This is used to deactivate the gateway
// when no VPN tunnels are active.
func (rm *RouteManager) RemoveDefaultRoute() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if len(rm.defaultRoutes) == 0 {
		return nil // not set
	}

	var lastErr error
	for _, row := range rm.defaultRoutes {
		r, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
		if r != 0 {
			lastErr = fmt.Errorf("DeleteIpForwardEntry2: 0x%x", r)
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

// AddBypassRoute adds a specific host route via the real NIC.
// Used for VPN server endpoints to avoid routing loops.
func (rm *RouteManager) AddBypassRoute(dst netip.Addr) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	prefix := netip.PrefixFrom(dst, 32)
	if err := rm.addRoute(prefix, rm.realNIC.LUID, rm.realNIC.Gateway); err != nil {
		return fmt.Errorf("[Route] bypass %s: %w", dst, err)
	}

	core.Log.Infof("Route", "Added bypass route: %s via real NIC", dst)
	return nil
}

// ClearBypassRoutes removes all bypass routes. Used before re-adding them
// after a network change (new gateway).
func (rm *RouteManager) ClearBypassRoutes() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for _, row := range rm.routes {
		procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	}
	rm.routes = nil
}

// Cleanup removes all routes we've added, restoring the original routing table.
func (rm *RouteManager) Cleanup() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	var lastErr error
	for _, row := range rm.defaultRoutes {
		r, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
		if r != 0 {
			lastErr = fmt.Errorf("DeleteIpForwardEntry2: 0x%x", r)
		}
	}
	rm.defaultRoutes = nil

	for _, row := range rm.routes {
		r, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
		if r != 0 {
			lastErr = fmt.Errorf("DeleteIpForwardEntry2: 0x%x", r)
		}
	}
	rm.routes = nil

	if lastErr != nil {
		core.Log.Warnf("Route", "Cleanup completed with errors: %v", lastErr)
		return lastErr
	}
	core.Log.Infof("Route", "Cleanup completed")
	return nil
}

// ---------------------------------------------------------------------------
// iphlpapi route manipulation
// ---------------------------------------------------------------------------

var (
	procInitializeIpForwardEntry = modIPHlpAPI.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2    = modIPHlpAPI.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2    = modIPHlpAPI.NewProc("DeleteIpForwardEntry2")
	procGetIpForwardTable2       = modIPHlpAPI.NewProc("GetIpForwardTable2")
	procFreeMibTable             = modIPHlpAPI.NewProc("FreeMibTable")
)

// MIB_IPFORWARD_ROW2 (simplified, 104 bytes on x64).
type mibIPForwardRow2 struct {
	data [104]byte
}

// MIB_IPFORWARD_ROW2 field offsets (x64).
//
// Layout (104 bytes total):
//   0:  NET_LUID          InterfaceLuid      (8)
//   8:  NET_IFINDEX       InterfaceIndex     (4)
//  12:  IP_ADDRESS_PREFIX DestinationPrefix  (32 = SOCKADDR_INET(28) + PrefixLen(1) + pad(3))
//       12: si_family (2)
//       16: sin_addr  (4)
//       40: PrefixLength (1)
//  44:  SOCKADDR_INET     NextHop            (28)
//       44: si_family (2)
//       48: sin_addr  (4)
//  72:  UCHAR             SitePrefixLength   (1 + 3 pad)
//  76:  ULONG             ValidLifetime      (4)
//  80:  ULONG             PreferredLifetime  (4)
//  84:  ULONG             Metric             (4)
//  88:  NL_ROUTE_PROTOCOL Protocol           (4)
//  92:  BOOLEAN[4]        Loopback..Immortal (4)
//  96:  ULONG             Age                (4)
// 100:  NL_ROUTE_ORIGIN   Origin             (4)
const (
	fwdInterfaceLUID  = 0   // NET_LUID
	fwdInterfaceIndex = 8   // IF_INDEX
	fwdDestFamily     = 12  // si_family of destination prefix
	fwdDestAddr       = 16  // sin_addr of destination prefix
	fwdDestPrefixLen  = 40  // PrefixLength (offset 12 + 28 within IP_ADDRESS_PREFIX)
	fwdNextHopFamily  = 44  // si_family of next hop (offset 12 + 32)
	fwdNextHopAddr    = 48  // sin_addr of next hop (offset 44 + 4)
	fwdSitePrefixLen  = 72
	fwdMetric         = 84  // ULONG
	fwdProtocol       = 88  // MIB_IPFORWARD_PROTOCOL
	fwdOrigin         = 100 // NL_ROUTE_ORIGIN
)

// createRoute creates a route entry in the system routing table and returns
// the row for later deletion. Does NOT append to any tracking slice.
func (rm *RouteManager) createRoute(dst netip.Prefix, luid uint64, nextHop netip.Addr, metric uint32) (mibIPForwardRow2, error) {
	var row mibIPForwardRow2
	initIpForwardEntry(&row)

	// Interface
	*(*uint64)(unsafe.Pointer(&row.data[fwdInterfaceLUID])) = luid

	// Destination prefix
	*(*uint16)(unsafe.Pointer(&row.data[fwdDestFamily])) = windows.AF_INET
	ip4 := dst.Addr().As4()
	copy(row.data[fwdDestAddr:fwdDestAddr+4], ip4[:])
	row.data[fwdDestPrefixLen] = uint8(dst.Bits())

	// Next hop
	*(*uint16)(unsafe.Pointer(&row.data[fwdNextHopFamily])) = windows.AF_INET
	if nextHop.IsValid() {
		gw4 := nextHop.As4()
		copy(row.data[fwdNextHopAddr:fwdNextHopAddr+4], gw4[:])
	}

	// Metric, Protocol, Origin
	*(*uint32)(unsafe.Pointer(&row.data[fwdMetric])) = metric
	*(*int32)(unsafe.Pointer(&row.data[fwdProtocol])) = 3 // MIB_IPPROTO_NETMGMT
	*(*int32)(unsafe.Pointer(&row.data[fwdOrigin])) = 1   // NlroManual

	r, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	// ERROR_OBJECT_ALREADY_EXISTS can come as HRESULT 0x80071392 or Win32 0x1392.
	if r != 0 && r != 0x80071392 && r != 0x1392 {
		return row, fmt.Errorf("CreateIpForwardEntry2 failed: 0x%x", r)
	}

	return row, nil
}

func (rm *RouteManager) addRouteWithMetric(dst netip.Prefix, luid uint64, nextHop netip.Addr, metric uint32) error {
	row, err := rm.createRoute(dst, luid, nextHop, metric)
	if err != nil {
		return err
	}
	rm.routes = append(rm.routes, row)
	return nil
}

func (rm *RouteManager) addRoute(dst netip.Prefix, luid uint64, nextHop netip.Addr) error {
	return rm.addRouteWithMetric(dst, luid, nextHop, 0)
}

func initIpForwardEntry(row *mibIPForwardRow2) {
	// Use Windows API to properly initialize the struct.
	// Sets ValidLifetime/PreferredLifetime to INFINITE and other required defaults.
	// MSDN: InitializeIpForwardEntry must be called before CreateIpForwardEntry2.
	procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(row)))
}

// fwdRowField reads a value of type T at the given byte offset within a
// MIB_IPFORWARD_ROW2 row. The row pointer must be derived from table in a
// single unsafe.Pointer expression to satisfy go vet's pointer rules.
func fwdRowUint16(table unsafe.Pointer, headerSize, rowSize uintptr, idx uint32, off int) uint16 {
	return *(*uint16)(unsafe.Pointer(uintptr(table) + headerSize + uintptr(idx)*rowSize + uintptr(off)))
}

func fwdRowUint32(table unsafe.Pointer, headerSize, rowSize uintptr, idx uint32, off int) uint32 {
	return *(*uint32)(unsafe.Pointer(uintptr(table) + headerSize + uintptr(idx)*rowSize + uintptr(off)))
}

func fwdRowUint64(table unsafe.Pointer, headerSize, rowSize uintptr, idx uint32, off int) uint64 {
	return *(*uint64)(unsafe.Pointer(uintptr(table) + headerSize + uintptr(idx)*rowSize + uintptr(off)))
}

func fwdRowBytes4(table unsafe.Pointer, headerSize, rowSize uintptr, idx uint32, off int) [4]byte {
	return *(*[4]byte)(unsafe.Pointer(uintptr(table) + headerSize + uintptr(idx)*rowSize + uintptr(off)))
}

func fwdRowByte(table unsafe.Pointer, headerSize, rowSize uintptr, idx uint32, off int) byte {
	return *(*byte)(unsafe.Pointer(uintptr(table) + headerSize + uintptr(idx)*rowSize + uintptr(off)))
}

// discoverRealNIC finds the default gateway NIC (the one with 0.0.0.0/0 that isn't our TUN).
func discoverRealNIC(tunLUID uint64) (RealNIC, error) {
	var table unsafe.Pointer
	r, _, _ := procGetIpForwardTable2.Call(
		uintptr(windows.AF_INET),
		uintptr(unsafe.Pointer(&table)),
	)
	if r != 0 {
		return RealNIC{}, fmt.Errorf("GetIpForwardTable2 failed: 0x%x", r)
	}
	defer procFreeMibTable.Call(uintptr(table))

	// Table structure: ULONG NumEntries + array of MIB_IPFORWARD_ROW2.
	numEntries := *(*uint32)(table)
	const rowSize = uintptr(104) // sizeof(MIB_IPFORWARD_ROW2)
	headerSize := unsafe.Sizeof(uint64(0)) // alignment padding after NumEntries

	var bestNIC RealNIC
	bestMetric := uint32(0xFFFFFFFF)
	found := false

	for i := uint32(0); i < numEntries; i++ {
		family := fwdRowUint16(table, headerSize, rowSize, i, fwdDestFamily)
		if family != windows.AF_INET {
			continue
		}

		// Check if destination is 0.0.0.0/0.
		dstIP := fwdRowBytes4(table, headerSize, rowSize, i, fwdDestAddr)
		prefixLen := fwdRowByte(table, headerSize, rowSize, i, fwdDestPrefixLen)
		if dstIP != [4]byte{0, 0, 0, 0} || prefixLen != 0 {
			continue
		}

		luid := fwdRowUint64(table, headerSize, rowSize, i, fwdInterfaceLUID)
		if luid == tunLUID {
			continue
		}

		metric := fwdRowUint32(table, headerSize, rowSize, i, fwdMetric)
		if !found || metric < bestMetric {
			ifIndex := fwdRowUint32(table, headerSize, rowSize, i, fwdInterfaceIndex)
			gwBytes := fwdRowBytes4(table, headerSize, rowSize, i, fwdNextHopAddr)
			gwIP := netip.AddrFrom4(gwBytes)

			bestNIC = RealNIC{
				LUID:    luid,
				Index:   ifIndex,
				Gateway: gwIP,
			}
			bestMetric = metric
			found = true
		}
	}

	if !found {
		return RealNIC{}, fmt.Errorf("no default gateway found")
	}
	return bestNIC, nil
}
