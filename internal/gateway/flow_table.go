//go:build windows

package gateway

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"awg-split-tunnel/internal/core"
)

// ---------------------------------------------------------------------------
// NAT key and entry types — ported from packet_router.go
// ---------------------------------------------------------------------------

// natKey is a compact, allocation-free key for NAT maps.
// Layout: 4 bytes IPv4 address + 2 bytes port (big-endian).
type natKey [6]byte

func makeNATKey(ip netip.Addr, port uint16) natKey {
	var k natKey
	ip4 := ip.As4()
	copy(k[:4], ip4[:])
	k[4] = byte(port >> 8)
	k[5] = byte(port)
	return k
}

// NATEntry maps a redirected TCP connection back to its original destination.
type NATEntry struct {
	LastActivity    int64 // atomic; Unix seconds
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	TunnelID        string
	ProxyPort       uint16
}

// UDPNATEntry maps a redirected UDP flow back to its original destination.
type UDPNATEntry struct {
	LastActivity    int64 // atomic; Unix seconds
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	TunnelID        string
	UDPProxyPort    uint16
}

// ---------------------------------------------------------------------------
// Raw flow types — for raw IP forwarding (bypass TCP proxy + gVisor)
// ---------------------------------------------------------------------------

// RawFlowEntry tracks a raw-forwarded flow (TCP or UDP) through a VPN tunnel.
type RawFlowEntry struct {
	LastActivity int64   // atomic; Unix seconds
	TunnelID     string
	VpnIP        [4]byte // cached VPN IP for fast src IP rewrite
}

// rawFlowKey is a compact key: proto(1) + dstIP(4) + srcPort(2) = 7 bytes.
type rawFlowKey [7]byte

func makeRawFlowKey(proto byte, dstIP [4]byte, srcPort uint16) rawFlowKey {
	var k rawFlowKey
	k[0] = proto
	copy(k[1:5], dstIP[:])
	k[5] = byte(srcPort >> 8)
	k[6] = byte(srcPort)
	return k
}

// rawFlowShardIndex selects a shard using FNV-1a hash.
func rawFlowShardIndex(k rawFlowKey) uint32 {
	h := uint32(2166136261)
	for _, b := range k {
		h = (h ^ uint32(b)) * 16777619
	}
	return h & (numNATShards - 1)
}

type rawFlowShard struct {
	mu sync.RWMutex
	m  map[rawFlowKey]*RawFlowEntry
}

// ---------------------------------------------------------------------------
// Sharded NAT tables — 64 shards reduce RWMutex contention
// ---------------------------------------------------------------------------

const numNATShards = 64

type tcpNATShard struct {
	mu sync.RWMutex
	m  map[natKey]*NATEntry
}

type udpNATShard struct {
	mu sync.RWMutex
	m  map[natKey]*UDPNATEntry
}

// natShardIndex selects a shard using FNV-1a hash of the 6-byte natKey.
func natShardIndex(k natKey) uint32 {
	h := uint32(2166136261)
	h = (h ^ uint32(k[0])) * 16777619
	h = (h ^ uint32(k[1])) * 16777619
	h = (h ^ uint32(k[2])) * 16777619
	h = (h ^ uint32(k[3])) * 16777619
	h = (h ^ uint32(k[4])) * 16777619
	h = (h ^ uint32(k[5])) * 16777619
	return h & (numNATShards - 1)
}

// ---------------------------------------------------------------------------
// FlowTable — main NAT state for the TUN router
// ---------------------------------------------------------------------------

// FlowTable manages sharded NAT tables and proxy port sets.
type FlowTable struct {
	tcp [numNATShards]tcpNATShard
	udp [numNATShards]udpNATShard
	raw [numNATShards]rawFlowShard

	// VPN IP reverse map: vpnIP → tunnelID (for inbound raw routing).
	// Lock-free reads via atomic copy-on-write.
	vpnIPMu  sync.Mutex
	vpnIPMap atomic.Pointer[map[[4]byte]string]

	// Proxy ports: atomic copy-on-write for lock-free reads on hot path.
	proxyPortsMu    sync.Mutex
	proxyPorts      atomic.Pointer[map[uint16]struct{}]
	udpProxyPortsMu sync.Mutex
	udpProxyPorts   atomic.Pointer[map[uint16]struct{}]

	// Cached Unix timestamp (seconds), updated every 250ms.
	nowSec atomic.Int64
}

// NewFlowTable creates an initialized flow table.
func NewFlowTable() *FlowTable {
	ft := &FlowTable{}
	for i := range ft.tcp {
		ft.tcp[i].m = make(map[natKey]*NATEntry)
	}
	for i := range ft.udp {
		ft.udp[i].m = make(map[natKey]*UDPNATEntry)
	}
	for i := range ft.raw {
		ft.raw[i].m = make(map[rawFlowKey]*RawFlowEntry)
	}
	emptyTCP := make(map[uint16]struct{})
	emptyUDP := make(map[uint16]struct{})
	emptyVPN := make(map[[4]byte]string)
	ft.proxyPorts.Store(&emptyTCP)
	ft.udpProxyPorts.Store(&emptyUDP)
	ft.vpnIPMap.Store(&emptyVPN)
	ft.nowSec.Store(time.Now().Unix())
	return ft
}

// StartTimestampUpdater launches a goroutine that updates nowSec every 250ms.
func (ft *FlowTable) StartTimestampUpdater(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ft.nowSec.Store(time.Now().Unix())
			}
		}
	}()
}

// NowSec returns the cached Unix timestamp.
func (ft *FlowTable) NowSec() int64 { return ft.nowSec.Load() }

// ---------------------------------------------------------------------------
// TCP NAT operations
// ---------------------------------------------------------------------------

// InsertTCP creates a NAT entry for a new TCP connection.
func (ft *FlowTable) InsertTCP(dstIP netip.Addr, srcPort uint16, entry *NATEntry) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.tcp[natShardIndex(nk)]
	shard.mu.Lock()
	shard.m[nk] = entry
	shard.mu.Unlock()
}

// GetTCP looks up a TCP NAT entry by destination IP and source port.
func (ft *FlowTable) GetTCP(dstIP netip.Addr, srcPort uint16) (*NATEntry, bool) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.tcp[natShardIndex(nk)]
	shard.mu.RLock()
	entry, ok := shard.m[nk]
	shard.mu.RUnlock()
	return entry, ok
}

// DeleteTCP removes a TCP NAT entry.
func (ft *FlowTable) DeleteTCP(dstIP netip.Addr, srcPort uint16) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.tcp[natShardIndex(nk)]
	shard.mu.Lock()
	delete(shard.m, nk)
	shard.mu.Unlock()
}

// LookupNAT returns the original destination for a NAT'd TCP connection.
// Compatible with proxy.NATLookup callback signature.
func (ft *FlowTable) LookupNAT(addrKey string) (originalDst string, tunnelID string, ok bool) {
	ap, err := netip.ParseAddrPort(addrKey)
	if err != nil {
		return "", "", false
	}
	nk := makeNATKey(ap.Addr(), ap.Port())
	shard := &ft.tcp[natShardIndex(nk)]

	shard.mu.RLock()
	entry, exists := shard.m[nk]
	shard.mu.RUnlock()
	if !exists || entry == nil {
		return "", "", false
	}

	dst := netip.AddrPortFrom(entry.OriginalDstIP, entry.OriginalDstPort)
	return dst.String(), entry.TunnelID, true
}

// ---------------------------------------------------------------------------
// UDP NAT operations
// ---------------------------------------------------------------------------

// InsertUDP creates a NAT entry for a new UDP flow.
func (ft *FlowTable) InsertUDP(dstIP netip.Addr, srcPort uint16, entry *UDPNATEntry) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.udp[natShardIndex(nk)]
	shard.mu.Lock()
	shard.m[nk] = entry
	shard.mu.Unlock()
}

// GetUDP looks up a UDP NAT entry.
func (ft *FlowTable) GetUDP(dstIP netip.Addr, srcPort uint16) (*UDPNATEntry, bool) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.udp[natShardIndex(nk)]
	shard.mu.RLock()
	entry, ok := shard.m[nk]
	shard.mu.RUnlock()
	return entry, ok
}

// LookupUDPNAT returns the original destination for a NAT'd UDP flow.
// Compatible with proxy.UDPNATLookup callback signature.
func (ft *FlowTable) LookupUDPNAT(addrKey string) (originalDst string, tunnelID string, ok bool) {
	ap, err := netip.ParseAddrPort(addrKey)
	if err != nil {
		return "", "", false
	}
	nk := makeNATKey(ap.Addr(), ap.Port())
	shard := &ft.udp[natShardIndex(nk)]

	shard.mu.RLock()
	entry, exists := shard.m[nk]
	shard.mu.RUnlock()
	if !exists {
		return "", "", false
	}

	dst := netip.AddrPortFrom(entry.OriginalDstIP, entry.OriginalDstPort)
	return dst.String(), entry.TunnelID, true
}

// ---------------------------------------------------------------------------
// Raw flow operations — for raw IP forwarding (bypass TCP proxy + gVisor)
// ---------------------------------------------------------------------------

// InsertRawFlow creates a raw flow entry for a TCP or UDP flow.
func (ft *FlowTable) InsertRawFlow(proto byte, dstIP [4]byte, srcPort uint16, entry *RawFlowEntry) {
	k := makeRawFlowKey(proto, dstIP, srcPort)
	shard := &ft.raw[rawFlowShardIndex(k)]
	shard.mu.Lock()
	shard.m[k] = entry
	shard.mu.Unlock()
}

// GetRawFlow looks up a raw flow entry.
func (ft *FlowTable) GetRawFlow(proto byte, dstIP [4]byte, srcPort uint16) (*RawFlowEntry, bool) {
	k := makeRawFlowKey(proto, dstIP, srcPort)
	shard := &ft.raw[rawFlowShardIndex(k)]
	shard.mu.RLock()
	entry, ok := shard.m[k]
	shard.mu.RUnlock()
	return entry, ok
}

// DeleteRawFlow removes a raw flow entry.
func (ft *FlowTable) DeleteRawFlow(proto byte, dstIP [4]byte, srcPort uint16) {
	k := makeRawFlowKey(proto, dstIP, srcPort)
	shard := &ft.raw[rawFlowShardIndex(k)]
	shard.mu.Lock()
	delete(shard.m, k)
	shard.mu.Unlock()
}

// ---------------------------------------------------------------------------
// VPN IP reverse map — lock-free reads via atomic copy-on-write
// ---------------------------------------------------------------------------

// RegisterVpnIP associates a VPN adapter IP with a tunnelID.
func (ft *FlowTable) RegisterVpnIP(vpnIP [4]byte, tunnelID string) {
	ft.vpnIPMu.Lock()
	defer ft.vpnIPMu.Unlock()
	old := ft.vpnIPMap.Load()
	newMap := make(map[[4]byte]string, len(*old)+1)
	for k, v := range *old {
		newMap[k] = v
	}
	newMap[vpnIP] = tunnelID
	ft.vpnIPMap.Store(&newMap)
}

// UnregisterVpnIP removes a VPN IP mapping.
func (ft *FlowTable) UnregisterVpnIP(vpnIP [4]byte) {
	ft.vpnIPMu.Lock()
	defer ft.vpnIPMu.Unlock()
	old := ft.vpnIPMap.Load()
	newMap := make(map[[4]byte]string, len(*old))
	for k, v := range *old {
		if k != vpnIP {
			newMap[k] = v
		}
	}
	ft.vpnIPMap.Store(&newMap)
}

// LookupVpnIP returns the tunnelID for a given VPN IP (lock-free).
func (ft *FlowTable) LookupVpnIP(ip [4]byte) (string, bool) {
	m := ft.vpnIPMap.Load()
	tid, ok := (*m)[ip]
	return tid, ok
}

// StartRawFlowCleanup periodically removes stale raw flow entries (>5 min idle).
func (ft *FlowTable) StartRawFlowCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().Unix()
				const timeout int64 = 300 // 5 minutes
				totalRemoved := 0

				for i := range ft.raw {
					shard := &ft.raw[i]
					var stale []rawFlowKey
					shard.mu.RLock()
					for key, entry := range shard.m {
						last := atomic.LoadInt64(&entry.LastActivity)
						if now-last > timeout {
							stale = append(stale, key)
						}
					}
					shard.mu.RUnlock()

					if len(stale) > 0 {
						shard.mu.Lock()
						for _, key := range stale {
							delete(shard.m, key)
						}
						shard.mu.Unlock()
						totalRemoved += len(stale)
					}
				}

				if totalRemoved > 0 {
					core.Log.Debugf("Gateway", "Raw flow cleanup: removed %d stale entries", totalRemoved)
				}
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// Proxy port management — lock-free reads via atomic copy-on-write
// ---------------------------------------------------------------------------

func (ft *FlowTable) RegisterProxyPort(port uint16) {
	ft.proxyPortsMu.Lock()
	defer ft.proxyPortsMu.Unlock()
	old := ft.proxyPorts.Load()
	newMap := make(map[uint16]struct{}, len(*old)+1)
	for k, v := range *old {
		newMap[k] = v
	}
	newMap[port] = struct{}{}
	ft.proxyPorts.Store(&newMap)
}

func (ft *FlowTable) UnregisterProxyPort(port uint16) {
	ft.proxyPortsMu.Lock()
	defer ft.proxyPortsMu.Unlock()
	old := ft.proxyPorts.Load()
	newMap := make(map[uint16]struct{}, len(*old))
	for k, v := range *old {
		if k != port {
			newMap[k] = v
		}
	}
	ft.proxyPorts.Store(&newMap)
}

func (ft *FlowTable) IsProxySourcePort(port uint16) bool {
	m := ft.proxyPorts.Load()
	_, ok := (*m)[port]
	return ok
}

func (ft *FlowTable) RegisterUDPProxyPort(port uint16) {
	ft.udpProxyPortsMu.Lock()
	defer ft.udpProxyPortsMu.Unlock()
	old := ft.udpProxyPorts.Load()
	newMap := make(map[uint16]struct{}, len(*old)+1)
	for k, v := range *old {
		newMap[k] = v
	}
	newMap[port] = struct{}{}
	ft.udpProxyPorts.Store(&newMap)
}

func (ft *FlowTable) UnregisterUDPProxyPort(port uint16) {
	ft.udpProxyPortsMu.Lock()
	defer ft.udpProxyPortsMu.Unlock()
	old := ft.udpProxyPorts.Load()
	newMap := make(map[uint16]struct{}, len(*old))
	for k, v := range *old {
		if k != port {
			newMap[k] = v
		}
	}
	ft.udpProxyPorts.Store(&newMap)
}

func (ft *FlowTable) IsUDPProxySourcePort(port uint16) bool {
	m := ft.udpProxyPorts.Load()
	_, ok := (*m)[port]
	return ok
}

// ---------------------------------------------------------------------------
// NAT cleanup routines
// ---------------------------------------------------------------------------

// StartTCPCleanup periodically removes stale TCP NAT entries (>5 min idle).
func (ft *FlowTable) StartTCPCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().Unix()
				const timeout int64 = 300 // 5 minutes
				totalRemoved := 0

				for i := range ft.tcp {
					shard := &ft.tcp[i]
					var stale []natKey
					shard.mu.RLock()
					for key, entry := range shard.m {
						last := atomic.LoadInt64(&entry.LastActivity)
						if now-last > timeout {
							stale = append(stale, key)
						}
					}
					shard.mu.RUnlock()

					if len(stale) > 0 {
						shard.mu.Lock()
						for _, key := range stale {
							delete(shard.m, key)
						}
						shard.mu.Unlock()
						totalRemoved += len(stale)
					}
				}

				if totalRemoved > 0 {
					core.Log.Debugf("Gateway", "TCP NAT cleanup: removed %d stale entries", totalRemoved)
				}
			}
		}
	}()
}

// StartUDPCleanup periodically removes stale UDP NAT entries
// (>2 min for normal, >10 sec for DNS port 53).
func (ft *FlowTable) StartUDPCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().Unix()

				for i := range ft.udp {
					shard := &ft.udp[i]
					var stale []natKey
					shard.mu.RLock()
					for key, entry := range shard.m {
						var timeout int64 = 120
						if entry.OriginalDstPort == 53 {
							timeout = 10
						}
						last := atomic.LoadInt64(&entry.LastActivity)
						if now-last > timeout {
							stale = append(stale, key)
						}
					}
					shard.mu.RUnlock()

					if len(stale) > 0 {
						shard.mu.Lock()
						for _, key := range stale {
							delete(shard.m, key)
						}
						shard.mu.Unlock()
					}
				}
			}
		}
	}()
}
