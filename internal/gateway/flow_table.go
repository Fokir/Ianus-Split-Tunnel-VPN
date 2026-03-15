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
	LastActivity    int64  // atomic; Unix seconds
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	TunnelID        string
	ProxyPort       uint16
	FinSeen         int32  // atomic; bitmask: 0x1=client FIN, 0x2=server FIN

	// Connection-level fallback context (populated by resolveFlow).
	Fallback  core.FallbackPolicy
	ExeLower  string // pre-lowered exe path for failover re-matching
	BaseLower string // pre-lowered exe basename
	RuleIdx   int    // index of matched rule in RuleEngine

	// FakeIP: real IP for dial when OriginalDstIP is a FakeIP.
	ResolvedDstIP netip.Addr
}

// UDPNATEntry maps a redirected UDP flow back to its original destination.
type UDPNATEntry struct {
	LastActivity    int64 // atomic; Unix seconds
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	TunnelID        string
	UDPProxyPort    uint16

	// Connection-level fallback context (populated by resolveFlow).
	Fallback  core.FallbackPolicy
	ExeLower  string
	BaseLower string
	RuleIdx   int

	// FakeIP: real IP for dial when OriginalDstIP is a FakeIP.
	ResolvedDstIP netip.Addr
}

// ---------------------------------------------------------------------------
// Raw flow types — for raw IP forwarding (bypass TCP proxy + gVisor)
// ---------------------------------------------------------------------------

// RawFlowEntry tracks a raw-forwarded flow (TCP or UDP) through a VPN tunnel.
type RawFlowEntry struct {
	LastActivity int64   // atomic; Unix seconds
	TunnelID     string
	VpnIP        [4]byte // cached VPN IP for fast src IP rewrite
	Priority     byte    // cached QoS priority (PrioHigh/PrioNormal/PrioLow)
	IsAuto       bool    // true when rule priority was "auto" (per-packet classification)
	FakeIP       [4]byte // original FakeIP dst (zero if not FakeIP)
	RealDstIP    [4]byte // real IP destination (for FakeIP rewriting)
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
	mu    sync.RWMutex
	index map[rawFlowKey]int32
	store []RawFlowEntry
	free  []int32
	_     [64]byte // cache line padding to prevent false sharing between shards
}

// ---------------------------------------------------------------------------
// Sharded NAT tables — 64 shards reduce RWMutex contention
// ---------------------------------------------------------------------------

const numNATShards = 64

// maxEntriesPerShard limits each shard to prevent unbounded growth under
// connection floods (port scans, torrents). Total max: 64 * 8192 = 524,288.
const maxEntriesPerShard = 8192

type tcpNATShard struct {
	mu    sync.RWMutex
	index map[natKey]int32
	store []NATEntry
	free  []int32
	_     [64]byte // cache line padding
}

type udpNATShard struct {
	mu    sync.RWMutex
	index map[natKey]int32
	store []UDPNATEntry
	free  []int32
	_     [64]byte // cache line padding
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

	// Hook called before removing stale raw flows (e.g. for FakeIP flow counting).
	rawFlowCleanupHook atomic.Pointer[func(*RawFlowEntry)]

	// wg tracks background goroutines (cleanup loops, timestamp updater).
	wg sync.WaitGroup
}

// initialShardCapacity is the initial map capacity per shard, chosen to avoid
// early rehashing while keeping memory usage reasonable.
const initialShardCapacity = 64

// NewFlowTable creates an initialized flow table.
func NewFlowTable() *FlowTable {
	ft := &FlowTable{}
	for i := range ft.tcp {
		ft.tcp[i].index = make(map[natKey]int32, initialShardCapacity)
		ft.tcp[i].store = make([]NATEntry, 0, initialShardCapacity)
	}
	for i := range ft.udp {
		ft.udp[i].index = make(map[natKey]int32, initialShardCapacity)
		ft.udp[i].store = make([]UDPNATEntry, 0, initialShardCapacity)
	}
	for i := range ft.raw {
		ft.raw[i].index = make(map[rawFlowKey]int32, initialShardCapacity)
		ft.raw[i].store = make([]RawFlowEntry, 0, initialShardCapacity)
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
	ft.wg.Add(1)
	core.SuperviseWG(ctx, &ft.wg, core.SupervisorConfig{Name: "flow.timestamp-updater"}, func(ctx context.Context) {
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
	})
}

// NowSec returns the cached Unix timestamp.
func (ft *FlowTable) NowSec() int64 { return ft.nowSec.Load() }

// Wait blocks until all background goroutines (cleanup loops, timestamp updater) exit.
// The caller must cancel the context passed to Start* methods first.
func (ft *FlowTable) Wait() { ft.wg.Wait() }

// ---------------------------------------------------------------------------
// TCP NAT operations
// ---------------------------------------------------------------------------

// InsertTCP creates a NAT entry for a new TCP connection.
// Evicts a random entry if the shard is at capacity.
func (ft *FlowTable) InsertTCP(dstIP netip.Addr, srcPort uint16, entry NATEntry) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.tcp[natShardIndex(nk)]
	shard.mu.Lock()
	if len(shard.index) >= maxEntriesPerShard {
		for k, idx := range shard.index {
			shard.store[idx] = NATEntry{} // zero to release strings
			shard.free = append(shard.free, idx)
			delete(shard.index, k)
			break
		}
	}
	idx := tcpAllocSlot(shard, entry)
	shard.index[nk] = idx
	shard.mu.Unlock()
}

func tcpAllocSlot(s *tcpNATShard, entry NATEntry) int32 {
	if n := len(s.free); n > 0 {
		idx := s.free[n-1]
		s.free = s.free[:n-1]
		s.store[idx] = entry
		return idx
	}
	idx := int32(len(s.store))
	s.store = append(s.store, entry)
	return idx
}

// GetTCP returns a copy of a TCP NAT entry.
func (ft *FlowTable) GetTCP(dstIP netip.Addr, srcPort uint16) (NATEntry, bool) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.tcp[natShardIndex(nk)]
	shard.mu.RLock()
	idx, ok := shard.index[nk]
	if !ok {
		shard.mu.RUnlock()
		return NATEntry{}, false
	}
	entry := shard.store[idx] // copy
	shard.mu.RUnlock()
	return entry, ok
}

// TouchTCP updates the LastActivity timestamp for a TCP NAT entry.
func (ft *FlowTable) TouchTCP(dstIP netip.Addr, srcPort uint16) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.tcp[natShardIndex(nk)]
	shard.mu.RLock()
	if idx, ok := shard.index[nk]; ok {
		atomic.StoreInt64(&shard.store[idx].LastActivity, ft.nowSec.Load())
	}
	shard.mu.RUnlock()
}

// SetFinTCP atomically ORs a FIN bit on a TCP entry and accelerates cleanup
// if both client and server FINs are seen.
func (ft *FlowTable) SetFinTCP(dstIP netip.Addr, srcPort uint16, finBit int32) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.tcp[natShardIndex(nk)]
	shard.mu.RLock()
	if idx, ok := shard.index[nk]; ok {
		old := atomic.OrInt32(&shard.store[idx].FinSeen, finBit)
		if old|finBit == 0x3 {
			// Both FINs seen — schedule near-immediate cleanup (2s grace).
			atomic.StoreInt64(&shard.store[idx].LastActivity, ft.nowSec.Load()-298)
		}
	}
	shard.mu.RUnlock()
}

// DeleteTCP removes a TCP NAT entry.
func (ft *FlowTable) DeleteTCP(dstIP netip.Addr, srcPort uint16) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.tcp[natShardIndex(nk)]
	shard.mu.Lock()
	if idx, ok := shard.index[nk]; ok {
		shard.store[idx] = NATEntry{} // zero to release strings
		shard.free = append(shard.free, idx)
		delete(shard.index, nk)
	}
	shard.mu.Unlock()
}

// LookupNAT returns the original destination and fallback context for a NAT'd TCP connection.
// Compatible with proxy.NATLookup callback signature.
func (ft *FlowTable) LookupNAT(addrKey string) (core.NATInfo, bool) {
	ap, err := netip.ParseAddrPort(addrKey)
	if err != nil {
		return core.NATInfo{}, false
	}
	nk := makeNATKey(ap.Addr(), ap.Port())
	shard := &ft.tcp[natShardIndex(nk)]

	shard.mu.RLock()
	idx, exists := shard.index[nk]
	if !exists {
		shard.mu.RUnlock()
		return core.NATInfo{}, false
	}
	entry := shard.store[idx] // copy
	shard.mu.RUnlock()

	dst := netip.AddrPortFrom(entry.OriginalDstIP, entry.OriginalDstPort)
	info := core.NATInfo{
		OriginalDst: dst.String(),
		TunnelID:    entry.TunnelID,
		Fallback:    entry.Fallback,
		ExeLower:    entry.ExeLower,
		BaseLower:   entry.BaseLower,
		RuleIdx:     entry.RuleIdx,
	}

	// If FakeIP resolved a real destination, provide it for dial.
	if entry.ResolvedDstIP.IsValid() {
		resolved := netip.AddrPortFrom(entry.ResolvedDstIP, entry.OriginalDstPort)
		info.ResolvedDst = resolved.String()
	}

	return info, true
}

// ---------------------------------------------------------------------------
// UDP NAT operations
// ---------------------------------------------------------------------------

// InsertUDP creates a NAT entry for a new UDP flow.
// Evicts a random entry if the shard is at capacity.
func (ft *FlowTable) InsertUDP(dstIP netip.Addr, srcPort uint16, entry UDPNATEntry) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.udp[natShardIndex(nk)]
	shard.mu.Lock()
	if len(shard.index) >= maxEntriesPerShard {
		for k, idx := range shard.index {
			shard.store[idx] = UDPNATEntry{}
			shard.free = append(shard.free, idx)
			delete(shard.index, k)
			break
		}
	}
	idx := udpAllocSlot(shard, entry)
	shard.index[nk] = idx
	shard.mu.Unlock()
}

func udpAllocSlot(s *udpNATShard, entry UDPNATEntry) int32 {
	if n := len(s.free); n > 0 {
		idx := s.free[n-1]
		s.free = s.free[:n-1]
		s.store[idx] = entry
		return idx
	}
	idx := int32(len(s.store))
	s.store = append(s.store, entry)
	return idx
}

// GetUDP returns a copy of a UDP NAT entry.
func (ft *FlowTable) GetUDP(dstIP netip.Addr, srcPort uint16) (UDPNATEntry, bool) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.udp[natShardIndex(nk)]
	shard.mu.RLock()
	idx, ok := shard.index[nk]
	if !ok {
		shard.mu.RUnlock()
		return UDPNATEntry{}, false
	}
	entry := shard.store[idx] // copy
	shard.mu.RUnlock()
	return entry, ok
}

// TouchUDP updates the LastActivity timestamp for a UDP NAT entry.
func (ft *FlowTable) TouchUDP(dstIP netip.Addr, srcPort uint16) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.udp[natShardIndex(nk)]
	shard.mu.RLock()
	if idx, ok := shard.index[nk]; ok {
		atomic.StoreInt64(&shard.store[idx].LastActivity, ft.nowSec.Load())
	}
	shard.mu.RUnlock()
}

// LookupUDPNAT returns the original destination and fallback context for a NAT'd UDP flow.
// Compatible with proxy.UDPNATLookup callback signature.
func (ft *FlowTable) LookupUDPNAT(addrKey string) (core.NATInfo, bool) {
	ap, err := netip.ParseAddrPort(addrKey)
	if err != nil {
		return core.NATInfo{}, false
	}
	nk := makeNATKey(ap.Addr(), ap.Port())
	shard := &ft.udp[natShardIndex(nk)]

	shard.mu.RLock()
	idx, exists := shard.index[nk]
	if !exists {
		shard.mu.RUnlock()
		return core.NATInfo{}, false
	}
	entry := shard.store[idx] // copy
	shard.mu.RUnlock()

	dst := netip.AddrPortFrom(entry.OriginalDstIP, entry.OriginalDstPort)
	info := core.NATInfo{
		OriginalDst: dst.String(),
		TunnelID:    entry.TunnelID,
		Fallback:    entry.Fallback,
		ExeLower:    entry.ExeLower,
		BaseLower:   entry.BaseLower,
		RuleIdx:     entry.RuleIdx,
	}

	// If FakeIP resolved a real destination, provide it for dial.
	if entry.ResolvedDstIP.IsValid() {
		resolved := netip.AddrPortFrom(entry.ResolvedDstIP, entry.OriginalDstPort)
		info.ResolvedDst = resolved.String()
	}

	return info, true
}

// ---------------------------------------------------------------------------
// Raw flow operations — for raw IP forwarding (bypass TCP proxy + gVisor)
// ---------------------------------------------------------------------------

// InsertRawFlow creates a raw flow entry for a TCP or UDP flow.
// Evicts a random entry if the shard is at capacity.
func (ft *FlowTable) InsertRawFlow(proto byte, dstIP [4]byte, srcPort uint16, entry RawFlowEntry) {
	k := makeRawFlowKey(proto, dstIP, srcPort)
	shard := &ft.raw[rawFlowShardIndex(k)]
	shard.mu.Lock()
	if len(shard.index) >= maxEntriesPerShard {
		for fk, idx := range shard.index {
			shard.store[idx] = RawFlowEntry{}
			shard.free = append(shard.free, idx)
			delete(shard.index, fk)
			break
		}
	}
	idx := rawAllocSlot(shard, entry)
	shard.index[k] = idx
	shard.mu.Unlock()
}

func rawAllocSlot(s *rawFlowShard, entry RawFlowEntry) int32 {
	if n := len(s.free); n > 0 {
		idx := s.free[n-1]
		s.free = s.free[:n-1]
		s.store[idx] = entry
		return idx
	}
	idx := int32(len(s.store))
	s.store = append(s.store, entry)
	return idx
}

// GetRawFlow returns a copy of a raw flow entry.
func (ft *FlowTable) GetRawFlow(proto byte, dstIP [4]byte, srcPort uint16) (RawFlowEntry, bool) {
	k := makeRawFlowKey(proto, dstIP, srcPort)
	shard := &ft.raw[rawFlowShardIndex(k)]
	shard.mu.RLock()
	idx, ok := shard.index[k]
	if !ok {
		shard.mu.RUnlock()
		return RawFlowEntry{}, false
	}
	entry := shard.store[idx] // copy
	shard.mu.RUnlock()
	return entry, ok
}

// TouchRawFlow updates the LastActivity timestamp for a raw flow entry.
func (ft *FlowTable) TouchRawFlow(proto byte, dstIP [4]byte, srcPort uint16) {
	k := makeRawFlowKey(proto, dstIP, srcPort)
	shard := &ft.raw[rawFlowShardIndex(k)]
	shard.mu.RLock()
	if idx, ok := shard.index[k]; ok {
		atomic.StoreInt64(&shard.store[idx].LastActivity, ft.nowSec.Load())
	}
	shard.mu.RUnlock()
}

// DeleteRawFlow removes a raw flow entry.
func (ft *FlowTable) DeleteRawFlow(proto byte, dstIP [4]byte, srcPort uint16) {
	k := makeRawFlowKey(proto, dstIP, srcPort)
	shard := &ft.raw[rawFlowShardIndex(k)]
	shard.mu.Lock()
	if idx, ok := shard.index[k]; ok {
		shard.store[idx] = RawFlowEntry{}
		shard.free = append(shard.free, idx)
		delete(shard.index, k)
	}
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
	ft.wg.Add(1)
	core.SuperviseWG(ctx, &ft.wg, core.SupervisorConfig{Name: "flow.raw-cleanup"}, func(ctx context.Context) {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		// Preallocate candidates slice — reused across ticks to avoid GC churn.
		candidates := make([]rawFlowKey, 0, 128)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupStart := time.Now()
				now := ft.NowSec()
				const timeout int64 = 300 // 5 minutes
				totalRemoved := 0

				for i := range ft.raw {
					shard := &ft.raw[i]
					// Phase 1: collect candidates under read lock.
					candidates = candidates[:0]
					shard.mu.RLock()
					for key, idx := range shard.index {
						if now-atomic.LoadInt64(&shard.store[idx].LastActivity) > timeout {
							candidates = append(candidates, key)
						}
					}
					shard.mu.RUnlock()

					if len(candidates) == 0 {
						continue
					}
					// Phase 2: delete under write lock with re-check (TOCTOU fix).
					shard.mu.Lock()
					hookPtr := ft.rawFlowCleanupHook.Load()
					for _, key := range candidates {
						if idx, ok := shard.index[key]; ok {
							if now-atomic.LoadInt64(&shard.store[idx].LastActivity) > timeout {
								if hookPtr != nil {
									(*hookPtr)(&shard.store[idx])
								}
								shard.store[idx] = RawFlowEntry{}
								shard.free = append(shard.free, idx)
								delete(shard.index, key)
								totalRemoved++
							}
						}
					}
					remaining := len(shard.index)
					shard.mu.Unlock()

					if totalRemoved > 0 && remaining < maxEntriesPerShard/4 && remaining > 0 {
						shard.mu.Lock()
						if len(shard.index) < maxEntriesPerShard/4 {
							newIndex := make(map[rawFlowKey]int32, len(shard.index)*2)
							for k, v := range shard.index {
								newIndex[k] = v
							}
							shard.index = newIndex
						}
						shard.mu.Unlock()
					}
				}

				if elapsed := time.Since(cleanupStart); elapsed > 5*time.Millisecond {
					core.Log.Warnf("Perf", "Raw flow cleanup took %s (removed %d)", elapsed, totalRemoved)
				} else if totalRemoved > 0 {
					core.Log.Debugf("Gateway", "Raw flow cleanup: removed %d stale entries", totalRemoved)
				}
			}
		}
	})
}

// SetRawFlowCleanupHook sets a callback invoked before removing stale raw flows.
// Used by FakeIP to decrement active flow counts on eviction.
func (ft *FlowTable) SetRawFlowCleanupHook(hook func(*RawFlowEntry)) {
	ft.rawFlowCleanupHook.Store(&hook)
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
// Flow table statistics
// ---------------------------------------------------------------------------

// FlowTableStats holds the current entry counts for all flow tables.
type FlowTableStats struct {
	TCPEntries int
	UDPEntries int
	RawEntries int
}

// Stats returns the current entry counts across all shards.
func (ft *FlowTable) Stats() FlowTableStats {
	var s FlowTableStats
	for i := range ft.tcp {
		ft.tcp[i].mu.RLock()
		s.TCPEntries += len(ft.tcp[i].index)
		ft.tcp[i].mu.RUnlock()
	}
	for i := range ft.udp {
		ft.udp[i].mu.RLock()
		s.UDPEntries += len(ft.udp[i].index)
		ft.udp[i].mu.RUnlock()
	}
	for i := range ft.raw {
		ft.raw[i].mu.RLock()
		s.RawEntries += len(ft.raw[i].index)
		ft.raw[i].mu.RUnlock()
	}
	return s
}

// ---------------------------------------------------------------------------
// NAT cleanup routines
// ---------------------------------------------------------------------------

// StartTCPCleanup periodically removes stale TCP NAT entries (>5 min idle).
func (ft *FlowTable) StartTCPCleanup(ctx context.Context) {
	ft.wg.Add(1)
	core.SuperviseWG(ctx, &ft.wg, core.SupervisorConfig{Name: "flow.tcp-cleanup"}, func(ctx context.Context) {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		// Preallocate candidates slice — reused across ticks to avoid GC churn.
		candidates := make([]natKey, 0, 128)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupStart := time.Now()
				now := ft.NowSec()
				const timeout int64 = 300 // 5 minutes
				totalRemoved := 0

				for i := range ft.tcp {
					shard := &ft.tcp[i]
					// Phase 1: collect candidates under read lock.
					candidates = candidates[:0]
					shard.mu.RLock()
					for key, idx := range shard.index {
						if now-atomic.LoadInt64(&shard.store[idx].LastActivity) > timeout {
							candidates = append(candidates, key)
						}
					}
					shard.mu.RUnlock()

					if len(candidates) == 0 {
						continue
					}
					// Phase 2: delete under write lock with re-check (TOCTOU fix).
					shard.mu.Lock()
					for _, key := range candidates {
						if idx, ok := shard.index[key]; ok {
							if now-atomic.LoadInt64(&shard.store[idx].LastActivity) > timeout {
								shard.store[idx] = NATEntry{}
								shard.free = append(shard.free, idx)
								delete(shard.index, key)
								totalRemoved++
							}
						}
					}
					remaining := len(shard.index)
					shard.mu.Unlock()

					if totalRemoved > 0 && remaining < maxEntriesPerShard/4 && remaining > 0 {
						shard.mu.Lock()
						if len(shard.index) < maxEntriesPerShard/4 {
							newIndex := make(map[natKey]int32, len(shard.index)*2)
							for k, v := range shard.index {
								newIndex[k] = v
							}
							shard.index = newIndex
						}
						shard.mu.Unlock()
					}
				}

				if elapsed := time.Since(cleanupStart); elapsed > 5*time.Millisecond {
					core.Log.Warnf("Perf", "TCP NAT cleanup took %s (removed %d)", elapsed, totalRemoved)
				} else if totalRemoved > 0 {
					core.Log.Debugf("Gateway", "TCP NAT cleanup: removed %d stale entries", totalRemoved)
				}
			}
		}
	})
}

// StartUDPCleanup periodically removes stale UDP NAT entries
// (>2 min for normal, >10 sec for DNS port 53).
func (ft *FlowTable) StartUDPCleanup(ctx context.Context) {
	ft.wg.Add(1)
	core.SuperviseWG(ctx, &ft.wg, core.SupervisorConfig{Name: "flow.udp-cleanup"}, func(ctx context.Context) {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		// Preallocate candidates slice — reused across ticks to avoid GC churn.
		type udpCandidate struct {
			key     natKey
			timeout int64
		}
		candidates := make([]udpCandidate, 0, 128)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupStart := time.Now()
				now := ft.NowSec()
				totalRemoved := 0

				for i := range ft.udp {
					shard := &ft.udp[i]
					// Phase 1: collect candidates under read lock.
					candidates = candidates[:0]
					shard.mu.RLock()
					for key, idx := range shard.index {
						entry := &shard.store[idx]
						var timeout int64 = 120
						if entry.OriginalDstPort == 53 {
							timeout = 10
						}
						if now-atomic.LoadInt64(&entry.LastActivity) > timeout {
							candidates = append(candidates, udpCandidate{key, timeout})
						}
					}
					shard.mu.RUnlock()

					if len(candidates) == 0 {
						continue
					}
					// Phase 2: delete under write lock with re-check (TOCTOU fix).
					shard.mu.Lock()
					for _, c := range candidates {
						if idx, ok := shard.index[c.key]; ok {
							if now-atomic.LoadInt64(&shard.store[idx].LastActivity) > c.timeout {
								shard.store[idx] = UDPNATEntry{}
								shard.free = append(shard.free, idx)
								delete(shard.index, c.key)
								totalRemoved++
							}
						}
					}
					remaining := len(shard.index)
					shard.mu.Unlock()

					if totalRemoved > 0 && remaining < maxEntriesPerShard/4 && remaining > 0 {
						shard.mu.Lock()
						if len(shard.index) < maxEntriesPerShard/4 {
							newIndex := make(map[natKey]int32, len(shard.index)*2)
							for k, v := range shard.index {
								newIndex[k] = v
							}
							shard.index = newIndex
						}
						shard.mu.Unlock()
					}
				}

				if elapsed := time.Since(cleanupStart); elapsed > 5*time.Millisecond {
					core.Log.Warnf("Perf", "UDP NAT cleanup took %s (removed %d)", elapsed, totalRemoved)
				}
			}
		}
	})
}
