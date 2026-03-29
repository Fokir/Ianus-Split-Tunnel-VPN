package gateway

import (
	"context"
	"maps"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"awg-split-tunnel/internal/core"
)

// stringIntern deduplicates frequently repeated strings (tunnelID, exeLower,
// baseLower). In practice there are ~5-10 unique values across 100K+ entries.
// Using sync.Map for read-heavy access pattern on the hot path.
var stringIntern sync.Map

func internStr(s string) string {
	if s == "" {
		return ""
	}
	if v, ok := stringIntern.Load(s); ok {
		return v.(string)
	}
	stringIntern.Store(s, s)
	return s
}

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
	Dead            int32  // atomic; 1 = marked for compaction, invisible to hot path
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
	Dead            int32 // atomic; 1 = marked for compaction, invisible to hot path
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
	Dead         int32   // atomic; 1 = marked for compaction, invisible to hot path
	LastActivity int64   // atomic; Unix seconds
	TunnelID     string
	VpnIP        [4]byte // cached VPN IP for fast src IP rewrite
	Priority     byte    // cached QoS priority (PrioHigh/PrioNormal/PrioLow)
	IsAuto       bool    // true when rule priority was "auto" (per-packet classification)
	FakeIP       [4]byte // original FakeIP dst (zero if not FakeIP)
	RealDstIP    [4]byte // real IP destination (for FakeIP rewriting)
	ExeLower     string  // cached lowercase exe path (for monitoring)
	BaseLower    string  // cached lowercase base name (for monitoring)
}

// NATSnapshotEntry is a lightweight copy of a TCP NAT entry for monitoring.
type NATSnapshotEntry struct {
	SrcPort         uint16
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	ResolvedDstIP   netip.Addr
	TunnelID        string
	ExeLower        string
	BaseLower       string
	LastActivity    int64
	FinSeen         int32
}

// UDPSnapshotEntry is a lightweight copy of a UDP NAT entry for monitoring.
type UDPSnapshotEntry struct {
	SrcPort         uint16
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	ResolvedDstIP   netip.Addr
	TunnelID        string
	ExeLower        string
	BaseLower       string
	LastActivity    int64
}

// RawSnapshotEntry is a lightweight copy of a raw flow entry for monitoring.
type RawSnapshotEntry struct {
	Protocol     uint8
	DstIP        netip.Addr
	SrcPort      uint16
	TunnelID     string
	LastActivity int64
	FakeIP       netip.Addr
	RealDstIP    netip.Addr
	ExeLower     string
	BaseLower    string
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
	entry.TunnelID = internStr(entry.TunnelID)
	entry.ExeLower = internStr(entry.ExeLower)
	entry.BaseLower = internStr(entry.BaseLower)
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
	if atomic.LoadInt32(&entry.Dead) != 0 {
		return NATEntry{}, false
	}
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

// GetAndTouchTCP returns a copy of a TCP NAT entry and updates its LastActivity
// timestamp in a single RLock acquisition, eliminating the double-lock overhead
// of a separate Get + Touch call pair on the hot path.
func (ft *FlowTable) GetAndTouchTCP(dstIP netip.Addr, srcPort uint16) (NATEntry, bool) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.tcp[natShardIndex(nk)]
	shard.mu.RLock()
	idx, ok := shard.index[nk]
	if !ok {
		shard.mu.RUnlock()
		return NATEntry{}, false
	}
	if atomic.LoadInt32(&shard.store[idx].Dead) != 0 {
		shard.mu.RUnlock()
		return NATEntry{}, false
	}
	atomic.StoreInt64(&shard.store[idx].LastActivity, ft.nowSec.Load())
	entry := shard.store[idx]
	shard.mu.RUnlock()
	return entry, true
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
	entry.TunnelID = internStr(entry.TunnelID)
	entry.ExeLower = internStr(entry.ExeLower)
	entry.BaseLower = internStr(entry.BaseLower)
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
	if atomic.LoadInt32(&entry.Dead) != 0 {
		return UDPNATEntry{}, false
	}
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

// GetAndTouchUDP returns a copy of a UDP NAT entry and updates its LastActivity
// timestamp in a single RLock acquisition, eliminating the double-lock overhead
// of a separate Get + Touch call pair on the hot path.
func (ft *FlowTable) GetAndTouchUDP(dstIP netip.Addr, srcPort uint16) (UDPNATEntry, bool) {
	nk := makeNATKey(dstIP, srcPort)
	shard := &ft.udp[natShardIndex(nk)]
	shard.mu.RLock()
	idx, ok := shard.index[nk]
	if !ok {
		shard.mu.RUnlock()
		return UDPNATEntry{}, false
	}
	if atomic.LoadInt32(&shard.store[idx].Dead) != 0 {
		shard.mu.RUnlock()
		return UDPNATEntry{}, false
	}
	atomic.StoreInt64(&shard.store[idx].LastActivity, ft.nowSec.Load())
	entry := shard.store[idx]
	shard.mu.RUnlock()
	return entry, true
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
	entry.TunnelID = internStr(entry.TunnelID)
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
	if atomic.LoadInt32(&entry.Dead) != 0 {
		return RawFlowEntry{}, false
	}
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

// GetAndTouchRawFlow returns a copy of a raw flow entry and updates its
// LastActivity timestamp in a single RLock acquisition, eliminating the
// double-lock overhead of a separate Get + Touch call pair on the hot path.
func (ft *FlowTable) GetAndTouchRawFlow(proto byte, dstIP [4]byte, srcPort uint16) (RawFlowEntry, bool) {
	k := makeRawFlowKey(proto, dstIP, srcPort)
	shard := &ft.raw[rawFlowShardIndex(k)]
	shard.mu.RLock()
	idx, ok := shard.index[k]
	if !ok {
		shard.mu.RUnlock()
		return RawFlowEntry{}, false
	}
	if atomic.LoadInt32(&shard.store[idx].Dead) != 0 {
		shard.mu.RUnlock()
		return RawFlowEntry{}, false
	}
	atomic.StoreInt64(&shard.store[idx].LastActivity, ft.nowSec.Load())
	entry := shard.store[idx]
	shard.mu.RUnlock()
	return entry, true
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
	maps.Copy(newMap, *old)
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
func (ft *FlowTable) StartRawFlowCleanup(ctx context.Context, initialDelay time.Duration) {
	ft.wg.Add(1)
	core.SuperviseWG(ctx, &ft.wg, core.SupervisorConfig{Name: "flow.raw-cleanup"}, func(ctx context.Context) {
		// Stagger start to avoid simultaneous cleanup with other flow tables.
		if initialDelay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(initialDelay):
			}
		}
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := ft.nowSec.Load()
				const timeout int64 = 300
				var marked int

				for i := range ft.raw {
					shard := &ft.raw[i]
					shard.mu.RLock()
					for _, idx := range shard.index {
						if atomic.LoadInt32(&shard.store[idx].Dead) != 0 {
							continue
						}
						if now-atomic.LoadInt64(&shard.store[idx].LastActivity) > timeout {
							atomic.StoreInt32(&shard.store[idx].Dead, 1)
							marked++
						}
					}
					shard.mu.RUnlock()
				}

				if marked > 0 {
					core.Log.Debugf("Gateway", "Raw flow cleanup: marked %d entries dead", marked)
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
	maps.Copy(newMap, *old)
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
	maps.Copy(newMap, *old)
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

// SnapshotNAT returns a read-only snapshot of all active TCP NAT entries.
func (ft *FlowTable) SnapshotNAT() []NATSnapshotEntry {
	var result []NATSnapshotEntry
	for i := range ft.tcp {
		s := &ft.tcp[i]
		s.mu.RLock()
		for _, idx := range s.index {
			if idx < 0 || int(idx) >= len(s.store) {
				continue
			}
			e := &s.store[idx]
			if e.TunnelID == "" {
				continue
			}
			result = append(result, NATSnapshotEntry{
				SrcPort:         e.ProxyPort,
				OriginalDstIP:   e.OriginalDstIP,
				OriginalDstPort: e.OriginalDstPort,
				ResolvedDstIP:   e.ResolvedDstIP,
				TunnelID:        e.TunnelID,
				ExeLower:        e.ExeLower,
				BaseLower:       e.BaseLower,
				LastActivity:    atomic.LoadInt64(&e.LastActivity),
				FinSeen:         atomic.LoadInt32(&e.FinSeen),
			})
		}
		s.mu.RUnlock()
	}
	return result
}

// SnapshotUDP returns a read-only snapshot of all active UDP NAT entries.
func (ft *FlowTable) SnapshotUDP() []UDPSnapshotEntry {
	var result []UDPSnapshotEntry
	for i := range ft.udp {
		s := &ft.udp[i]
		s.mu.RLock()
		for _, idx := range s.index {
			if idx < 0 || int(idx) >= len(s.store) {
				continue
			}
			e := &s.store[idx]
			if e.TunnelID == "" {
				continue
			}
			result = append(result, UDPSnapshotEntry{
				SrcPort:         e.UDPProxyPort,
				OriginalDstIP:   e.OriginalDstIP,
				OriginalDstPort: e.OriginalDstPort,
				ResolvedDstIP:   e.ResolvedDstIP,
				TunnelID:        e.TunnelID,
				ExeLower:        e.ExeLower,
				BaseLower:       e.BaseLower,
				LastActivity:    atomic.LoadInt64(&e.LastActivity),
			})
		}
		s.mu.RUnlock()
	}
	return result
}

// SnapshotRaw returns a read-only snapshot of all active raw flow entries.
func (ft *FlowTable) SnapshotRaw() []RawSnapshotEntry {
	var result []RawSnapshotEntry
	for i := range ft.raw {
		s := &ft.raw[i]
		s.mu.RLock()
		for k, idx := range s.index {
			if idx < 0 || int(idx) >= len(s.store) {
				continue
			}
			e := &s.store[idx]
			if e.TunnelID == "" {
				continue
			}
			proto := k[0]
			var dstIP4 [4]byte
			copy(dstIP4[:], k[1:5])
			srcPort := uint16(k[5])<<8 | uint16(k[6])
			var fakeIP, realDstIP netip.Addr
			if e.FakeIP != [4]byte{} {
				fakeIP = netip.AddrFrom4(e.FakeIP)
			}
			if e.RealDstIP != [4]byte{} {
				realDstIP = netip.AddrFrom4(e.RealDstIP)
			}
			result = append(result, RawSnapshotEntry{
				Protocol:     proto,
				DstIP:        netip.AddrFrom4(dstIP4),
				SrcPort:      srcPort,
				TunnelID:     e.TunnelID,
				LastActivity: atomic.LoadInt64(&e.LastActivity),
				FakeIP:       fakeIP,
				RealDstIP:    realDstIP,
				ExeLower:     e.ExeLower,
				BaseLower:    e.BaseLower,
			})
		}
		s.mu.RUnlock()
	}
	return result
}

// ---------------------------------------------------------------------------
// NAT cleanup routines
// ---------------------------------------------------------------------------

// StartTCPCleanup periodically removes stale TCP NAT entries (>5 min idle).
func (ft *FlowTable) StartTCPCleanup(ctx context.Context, initialDelay time.Duration) {
	ft.wg.Add(1)
	core.SuperviseWG(ctx, &ft.wg, core.SupervisorConfig{Name: "flow.tcp-cleanup"}, func(ctx context.Context) {
		// Stagger start to avoid simultaneous cleanup with other flow tables.
		if initialDelay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(initialDelay):
			}
		}
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := ft.nowSec.Load()
				const timeout int64 = 300
				var marked int

				for i := range ft.tcp {
					shard := &ft.tcp[i]
					shard.mu.RLock()
					for _, idx := range shard.index {
						if atomic.LoadInt32(&shard.store[idx].Dead) != 0 {
							continue
						}
						if now-atomic.LoadInt64(&shard.store[idx].LastActivity) > timeout {
							atomic.StoreInt32(&shard.store[idx].Dead, 1)
							marked++
						}
					}
					shard.mu.RUnlock()
				}

				if marked > 0 {
					core.Log.Debugf("Gateway", "TCP NAT cleanup: marked %d entries dead", marked)
				}
			}
		}
	})
}

// udpFlowTimeout returns the idle timeout in seconds for a UDP flow based on
// its destination port. Gaming and media ports get longer timeouts; DNS gets
// a short 10-second timeout.
func udpFlowTimeout(dstPort uint16) int64 {
	switch {
	case dstPort == 53:
		return 10
	case dstPort >= 27015 && dstPort <= 27050:
		return 600
	case dstPort >= 3478 && dstPort <= 3479:
		return 600
	case dstPort >= 7000 && dstPort <= 9000:
		return 600
	case dstPort == 443:
		return 300
	case dstPort >= 3480 && dstPort <= 3497:
		return 300
	case dstPort >= 5004 && dstPort <= 5005:
		return 300
	case dstPort >= 16384 && dstPort <= 32767:
		return 300
	default:
		return 300
	}
}

// StartUDPCleanup periodically marks stale UDP NAT entries as dead using
// adaptive per-port timeouts. Actual removal is performed by the compaction
// goroutine (StartCompaction).
func (ft *FlowTable) StartUDPCleanup(ctx context.Context, initialDelay time.Duration) {
	ft.wg.Add(1)
	core.SuperviseWG(ctx, &ft.wg, core.SupervisorConfig{Name: "flow.udp-cleanup"}, func(ctx context.Context) {
		// Stagger start to avoid simultaneous cleanup with other flow tables.
		if initialDelay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(initialDelay):
			}
		}
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := ft.nowSec.Load()
				var marked int

				for i := range ft.udp {
					shard := &ft.udp[i]
					shard.mu.RLock()
					for _, idx := range shard.index {
						if atomic.LoadInt32(&shard.store[idx].Dead) != 0 {
							continue
						}
						timeout := udpFlowTimeout(shard.store[idx].OriginalDstPort)
						if now-atomic.LoadInt64(&shard.store[idx].LastActivity) > timeout {
							atomic.StoreInt32(&shard.store[idx].Dead, 1)
							marked++
						}
					}
					shard.mu.RUnlock()
				}

				if marked > 0 {
					core.Log.Debugf("Gateway", "UDP NAT cleanup: marked %d entries dead", marked)
				}
			}
		}
	})
}

// StartCompaction periodically removes dead entries from shard maps and returns
// their slots to the free list. Runs every 2 minutes with write-lock on one
// shard at a time, yielding between shards to minimize hot-path interference.
func (ft *FlowTable) StartCompaction(ctx context.Context) {
	ft.wg.Add(1)
	core.SuperviseWG(ctx, &ft.wg, core.SupervisorConfig{Name: "flow.compaction"}, func(ctx context.Context) {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			var totalTCP, totalUDP, totalRaw int

			for i := range ft.tcp {
				if ctx.Err() != nil {
					return
				}
				totalTCP += ft.compactTCPShard(&ft.tcp[i])
				runtime.Gosched()
			}

			for i := range ft.udp {
				if ctx.Err() != nil {
					return
				}
				totalUDP += ft.compactUDPShard(&ft.udp[i])
				runtime.Gosched()
			}

			hookPtr := ft.rawFlowCleanupHook.Load()
			for i := range ft.raw {
				if ctx.Err() != nil {
					return
				}
				totalRaw += ft.compactRawShard(&ft.raw[i], hookPtr)
				runtime.Gosched()
			}

			total := totalTCP + totalUDP + totalRaw
			if total > 0 {
				core.Log.Debugf("Gateway", "Compaction: removed %d entries (tcp=%d udp=%d raw=%d)",
					total, totalTCP, totalUDP, totalRaw)
			}
		}
	})
}

func (ft *FlowTable) compactTCPShard(shard *tcpNATShard) int {
	shard.mu.Lock()
	defer shard.mu.Unlock()

	var removed int
	for k, idx := range shard.index {
		if atomic.LoadInt32(&shard.store[idx].Dead) != 0 {
			shard.store[idx] = NATEntry{}
			shard.free = append(shard.free, idx)
			delete(shard.index, k)
			removed++
		}
	}

	remaining := len(shard.index)
	if removed > 0 && remaining < maxEntriesPerShard/4 && remaining > 0 {
		newIndex := make(map[natKey]int32, remaining*2)
		maps.Copy(newIndex, shard.index)
		shard.index = newIndex
	}
	return removed
}

func (ft *FlowTable) compactUDPShard(shard *udpNATShard) int {
	shard.mu.Lock()
	defer shard.mu.Unlock()

	var removed int
	for k, idx := range shard.index {
		if atomic.LoadInt32(&shard.store[idx].Dead) != 0 {
			shard.store[idx] = UDPNATEntry{}
			shard.free = append(shard.free, idx)
			delete(shard.index, k)
			removed++
		}
	}

	remaining := len(shard.index)
	if removed > 0 && remaining < maxEntriesPerShard/4 && remaining > 0 {
		newIndex := make(map[natKey]int32, remaining*2)
		maps.Copy(newIndex, shard.index)
		shard.index = newIndex
	}
	return removed
}

func (ft *FlowTable) compactRawShard(shard *rawFlowShard, hookPtr *func(*RawFlowEntry)) int {
	shard.mu.Lock()
	defer shard.mu.Unlock()

	var removed int
	for k, idx := range shard.index {
		if atomic.LoadInt32(&shard.store[idx].Dead) != 0 {
			if hookPtr != nil {
				(*hookPtr)(&shard.store[idx])
			}
			shard.store[idx] = RawFlowEntry{}
			shard.free = append(shard.free, idx)
			delete(shard.index, k)
			removed++
		}
	}

	remaining := len(shard.index)
	if removed > 0 && remaining < maxEntriesPerShard/4 && remaining > 0 {
		newIndex := make(map[rawFlowKey]int32, remaining*2)
		maps.Copy(newIndex, shard.index)
		shard.index = newIndex
	}
	return removed
}
