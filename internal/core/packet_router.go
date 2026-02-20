//go:build windows

package core

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	A "github.com/wiresock/ndisapi-go"
	D "github.com/wiresock/ndisapi-go/driver"
	N "github.com/wiresock/ndisapi-go/netlib"
)

// ---------------------------------------------------------------------------
// NAT key and entry types
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
// Stored as pointer in the NAT map to allow atomic LastActivity updates.
type NATEntry struct {
	LastActivity    int64 // atomic; Unix seconds (for periodic cleanup)
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
// Sharded NAT tables — 64 shards reduce RWMutex contention under high
// concurrency. Each shard has its own lock, so a SYN (write lock) on one
// shard doesn't block packet lookups on other shards.
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
// In-place packet manipulation helpers (zero-copy, incremental checksums)
// ---------------------------------------------------------------------------

const (
	ethHdrLen  = 14
	minIPv4Hdr = 20
	minTCPHdr  = 20
	minUDPHdr  = 8

	protoTCP byte = 6
	protoUDP byte = 17

	tcpFIN byte = 0x01
	tcpSYN byte = 0x02
	tcpRST byte = 0x04
	tcpACK byte = 0x10
)

// checksumFold folds a 32-bit accumulator to a 16-bit one's complement value.
func checksumFold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(sum)
}

// checksumUpdate16 incrementally updates a one's complement checksum
// when a single 16-bit field changes from oldVal to newVal (RFC 1624).
func checksumUpdate16(oldCk, oldVal, newVal uint16) uint16 {
	// HC' = ~(~HC + ~m + m')
	sum := uint32(^oldCk) + uint32(^oldVal) + uint32(newVal)
	return ^checksumFold(sum)
}

// swapMACs swaps Ethernet src/dst MAC addresses in-place (bytes 0-11).
func swapMACs(pkt []byte) {
	var tmp [6]byte
	copy(tmp[:], pkt[0:6])
	copy(pkt[0:6], pkt[6:12])
	copy(pkt[6:12], tmp[:])
}

// swapIPs swaps IPv4 src/dst addresses in-place.
// No checksum update needed: the one's complement sum is commutative,
// so swapping terms doesn't change the IP header checksum or
// the TCP/UDP pseudo-header contribution.
func swapIPs(pkt []byte) {
	s := ethHdrLen + 12
	d := ethHdrLen + 16
	var tmp [4]byte
	copy(tmp[:], pkt[s:s+4])
	copy(pkt[s:s+4], pkt[d:d+4])
	copy(pkt[d:d+4], tmp[:])
}

// overwriteSrcIP sets a new IPv4 source address and incrementally updates
// both the IP header checksum and the transport checksum at transportCkOff.
// transportCkOff == 0 means skip transport checksum update.
func overwriteSrcIP(pkt []byte, newSrc [4]byte, transportCkOff int) {
	off := ethHdrLen + 12 // srcIP offset

	oldHi := binary.BigEndian.Uint16(pkt[off:])
	oldLo := binary.BigEndian.Uint16(pkt[off+2:])
	newHi := binary.BigEndian.Uint16(newSrc[:2])
	newLo := binary.BigEndian.Uint16(newSrc[2:])

	copy(pkt[off:off+4], newSrc[:])

	// IP header checksum at ethHdrLen+10.
	ipCkOff := ethHdrLen + 10
	ipCk := binary.BigEndian.Uint16(pkt[ipCkOff:])
	ipCk = checksumUpdate16(ipCk, oldHi, newHi)
	ipCk = checksumUpdate16(ipCk, oldLo, newLo)
	binary.BigEndian.PutUint16(pkt[ipCkOff:], ipCk)

	// Transport checksum (TCP or UDP pseudo-header includes srcIP).
	if transportCkOff > 0 {
		tCk := binary.BigEndian.Uint16(pkt[transportCkOff:])
		if tCk != 0 { // UDP checksum 0 means disabled
			tCk = checksumUpdate16(tCk, oldHi, newHi)
			tCk = checksumUpdate16(tCk, oldLo, newLo)
			binary.BigEndian.PutUint16(pkt[transportCkOff:], tCk)
		}
	}
}

// setTCPPort writes a new 16-bit value at portOff and updates the TCP checksum.
// tcpCkOff is the absolute offset of the TCP checksum field.
func setTCPPort(pkt []byte, portOff int, newPort uint16, tcpCkOff int) {
	old := binary.BigEndian.Uint16(pkt[portOff:])
	binary.BigEndian.PutUint16(pkt[portOff:], newPort)

	ck := binary.BigEndian.Uint16(pkt[tcpCkOff:])
	binary.BigEndian.PutUint16(pkt[tcpCkOff:], checksumUpdate16(ck, old, newPort))
}

// setUDPPort writes a new 16-bit value at portOff and updates the UDP checksum.
// Skips update if UDP checksum is 0 (disabled in IPv4).
func setUDPPort(pkt []byte, portOff int, newPort uint16, udpCkOff int) {
	old := binary.BigEndian.Uint16(pkt[portOff:])
	binary.BigEndian.PutUint16(pkt[portOff:], newPort)

	ck := binary.BigEndian.Uint16(pkt[udpCkOff:])
	if ck == 0 {
		return // UDP checksum disabled
	}
	binary.BigEndian.PutUint16(pkt[udpCkOff:], checksumUpdate16(ck, old, newPort))
}

// ---------------------------------------------------------------------------
// pktMeta — stack-allocated packet metadata from direct buffer parsing.
// Replaces gopacket DecodingLayerParser for zero-alloc, zero-dependency
// header extraction on the hot path (~10ns vs ~200-500ns).
// ---------------------------------------------------------------------------

type pktMeta struct {
	srcIP netip.Addr
	dstIP netip.Addr
	srcP  uint16
	dstP  uint16
	flags byte // TCP flags byte; 0 for UDP
	tpOff int  // transport header offset in pkt (ethHdrLen + ipHdrLen)
}

// ---------------------------------------------------------------------------
// PacketRouter
// ---------------------------------------------------------------------------

type PacketRouter struct {
	api           *A.NdisApi
	filter        D.SingleInterfacePacketFilter
	staticFilters *D.StaticFilters
	process       *N.ProcessLookup

	registry *TunnelRegistry
	rules    *RuleEngine
	bus      *EventBus

	// Sharded NAT tables (64 shards each) for reduced lock contention.
	tcpNAT [numNATShards]tcpNATShard
	udpNAT [numNATShards]udpNATShard

	// Proxy ports: atomic copy-on-write for lock-free reads on hot path.
	proxyPortsMu    sync.Mutex // protects writes only (rare: tunnel add/remove)
	proxyPorts      atomic.Pointer[map[uint16]struct{}]
	udpProxyPortsMu sync.Mutex
	udpProxyPorts   atomic.Pointer[map[uint16]struct{}]

	// Cached Unix timestamp (seconds), updated every 250ms.
	// Eliminates time.Now() syscall from the UDP fast path.
	nowSec atomic.Int64

	adapterIndex int
}

func NewPacketRouter(
	registry *TunnelRegistry,
	rules *RuleEngine,
	bus *EventBus,
	adapterIndex int,
) (*PacketRouter, error) {
	api, err := A.NewNdisApi()
	if err != nil {
		return nil, err
	}

	pr := &PacketRouter{
		api:          api,
		process:      N.NewProcessLookup(),
		registry:     registry,
		rules:        rules,
		bus:          bus,
		adapterIndex: adapterIndex,
	}
	// Initialize all NAT shard maps.
	for i := range pr.tcpNAT {
		pr.tcpNAT[i].m = make(map[natKey]*NATEntry)
	}
	for i := range pr.udpNAT {
		pr.udpNAT[i].m = make(map[natKey]*UDPNATEntry)
	}

	// Initialize atomic proxy port sets with empty maps.
	emptyTCP := make(map[uint16]struct{})
	emptyUDP := make(map[uint16]struct{})
	pr.proxyPorts.Store(&emptyTCP)
	pr.udpProxyPorts.Store(&emptyUDP)

	sf, err := D.NewStaticFilters(api, true, true)
	if err != nil {
		log.Printf("[Router] Warning: static filters unavailable: %v", err)
	} else {
		pr.staticFilters = sf
		sf.AddFilterBack(&D.Filter{
			Action:             A.FilterActionPass,
			Direction:          D.PacketDirectionBoth,
			SourceAddress:      net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			DestinationAddress: net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Protocol:           1, // ICMP
		})
	}

	return pr, nil
}

func (pr *PacketRouter) Start(ctx context.Context) error {
	adapters, err := pr.api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return err
	}

	log.Printf("[Router] Found %d adapters:", adapters.AdapterCount)
	for i := 0; i < int(adapters.AdapterCount); i++ {
		name := string(adapters.AdapterNameList[i][:])
		friendly := pr.api.ConvertWindows2000AdapterName(name)
		log.Printf("[Router]   [%d] %s", i, friendly)
	}

	go pr.process.StartCleanup(ctx, time.Minute)

	// Start cached timestamp updater for the UDP fast path.
	pr.startTimestampUpdater(ctx)

	// QueuedPacketFilter uses a 4-goroutine pipeline (1 reader + 4 processors),
	// which provides significantly higher throughput than FastIO's single-threaded
	// shared memory approach. FastIO has lower per-packet latency but serializes
	// all processing in one goroutine, bottlenecking under high PPS loads.
	queued, qErr := D.NewQueuedPacketFilter(
		ctx, pr.api, adapters, nil, pr.outgoingCallback,
	)
	if qErr != nil {
		return qErr
	}
	pr.filter = queued
	if err := pr.filter.StartFilter(pr.adapterIndex); err != nil {
		return err
	}
	log.Printf("[Router] Packet filter started (QueuedPacketFilter pipeline)")

	go pr.tcpNATCleanup(ctx)
	go pr.udpNATCleanup(ctx)

	log.Printf("[Router] Packet filter started on adapter %d", pr.adapterIndex)
	return nil
}

// startTimestampUpdater launches a background goroutine that updates the
// cached Unix timestamp every 250ms, eliminating time.Now() syscalls
// from the per-packet hot path.
func (pr *PacketRouter) startTimestampUpdater(ctx context.Context) {
	pr.nowSec.Store(time.Now().Unix())
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pr.nowSec.Store(time.Now().Unix())
			}
		}
	}()
}

func (pr *PacketRouter) Stop() {
	if pr.filter != nil {
		pr.filter.Close()
	}
	if pr.staticFilters != nil {
		pr.staticFilters.Close()
	}
	if pr.api != nil {
		pr.api.Close()
	}
	log.Printf("[Router] Packet filter stopped")
}

func (pr *PacketRouter) AddEndpointBypass(ip net.IP, port uint16) {
	if pr.staticFilters == nil {
		return
	}

	pr.staticFilters.AddFilterBack(&D.Filter{
		Action:             A.FilterActionPass,
		Direction:          D.PacketDirectionOut,
		SourceAddress:      net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		DestinationAddress: net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		Protocol:           uint8(syscall.IPPROTO_UDP),
		DestinationPort:    [2]uint16{port, port},
	})

	pr.staticFilters.AddFilterBack(&D.Filter{
		Action:             A.FilterActionPass,
		Direction:          D.PacketDirectionIn,
		SourceAddress:      net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		DestinationAddress: net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Protocol:           uint8(syscall.IPPROTO_UDP),
		SourcePort:         [2]uint16{port, port},
	})

	log.Printf("[Router] Added static bypass for VPN endpoint %s:%d", ip, port)
}

// ---------------------------------------------------------------------------
// Outgoing packet callback — direct binary parsing, zero allocations
// ---------------------------------------------------------------------------

func (pr *PacketRouter) outgoingCallback(handle A.Handle, b *A.IntermediateBuffer) A.FilterAction {
	// Minimum: Ethernet header (14) + IPv4 minimum header (20).
	if b.Length < ethHdrLen+minIPv4Hdr {
		return A.FilterActionPass
	}

	pkt := b.Buffer[:b.Length]

	// EtherType must be IPv4 (0x0800).
	if binary.BigEndian.Uint16(pkt[12:14]) != 0x0800 {
		return A.FilterActionPass
	}

	ihl := int(pkt[14]&0x0f) * 4
	if ihl < minIPv4Hdr {
		return A.FilterActionPass
	}

	tpOff := ethHdrLen + ihl

	switch pkt[23] { // IP protocol field
	case protoTCP:
		if int(b.Length) < tpOff+minTCPHdr {
			return A.FilterActionPass
		}
		return pr.handleTCPPacket(pkt, pktMeta{
			srcIP: netip.AddrFrom4([4]byte(pkt[26:30])),
			dstIP: netip.AddrFrom4([4]byte(pkt[30:34])),
			srcP:  binary.BigEndian.Uint16(pkt[tpOff:]),
			dstP:  binary.BigEndian.Uint16(pkt[tpOff+2:]),
			flags: pkt[tpOff+13],
			tpOff: tpOff,
		})

	case protoUDP:
		if int(b.Length) < tpOff+minUDPHdr {
			return A.FilterActionPass
		}
		return pr.handleUDPOutgoing(pkt, pktMeta{
			srcIP: netip.AddrFrom4([4]byte(pkt[26:30])),
			dstIP: netip.AddrFrom4([4]byte(pkt[30:34])),
			srcP:  binary.BigEndian.Uint16(pkt[tpOff:]),
			dstP:  binary.BigEndian.Uint16(pkt[tpOff+2:]),
			tpOff: tpOff,
		})
	}

	return A.FilterActionPass
}

// ---------------------------------------------------------------------------
// TCP handling
// ---------------------------------------------------------------------------

func (pr *PacketRouter) handleTCPPacket(pkt []byte, m pktMeta) A.FilterAction {
	if pr.isProxySourcePort(m.srcP) {
		dst := netip.AddrPortFrom(m.dstIP, m.dstP)
		return pr.handleProxyResponse(pkt, m, dst)
	}

	if m.flags&tcpSYN != 0 && m.flags&tcpACK == 0 {
		src := netip.AddrPortFrom(m.srcIP, m.srcP)
		dst := netip.AddrPortFrom(m.dstIP, m.dstP)
		return pr.handleSYN(pkt, m, src, dst)
	}

	src := netip.AddrPortFrom(m.srcIP, m.srcP)
	dst := netip.AddrPortFrom(m.dstIP, m.dstP)
	return pr.handleExistingConnection(pkt, m, src, dst)
}

func (pr *PacketRouter) handleSYN(
	pkt []byte,
	m pktMeta,
	src, dst netip.AddrPort,
) A.FilterAction {
	info, err := pr.process.FindProcessInfo(context.Background(), false, src, dst, false)
	if err != nil {
		return A.FilterActionPass
	}

	result := pr.rules.Match(info.PathName)
	if !result.Matched {
		return A.FilterActionPass
	}

	if result.Fallback == PolicyDrop {
		return A.FilterActionDrop
	}

	entry, ok := pr.registry.Get(result.TunnelID)
	if !ok {
		if result.Fallback == PolicyBlock {
			return A.FilterActionDrop
		}
		return A.FilterActionPass
	}

	if entry.State != TunnelStateUp {
		switch result.Fallback {
		case PolicyBlock:
			return A.FilterActionDrop
		case PolicyAllowDirect:
			return A.FilterActionPass
		}
		return A.FilterActionPass
	}

	nk := makeNATKey(dst.Addr(), src.Port())
	shard := &pr.tcpNAT[natShardIndex(nk)]
	shard.mu.Lock()
	shard.m[nk] = &NATEntry{
		LastActivity:    pr.nowSec.Load(),
		OriginalDstIP:   dst.Addr(),
		OriginalDstPort: dst.Port(),
		TunnelID:        result.TunnelID,
		ProxyPort:       entry.ProxyPort,
	}
	shard.mu.Unlock()

	// In-place hairpin redirect: swap MACs, swap IPs, change TCP DstPort.
	swapMACs(pkt)
	swapIPs(pkt)
	setTCPPort(pkt, m.tpOff+2, entry.ProxyPort, m.tpOff+16)

	return A.FilterActionRedirect
}

func (pr *PacketRouter) handleProxyResponse(pkt []byte, m pktMeta, dst netip.AddrPort) A.FilterAction {
	nk := makeNATKey(dst.Addr(), dst.Port())
	shard := &pr.tcpNAT[natShardIndex(nk)]

	shard.mu.RLock()
	entry, ok := shard.m[nk]
	shard.mu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	// Update activity timestamp for periodic cleanup.
	atomic.StoreInt64(&entry.LastActivity, pr.nowSec.Load())

	// RST: connection aborted, delete NAT entry immediately.
	// FIN: let the 4-way handshake complete; periodic cleanup handles stale entries.
	if m.flags&tcpRST != 0 {
		shard.mu.Lock()
		delete(shard.m, nk)
		shard.mu.Unlock()
	}

	tcpCkOff := m.tpOff + 16

	// Restore original source port.
	setTCPPort(pkt, m.tpOff, entry.OriginalDstPort, tcpCkOff)
	// Swap MACs and IPs.
	swapMACs(pkt)
	swapIPs(pkt)
	// Overwrite srcIP with original destination IP (updates IP + TCP checksums).
	overwriteSrcIP(pkt, entry.OriginalDstIP.As4(), tcpCkOff)

	return A.FilterActionRedirect
}

func (pr *PacketRouter) handleExistingConnection(
	pkt []byte,
	m pktMeta,
	src, dst netip.AddrPort,
) A.FilterAction {
	nk := makeNATKey(dst.Addr(), src.Port())
	shard := &pr.tcpNAT[natShardIndex(nk)]

	shard.mu.RLock()
	entry, ok := shard.m[nk]
	shard.mu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	// Update activity timestamp for periodic cleanup.
	atomic.StoreInt64(&entry.LastActivity, pr.nowSec.Load())

	// RST: connection aborted, delete NAT entry immediately.
	// FIN: let the 4-way handshake complete; periodic cleanup handles stale entries.
	if m.flags&tcpRST != 0 {
		shard.mu.Lock()
		delete(shard.m, nk)
		shard.mu.Unlock()
	}

	// In-place hairpin redirect: swap MACs, swap IPs, change TCP DstPort.
	swapMACs(pkt)
	swapIPs(pkt)
	setTCPPort(pkt, m.tpOff+2, entry.ProxyPort, m.tpOff+16)

	return A.FilterActionRedirect
}

// ---------------------------------------------------------------------------
// Proxy port management — lock-free reads via atomic copy-on-write
// ---------------------------------------------------------------------------

func (pr *PacketRouter) RegisterProxyPort(port uint16) {
	pr.proxyPortsMu.Lock()
	defer pr.proxyPortsMu.Unlock()

	old := pr.proxyPorts.Load()
	newMap := make(map[uint16]struct{}, len(*old)+1)
	for k, v := range *old {
		newMap[k] = v
	}
	newMap[port] = struct{}{}
	pr.proxyPorts.Store(&newMap)
}

func (pr *PacketRouter) UnregisterProxyPort(port uint16) {
	pr.proxyPortsMu.Lock()
	defer pr.proxyPortsMu.Unlock()

	old := pr.proxyPorts.Load()
	newMap := make(map[uint16]struct{}, len(*old))
	for k, v := range *old {
		if k != port {
			newMap[k] = v
		}
	}
	pr.proxyPorts.Store(&newMap)
}

func (pr *PacketRouter) isProxySourcePort(port uint16) bool {
	m := pr.proxyPorts.Load()
	_, ok := (*m)[port]
	return ok
}

// LookupNAT returns the original destination for a NAT'd TCP connection.
func (pr *PacketRouter) LookupNAT(addrKey string) (originalDst string, tunnelID string, ok bool) {
	ap, err := netip.ParseAddrPort(addrKey)
	if err != nil {
		return "", "", false
	}
	nk := makeNATKey(ap.Addr(), ap.Port())
	shard := &pr.tcpNAT[natShardIndex(nk)]

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
// UDP interception, NAT hairpin, and proxy port management
// ---------------------------------------------------------------------------

func (pr *PacketRouter) handleUDPOutgoing(pkt []byte, m pktMeta) A.FilterAction {
	if m.dstIP.IsMulticast() || m.dstIP == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return A.FilterActionPass
	}

	if pr.isUDPProxySourcePort(m.srcP) {
		dst := netip.AddrPortFrom(m.dstIP, m.dstP)
		return pr.handleUDPProxyResponse(pkt, m, dst)
	}

	nk := makeNATKey(m.dstIP, m.srcP)
	ushard := &pr.udpNAT[natShardIndex(nk)]

	// Fast path: existing NAT entry — atomic timestamp, no time.Now() syscall.
	ushard.mu.RLock()
	entry, exists := ushard.m[nk]
	ushard.mu.RUnlock()

	if exists {
		atomic.StoreInt64(&entry.LastActivity, pr.nowSec.Load())

		swapMACs(pkt)
		swapIPs(pkt)
		setUDPPort(pkt, m.tpOff+2, entry.UDPProxyPort, m.tpOff+6)

		return A.FilterActionRedirect
	}

	// Slow path: new flow.
	src := netip.AddrPortFrom(m.srcIP, m.srcP)
	dst := netip.AddrPortFrom(m.dstIP, m.dstP)

	info, err := pr.process.FindProcessInfo(context.Background(), false, src, dst, true)
	if err != nil {
		return A.FilterActionPass
	}

	result := pr.rules.Match(info.PathName)
	if !result.Matched {
		return A.FilterActionPass
	}

	if result.Fallback == PolicyDrop {
		return A.FilterActionDrop
	}

	tunnelEntry, ok := pr.registry.Get(result.TunnelID)
	if !ok {
		if result.Fallback == PolicyBlock {
			return A.FilterActionDrop
		}
		return A.FilterActionPass
	}

	if tunnelEntry.State != TunnelStateUp {
		switch result.Fallback {
		case PolicyBlock:
			return A.FilterActionDrop
		case PolicyAllowDirect:
			return A.FilterActionPass
		}
		return A.FilterActionPass
	}

	udpProxyPort, ok := pr.registry.GetUDPProxyPort(result.TunnelID)
	if !ok {
		return A.FilterActionPass
	}

	ushard.mu.Lock()
	ushard.m[nk] = &UDPNATEntry{
		LastActivity:    pr.nowSec.Load(),
		OriginalDstIP:   dst.Addr(),
		OriginalDstPort: dst.Port(),
		TunnelID:        result.TunnelID,
		UDPProxyPort:    udpProxyPort,
	}
	ushard.mu.Unlock()

	swapMACs(pkt)
	swapIPs(pkt)
	setUDPPort(pkt, m.tpOff+2, udpProxyPort, m.tpOff+6)

	return A.FilterActionRedirect
}

func (pr *PacketRouter) handleUDPProxyResponse(pkt []byte, m pktMeta, dst netip.AddrPort) A.FilterAction {
	nk := makeNATKey(dst.Addr(), dst.Port())
	ushard := &pr.udpNAT[natShardIndex(nk)]

	ushard.mu.RLock()
	entry, ok := ushard.m[nk]
	ushard.mu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	udpCkOff := m.tpOff + 6

	// Restore original source port.
	setUDPPort(pkt, m.tpOff, entry.OriginalDstPort, udpCkOff)
	// Swap MACs and IPs.
	swapMACs(pkt)
	swapIPs(pkt)
	// Overwrite srcIP with original destination IP.
	overwriteSrcIP(pkt, entry.OriginalDstIP.As4(), udpCkOff)

	return A.FilterActionRedirect
}

// ---------------------------------------------------------------------------
// UDP proxy port management — lock-free reads via atomic copy-on-write
// ---------------------------------------------------------------------------

func (pr *PacketRouter) RegisterUDPProxyPort(port uint16) {
	pr.udpProxyPortsMu.Lock()
	defer pr.udpProxyPortsMu.Unlock()

	old := pr.udpProxyPorts.Load()
	newMap := make(map[uint16]struct{}, len(*old)+1)
	for k, v := range *old {
		newMap[k] = v
	}
	newMap[port] = struct{}{}
	pr.udpProxyPorts.Store(&newMap)
}

func (pr *PacketRouter) UnregisterUDPProxyPort(port uint16) {
	pr.udpProxyPortsMu.Lock()
	defer pr.udpProxyPortsMu.Unlock()

	old := pr.udpProxyPorts.Load()
	newMap := make(map[uint16]struct{}, len(*old))
	for k, v := range *old {
		if k != port {
			newMap[k] = v
		}
	}
	pr.udpProxyPorts.Store(&newMap)
}

func (pr *PacketRouter) isUDPProxySourcePort(port uint16) bool {
	m := pr.udpProxyPorts.Load()
	_, ok := (*m)[port]
	return ok
}

func (pr *PacketRouter) LookupUDPNAT(addrKey string) (originalDst string, tunnelID string, ok bool) {
	ap, err := netip.ParseAddrPort(addrKey)
	if err != nil {
		return "", "", false
	}
	nk := makeNATKey(ap.Addr(), ap.Port())
	ushard := &pr.udpNAT[natShardIndex(nk)]

	ushard.mu.RLock()
	entry, exists := ushard.m[nk]
	ushard.mu.RUnlock()
	if !exists {
		return "", "", false
	}

	dst := netip.AddrPortFrom(entry.OriginalDstIP, entry.OriginalDstPort)
	return dst.String(), entry.TunnelID, true
}

// tcpNATCleanup periodically removes stale TCP NAT entries.
// Entries become stale when there's no packet activity for 5 minutes (e.g. process
// crash, network timeout, or completed 4-way handshake where FIN/ACK have passed).
// Iterates all 64 shards; each shard locked independently.
func (pr *PacketRouter) tcpNATCleanup(ctx context.Context) {
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

			for i := range pr.tcpNAT {
				shard := &pr.tcpNAT[i]

				// Collect stale keys under read lock.
				var stale []natKey
				shard.mu.RLock()
				for key, entry := range shard.m {
					last := atomic.LoadInt64(&entry.LastActivity)
					if now-last > timeout {
						stale = append(stale, key)
					}
				}
				shard.mu.RUnlock()

				// Delete stale entries under write lock (brief).
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
				log.Printf("[Router] TCP NAT cleanup: removed %d stale entries", totalRemoved)
			}
		}
	}
}

// udpNATCleanup periodically removes stale UDP NAT entries.
// Iterates all 64 shards; each shard locked independently.
func (pr *PacketRouter) udpNATCleanup(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()

			for i := range pr.udpNAT {
				shard := &pr.udpNAT[i]

				// Collect stale keys under read lock.
				var stale []natKey
				shard.mu.RLock()
				for key, entry := range shard.m {
					var timeout int64 = 120 // 2 minutes
					if entry.OriginalDstPort == 53 {
						timeout = 10
					}
					last := atomic.LoadInt64(&entry.LastActivity)
					if now-last > timeout {
						stale = append(stale, key)
					}
				}
				shard.mu.RUnlock()

				// Delete stale entries under write lock (brief).
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
}
