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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
type NATEntry struct {
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	TunnelID        string
	ProxyPort       uint16
}

// UDPNATEntry maps a redirected UDP flow back to its original destination.
type UDPNATEntry struct {
	LastActivity    int64 // atomic; UnixNano
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	TunnelID        string
	UDPProxyPort    uint16
}

// ---------------------------------------------------------------------------
// In-place packet manipulation helpers (zero-copy, incremental checksums)
// ---------------------------------------------------------------------------

const ethHdrLen = 14

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
// parseCtx — pooled parser state for concurrent filter callbacks
// ---------------------------------------------------------------------------

type parseCtx struct {
	eth     layers.Ethernet
	ip4     layers.IPv4
	tcp     layers.TCP
	udp     layers.UDP
	payload gopacket.Payload
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

func newParseCtx() *parseCtx {
	pc := &parseCtx{
		decoded: make([]gopacket.LayerType, 0, 4),
	}
	pc.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&pc.eth, &pc.ip4, &pc.tcp, &pc.udp, &pc.payload,
	)
	pc.parser.IgnoreUnsupported = true
	return pc
}

// ---------------------------------------------------------------------------
// PacketRouter
// ---------------------------------------------------------------------------

type PacketRouter struct {
	api           *A.NdisApi
	filter        *D.QueuedPacketFilter
	staticFilters *D.StaticFilters
	process       *N.ProcessLookup

	registry *TunnelRegistry
	rules    *RuleEngine
	bus      *EventBus

	natMu sync.RWMutex
	nat   map[natKey]NATEntry

	proxyPortsMu sync.RWMutex
	proxyPorts   map[uint16]struct{}

	udpNatMu sync.RWMutex
	udpNat   map[natKey]*UDPNATEntry

	udpProxyPortsMu sync.RWMutex
	udpProxyPorts   map[uint16]struct{}

	parsePool sync.Pool

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
		api:           api,
		process:       N.NewProcessLookup(),
		registry:      registry,
		rules:         rules,
		bus:           bus,
		nat:           make(map[natKey]NATEntry),
		proxyPorts:    make(map[uint16]struct{}),
		udpNat:        make(map[natKey]*UDPNATEntry),
		udpProxyPorts: make(map[uint16]struct{}),
		parsePool: sync.Pool{
			New: func() any { return newParseCtx() },
		},
		adapterIndex: adapterIndex,
	}

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

	pr.filter, err = D.NewQueuedPacketFilter(
		ctx,
		pr.api,
		adapters,
		nil,
		pr.outgoingCallback,
	)
	if err != nil {
		return err
	}

	if err := pr.filter.StartFilter(pr.adapterIndex); err != nil {
		return err
	}

	go pr.udpNATCleanup(ctx)

	log.Printf("[Router] Packet filter started on adapter %d", pr.adapterIndex)
	return nil
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
// Outgoing packet callback — thread-safe via parseCtx pool
// ---------------------------------------------------------------------------

func (pr *PacketRouter) outgoingCallback(handle A.Handle, b *A.IntermediateBuffer) A.FilterAction {
	pc := pr.parsePool.Get().(*parseCtx)
	defer pr.parsePool.Put(pc)

	if err := pc.parser.DecodeLayers(b.Buffer[:b.Length], &pc.decoded); err != nil {
		return A.FilterActionPass
	}

	var hasIPv4, hasTCP, hasUDP bool
	for _, lt := range pc.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			hasIPv4 = true
		case layers.LayerTypeTCP:
			hasTCP = true
		case layers.LayerTypeUDP:
			hasUDP = true
		}
	}
	if !hasIPv4 {
		return A.FilterActionPass
	}

	if hasTCP {
		return pr.handleTCPPacket(pc, b, handle)
	}
	if hasUDP {
		return pr.handleUDPOutgoing(pc, b, handle)
	}
	return A.FilterActionPass
}

// ---------------------------------------------------------------------------
// TCP handling
// ---------------------------------------------------------------------------

func (pr *PacketRouter) handleTCPPacket(pc *parseCtx, b *A.IntermediateBuffer, handle A.Handle) A.FilterAction {
	srcIP, _ := netip.AddrFromSlice(pc.ip4.SrcIP)
	dstIP, _ := netip.AddrFromSlice(pc.ip4.DstIP)
	srcPort := uint16(pc.tcp.SrcPort)
	dstPort := uint16(pc.tcp.DstPort)

	src := netip.AddrPortFrom(srcIP, srcPort)
	dst := netip.AddrPortFrom(dstIP, dstPort)

	if pr.isProxySourcePort(srcPort) {
		return pr.handleProxyResponse(pc, b, dst)
	}

	if pc.tcp.SYN && !pc.tcp.ACK {
		return pr.handleSYN(pc, b, handle, src, dst)
	}

	return pr.handleExistingConnection(pc, b, src, dst)
}

func (pr *PacketRouter) handleSYN(
	pc *parseCtx,
	b *A.IntermediateBuffer,
	handle A.Handle,
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
	pr.natMu.Lock()
	pr.nat[nk] = NATEntry{
		OriginalDstIP:   dst.Addr(),
		OriginalDstPort: dst.Port(),
		TunnelID:        result.TunnelID,
		ProxyPort:       entry.ProxyPort,
	}
	pr.natMu.Unlock()

	// In-place hairpin redirect: swap MACs, swap IPs, change TCP DstPort.
	pkt := b.Buffer[:b.Length]
	ipHdrLen := int(pc.ip4.IHL) * 4
	tcpStart := ethHdrLen + ipHdrLen

	swapMACs(pkt)
	swapIPs(pkt)
	setTCPPort(pkt, tcpStart+2, entry.ProxyPort, tcpStart+16)

	return A.FilterActionRedirect
}

func (pr *PacketRouter) handleProxyResponse(pc *parseCtx, b *A.IntermediateBuffer, dst netip.AddrPort) A.FilterAction {
	nk := makeNATKey(dst.Addr(), dst.Port())

	pr.natMu.RLock()
	entry, ok := pr.nat[nk]
	pr.natMu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	if pc.tcp.FIN || pc.tcp.RST {
		pr.natMu.Lock()
		delete(pr.nat, nk)
		pr.natMu.Unlock()
	}

	pkt := b.Buffer[:b.Length]
	ipHdrLen := int(pc.ip4.IHL) * 4
	tcpStart := ethHdrLen + ipHdrLen
	tcpCkOff := tcpStart + 16

	// Restore original source port.
	setTCPPort(pkt, tcpStart, entry.OriginalDstPort, tcpCkOff)
	// Swap MACs and IPs.
	swapMACs(pkt)
	swapIPs(pkt)
	// Overwrite srcIP with original destination IP (updates IP + TCP checksums).
	overwriteSrcIP(pkt, entry.OriginalDstIP.As4(), tcpCkOff)

	return A.FilterActionRedirect
}

func (pr *PacketRouter) handleExistingConnection(
	pc *parseCtx,
	b *A.IntermediateBuffer,
	src, dst netip.AddrPort,
) A.FilterAction {
	nk := makeNATKey(dst.Addr(), src.Port())

	pr.natMu.RLock()
	entry, ok := pr.nat[nk]
	pr.natMu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	if pc.tcp.FIN || pc.tcp.RST {
		pr.natMu.Lock()
		delete(pr.nat, nk)
		pr.natMu.Unlock()
	}

	// In-place hairpin redirect: swap MACs, swap IPs, change TCP DstPort.
	pkt := b.Buffer[:b.Length]
	ipHdrLen := int(pc.ip4.IHL) * 4
	tcpStart := ethHdrLen + ipHdrLen

	swapMACs(pkt)
	swapIPs(pkt)
	setTCPPort(pkt, tcpStart+2, entry.ProxyPort, tcpStart+16)

	return A.FilterActionRedirect
}

// ---------------------------------------------------------------------------
// Proxy port management
// ---------------------------------------------------------------------------

func (pr *PacketRouter) RegisterProxyPort(port uint16) {
	pr.proxyPortsMu.Lock()
	pr.proxyPorts[port] = struct{}{}
	pr.proxyPortsMu.Unlock()
}

func (pr *PacketRouter) UnregisterProxyPort(port uint16) {
	pr.proxyPortsMu.Lock()
	delete(pr.proxyPorts, port)
	pr.proxyPortsMu.Unlock()
}

func (pr *PacketRouter) isProxySourcePort(port uint16) bool {
	pr.proxyPortsMu.RLock()
	_, ok := pr.proxyPorts[port]
	pr.proxyPortsMu.RUnlock()
	return ok
}

// LookupNAT returns the original destination for a NAT'd TCP connection.
func (pr *PacketRouter) LookupNAT(addrKey string) (originalDst string, tunnelID string, ok bool) {
	ap, err := netip.ParseAddrPort(addrKey)
	if err != nil {
		return "", "", false
	}
	nk := makeNATKey(ap.Addr(), ap.Port())

	pr.natMu.RLock()
	entry, exists := pr.nat[nk]
	pr.natMu.RUnlock()
	if !exists {
		return "", "", false
	}

	dst := netip.AddrPortFrom(entry.OriginalDstIP, entry.OriginalDstPort)
	return dst.String(), entry.TunnelID, true
}

// ---------------------------------------------------------------------------
// UDP interception, NAT hairpin, and proxy port management
// ---------------------------------------------------------------------------

func (pr *PacketRouter) handleUDPOutgoing(pc *parseCtx, b *A.IntermediateBuffer, handle A.Handle) A.FilterAction {
	srcIP, _ := netip.AddrFromSlice(pc.ip4.SrcIP)
	dstIP, _ := netip.AddrFromSlice(pc.ip4.DstIP)
	srcPort := uint16(pc.udp.SrcPort)
	dstPort := uint16(pc.udp.DstPort)

	if dstIP.IsMulticast() || dstIP == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return A.FilterActionPass
	}

	src := netip.AddrPortFrom(srcIP, srcPort)
	dst := netip.AddrPortFrom(dstIP, dstPort)

	if pr.isUDPProxySourcePort(srcPort) {
		return pr.handleUDPProxyResponse(pc, b, dst)
	}

	nk := makeNATKey(dst.Addr(), src.Port())

	// Fast path: existing NAT entry.
	pr.udpNatMu.RLock()
	entry, exists := pr.udpNat[nk]
	pr.udpNatMu.RUnlock()

	if exists {
		atomic.StoreInt64(&entry.LastActivity, time.Now().UnixNano())

		pkt := b.Buffer[:b.Length]
		ipHdrLen := int(pc.ip4.IHL) * 4
		udpStart := ethHdrLen + ipHdrLen

		swapMACs(pkt)
		swapIPs(pkt)
		setUDPPort(pkt, udpStart+2, entry.UDPProxyPort, udpStart+6)

		return A.FilterActionRedirect
	}

	// Slow path: new flow.
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

	pr.udpNatMu.Lock()
	pr.udpNat[nk] = &UDPNATEntry{
		LastActivity:    time.Now().UnixNano(),
		OriginalDstIP:   dst.Addr(),
		OriginalDstPort: dst.Port(),
		TunnelID:        result.TunnelID,
		UDPProxyPort:    udpProxyPort,
	}
	pr.udpNatMu.Unlock()

	pkt := b.Buffer[:b.Length]
	ipHdrLen := int(pc.ip4.IHL) * 4
	udpStart := ethHdrLen + ipHdrLen

	swapMACs(pkt)
	swapIPs(pkt)
	setUDPPort(pkt, udpStart+2, udpProxyPort, udpStart+6)

	return A.FilterActionRedirect
}

func (pr *PacketRouter) handleUDPProxyResponse(pc *parseCtx, b *A.IntermediateBuffer, dst netip.AddrPort) A.FilterAction {
	nk := makeNATKey(dst.Addr(), dst.Port())

	pr.udpNatMu.RLock()
	entry, ok := pr.udpNat[nk]
	pr.udpNatMu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	pkt := b.Buffer[:b.Length]
	ipHdrLen := int(pc.ip4.IHL) * 4
	udpStart := ethHdrLen + ipHdrLen
	udpCkOff := udpStart + 6

	// Restore original source port.
	setUDPPort(pkt, udpStart, entry.OriginalDstPort, udpCkOff)
	// Swap MACs and IPs.
	swapMACs(pkt)
	swapIPs(pkt)
	// Overwrite srcIP with original destination IP.
	overwriteSrcIP(pkt, entry.OriginalDstIP.As4(), udpCkOff)

	return A.FilterActionRedirect
}

// ---------------------------------------------------------------------------
// UDP proxy port management
// ---------------------------------------------------------------------------

func (pr *PacketRouter) RegisterUDPProxyPort(port uint16) {
	pr.udpProxyPortsMu.Lock()
	pr.udpProxyPorts[port] = struct{}{}
	pr.udpProxyPortsMu.Unlock()
}

func (pr *PacketRouter) UnregisterUDPProxyPort(port uint16) {
	pr.udpProxyPortsMu.Lock()
	delete(pr.udpProxyPorts, port)
	pr.udpProxyPortsMu.Unlock()
}

func (pr *PacketRouter) isUDPProxySourcePort(port uint16) bool {
	pr.udpProxyPortsMu.RLock()
	_, ok := pr.udpProxyPorts[port]
	pr.udpProxyPortsMu.RUnlock()
	return ok
}

func (pr *PacketRouter) LookupUDPNAT(addrKey string) (originalDst string, tunnelID string, ok bool) {
	ap, err := netip.ParseAddrPort(addrKey)
	if err != nil {
		return "", "", false
	}
	nk := makeNATKey(ap.Addr(), ap.Port())

	pr.udpNatMu.RLock()
	entry, exists := pr.udpNat[nk]
	pr.udpNatMu.RUnlock()
	if !exists {
		return "", "", false
	}

	dst := netip.AddrPortFrom(entry.OriginalDstIP, entry.OriginalDstPort)
	return dst.String(), entry.TunnelID, true
}

// udpNATCleanup periodically removes stale UDP NAT entries.
func (pr *PacketRouter) udpNATCleanup(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			pr.udpNatMu.Lock()
			for key, entry := range pr.udpNat {
				timeout := 2 * time.Minute
				if entry.OriginalDstPort == 53 {
					timeout = 10 * time.Second
				}
				last := time.Unix(0, atomic.LoadInt64(&entry.LastActivity))
				if now.Sub(last) > timeout {
					delete(pr.udpNat, key)
				}
			}
			pr.udpNatMu.Unlock()
		}
	}
}
