//go:build windows

package core

import (
	"context"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	A "github.com/wiresock/ndisapi-go"
	D "github.com/wiresock/ndisapi-go/driver"
	N "github.com/wiresock/ndisapi-go/netlib"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// NATEntry maps a redirected connection back to its original destination.
type NATEntry struct {
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	TunnelID        string
}

// PacketRouter intercepts network packets via NDISAPI, performs process-based
// routing decisions, and manages the NAT table for hairpin redirects.
type PacketRouter struct {
	api     *A.NdisApi
	filter  *D.SimplePacketFilter
	process *N.ProcessLookup

	registry *TunnelRegistry
	rules    *RuleEngine
	bus      *EventBus

	// NAT table: key = "srcIP:srcPort" (from the original client connection)
	natMu sync.RWMutex
	nat   map[string]NATEntry

	// Pre-allocated gopacket layers for zero-alloc parsing.
	// These are ONLY used inside the filter callback — single-threaded.
	eth     layers.Ethernet
	ip4     layers.IPv4
	tcp     layers.TCP
	udp     layers.UDP
	payload gopacket.Payload
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType

	adapterIndex int
}

// NewPacketRouter creates a packet router with the given dependencies.
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
		nat:          make(map[string]NATEntry),
		decoded:      make([]gopacket.LayerType, 0, 4),
		adapterIndex: adapterIndex,
	}

	// Initialize zero-alloc parser.
	pr.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&pr.eth, &pr.ip4, &pr.tcp, &pr.udp, &pr.payload,
	)
	pr.parser.IgnoreUnsupported = true

	return pr, nil
}

// Start begins packet filtering on the configured adapter.
func (pr *PacketRouter) Start(ctx context.Context) error {
	adapters, err := pr.api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return err
	}

	pr.process.StartCleanup(ctx, time.Minute)

	pr.filter, err = D.NewSimplePacketFilter(
		ctx,
		pr.api,
		adapters,
		nil, // no incoming callback
		pr.outgoingCallback,
	)
	if err != nil {
		return err
	}

	if err := pr.filter.StartFilter(pr.adapterIndex); err != nil {
		return err
	}

	log.Printf("[Router] Packet filter started on adapter %d", pr.adapterIndex)
	return nil
}

// Stop stops the packet filter and cleans up.
func (pr *PacketRouter) Stop() {
	if pr.filter != nil {
		pr.filter.Close()
	}
	if pr.api != nil {
		pr.api.Close()
	}
	log.Printf("[Router] Packet filter stopped")
}

// outgoingCallback is the NDISAPI filter callback for outgoing packets.
// CRITICAL: No allocations, no blocking, no network calls allowed here.
func (pr *PacketRouter) outgoingCallback(handle A.Handle, b *A.IntermediateBuffer) A.FilterAction {
	// Parse packet using zero-alloc DecodingLayerParser.
	if err := pr.parser.DecodeLayers(b.Buffer[:b.Length], &pr.decoded); err != nil {
		return A.FilterActionPass
	}

	// We only handle IPv4 TCP for now.
	var hasIPv4, hasTCP bool
	for _, lt := range pr.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			hasIPv4 = true
		case layers.LayerTypeTCP:
			hasTCP = true
		}
	}
	if !hasIPv4 || !hasTCP {
		return A.FilterActionPass
	}

	srcIP, _ := netip.AddrFromSlice(pr.ip4.SrcIP)
	dstIP, _ := netip.AddrFromSlice(pr.ip4.DstIP)
	srcPort := uint16(pr.tcp.SrcPort)
	dstPort := uint16(pr.tcp.DstPort)

	src := netip.AddrPortFrom(srcIP, srcPort)
	dst := netip.AddrPortFrom(dstIP, dstPort)

	// --- Handle packets FROM proxy back to client ---
	// Check if this is a response from one of our tunnel proxies.
	if pr.isProxySourcePort(srcPort) {
		return pr.handleProxyResponse(b, dst)
	}

	// --- Handle TCP SYN: new connection, perform process lookup ---
	if pr.tcp.SYN && !pr.tcp.ACK {
		return pr.handleSYN(b, handle, src, dst)
	}

	// --- Handle existing NAT'd connections ---
	return pr.handleExistingConnection(b, src, dst)
}

// handleSYN processes a new TCP connection (SYN packet).
func (pr *PacketRouter) handleSYN(
	b *A.IntermediateBuffer,
	handle A.Handle,
	src, dst netip.AddrPort,
) A.FilterAction {
	// Lookup process by connection.
	info, err := pr.process.FindProcessInfo(context.Background(), false, src, dst, false)
	if err != nil {
		return A.FilterActionPass
	}

	// Match against rules.
	result := pr.rules.Match(info.PathName)
	if !result.Matched {
		return A.FilterActionPass
	}

	// Drop policy — always block.
	if result.Fallback == PolicyDrop {
		return A.FilterActionDrop
	}

	// Get tunnel state.
	entry, ok := pr.registry.Get(result.TunnelID)
	if !ok {
		// Tunnel not registered.
		if result.Fallback == PolicyBlock {
			return A.FilterActionDrop
		}
		return A.FilterActionPass
	}

	if entry.State != TunnelStateUp {
		// Tunnel is down, apply fallback.
		switch result.Fallback {
		case PolicyBlock:
			return A.FilterActionDrop
		case PolicyAllowDirect:
			return A.FilterActionPass
		}
		return A.FilterActionPass
	}

	// Tunnel is UP — redirect through proxy via NAT hairpin.
	natKey := src.String()
	pr.natMu.Lock()
	pr.nat[natKey] = NATEntry{
		OriginalDstIP:   dst.Addr(),
		OriginalDstPort: dst.Port(),
		TunnelID:        result.TunnelID,
	}
	pr.natMu.Unlock()

	// Hairpin redirect: swap MACs and IPs, redirect to proxy port.
	pr.eth.SrcMAC, pr.eth.DstMAC = pr.eth.DstMAC, pr.eth.SrcMAC
	pr.ip4.DstIP, pr.ip4.SrcIP = pr.ip4.SrcIP.To4(), pr.ip4.DstIP.To4()
	pr.tcp.DstPort = layers.TCPPort(entry.ProxyPort)

	pr.serializePacket(b)
	return A.FilterActionRedirect
}

// handleProxyResponse handles packets from a tunnel proxy back to the client.
func (pr *PacketRouter) handleProxyResponse(b *A.IntermediateBuffer, dst netip.AddrPort) A.FilterAction {
	natKey := dst.String()

	pr.natMu.RLock()
	entry, ok := pr.nat[natKey]
	pr.natMu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	// Clean up NAT entry on FIN/RST.
	if pr.tcp.FIN || pr.tcp.RST {
		pr.natMu.Lock()
		delete(pr.nat, natKey)
		pr.natMu.Unlock()
	}

	// Restore original source: the destination the client intended to reach.
	pr.tcp.SrcPort = layers.TCPPort(entry.OriginalDstPort)
	pr.eth.SrcMAC, pr.eth.DstMAC = pr.eth.DstMAC, pr.eth.SrcMAC
	pr.ip4.DstIP, pr.ip4.SrcIP = pr.ip4.SrcIP.To4(), pr.ip4.DstIP.To4()

	// Overwrite source IP to the original destination IP.
	pr.ip4.SrcIP = entry.OriginalDstIP.AsSlice()

	pr.serializePacket(b)
	return A.FilterActionRedirect
}

// handleExistingConnection handles data packets for already-NAT'd connections.
func (pr *PacketRouter) handleExistingConnection(
	b *A.IntermediateBuffer,
	src, dst netip.AddrPort,
) A.FilterAction {
	natKey := src.String()

	pr.natMu.RLock()
	entry, ok := pr.nat[natKey]
	pr.natMu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	// Clean up NAT entry on FIN/RST.
	if pr.tcp.FIN || pr.tcp.RST {
		pr.natMu.Lock()
		delete(pr.nat, natKey)
		pr.natMu.Unlock()
	}

	// Get proxy port for this tunnel.
	proxyPort, portOk := pr.registry.GetProxyPort(entry.TunnelID)
	if !portOk {
		return A.FilterActionPass
	}

	// Hairpin redirect to proxy.
	pr.eth.SrcMAC, pr.eth.DstMAC = pr.eth.DstMAC, pr.eth.SrcMAC
	pr.ip4.DstIP, pr.ip4.SrcIP = pr.ip4.SrcIP.To4(), pr.ip4.DstIP.To4()
	pr.tcp.DstPort = layers.TCPPort(proxyPort)

	pr.serializePacket(b)
	return A.FilterActionRedirect
}

// isProxySourcePort checks if the source port belongs to one of our tunnel proxies.
func (pr *PacketRouter) isProxySourcePort(port uint16) bool {
	for _, entry := range pr.registry.All() {
		if entry.ProxyPort == port {
			return true
		}
	}
	return false
}

// serializePacket recomputes checksums and writes the modified packet back.
func (pr *PacketRouter) serializePacket(b *A.IntermediateBuffer) {
	pr.tcp.SetNetworkLayerForChecksum(&pr.ip4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts,
		&pr.eth, &pr.ip4, &pr.tcp, gopacket.Payload(pr.tcp.Payload),
	); err != nil {
		return
	}

	data := buf.Bytes()
	copy(b.Buffer[:len(data)], data)
	b.Length = uint32(len(data))
}

// LookupNAT returns the original destination for a NAT'd connection.
// Used by the tunnel proxy to know where to dial.
func (pr *PacketRouter) LookupNAT(clientAddr net.Addr) (originalDst string, tunnelID string, ok bool) {
	tcpAddr, isTCP := clientAddr.(*net.TCPAddr)
	if !isTCP {
		return "", "", false
	}

	addr, _ := netip.AddrFromSlice(tcpAddr.IP)
	key := netip.AddrPortFrom(addr, uint16(tcpAddr.Port)).String()

	pr.natMu.RLock()
	entry, exists := pr.nat[key]
	pr.natMu.RUnlock()
	if !exists {
		return "", "", false
	}

	dst := netip.AddrPortFrom(entry.OriginalDstIP, entry.OriginalDstPort)
	return dst.String(), entry.TunnelID, true
}
