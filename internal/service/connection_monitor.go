//go:build windows

package service

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"time"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/gateway"
)

const (
	connectionSnapshotInterval = 2 * time.Second
	maxSnapshotEntries         = 2000
)

// ConnectionMonitor periodically snapshots active flows from the FlowTable
// and publishes them to subscribers via channels.
type ConnectionMonitor struct {
	flows       *gateway.FlowTable
	domainTable *gateway.DomainTable
	geoIP       *gateway.GeoIPResolver

	mu          sync.Mutex
	subscribers map[chan *vpnapi.ConnectionSnapshot]struct{}
}

// NewConnectionMonitor creates a new connection monitor.
// geoIP may be nil if country lookup is not available.
func NewConnectionMonitor(flows *gateway.FlowTable, domainTable *gateway.DomainTable, geoIP *gateway.GeoIPResolver) *ConnectionMonitor {
	return &ConnectionMonitor{
		flows:       flows,
		domainTable: domainTable,
		geoIP:       geoIP,
		subscribers: make(map[chan *vpnapi.ConnectionSnapshot]struct{}),
	}
}

// Subscribe creates and returns a channel that will receive connection snapshots.
// The caller must call Unsubscribe when done to avoid goroutine leaks.
func (cm *ConnectionMonitor) Subscribe() chan *vpnapi.ConnectionSnapshot {
	ch := make(chan *vpnapi.ConnectionSnapshot, 4)
	cm.mu.Lock()
	cm.subscribers[ch] = struct{}{}
	cm.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel and closes it.
func (cm *ConnectionMonitor) Unsubscribe(ch chan *vpnapi.ConnectionSnapshot) {
	cm.mu.Lock()
	delete(cm.subscribers, ch)
	cm.mu.Unlock()
	close(ch)
}

// Start runs the snapshot loop until the context is cancelled.
// It skips snapshot building when there are no subscribers.
func (cm *ConnectionMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(connectionSnapshotInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cm.mu.Lock()
			n := len(cm.subscribers)
			cm.mu.Unlock()
			if n == 0 {
				continue
			}
			snap := cm.buildSnapshot()
			cm.publish(snap)
		}
	}
}

// buildSnapshot collects all active flows and returns a ConnectionSnapshot.
func (cm *ConnectionMonitor) buildSnapshot() *vpnapi.ConnectionSnapshot {
	var entries []*vpnapi.ConnectionEntry

	// TCP NAT entries.
	for _, e := range cm.flows.SnapshotNAT() {
		dstIP := e.OriginalDstIP
		if e.ResolvedDstIP.IsValid() {
			dstIP = e.ResolvedDstIP
		}
		state := "active"
		if e.FinSeen != 0 {
			state = "fin"
		}
		entry := &vpnapi.ConnectionEntry{
			ProcessName:  e.BaseLower,
			ProcessPath:  e.ExeLower,
			Protocol:     "TCP",
			DstIp:        dstIP.String(),
			DstPort:      uint32(e.OriginalDstPort),
			TunnelId:     e.TunnelID,
			State:        state,
			LastActivity: e.LastActivity,
		}
		cm.enrichEntry(entry, e.OriginalDstIP, dstIP)
		entries = append(entries, entry)
	}

	// UDP NAT entries.
	for _, e := range cm.flows.SnapshotUDP() {
		dstIP := e.OriginalDstIP
		if e.ResolvedDstIP.IsValid() {
			dstIP = e.ResolvedDstIP
		}
		entry := &vpnapi.ConnectionEntry{
			ProcessName:  e.BaseLower,
			ProcessPath:  e.ExeLower,
			Protocol:     "UDP",
			DstIp:        dstIP.String(),
			DstPort:      uint32(e.OriginalDstPort),
			TunnelId:     e.TunnelID,
			State:        "active",
			LastActivity: e.LastActivity,
		}
		cm.enrichEntry(entry, e.OriginalDstIP, dstIP)
		entries = append(entries, entry)
	}

	// Raw flow entries (no process info available).
	for _, e := range cm.flows.SnapshotRaw() {
		dstIP := e.DstIP
		if e.RealDstIP.IsValid() {
			dstIP = e.RealDstIP
		}
		protoStr := "IP"
		switch e.Protocol {
		case 6:
			protoStr = "TCP"
		case 17:
			protoStr = "UDP"
		}
		entry := &vpnapi.ConnectionEntry{
			Protocol:     protoStr,
			DstIp:        dstIP.String(),
			DstPort:      0,
			TunnelId:     e.TunnelID,
			State:        "active",
			LastActivity: e.LastActivity,
		}
		cm.enrichEntry(entry, e.DstIP, dstIP)
		entries = append(entries, entry)
	}

	// Sort by LastActivity descending, limit to maxSnapshotEntries.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LastActivity > entries[j].LastActivity
	})
	if len(entries) > maxSnapshotEntries {
		entries = entries[:maxSnapshotEntries]
	}

	return &vpnapi.ConnectionSnapshot{Connections: entries}
}

// enrichEntry populates Domain and Country fields via reverse DNS and GeoIP lookups.
func (cm *ConnectionMonitor) enrichEntry(entry *vpnapi.ConnectionEntry, originalIP, resolvedIP netip.Addr) {
	if cm.domainTable != nil {
		if domain := cm.domainTable.ReverseLookup(originalIP); domain != "" {
			entry.Domain = domain
		}
	}
	if cm.geoIP != nil && resolvedIP.IsValid() {
		entry.Country = cm.geoIP.Lookup(resolvedIP)
	}
}

// publish sends a snapshot to all subscribers, dropping if a subscriber is slow.
func (cm *ConnectionMonitor) publish(snap *vpnapi.ConnectionSnapshot) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for ch := range cm.subscribers {
		select {
		case ch <- snap:
		default: // drop if subscriber is slow
		}
	}
}
