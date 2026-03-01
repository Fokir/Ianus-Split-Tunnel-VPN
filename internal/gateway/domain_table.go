package gateway

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
)

// DomainEntry maps a resolved IP to its domain routing decision.
type DomainEntry struct {
	TunnelID  string
	Action    core.DomainAction
	Domain    string // for logging
	ExpiresAt int64  // unix seconds
}

// DomainTable is a dynamic IP→tunnel map populated from DNS responses.
// RWMutex-based (not sharded) — expected <5K entries.
type DomainTable struct {
	mu      sync.RWMutex
	entries map[[4]byte]*DomainEntry

	// onDirectIPsExpired is called during cleanup when direct-routed IPs expire.
	// Used to remove corresponding WFP permit rules.
	onDirectIPsExpired func(ips []netip.Addr)
}

// NewDomainTable creates an empty domain table.
func NewDomainTable() *DomainTable {
	return &DomainTable{
		entries: make(map[[4]byte]*DomainEntry),
	}
}

// Lookup returns the domain entry for the given IPv4 address.
// Hot-path read — uses RLock.
func (dt *DomainTable) Lookup(ip [4]byte) (*DomainEntry, bool) {
	dt.mu.RLock()
	entry, ok := dt.entries[ip]
	dt.mu.RUnlock()
	return entry, ok
}

// Insert adds or updates an IP→domain mapping.
func (dt *DomainTable) Insert(ip [4]byte, entry *DomainEntry) {
	dt.mu.Lock()
	dt.entries[ip] = entry
	dt.mu.Unlock()
}

// SetDirectIPsExpiredCallback sets the callback invoked during cleanup
// when direct-routed IP entries expire.
func (dt *DomainTable) SetDirectIPsExpiredCallback(fn func(ips []netip.Addr)) {
	dt.mu.Lock()
	dt.onDirectIPsExpired = fn
	dt.mu.Unlock()
}

// Flush removes all entries (used when domain rules change).
func (dt *DomainTable) Flush() {
	dt.mu.Lock()
	dt.entries = make(map[[4]byte]*DomainEntry)
	dt.mu.Unlock()
}

// Len returns the number of entries.
func (dt *DomainTable) Len() int {
	dt.mu.RLock()
	n := len(dt.entries)
	dt.mu.RUnlock()
	return n
}

// StartCleanup runs a background goroutine that removes expired entries every 60s.
func (dt *DomainTable) StartCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				dt.cleanup()
			}
		}
	}()
}

// cleanup removes entries whose TTL has expired.
func (dt *DomainTable) cleanup() {
	now := time.Now().Unix()
	var expiredDirectIPs []netip.Addr

	dt.mu.Lock()
	for ip, entry := range dt.entries {
		if entry.ExpiresAt > 0 && entry.ExpiresAt < now {
			if entry.Action == core.DomainDirect {
				expiredDirectIPs = append(expiredDirectIPs, netip.AddrFrom4(ip))
			}
			delete(dt.entries, ip)
		}
	}
	cb := dt.onDirectIPsExpired
	dt.mu.Unlock()

	if len(expiredDirectIPs) > 0 && cb != nil {
		cb(expiredDirectIPs)
	}
}
