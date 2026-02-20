//go:build windows

package gateway

import (
	"context"
	"encoding/binary"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"awg-split-tunnel/internal/core"
)

// dnsCacheKey is the lookup key for cached DNS responses.
type dnsCacheKey struct {
	name  string // lowercased FQDN with trailing dot, e.g. "example.com."
	qtype uint16 // DNS query type (A=1, AAAA=28, etc.)
	class uint16 // DNS query class (IN=1)
}

// dnsCacheEntry holds a cached DNS response with expiration metadata.
type dnsCacheEntry struct {
	response  []byte    // Raw DNS response (transaction ID will be swapped on Get)
	storedAt  time.Time // When the entry was cached
	expiresAt time.Time // storedAt + effectiveTTL
	minTTL    uint32    // Original minimum TTL from RRs (seconds)
}

// DNSCacheConfig holds cache configuration parameters.
type DNSCacheConfig struct {
	MaxSize         int           // Max entries (default 10000)
	MinTTL          time.Duration // Min TTL floor (default 30s)
	MaxTTL          time.Duration // Max TTL cap (default 5m)
	NegTTL          time.Duration // NXDOMAIN cache TTL (default 60s)
	CleanupInterval time.Duration // Purge interval (default 60s)
}

// DNSCache is a thread-safe TTL-based DNS response cache.
type DNSCache struct {
	mu      sync.RWMutex
	entries map[dnsCacheKey]*dnsCacheEntry

	maxSize int
	minTTL  time.Duration
	maxTTL  time.Duration
	negTTL  time.Duration

	hits   atomic.Uint64
	misses atomic.Uint64

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDNSCache creates a new DNS cache and starts the cleanup goroutine.
func NewDNSCache(cfg DNSCacheConfig) *DNSCache {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 10000
	}
	if cfg.MinTTL <= 0 {
		cfg.MinTTL = 30 * time.Second
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = 5 * time.Minute
	}
	if cfg.NegTTL <= 0 {
		cfg.NegTTL = 60 * time.Second
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 60 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &DNSCache{
		entries: make(map[dnsCacheKey]*dnsCacheEntry),
		maxSize: cfg.MaxSize,
		minTTL:  cfg.MinTTL,
		maxTTL:  cfg.MaxTTL,
		negTTL:  cfg.NegTTL,
		cancel:  cancel,
	}

	c.wg.Add(1)
	go c.cleanup(ctx, cfg.CleanupInterval)

	core.Log.Infof("DNS", "Cache enabled (max_size=%d, min_ttl=%s, max_ttl=%s, neg_ttl=%s)",
		cfg.MaxSize, cfg.MinTTL, cfg.MaxTTL, cfg.NegTTL)
	return c
}

// Get looks up a cached response. Returns the response with adjusted TTLs
// and swapped transaction ID on hit, or (nil, false) on miss/expired.
func (c *DNSCache) Get(queryID uint16, name string, qtype, qclass uint16) ([]byte, bool) {
	key := dnsCacheKey{name: name, qtype: qtype, class: qclass}
	now := time.Now()

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		c.misses.Add(1)
		return nil, false
	}

	if now.After(entry.expiresAt) {
		c.misses.Add(1)
		return nil, false
	}

	elapsed := uint32(now.Sub(entry.storedAt).Seconds())
	resp := adjustTTLs(entry.response, elapsed, queryID)

	c.hits.Add(1)
	return resp, true
}

// Put stores a DNS response in the cache. Parses the minimum TTL from all
// RR sections and applies min/max TTL clamping.
func (c *DNSCache) Put(name string, qtype, qclass uint16, response []byte) {
	if len(response) < 12 {
		return
	}
	// Don't cache responses with QDCOUNT != 1 (unusual).
	qdcount := binary.BigEndian.Uint16(response[4:6])
	if qdcount != 1 {
		return
	}

	// Don't cache truncated responses (TC bit set).
	if response[2]&0x02 != 0 {
		return
	}

	now := time.Now()
	var effectiveTTL time.Duration

	rcode := response[3] & 0x0F
	if rcode == 3 { // NXDOMAIN
		effectiveTTL = c.negTTL
	} else if rcode != 0 { // Don't cache other errors (SERVFAIL, REFUSED, etc.)
		return
	} else {
		rawTTL := parseMinTTL(response)
		if rawTTL == 0 {
			// No RRs or zero TTL — use minTTL.
			effectiveTTL = c.minTTL
		} else {
			effectiveTTL = time.Duration(rawTTL) * time.Second
			if effectiveTTL < c.minTTL {
				effectiveTTL = c.minTTL
			}
			if effectiveTTL > c.maxTTL {
				effectiveTTL = c.maxTTL
			}
		}
	}

	key := dnsCacheKey{name: name, qtype: qtype, class: qclass}

	// Store a copy of the response to avoid aliasing.
	stored := make([]byte, len(response))
	copy(stored, response)

	entry := &dnsCacheEntry{
		response:  stored,
		storedAt:  now,
		expiresAt: now.Add(effectiveTTL),
		minTTL:    uint32(effectiveTTL.Seconds()),
	}

	c.mu.Lock()
	// Evict if at capacity.
	if len(c.entries) >= c.maxSize {
		c.evictLocked(now)
	}
	c.entries[key] = entry
	c.mu.Unlock()
}

// evictLocked removes expired entries; if still full, removes the oldest entry.
// Must be called with c.mu held for writing.
func (c *DNSCache) evictLocked(now time.Time) {
	// First pass: remove expired.
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < c.maxSize {
		return
	}

	// Still full: remove the entry expiring soonest (oldest effective).
	var oldestKey dnsCacheKey
	var oldestTime time.Time
	first := true
	for k, e := range c.entries {
		if first || e.expiresAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.expiresAt
			first = false
		}
	}
	if !first {
		delete(c.entries, oldestKey)
	}
}

// Flush clears all cache entries.
func (c *DNSCache) Flush() {
	c.mu.Lock()
	c.entries = make(map[dnsCacheKey]*dnsCacheEntry)
	c.mu.Unlock()
}

// Stop stops the cleanup goroutine.
func (c *DNSCache) Stop() {
	c.cancel()
	c.wg.Wait()
	hits, misses := c.hits.Load(), c.misses.Load()
	core.Log.Infof("DNS", "Cache stopped (hits=%d, misses=%d, entries=%d)", hits, misses, len(c.entries))
}

// Stats returns cache hit/miss counters.
func (c *DNSCache) Stats() (hits, misses uint64) {
	return c.hits.Load(), c.misses.Load()
}

// cleanup periodically removes expired entries.
func (c *DNSCache) cleanup(ctx context.Context, interval time.Duration) {
	defer c.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			purged := 0
			c.mu.Lock()
			for k, e := range c.entries {
				if now.After(e.expiresAt) {
					delete(c.entries, k)
					purged++
				}
			}
			remaining := len(c.entries)
			c.mu.Unlock()
			if purged > 0 {
				core.Log.Debugf("DNS", "Cache cleanup: purged %d expired, %d remaining", purged, remaining)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// DNS message parsing helpers
// ---------------------------------------------------------------------------

// parseDNSQuestion extracts the question name, type, and class from a raw DNS query.
// Name is returned lowercased with trailing dot.
func parseDNSQuestion(query []byte) (name string, qtype, qclass uint16, err error) {
	if len(query) < 12 {
		return "", 0, 0, errDNSTooShort
	}

	pos := 12
	var labels []string
	for pos < len(query) {
		labelLen := int(query[pos])
		if labelLen == 0 {
			pos++ // skip root label
			break
		}
		if labelLen >= 64 {
			// Compression pointer — shouldn't appear in question section of a query.
			return "", 0, 0, errDNSPointerInQuestion
		}
		pos++
		if pos+labelLen > len(query) {
			return "", 0, 0, errDNSTruncatedLabel
		}
		labels = append(labels, strings.ToLower(string(query[pos:pos+labelLen])))
		pos += labelLen
	}

	if pos+4 > len(query) {
		return "", 0, 0, errDNSTooShort
	}

	qtype = binary.BigEndian.Uint16(query[pos:])
	qclass = binary.BigEndian.Uint16(query[pos+2:])

	name = strings.Join(labels, ".") + "."
	return name, qtype, qclass, nil
}

// parseMinTTL scans all RR sections (answer, authority, additional) and returns
// the minimum TTL. Returns 0 if no RRs found.
func parseMinTTL(msg []byte) uint32 {
	if len(msg) < 12 {
		return 0
	}

	qdcount := binary.BigEndian.Uint16(msg[4:6])
	ancount := binary.BigEndian.Uint16(msg[6:8])
	nscount := binary.BigEndian.Uint16(msg[8:10])
	arcount := binary.BigEndian.Uint16(msg[10:12])
	totalRR := int(ancount) + int(nscount) + int(arcount)

	// Skip question section.
	pos := 12
	for i := 0; i < int(qdcount); i++ {
		pos = skipDNSName(msg, pos)
		if pos < 0 || pos+4 > len(msg) {
			return 0
		}
		pos += 4 // QTYPE + QCLASS
	}

	var minTTL uint32
	found := false

	for i := 0; i < totalRR; i++ {
		pos = skipDNSName(msg, pos)
		if pos < 0 || pos+10 > len(msg) {
			break
		}
		rrType := binary.BigEndian.Uint16(msg[pos:])
		ttl := binary.BigEndian.Uint32(msg[pos+4:])
		rdlen := binary.BigEndian.Uint16(msg[pos+8:])
		pos += 10 + int(rdlen)
		if pos > len(msg) {
			break
		}
		// Skip OPT pseudo-record (type 41) — it doesn't have a real TTL.
		if rrType == 41 {
			continue
		}
		if !found || ttl < minTTL {
			minTTL = ttl
			found = true
		}
	}

	if !found {
		return 0
	}
	return minTTL
}

// adjustTTLs returns a copy of the DNS response with all RR TTLs decremented
// by elapsed seconds (floored at 1) and the transaction ID replaced with newID.
func adjustTTLs(response []byte, elapsed uint32, newID uint16) []byte {
	resp := make([]byte, len(response))
	copy(resp, response)

	// Replace transaction ID.
	binary.BigEndian.PutUint16(resp[0:2], newID)

	if len(resp) < 12 {
		return resp
	}

	qdcount := binary.BigEndian.Uint16(resp[4:6])
	ancount := binary.BigEndian.Uint16(resp[6:8])
	nscount := binary.BigEndian.Uint16(resp[8:10])
	arcount := binary.BigEndian.Uint16(resp[10:12])
	totalRR := int(ancount) + int(nscount) + int(arcount)

	// Skip question section.
	pos := 12
	for i := 0; i < int(qdcount); i++ {
		pos = skipDNSName(resp, pos)
		if pos < 0 || pos+4 > len(resp) {
			return resp
		}
		pos += 4
	}

	for i := 0; i < totalRR; i++ {
		pos = skipDNSName(resp, pos)
		if pos < 0 || pos+10 > len(resp) {
			break
		}
		ttl := binary.BigEndian.Uint32(resp[pos+4:])
		if ttl > elapsed {
			ttl -= elapsed
		} else {
			ttl = 1 // floor at 1 to avoid "unknown TTL" interpretation
		}
		binary.BigEndian.PutUint32(resp[pos+4:], ttl)
		rdlen := binary.BigEndian.Uint16(resp[pos+8:])
		pos += 10 + int(rdlen)
		if pos > len(resp) {
			break
		}
	}

	return resp
}

// getDNSTransactionID extracts the 16-bit transaction ID from bytes 0-1.
func getDNSTransactionID(msg []byte) uint16 {
	if len(msg) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(msg[0:2])
}

// isNXDOMAIN checks the RCODE field (bits 0-3 of byte 3). RCODE 3 = NXDOMAIN.
func isNXDOMAIN(response []byte) bool {
	if len(response) < 4 {
		return false
	}
	return response[3]&0x0F == 3
}

// skipDNSName advances past a DNS name (handling compression pointers).
// Returns the new position, or -1 on error.
func skipDNSName(msg []byte, pos int) int {
	if pos >= len(msg) {
		return -1
	}
	// Handle compression pointer or labels.
	jumped := false
	for pos < len(msg) {
		labelLen := int(msg[pos])
		if labelLen == 0 {
			pos++
			break
		}
		if labelLen&0xC0 == 0xC0 {
			// Compression pointer — 2 bytes, name ends here.
			if pos+2 > len(msg) {
				return -1
			}
			pos += 2
			jumped = true
			break
		}
		pos += 1 + labelLen
		if pos > len(msg) {
			return -1
		}
	}
	_ = jumped
	return pos
}

// Sentinel errors for DNS parsing.
var (
	errDNSTooShort         = &dnsParseError{"message too short"}
	errDNSPointerInQuestion = &dnsParseError{"compression pointer in question"}
	errDNSTruncatedLabel   = &dnsParseError{"truncated label"}
)

type dnsParseError struct{ msg string }

func (e *dnsParseError) Error() string { return "dns: " + e.msg }
