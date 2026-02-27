package gateway

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"awg-split-tunnel/internal/core"
)

// FakeIPPool allocates synthetic IPs from a CIDR range for domain-based routing.
// DNS responses for matched domains are rewritten to use FakeIPs, ensuring
// routing decisions remain correct even when browsers cache DNS internally.
//
// One FakeIP per domain. All A records for a domain map to the same FakeIP.
// LRU eviction with active flow protection.
type FakeIPPool struct {
	mu sync.RWMutex

	byFakeIP  map[[4]byte]*FakeIPEntry // forward: fakeIP → entry
	byDomain  map[string][4]byte       // domain → fakeIP (dedup)
	byRealIP  map[[4]byte][4]byte      // reverse: realIP → fakeIP (fallback)
	lruHead   *FakeIPEntry             // MRU end
	lruTail   *FakeIPEntry             // LRU end (eviction candidate)

	prefix   netip.Prefix // CIDR for IsFakeIP
	baseIP   [4]byte      // first IP of pool
	poolSize uint32       // total IPs in pool
	nextIdx  uint32       // ring-buffer allocator index
}

// FakeIPEntry holds the mapping between a FakeIP and its domain + real IPs.
type FakeIPEntry struct {
	RealIPs     [][4]byte         // all real IPs for the domain
	TunnelID    string
	Action      core.DomainAction
	Domain      string
	ActiveFlows atomic.Int32      // >0 prevents eviction

	fakeIP  [4]byte      // back-reference
	lruPrev *FakeIPEntry // towards MRU
	lruNext *FakeIPEntry // towards LRU
}

// NewFakeIPPool creates a pool from a CIDR string (e.g. "198.18.0.0/15").
func NewFakeIPPool(cidr string) (*FakeIPPool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("fakeip: invalid CIDR %q: %w", cidr, err)
	}
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("fakeip: only IPv4 CIDR supported, got %s", cidr)
	}

	base4 := prefix.Addr().As4()
	bits := prefix.Bits()
	poolSize := uint32(1) << (32 - bits)

	// Reserve first IP (network) and last IP (broadcast).
	if poolSize < 4 {
		return nil, fmt.Errorf("fakeip: CIDR %s too small (need at least /30)", cidr)
	}

	// Start allocation from base+1, pool size = total-2 (skip network and broadcast).
	startIP := ipAdd(base4, 1)

	return &FakeIPPool{
		byFakeIP: make(map[[4]byte]*FakeIPEntry),
		byDomain: make(map[string][4]byte),
		byRealIP: make(map[[4]byte][4]byte),
		prefix:   prefix,
		baseIP:   startIP,
		poolSize: poolSize - 2,
	}, nil
}

// IsFakeIP returns true if the IP is within the FakeIP CIDR range.
// Lock-free, pure arithmetic — safe for hot path.
func (p *FakeIPPool) IsFakeIP(ip [4]byte) bool {
	return p.prefix.Contains(netip.AddrFrom4(ip))
}

// Lookup returns the FakeIP entry for the given FakeIP address.
func (p *FakeIPPool) Lookup(fakeIP [4]byte) (*FakeIPEntry, bool) {
	p.mu.RLock()
	entry, ok := p.byFakeIP[fakeIP]
	p.mu.RUnlock()
	if ok {
		p.mu.Lock()
		p.lruPromote(entry)
		p.mu.Unlock()
	}
	return entry, ok
}

// LookupByDomain returns the FakeIP and entry for a domain, if allocated.
func (p *FakeIPPool) LookupByDomain(domain string) ([4]byte, *FakeIPEntry, bool) {
	p.mu.RLock()
	fakeIP, ok := p.byDomain[domain]
	if !ok {
		p.mu.RUnlock()
		return [4]byte{}, nil, false
	}
	entry := p.byFakeIP[fakeIP]
	p.mu.RUnlock()
	return fakeIP, entry, true
}

// LookupByRealIP returns the FakeIP for a real IP, if any domain mapped to it.
func (p *FakeIPPool) LookupByRealIP(realIP [4]byte) ([4]byte, bool) {
	p.mu.RLock()
	fakeIP, ok := p.byRealIP[realIP]
	p.mu.RUnlock()
	return fakeIP, ok
}

// AllocateForDomain allocates or returns an existing FakeIP for the domain.
// realIPs are the actual A-record IPs from the DNS response.
func (p *FakeIPPool) AllocateForDomain(domain string, realIPs [][4]byte, tunnelID string, action core.DomainAction) ([4]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if domain already has an allocation.
	if fakeIP, ok := p.byDomain[domain]; ok {
		entry := p.byFakeIP[fakeIP]
		// Update real IPs, tunnel, action (may have changed).
		p.removeRealIPMappings(entry)
		entry.RealIPs = realIPs
		entry.TunnelID = tunnelID
		entry.Action = action
		p.addRealIPMappings(fakeIP, realIPs)
		p.lruPromote(entry)
		return fakeIP, nil
	}

	// Allocate new FakeIP.
	fakeIP, err := p.allocateIP()
	if err != nil {
		return [4]byte{}, err
	}

	entry := &FakeIPEntry{
		RealIPs:  realIPs,
		TunnelID: tunnelID,
		Action:   action,
		Domain:   domain,
		fakeIP:   fakeIP,
	}

	p.byFakeIP[fakeIP] = entry
	p.byDomain[domain] = fakeIP
	p.addRealIPMappings(fakeIP, realIPs)
	p.lruPush(entry)

	return fakeIP, nil
}

// IncrementFlows marks that a new flow is using this FakeIP.
func (p *FakeIPPool) IncrementFlows(fakeIP [4]byte) {
	p.mu.RLock()
	entry, ok := p.byFakeIP[fakeIP]
	p.mu.RUnlock()
	if ok {
		entry.ActiveFlows.Add(1)
	}
}

// DecrementFlows marks that a flow using this FakeIP has ended.
func (p *FakeIPPool) DecrementFlows(fakeIP [4]byte) {
	p.mu.RLock()
	entry, ok := p.byFakeIP[fakeIP]
	p.mu.RUnlock()
	if ok {
		entry.ActiveFlows.Add(-1)
	}
}

// Flush clears all mappings. Called on domain rule reload.
// Active flows continue with stale mappings until they expire.
func (p *FakeIPPool) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.byFakeIP = make(map[[4]byte]*FakeIPEntry)
	p.byDomain = make(map[string][4]byte)
	p.byRealIP = make(map[[4]byte][4]byte)
	p.lruHead = nil
	p.lruTail = nil
	p.nextIdx = 0

	core.Log.Infof("DNS", "FakeIP pool flushed")
}

// allocateIP returns the next available FakeIP, evicting LRU if needed.
// Must be called with mu held.
func (p *FakeIPPool) allocateIP() ([4]byte, error) {
	// If pool is not full, use ring-buffer allocation.
	if uint32(len(p.byFakeIP)) < p.poolSize {
		ip := ipAdd(p.baseIP, p.nextIdx)
		p.nextIdx = (p.nextIdx + 1) % p.poolSize
		// Skip if already allocated (ring wrapped).
		if _, exists := p.byFakeIP[ip]; !exists {
			return ip, nil
		}
	}

	// Pool is full — evict LRU entry without active flows.
	return p.evictLRU()
}

// evictLRU removes the least recently used entry without active flows.
// Must be called with mu held.
func (p *FakeIPPool) evictLRU() ([4]byte, error) {
	for entry := p.lruTail; entry != nil; entry = entry.lruPrev {
		if entry.ActiveFlows.Load() > 0 {
			continue
		}

		fakeIP := entry.fakeIP
		p.removeEntry(entry)

		core.Log.Debugf("DNS", "FakeIP evicted: %s (%d.%d.%d.%d)",
			entry.Domain, fakeIP[0], fakeIP[1], fakeIP[2], fakeIP[3])

		return fakeIP, nil
	}

	return [4]byte{}, fmt.Errorf("fakeip: pool exhausted, all %d entries have active flows", len(p.byFakeIP))
}

// removeEntry removes an entry from all maps and LRU list.
// Must be called with mu held.
func (p *FakeIPPool) removeEntry(entry *FakeIPEntry) {
	p.lruRemove(entry)
	p.removeRealIPMappings(entry)
	delete(p.byDomain, entry.Domain)
	delete(p.byFakeIP, entry.fakeIP)
}

// addRealIPMappings adds reverse mappings for all real IPs of an entry.
func (p *FakeIPPool) addRealIPMappings(fakeIP [4]byte, realIPs [][4]byte) {
	for _, rip := range realIPs {
		p.byRealIP[rip] = fakeIP
	}
}

// removeRealIPMappings removes reverse mappings for all real IPs of an entry.
func (p *FakeIPPool) removeRealIPMappings(entry *FakeIPEntry) {
	for _, rip := range entry.RealIPs {
		if mapped, ok := p.byRealIP[rip]; ok && mapped == entry.fakeIP {
			delete(p.byRealIP, rip)
		}
	}
}

// LRU doubly-linked list operations. All require mu held.

func (p *FakeIPPool) lruPush(entry *FakeIPEntry) {
	entry.lruPrev = nil
	entry.lruNext = p.lruHead
	if p.lruHead != nil {
		p.lruHead.lruPrev = entry
	}
	p.lruHead = entry
	if p.lruTail == nil {
		p.lruTail = entry
	}
}

func (p *FakeIPPool) lruRemove(entry *FakeIPEntry) {
	if entry.lruPrev != nil {
		entry.lruPrev.lruNext = entry.lruNext
	} else {
		p.lruHead = entry.lruNext
	}
	if entry.lruNext != nil {
		entry.lruNext.lruPrev = entry.lruPrev
	} else {
		p.lruTail = entry.lruPrev
	}
	entry.lruPrev = nil
	entry.lruNext = nil
}

func (p *FakeIPPool) lruPromote(entry *FakeIPEntry) {
	if p.lruHead == entry {
		return // already MRU
	}
	p.lruRemove(entry)
	p.lruPush(entry)
}

// ipAdd adds an offset to an IPv4 address in network byte order.
func ipAdd(base [4]byte, offset uint32) [4]byte {
	v := binary.BigEndian.Uint32(base[:]) + offset
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], v)
	return result
}
