//go:build windows

package gateway

import (
	"net"
	"net/netip"
	"regexp"
	"strings"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/process"
)

// trieNode is a node in a flat binary prefix trie for CIDR matching.
type trieNode struct {
	children [2]int32 // indices into the trie slice; -1 = no child
	terminal bool     // true if this node marks the end of a prefix
}

// PrefixTrie is a flat binary prefix trie for fast CIDR lookups.
// O(32) worst case for IPv4, zero allocations on lookup.
type PrefixTrie struct {
	nodes []trieNode
}

// NewPrefixTrie creates a new empty prefix trie.
func NewPrefixTrie() *PrefixTrie {
	// Start with root node.
	return &PrefixTrie{
		nodes: []trieNode{{children: [2]int32{-1, -1}}},
	}
}

// Insert adds a CIDR prefix to the trie.
func (t *PrefixTrie) Insert(ip [4]byte, prefixLen int) {
	idx := int32(0)
	for i := 0; i < prefixLen; i++ {
		byteIdx := i / 8
		bitIdx := uint(7 - i%8)
		bit := (ip[byteIdx] >> bitIdx) & 1

		child := t.nodes[idx].children[bit]
		if child == -1 {
			child = int32(len(t.nodes))
			t.nodes[idx].children[bit] = child
			t.nodes = append(t.nodes, trieNode{children: [2]int32{-1, -1}})
		}
		idx = child
	}
	t.nodes[idx].terminal = true
}

// Contains returns true if the given IP matches any prefix in the trie.
func (t *PrefixTrie) Contains(ip [4]byte) bool {
	if len(t.nodes) == 0 {
		return false
	}
	idx := int32(0)
	// Check root (matches /0 prefix = everything).
	if t.nodes[0].terminal {
		return true
	}
	for i := 0; i < 32; i++ {
		byteIdx := i / 8
		bitIdx := uint(7 - i%8)
		bit := (ip[byteIdx] >> bitIdx) & 1

		child := t.nodes[idx].children[bit]
		if child == -1 {
			return false
		}
		idx = child
		if t.nodes[idx].terminal {
			return true
		}
	}
	return false
}

// IsEmpty returns true if the trie has no prefixes.
func (t *PrefixTrie) IsEmpty() bool {
	// Only root node and it's not terminal.
	return len(t.nodes) <= 1 && (len(t.nodes) == 0 || !t.nodes[0].terminal)
}

// Len returns the number of nodes in the trie (for diagnostics).
func (t *PrefixTrie) Len() int {
	return len(t.nodes)
}

// appPattern holds a pre-lowercased app pattern for matching.
type appPattern struct {
	original string         // original pattern (for MatchPreprocessed)
	lower    string         // pre-lowercased
	regex    *regexp.Regexp // compiled regex for "regex:" patterns (nil otherwise)
}

// tunnelFilter holds per-tunnel filter data.
type tunnelFilter struct {
	disallowedIPs  *PrefixTrie
	allowedIPs     *PrefixTrie
	hasAllowedIPs  bool
	disallowedApps []appPattern
}

// IPFilter is the compiled composite filter for IP and app-based filtering.
// It is immutable after construction and safe for concurrent reads.
type IPFilter struct {
	// Global filters.
	globalDisallowedIPs  *PrefixTrie
	globalAllowedIPs     *PrefixTrie
	globalHasAllowedIPs  bool
	globalDisallowedApps []appPattern

	// Local bypass trie: only hardcoded localBypassCIDRs (RFC 1918, link-local,
	// multicast, loopback, broadcast). Nil when DisableLocal is set.
	// Used by the router to drop packets to local networks early — if they
	// reached TUN, there's no direct route through any local interface, and
	// the __direct__ proxy (bound to the physical NIC) cannot deliver them.
	localBypassIPs *PrefixTrie

	// Per-tunnel filters.
	tunnels map[string]*tunnelFilter
}

// NewIPFilter builds a compiled IPFilter from global and per-tunnel config.
// localBypassCIDRs are private/local networks that bypass VPN by default.
// Injected into globalDisallowedIPs unless global.disable_local is set.
var localBypassCIDRs = []struct {
	ip      [4]byte
	prefLen int
}{
	{[4]byte{10, 0, 0, 0}, 8},          // 10.0.0.0/8       — RFC 1918
	{[4]byte{172, 16, 0, 0}, 12},       // 172.16.0.0/12    — RFC 1918
	{[4]byte{192, 168, 0, 0}, 16},      // 192.168.0.0/16   — RFC 1918
	{[4]byte{169, 254, 0, 0}, 16},      // 169.254.0.0/16   — link-local
	{[4]byte{224, 0, 0, 0}, 4},         // 224.0.0.0/4      — multicast (mDNS etc.)
	{[4]byte{127, 0, 0, 0}, 8},         // 127.0.0.0/8      — loopback
	{[4]byte{255, 255, 255, 255}, 32},  // 255.255.255.255  — broadcast
}

func NewIPFilter(global core.GlobalFilterConfig, tunnels []core.TunnelConfig) *IPFilter {
	f := &IPFilter{
		tunnels: make(map[string]*tunnelFilter, len(tunnels)),
	}

	// Build global disallowed IPs trie.
	f.globalDisallowedIPs = buildTrie(global.DisallowedIPs)

	// Inject local/private networks unless explicitly disabled.
	if !global.DisableLocal {
		f.localBypassIPs = NewPrefixTrie()
		for _, cidr := range localBypassCIDRs {
			f.globalDisallowedIPs.Insert(cidr.ip, cidr.prefLen)
			f.localBypassIPs.Insert(cidr.ip, cidr.prefLen)
		}
	}

	// Build global allowed IPs trie.
	f.globalAllowedIPs = buildTrie(global.AllowedIPs)
	f.globalHasAllowedIPs = len(global.AllowedIPs) > 0

	// Build global disallowed apps.
	f.globalDisallowedApps = buildAppPatterns(global.DisallowedApps)

	// Build per-tunnel filters.
	for _, tc := range tunnels {
		tf := &tunnelFilter{
			disallowedIPs:  buildTrie(tc.DisallowedIPs),
			allowedIPs:     buildTrie(tc.AllowedIPs),
			hasAllowedIPs:  len(tc.AllowedIPs) > 0,
			disallowedApps: buildAppPatterns(tc.DisallowedApps),
		}
		f.tunnels[tc.ID] = tf
	}

	return f
}

// IsDisallowedApp checks if the process (by pre-lowercased exe path and base name)
// matches any global DisallowedApps pattern.
func (f *IPFilter) IsDisallowedApp(exeLower, baseLower string) bool {
	for _, p := range f.globalDisallowedApps {
		if p.regex != nil {
			if p.regex.MatchString(exeLower) {
				return true
			}
		} else if process.MatchPreprocessed(exeLower, baseLower, p.original, p.lower) {
			return true
		}
	}
	return false
}

// IsTunnelDisallowedApp checks if the process matches any DisallowedApps pattern
// for the specified tunnel.
func (f *IPFilter) IsTunnelDisallowedApp(tunnelID, exeLower, baseLower string) bool {
	tf, ok := f.tunnels[tunnelID]
	if !ok {
		return false
	}
	for _, p := range tf.disallowedApps {
		if p.regex != nil {
			if p.regex.MatchString(exeLower) {
				return true
			}
		} else if process.MatchPreprocessed(exeLower, baseLower, p.original, p.lower) {
			return true
		}
	}
	return false
}

// IsLocalBypassIP returns true if the IP belongs to hardcoded local bypass
// CIDRs (RFC 1918, link-local, multicast, loopback, broadcast).
// Returns false when DisableLocal is set (localBypassIPs is nil).
func (f *IPFilter) IsLocalBypassIP(dstIP [4]byte) bool {
	return f.localBypassIPs != nil && f.localBypassIPs.Contains(dstIP)
}

// ShouldBypassIP checks if the destination IP should bypass the tunnel.
// Evaluation: DisallowedIPs (global, then per-tunnel) → bypass.
// Then AllowedIPs (per-tunnel, then global) → not in list → bypass.
func (f *IPFilter) ShouldBypassIP(tunnelID string, dstIP [4]byte) bool {
	// 1. Global DisallowedIPs.
	if f.globalDisallowedIPs.Contains(dstIP) {
		return true
	}

	// 2. Per-tunnel DisallowedIPs.
	tf := f.tunnels[tunnelID] // may be nil
	if tf != nil && tf.disallowedIPs.Contains(dstIP) {
		return true
	}

	// 3. Per-tunnel AllowedIPs (if configured).
	if tf != nil && tf.hasAllowedIPs {
		return !tf.allowedIPs.Contains(dstIP)
	}

	// 4. Global AllowedIPs (if configured).
	if f.globalHasAllowedIPs {
		return !f.globalAllowedIPs.Contains(dstIP)
	}

	// No AllowedIPs restriction — allow.
	return false
}

// HasFilters returns true if any filters are configured (for logging).
func (f *IPFilter) HasFilters() bool {
	if len(f.globalDisallowedApps) > 0 || f.globalHasAllowedIPs {
		return true
	}
	if !f.globalDisallowedIPs.IsEmpty() {
		return true
	}
	for _, tf := range f.tunnels {
		if len(tf.disallowedApps) > 0 || tf.hasAllowedIPs || !tf.disallowedIPs.IsEmpty() {
			return true
		}
	}
	return false
}

// buildTrie parses CIDR strings and builds a PrefixTrie.
// Bare IPs (without /mask) are treated as /32.
func buildTrie(cidrs []string) *PrefixTrie {
	t := NewPrefixTrie()
	for _, s := range cidrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		// Skip IPv6 for now.
		if strings.Contains(s, ":") {
			continue
		}

		// Auto-expand bare IPs to /32.
		if !strings.Contains(s, "/") {
			s += "/32"
		}

		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			core.Log.Warnf("Gateway", "Invalid CIDR %q: %v", s, err)
			continue
		}

		var ip4 [4]byte
		ip := ipNet.IP.To4()
		if ip == nil {
			continue
		}
		copy(ip4[:], ip)

		ones, _ := ipNet.Mask.Size()
		t.Insert(ip4, ones)
	}
	return t
}

// GetBypassPrefixes returns all global bypass CIDRs as netip.Prefix values.
// Used by WFPManager to create PERMIT rules for bypass traffic on real NIC.
// Without these, WFP BLOCK rules prevent blocked processes from reaching
// local subnet IPs (e.g. 192.168.1.x) which route via real NIC, not TUN.
func GetBypassPrefixes(global core.GlobalFilterConfig) []netip.Prefix {
	var prefixes []netip.Prefix

	// Local bypass CIDRs (unless disabled).
	if !global.DisableLocal {
		for _, cidr := range localBypassCIDRs {
			addr := netip.AddrFrom4(cidr.ip)
			prefixes = append(prefixes, netip.PrefixFrom(addr, cidr.prefLen))
		}
	}

	// User-configured global disallowed IPs.
	for _, s := range global.DisallowedIPs {
		s = strings.TrimSpace(s)
		if s == "" || strings.Contains(s, ":") {
			continue
		}
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		prefixes = append(prefixes, p)
	}

	return prefixes
}

// buildAppPatterns pre-lowercases app patterns and compiles regex patterns.
func buildAppPatterns(patterns []string) []appPattern {
	if len(patterns) == 0 {
		return nil
	}
	result := make([]appPattern, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ap := appPattern{
			original: p,
			lower:    strings.ToLower(p),
		}
		if strings.HasPrefix(p, "regex:") {
			if re, err := regexp.Compile(p[6:]); err == nil {
				ap.regex = re
			} else {
				core.Log.Warnf("Gateway", "Invalid regex in DisallowedApps %q: %v", p, err)
			}
		}
		result = append(result, ap)
	}
	return result
}
