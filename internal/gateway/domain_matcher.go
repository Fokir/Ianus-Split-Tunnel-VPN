package gateway

import (
	"strings"

	"awg-split-tunnel/internal/core"
)

// DomainMatchResult holds the outcome of a domain matcher lookup.
type DomainMatchResult struct {
	Matched  bool
	TunnelID string
	Action   core.DomainAction
}

// keywordEntry stores a keyword pattern and its associated result.
type keywordEntry struct {
	keyword string
	result  DomainMatchResult
}

// domainTrieNode is a node in the reversed-label suffix trie.
type domainTrieNode struct {
	children map[string]*domainTrieNode
	result   *DomainMatchResult // non-nil for terminal matches
}

// DomainMatcher performs O(k) domain matching using a reversed-label suffix trie,
// exact hashmap for full: patterns, and linear scan for keyword: patterns.
// Immutable after creation — swap atomically via atomic.Pointer[DomainMatcher].
type DomainMatcher struct {
	trie     *domainTrieNode
	fullOnly map[string]DomainMatchResult
	keywords []keywordEntry
}

// GeositeExpanded represents an expanded geosite entry with our pattern syntax.
type GeositeExpanded struct {
	Type  string // "domain", "full", "keyword"
	Value string
	Rule  core.DomainRule // original rule for tunnel_id and action
}

// NewDomainMatcher builds a matcher from domain rules and expanded geosite entries.
func NewDomainMatcher(rules []core.DomainRule, geositeEntries []GeositeExpanded) *DomainMatcher {
	m := &DomainMatcher{
		trie:     &domainTrieNode{},
		fullOnly: make(map[string]DomainMatchResult),
	}

	// Process regular rules.
	for _, r := range rules {
		result := DomainMatchResult{
			Matched:  true,
			TunnelID: r.TunnelID,
			Action:   r.Action,
		}

		prefix, value := splitPattern(r.Pattern)
		if value == "" {
			continue
		}
		value = strings.ToLower(value)

		switch prefix {
		case "full":
			m.fullOnly[value] = result
		case "domain":
			m.insertTrie(value, result)
		case "keyword":
			m.keywords = append(m.keywords, keywordEntry{keyword: value, result: result})
		}
		// geosite: patterns are handled via geositeEntries
	}

	// Process geosite entries.
	for _, ge := range geositeEntries {
		result := DomainMatchResult{
			Matched:  true,
			TunnelID: ge.Rule.TunnelID,
			Action:   ge.Rule.Action,
		}
		value := strings.ToLower(ge.Value)

		switch ge.Type {
		case "full":
			if _, exists := m.fullOnly[value]; !exists {
				m.fullOnly[value] = result
			}
		case "domain":
			m.insertTrie(value, result)
		case "keyword":
			m.keywords = append(m.keywords, keywordEntry{keyword: value, result: result})
		}
	}

	return m
}

// Match looks up a domain name and returns the routing decision.
// Priority: full: (exact) > domain: (suffix trie) > keyword: (linear scan).
func (m *DomainMatcher) Match(domain string) DomainMatchResult {
	if m == nil {
		return DomainMatchResult{}
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return DomainMatchResult{}
	}

	// 1. Exact match (full:).
	if result, ok := m.fullOnly[domain]; ok {
		return result
	}

	// 2. Suffix trie (domain:) — matches domain and all subdomains.
	if result := m.lookupTrie(domain); result != nil {
		return *result
	}

	// 3. Keyword scan.
	for _, kw := range m.keywords {
		if strings.Contains(domain, kw.keyword) {
			return kw.result
		}
	}

	return DomainMatchResult{}
}

// IsEmpty returns true if the matcher has no rules.
func (m *DomainMatcher) IsEmpty() bool {
	if m == nil {
		return true
	}
	return len(m.fullOnly) == 0 && len(m.keywords) == 0 && len(m.trie.children) == 0
}

// insertTrie inserts a domain into the reversed-label suffix trie.
// For "vk.com", labels are reversed to ["com", "vk"] and inserted as trie path.
func (m *DomainMatcher) insertTrie(domain string, result DomainMatchResult) {
	labels := strings.Split(domain, ".")
	node := m.trie
	// Walk labels in reverse order.
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if label == "" {
			continue
		}
		if node.children == nil {
			node.children = make(map[string]*domainTrieNode)
		}
		child, ok := node.children[label]
		if !ok {
			child = &domainTrieNode{}
			node.children[label] = child
		}
		node = child
	}
	if node.result == nil {
		r := result
		node.result = &r
	}
}

// lookupTrie walks the reversed-label trie for the given domain.
// Returns the deepest (most specific) match, or nil if no match.
func (m *DomainMatcher) lookupTrie(domain string) *DomainMatchResult {
	labels := strings.Split(domain, ".")
	node := m.trie
	var lastMatch *DomainMatchResult

	// Walk labels in reverse order (TLD first).
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if label == "" {
			continue
		}
		child, ok := node.children[label]
		if !ok {
			break
		}
		node = child
		if node.result != nil {
			lastMatch = node.result
		}
	}

	return lastMatch
}

// splitPattern splits "prefix:value" into (prefix, value).
// If no prefix, returns ("domain", pattern) as default.
func splitPattern(pattern string) (string, string) {
	if idx := strings.Index(pattern, ":"); idx > 0 {
		prefix := pattern[:idx]
		switch prefix {
		case "domain", "full", "keyword", "geosite", "geoip":
			return prefix, pattern[idx+1:]
		}
	}
	// Default: treat bare pattern as domain: prefix.
	return "domain", pattern
}
