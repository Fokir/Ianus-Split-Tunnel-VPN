package core

import (
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"awg-split-tunnel/internal/process"
)

// MatchResult holds the routing decision for a process.
type MatchResult struct {
	Matched  bool
	TunnelID string
	Fallback FallbackPolicy
	Priority RulePriority
}

// RuleEngine evaluates process paths against configured rules.
type RuleEngine struct {
	mu            sync.RWMutex
	rules         []Rule
	rulesLower    []string         // pre-lowercased patterns, parallel to rules
	regexCache    []*regexp.Regexp // compiled regex patterns, parallel to rules (nil for non-regex)
	activeTunnels map[string]bool  // set of connected tunnel IDs
	bus           *EventBus
	matcher       *process.Matcher
}

// compileRegexPatterns builds a parallel slice of compiled regexps for rules
// that use the "regex:" prefix. Non-regex rules get nil entries.
func compileRegexPatterns(rules []Rule) []*regexp.Regexp {
	result := make([]*regexp.Regexp, len(rules))
	for i, r := range rules {
		if strings.HasPrefix(r.Pattern, "regex:") {
			if re, err := regexp.Compile(r.Pattern[6:]); err == nil {
				result[i] = re
			} else {
				Log.Warnf("Rule", "Invalid regex %q: %v", r.Pattern, err)
			}
		}
	}
	return result
}

// NewRuleEngine creates a rule engine with the given initial rules.
func NewRuleEngine(rules []Rule, bus *EventBus, matcher *process.Matcher) *RuleEngine {
	lower := make([]string, len(rules))
	for i, r := range rules {
		lower[i] = strings.ToLower(r.Pattern)
	}
	return &RuleEngine{
		rules:         rules,
		rulesLower:    lower,
		regexCache:    compileRegexPatterns(rules),
		activeTunnels: make(map[string]bool),
		bus:           bus,
		matcher:       matcher,
	}
}

// Match finds the first rule that matches the given executable path.
// Returns the routing decision. Called on hot path — must be fast.
// Pre-lowercases exePath once (O(1) allocs) instead of per-pattern.
func (re *RuleEngine) Match(exePath string) MatchResult {
	re.mu.RLock()
	defer re.mu.RUnlock()

	exeLower := strings.ToLower(exePath)
	baseLower := filepath.Base(exeLower)

	for i, rule := range re.rules {
		var matched bool
		if re.regexCache[i] != nil {
			matched = re.regexCache[i].MatchString(exeLower)
		} else {
			matched = process.MatchPreprocessed(exeLower, baseLower, rule.Pattern, re.rulesLower[i])
		}
		if matched {
			if rule.TunnelID != "" && rule.TunnelID != "__direct__" && !re.activeTunnels[rule.TunnelID] {
				continue // skip rule — its tunnel is not connected
			}
			return MatchResult{
				Matched:  true,
				TunnelID: rule.TunnelID,
				Fallback: rule.Fallback,
				Priority: rule.Priority,
			}
		}
	}

	return MatchResult{Matched: false}
}

// MatchPreLowered finds the first rule matching the given pre-lowercased exe path.
// Avoids redundant strings.ToLower when the caller has already lowercased the path
// (e.g. after checking DisallowedApps in resolveFlow).
func (re *RuleEngine) MatchPreLowered(exeLower, baseLower string) MatchResult {
	re.mu.RLock()
	defer re.mu.RUnlock()

	for i, rule := range re.rules {
		var matched bool
		if re.regexCache[i] != nil {
			matched = re.regexCache[i].MatchString(exeLower)
		} else {
			matched = process.MatchPreprocessed(exeLower, baseLower, rule.Pattern, re.rulesLower[i])
		}
		if matched {
			if rule.TunnelID != "" && rule.TunnelID != "__direct__" && !re.activeTunnels[rule.TunnelID] {
				continue
			}
			return MatchResult{
				Matched:  true,
				TunnelID: rule.TunnelID,
				Fallback: rule.Fallback,
				Priority: rule.Priority,
			}
		}
	}

	return MatchResult{Matched: false}
}

// MatchPreLoweredFrom finds the first matching rule starting from startIdx.
// Returns the match result and the index where the match was found.
// Used by the failover fallback policy to continue searching from the next rule.
// Caller must hold no lock — the method acquires RLock internally.
func (re *RuleEngine) MatchPreLoweredFrom(exeLower, baseLower string, startIdx int) (MatchResult, int) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	for i := startIdx; i < len(re.rules); i++ {
		var matched bool
		if re.regexCache[i] != nil {
			matched = re.regexCache[i].MatchString(exeLower)
		} else {
			matched = process.MatchPreprocessed(exeLower, baseLower, re.rules[i].Pattern, re.rulesLower[i])
		}
		if matched {
			if re.rules[i].TunnelID != "" && re.rules[i].TunnelID != "__direct__" && !re.activeTunnels[re.rules[i].TunnelID] {
				continue
			}
			return MatchResult{
				Matched:  true,
				TunnelID: re.rules[i].TunnelID,
				Fallback: re.rules[i].Fallback,
				Priority: re.rules[i].Priority,
			}, i
		}
	}

	return MatchResult{Matched: false}, -1
}

// MatchByPID resolves PID to exe path and then matches.
func (re *RuleEngine) MatchByPID(pid uint32) MatchResult {
	exePath, ok := re.matcher.GetExePath(pid)
	if !ok {
		return MatchResult{Matched: false}
	}
	return re.Match(exePath)
}

// SetRules replaces all routing rules.
func (re *RuleEngine) SetRules(rules []Rule) {
	lower := make([]string, len(rules))
	for i, r := range rules {
		lower[i] = strings.ToLower(r.Pattern)
	}
	rxCache := compileRegexPatterns(rules)

	re.mu.Lock()
	re.rules = make([]Rule, len(rules))
	copy(re.rules, rules)
	re.rulesLower = lower
	re.regexCache = rxCache
	re.mu.Unlock()

	Log.Infof("Rule", "Updated %d rules", len(rules))
}

// AddRule appends a rule and notifies subscribers.
func (re *RuleEngine) AddRule(rule Rule) {
	var compiled *regexp.Regexp
	if strings.HasPrefix(rule.Pattern, "regex:") {
		if rx, err := regexp.Compile(rule.Pattern[6:]); err == nil {
			compiled = rx
		} else {
			Log.Warnf("Rule", "Invalid regex %q: %v", rule.Pattern, err)
		}
	}
	re.mu.Lock()
	re.rules = append(re.rules, rule)
	re.rulesLower = append(re.rulesLower, strings.ToLower(rule.Pattern))
	re.regexCache = append(re.regexCache, compiled)
	re.mu.Unlock()

	Log.Infof("Rule", "Added: %s → %s (fallback=%s)", rule.Pattern, rule.TunnelID, rule.Fallback)
	if re.bus != nil {
		re.bus.Publish(Event{Type: EventRuleAdded, Payload: RulePayload{Rule: rule}})
	}
}

// RemoveRule removes the first rule matching the given pattern.
func (re *RuleEngine) RemoveRule(pattern string) bool {
	re.mu.Lock()
	defer re.mu.Unlock()

	for i, rule := range re.rules {
		if rule.Pattern == pattern {
			re.rules = append(re.rules[:i], re.rules[i+1:]...)
			re.rulesLower = append(re.rulesLower[:i], re.rulesLower[i+1:]...)
			re.regexCache = append(re.regexCache[:i], re.regexCache[i+1:]...)
			Log.Infof("Rule", "Removed: %s", pattern)
			if re.bus != nil {
				re.bus.Publish(Event{Type: EventRuleRemoved, Payload: RulePayload{Rule: rule}})
			}
			return true
		}
	}
	return false
}

// GetRules returns a copy of current rules.
func (re *RuleEngine) GetRules() []Rule {
	re.mu.RLock()
	defer re.mu.RUnlock()
	result := make([]Rule, len(re.rules))
	copy(result, re.rules)
	return result
}

// SetTunnelActive marks a tunnel as connected or disconnected.
// Rules referencing inactive tunnels are skipped during matching.
func (re *RuleEngine) SetTunnelActive(tunnelID string, active bool) {
	re.mu.Lock()
	defer re.mu.Unlock()
	if active {
		re.activeTunnels[tunnelID] = true
	} else {
		delete(re.activeTunnels, tunnelID)
	}
	Log.Infof("Rule", "Tunnel %q active=%v (active tunnels: %d)", tunnelID, active, len(re.activeTunnels))
}

// IsTunnelActive returns true if the tunnel is marked as connected.
func (re *RuleEngine) IsTunnelActive(tunnelID string) bool {
	re.mu.RLock()
	defer re.mu.RUnlock()
	return re.activeTunnels[tunnelID]
}
