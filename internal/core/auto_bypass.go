package core

import (
	"strings"
	"sync"
)

var builtinGamePatterns = []string{
	`steamapps\common`, `steamapps/common`,
	`epic games`,
	`gog galaxy\games`, `gog galaxy/games`,
	`riot games`, `riotclient`,
	`battle.net`,
	`blizzard entertainment`,
	`ubisoft game launcher\games`, `ubisoft game launcher/games`,
	`ea games`,
	`origin games`,
	`xbox games`,
	`rockstar games`,
	`amazon games`,
}

type AutoBypassConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	ExtraPatterns []string `yaml:"extra_patterns,omitempty" json:"extraPatterns,omitempty"`
	ExtraBypass   []string `yaml:"extra_bypass,omitempty" json:"extraBypass,omitempty"`
	NeverBypass   []string `yaml:"never_bypass,omitempty" json:"neverBypass,omitempty"`
}

type AutoBypass struct {
	enabled     bool
	patterns    []string
	extraBypass []string
	neverBypass []string
	cache       sync.Map
	permits     sync.Map
}

func NewAutoBypass(cfg AutoBypassConfig) *AutoBypass {
	ab := &AutoBypass{
		enabled: cfg.Enabled,
	}
	ab.patterns = make([]string, 0, len(builtinGamePatterns)+len(cfg.ExtraPatterns))
	ab.patterns = append(ab.patterns, builtinGamePatterns...)
	for _, p := range cfg.ExtraPatterns {
		ab.patterns = append(ab.patterns, strings.ToLower(p))
	}
	ab.extraBypass = make([]string, len(cfg.ExtraBypass))
	for i, e := range cfg.ExtraBypass {
		ab.extraBypass[i] = strings.ToLower(e)
	}
	ab.neverBypass = make([]string, len(cfg.NeverBypass))
	for i, e := range cfg.NeverBypass {
		ab.neverBypass[i] = strings.ToLower(e)
	}
	return ab
}

func (ab *AutoBypass) ShouldBypass(exePathLower, baseNameLower string) bool {
	if !ab.enabled {
		return false
	}
	if v, ok := ab.cache.Load(exePathLower); ok {
		return v.(bool)
	}
	result := ab.evaluate(exePathLower, baseNameLower)
	ab.cache.Store(exePathLower, result)
	return result
}

func (ab *AutoBypass) evaluate(exePathLower, baseNameLower string) bool {
	for _, n := range ab.neverBypass {
		if baseNameLower == n {
			return false
		}
	}
	for _, e := range ab.extraBypass {
		if baseNameLower == e {
			return true
		}
	}
	for _, p := range ab.patterns {
		if strings.Contains(exePathLower, p) {
			return true
		}
	}
	return false
}

func (ab *AutoBypass) TrackPermit(exePathLower string) {
	ab.permits.Store(exePathLower, struct{}{})
}

func (ab *AutoBypass) PermittedPaths() []string {
	var paths []string
	ab.permits.Range(func(key, _ any) bool {
		paths = append(paths, key.(string))
		return true
	})
	return paths
}

func (ab *AutoBypass) ClearCache() {
	ab.cache = sync.Map{}
	ab.permits = sync.Map{}
}
