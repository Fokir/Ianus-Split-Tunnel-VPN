//go:build windows

package service

import (
	"fmt"
	"strings"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/core"
)

// ─── Tunnel conversions ─────────────────────────────────────────────

func tunnelEntryToProto(e *core.TunnelEntry, ctrl TunnelController) *vpnapi.TunnelStatus {
	ts := &vpnapi.TunnelStatus{
		Id:     e.ID,
		Config: tunnelConfigToProto(e.Config),
		State:  vpnapi.TunnelState(e.State),
	}
	if e.Error != nil {
		ts.Error = e.Error.Error()
	}
	if ctrl != nil {
		ts.AdapterIp = ctrl.GetAdapterIP(e.ID)
	}
	return ts
}

func tunnelConfigToProto(c core.TunnelConfig) *vpnapi.TunnelConfig {
	settings := make(map[string]string, len(c.Settings))
	for k, v := range c.Settings {
		settings[k] = fmt.Sprintf("%v", v)
	}
	return &vpnapi.TunnelConfig{
		Id:             c.ID,
		Protocol:       c.Protocol,
		Name:           c.Name,
		Settings:       settings,
		AllowedIps:     c.AllowedIPs,
		DisallowedIps:  c.DisallowedIPs,
		DisallowedApps: c.DisallowedApps,
	}
}

func tunnelConfigFromProto(pc *vpnapi.TunnelConfig) core.TunnelConfig {
	settings := unflattenSettings(pc.Settings)
	return core.TunnelConfig{
		ID:             pc.Id,
		Protocol:       pc.Protocol,
		Name:           pc.Name,
		Settings:       settings,
		AllowedIPs:     pc.AllowedIps,
		DisallowedIPs:  pc.DisallowedIps,
		DisallowedApps: pc.DisallowedApps,
	}
}

// unflattenSettings converts flat dot-notation keys into nested maps.
// For example: {"reality.public_key": "abc", "port": "443"}
// becomes:     {"reality": {"public_key": "abc"}, "port": "443"}
func unflattenSettings(flat map[string]string) map[string]any {
	result := make(map[string]any, len(flat))
	for k, v := range flat {
		parts := strings.SplitN(k, ".", 2)
		if len(parts) == 1 {
			// Simple key — store directly.
			result[k] = v
			continue
		}
		// Nested key — create or get sub-map.
		prefix, rest := parts[0], parts[1]
		sub, ok := result[prefix]
		if !ok {
			sub = make(map[string]any)
			result[prefix] = sub
		}
		if m, ok := sub.(map[string]any); ok {
			// Recursively handle deeper nesting.
			nested := unflattenSettings(map[string]string{rest: v})
			for nk, nv := range nested {
				m[nk] = nv
			}
		}
	}
	return result
}

// ─── Rule conversions ───────────────────────────────────────────────

func ruleToProto(r core.Rule) *vpnapi.Rule {
	var prio string
	if r.Priority != core.PriorityAuto {
		prio = r.Priority.String()
	}
	return &vpnapi.Rule{
		Pattern:  r.Pattern,
		TunnelId: r.TunnelID,
		Fallback: vpnapi.FallbackPolicy(r.Fallback),
		Priority: prio,
	}
}

func ruleFromProto(pr *vpnapi.Rule) core.Rule {
	return core.Rule{
		Pattern:  pr.Pattern,
		TunnelID: pr.TunnelId,
		Fallback: core.FallbackPolicy(pr.Fallback),
		Priority: parsePriorityProto(pr.Priority),
	}
}

func parsePriorityProto(s string) core.RulePriority {
	p, _ := core.ParseRulePriority(s)
	return p
}

// ─── Domain rule conversions ────────────────────────────────────────

func domainRuleToProto(r core.DomainRule) *vpnapi.DomainRule {
	return &vpnapi.DomainRule{
		Pattern:  r.Pattern,
		TunnelId: r.TunnelID,
		Action:   vpnapi.DomainAction(r.Action),
	}
}

func domainRuleFromProto(pr *vpnapi.DomainRule) core.DomainRule {
	return core.DomainRule{
		Pattern:  pr.Pattern,
		TunnelID: pr.TunnelId,
		Action:   core.DomainAction(pr.Action),
	}
}

// ─── Subscription conversions ────────────────────────────────────────

func subscriptionConfigToProto(name string, c core.SubscriptionConfig) *vpnapi.SubscriptionConfig {
	return &vpnapi.SubscriptionConfig{
		Name:            name,
		Url:             c.URL,
		RefreshInterval: c.RefreshInterval,
		UserAgent:       c.UserAgent,
		Prefix:          c.Prefix,
	}
}

func subscriptionConfigFromProto(pc *vpnapi.SubscriptionConfig) (string, core.SubscriptionConfig) {
	return pc.Name, core.SubscriptionConfig{
		URL:             pc.Url,
		RefreshInterval: pc.RefreshInterval,
		UserAgent:       pc.UserAgent,
		Prefix:          pc.Prefix,
	}
}

// ─── Config conversions ─────────────────────────────────────────────

func configToProto(c core.Config) *vpnapi.AppConfig {
	tunnels := make([]*vpnapi.TunnelConfig, 0, len(c.Tunnels))
	for _, t := range c.Tunnels {
		tunnels = append(tunnels, tunnelConfigToProto(t))
	}

	rules := make([]*vpnapi.Rule, 0, len(c.Rules))
	for _, r := range c.Rules {
		rules = append(rules, ruleToProto(r))
	}

	domainRules := make([]*vpnapi.DomainRule, 0, len(c.DomainRules))
	for _, r := range c.DomainRules {
		domainRules = append(domainRules, domainRuleToProto(r))
	}

	subs := make([]*vpnapi.SubscriptionConfig, 0, len(c.Subscriptions))
	for name, sub := range c.Subscriptions {
		subs = append(subs, subscriptionConfigToProto(name, sub))
	}

	return &vpnapi.AppConfig{
		Global: &vpnapi.GlobalFilterConfig{
			AllowedIps:     c.Global.AllowedIPs,
			DisallowedIps:  c.Global.DisallowedIPs,
			DisallowedApps: c.Global.DisallowedApps,
			DisableLocal:   c.Global.DisableLocal,
		},
		Tunnels:       tunnels,
		Rules:         rules,
		DomainRules:   domainRules,
		Subscriptions: subs,
		Dns: &vpnapi.DNSConfig{
			TunnelIds: c.DNS.TunnelIDs,
			Servers:   c.DNS.Servers,
			Cache: &vpnapi.DNSCacheConfig{
				Enabled: c.DNS.Cache.Enabled == nil || *c.DNS.Cache.Enabled,
				MaxSize: int32(c.DNS.Cache.MaxSize),
				MinTtl:  c.DNS.Cache.MinTTL,
				MaxTtl:  c.DNS.Cache.MaxTTL,
				NegTtl:  c.DNS.Cache.NegTTL,
			},
		},
		Logging: &vpnapi.LogConfig{
			Level:              c.Logging.Level,
			Components:         c.Logging.Components,
			FileLoggingEnabled: c.Logging.FileEnabled != nil && *c.Logging.FileEnabled,
		},
		Reconnect: &vpnapi.ReconnectConfig{
			Enabled:    c.GUI.Reconnect.Enabled,
			Interval:   c.GUI.Reconnect.Interval,
			MaxRetries: int32(c.GUI.Reconnect.MaxRetries),
		},
	}
}

func configFromProto(pc *vpnapi.AppConfig) core.Config {
	cfg := core.Config{}

	if pc.Global != nil {
		cfg.Global = core.GlobalFilterConfig{
			AllowedIPs:     pc.Global.AllowedIps,
			DisallowedIPs:  pc.Global.DisallowedIps,
			DisallowedApps: pc.Global.DisallowedApps,
			DisableLocal:   pc.Global.DisableLocal,
		}
	}

	for _, pt := range pc.Tunnels {
		cfg.Tunnels = append(cfg.Tunnels, tunnelConfigFromProto(pt))
	}

	for _, pr := range pc.Rules {
		cfg.Rules = append(cfg.Rules, ruleFromProto(pr))
	}

	for _, pr := range pc.DomainRules {
		cfg.DomainRules = append(cfg.DomainRules, domainRuleFromProto(pr))
	}

	if pc.Dns != nil {
		enabled := pc.Dns.Cache != nil && pc.Dns.Cache.Enabled
		cfg.DNS = core.DNSRouteConfig{
			TunnelIDs: pc.Dns.TunnelIds,
			Servers:   pc.Dns.Servers,
		}
		// Backward compat: if tunnel_ids is empty but deprecated tunnel_id is set, use it.
		if len(cfg.DNS.TunnelIDs) == 0 && pc.Dns.TunnelId != "" {
			cfg.DNS.TunnelIDs = []string{pc.Dns.TunnelId}
		}
		if pc.Dns.Cache != nil {
			cfg.DNS.Cache = core.DNSCacheYAMLConfig{
				Enabled: &enabled,
				MaxSize: int(pc.Dns.Cache.MaxSize),
				MinTTL:  pc.Dns.Cache.MinTtl,
				MaxTTL:  pc.Dns.Cache.MaxTtl,
				NegTTL:  pc.Dns.Cache.NegTtl,
			}
		}
	}

	if pc.Logging != nil {
		fileEnabled := pc.Logging.FileLoggingEnabled
		cfg.Logging = core.LogConfig{
			Level:       pc.Logging.Level,
			Components:  pc.Logging.Components,
			FileEnabled: &fileEnabled,
		}
	}

	if len(pc.Subscriptions) > 0 {
		cfg.Subscriptions = make(map[string]core.SubscriptionConfig, len(pc.Subscriptions))
		for _, ps := range pc.Subscriptions {
			name, sub := subscriptionConfigFromProto(ps)
			cfg.Subscriptions[name] = sub
		}
	}

	if pc.Reconnect != nil {
		cfg.GUI.Reconnect = core.ReconnectConfig{
			Enabled:    pc.Reconnect.Enabled,
			Interval:   pc.Reconnect.Interval,
			MaxRetries: int(pc.Reconnect.MaxRetries),
		}
	}

	return cfg
}

// ─── Log level conversions ──────────────────────────────────────────

func logLevelToProto(l core.LogLevel) vpnapi.LogLevel {
	switch l {
	case core.LevelDebug:
		return vpnapi.LogLevel_LOG_LEVEL_DEBUG
	case core.LevelInfo:
		return vpnapi.LogLevel_LOG_LEVEL_INFO
	case core.LevelWarn:
		return vpnapi.LogLevel_LOG_LEVEL_WARN
	case core.LevelError:
		return vpnapi.LogLevel_LOG_LEVEL_ERROR
	case core.LevelOff:
		return vpnapi.LogLevel_LOG_LEVEL_OFF
	default:
		return vpnapi.LogLevel_LOG_LEVEL_INFO
	}
}

func logLevelFromProto(l vpnapi.LogLevel) core.LogLevel {
	switch l {
	case vpnapi.LogLevel_LOG_LEVEL_DEBUG:
		return core.LevelDebug
	case vpnapi.LogLevel_LOG_LEVEL_INFO:
		return core.LevelInfo
	case vpnapi.LogLevel_LOG_LEVEL_WARN:
		return core.LevelWarn
	case vpnapi.LogLevel_LOG_LEVEL_ERROR:
		return core.LevelError
	case vpnapi.LogLevel_LOG_LEVEL_OFF:
		return core.LevelOff
	default:
		return core.LevelInfo
	}
}

// ─── Errors ─────────────────────────────────────────────────────────

func errNotFound(kind, id string) error {
	return fmt.Errorf("%s %q not found", kind, id)
}
