//go:build windows

package service

import (
	"fmt"

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
	settings := make(map[string]any, len(pc.Settings))
	for k, v := range pc.Settings {
		settings[k] = v
	}
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

// ─── Rule conversions ───────────────────────────────────────────────

func ruleToProto(r core.Rule) *vpnapi.Rule {
	return &vpnapi.Rule{
		Pattern:  r.Pattern,
		TunnelId: r.TunnelID,
		Fallback: vpnapi.FallbackPolicy(r.Fallback),
	}
}

func ruleFromProto(pr *vpnapi.Rule) core.Rule {
	return core.Rule{
		Pattern:  pr.Pattern,
		TunnelID: pr.TunnelId,
		Fallback: core.FallbackPolicy(pr.Fallback),
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

	return &vpnapi.AppConfig{
		Global: &vpnapi.GlobalFilterConfig{
			AllowedIps:     c.Global.AllowedIPs,
			DisallowedIps:  c.Global.DisallowedIPs,
			DisallowedApps: c.Global.DisallowedApps,
			DisableLocal:   c.Global.DisableLocal,
		},
		Tunnels: tunnels,
		Rules:   rules,
		Dns: &vpnapi.DNSConfig{
			TunnelId: c.DNS.FallbackTunnelID,
			Servers:  c.DNS.Servers,
			Cache: &vpnapi.DNSCacheConfig{
				Enabled: c.DNS.Cache.Enabled == nil || *c.DNS.Cache.Enabled,
				MaxSize: int32(c.DNS.Cache.MaxSize),
				MinTtl:  c.DNS.Cache.MinTTL,
				MaxTtl:  c.DNS.Cache.MaxTTL,
				NegTtl:  c.DNS.Cache.NegTTL,
			},
		},
		Logging: &vpnapi.LogConfig{
			Level:      c.Logging.Level,
			Components: c.Logging.Components,
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

	if pc.Dns != nil {
		enabled := pc.Dns.Cache != nil && pc.Dns.Cache.Enabled
		cfg.DNS = core.DNSRouteConfig{
			FallbackTunnelID: pc.Dns.TunnelId,
			Servers:          pc.Dns.Servers,
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
		cfg.Logging = core.LogConfig{
			Level:      pc.Logging.Level,
			Components: pc.Logging.Components,
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
