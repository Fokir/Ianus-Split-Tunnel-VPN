//go:build windows

package vless

import (
	"awg-split-tunnel/internal/core"
)

// ParseURIToTunnelConfig parses a vless:// URI and converts it into a
// core.TunnelConfig suitable for use by the subscription manager.
func ParseURIToTunnelConfig(uri string) (core.TunnelConfig, error) {
	cfg, name, err := ParseVLESSURI(uri)
	if err != nil {
		return core.TunnelConfig{}, err
	}

	settings := ConfigToSettings(cfg)

	tc := core.TunnelConfig{
		ID:       sanitizeID(name),
		Protocol: core.ProtocolVLESS,
		Name:     name,
		Settings: settings,
	}

	return tc, nil
}

// ConfigToSettings converts a parsed VLESS Config to a map[string]any
// suitable for use as TunnelConfig.Settings.
func ConfigToSettings(cfg Config) map[string]any {
	settings := map[string]any{
		"address":    cfg.Address,
		"port":       cfg.Port,
		"uuid":       cfg.UUID,
		"encryption": cfg.Encryption,
		"network":    cfg.Network,
		"security":   cfg.Security,
	}

	if cfg.Flow != "" {
		settings["flow"] = cfg.Flow
	}

	// Reality settings.
	if cfg.Security == "reality" {
		reality := map[string]any{
			"public_key":  cfg.Reality.PublicKey,
			"short_id":    cfg.Reality.ShortID,
			"server_name": cfg.Reality.ServerName,
			"fingerprint": cfg.Reality.Fingerprint,
		}
		if cfg.Reality.SpiderX != "" {
			reality["spider_x"] = cfg.Reality.SpiderX
		}
		settings["reality"] = reality
	}

	// TLS settings.
	if cfg.Security == "tls" {
		tls := map[string]any{}
		if cfg.TLS.ServerName != "" {
			tls["server_name"] = cfg.TLS.ServerName
		}
		if cfg.TLS.Fingerprint != "" {
			tls["fingerprint"] = cfg.TLS.Fingerprint
		}
		if cfg.TLS.AllowInsecure {
			tls["allow_insecure"] = true
		}
		if len(tls) > 0 {
			settings["tls"] = tls
		}
	}

	// WebSocket settings.
	if cfg.Network == "ws" {
		ws := map[string]any{}
		if cfg.WebSocket.Path != "" {
			ws["path"] = cfg.WebSocket.Path
		}
		if len(cfg.WebSocket.Headers) > 0 {
			ws["headers"] = cfg.WebSocket.Headers
		}
		if len(ws) > 0 {
			settings["ws"] = ws
		}
	}

	// gRPC settings.
	if cfg.Network == "grpc" && cfg.GRPC.ServiceName != "" {
		settings["grpc"] = map[string]any{
			"service_name": cfg.GRPC.ServiceName,
		}
	}

	// XHTTP settings.
	if cfg.Network == "xhttp" || cfg.Network == "splithttp" {
		xhttp := map[string]any{}
		if cfg.XHTTP.Path != "" {
			xhttp["path"] = cfg.XHTTP.Path
		}
		if cfg.XHTTP.Host != "" {
			xhttp["host"] = cfg.XHTTP.Host
		}
		if cfg.XHTTP.Mode != "" {
			xhttp["mode"] = cfg.XHTTP.Mode
		}
		if len(cfg.XHTTP.Extra) > 0 {
			xhttp["extra"] = cfg.XHTTP.Extra
		}
		if len(xhttp) > 0 {
			settings["xhttp"] = xhttp
		}
	}

	return settings
}

// sanitizeID creates a safe tunnel ID from a display name.
func sanitizeID(name string) string {
	if name == "" {
		return ""
	}
	// Replace common problematic characters.
	result := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			result = append(result, c)
		case c == ' ':
			result = append(result, '_')
		default:
			result = append(result, '_')
		}
	}
	return string(result)
}
