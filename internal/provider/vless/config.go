//go:build windows

package vless

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Config holds VLESS-specific tunnel configuration.
type Config struct {
	// Address is the VLESS server hostname or IP.
	Address string `yaml:"address"`
	// Port is the VLESS server port.
	Port int `yaml:"port"`
	// UUID is the VLESS user UUID.
	UUID string `yaml:"uuid"`
	// Flow is the XTLS flow type (e.g. "xtls-rprx-vision"). Optional.
	Flow string `yaml:"flow"`
	// Encryption is always "none" for VLESS.
	Encryption string `yaml:"encryption"`
	// Network is the transport protocol: "tcp", "ws", "grpc", "h2".
	Network string `yaml:"network"`
	// Security is the TLS layer: "reality", "tls", "none".
	Security string `yaml:"security"`

	// Reality holds Reality-specific settings.
	Reality RealityConfig `yaml:"reality"`

	// TLS holds TLS-specific settings (when Security == "tls").
	TLS TLSConfig `yaml:"tls"`

	// WebSocket holds WS-specific settings (when Network == "ws").
	WebSocket WSConfig `yaml:"ws"`

	// GRPC holds gRPC-specific settings (when Network == "grpc").
	GRPC GRPCConfig `yaml:"grpc"`

	// XHTTP holds XHTTP/SplitHTTP-specific settings (when Network == "xhttp" or "splithttp").
	XHTTP XHTTPConfig `yaml:"xhttp"`
}

// RealityConfig holds REALITY TLS settings.
type RealityConfig struct {
	// PublicKey is the x25519 public key.
	PublicKey string `yaml:"public_key"`
	// ShortID is the hex short ID (0-8 chars).
	ShortID string `yaml:"short_id"`
	// ServerName is the SNI to impersonate.
	ServerName string `yaml:"server_name"`
	// Fingerprint is the uTLS fingerprint: "chrome", "firefox", "safari", "random".
	Fingerprint string `yaml:"fingerprint"`
	// SpiderX is the path prefix for web crawling (optional).
	SpiderX string `yaml:"spider_x"`
}

// TLSConfig holds standard TLS settings.
type TLSConfig struct {
	// ServerName overrides the SNI.
	ServerName string `yaml:"server_name"`
	// Fingerprint is the uTLS fingerprint.
	Fingerprint string `yaml:"fingerprint"`
	// AllowInsecure disables TLS verification.
	AllowInsecure bool `yaml:"allow_insecure"`
}

// WSConfig holds WebSocket transport settings.
type WSConfig struct {
	// Path is the WebSocket path.
	Path string `yaml:"path"`
	// Headers are custom HTTP headers.
	Headers map[string]string `yaml:"headers"`
}

// GRPCConfig holds gRPC transport settings.
type GRPCConfig struct {
	// ServiceName is the gRPC service name.
	ServiceName string `yaml:"service_name"`
}

// XHTTPConfig holds XHTTP (SplitHTTP) transport settings.
type XHTTPConfig struct {
	// Path is the HTTP request path.
	Path string `yaml:"path"`
	// Host is the HTTP Host header value.
	Host string `yaml:"host"`
	// Mode is the XHTTP mode: "auto", "packet-up", "stream-up", "stream-one".
	Mode string `yaml:"mode"`
	// Extra holds additional xhttp settings passed directly to xray-core.
	Extra map[string]any `yaml:"extra,omitempty"`
}

// buildXrayJSON builds the xray-core JSON config from Config.
func buildXrayJSON(cfg Config) ([]byte, error) {
	if cfg.Encryption == "" {
		cfg.Encryption = "none"
	}
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	if cfg.Security == "" {
		cfg.Security = "reality"
	}

	user := map[string]any{
		"id":         cfg.UUID,
		"encryption": cfg.Encryption,
	}
	if cfg.Flow != "" {
		user["flow"] = cfg.Flow
	}

	outbound := map[string]any{
		"tag":      "vless-out",
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []map[string]any{
				{
					"address": cfg.Address,
					"port":    cfg.Port,
					"users":   []map[string]any{user},
				},
			},
		},
	}

	// Stream settings.
	stream := map[string]any{
		"network": cfg.Network,
	}

	// Security settings.
	stream["security"] = cfg.Security
	switch cfg.Security {
	case "reality":
		fp := cfg.Reality.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		stream["realitySettings"] = map[string]any{
			"show":        false,
			"fingerprint": fp,
			"serverName":  cfg.Reality.ServerName,
			"publicKey":   cfg.Reality.PublicKey,
			"shortId":     cfg.Reality.ShortID,
			"spiderX":     cfg.Reality.SpiderX,
		}
	case "tls":
		tlsSettings := map[string]any{
			"allowInsecure": cfg.TLS.AllowInsecure,
		}
		if cfg.TLS.ServerName != "" {
			tlsSettings["serverName"] = cfg.TLS.ServerName
		}
		if cfg.TLS.Fingerprint != "" {
			tlsSettings["fingerprint"] = cfg.TLS.Fingerprint
		}
		stream["tlsSettings"] = tlsSettings
	}

	// Transport settings.
	switch cfg.Network {
	case "ws":
		wsSettings := map[string]any{
			"path": cfg.WebSocket.Path,
		}
		if len(cfg.WebSocket.Headers) > 0 {
			wsSettings["headers"] = cfg.WebSocket.Headers
		}
		stream["wsSettings"] = wsSettings
	case "grpc":
		stream["grpcSettings"] = map[string]any{
			"serviceName": cfg.GRPC.ServiceName,
		}
	case "xhttp", "splithttp":
		stream["network"] = "xhttp"
		xhttpSettings := map[string]any{}
		if cfg.XHTTP.Path != "" {
			xhttpSettings["path"] = cfg.XHTTP.Path
		}
		if cfg.XHTTP.Host != "" {
			xhttpSettings["host"] = cfg.XHTTP.Host
		}
		if cfg.XHTTP.Mode != "" {
			xhttpSettings["mode"] = cfg.XHTTP.Mode
		}
		for k, v := range cfg.XHTTP.Extra {
			xhttpSettings[k] = v
		}
		stream["xhttpSettings"] = xhttpSettings
	}

	outbound["streamSettings"] = stream

	xrayConfig := map[string]any{
		"log": map[string]any{
			"loglevel": "warning",
		},
		"outbounds": []map[string]any{
			outbound,
			{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]any{},
			},
		},
	}

	data, err := json.Marshal(xrayConfig)
	if err != nil {
		return nil, fmt.Errorf("marshal xray config: %w", err)
	}
	return data, nil
}

// ParseXrayJSON parses a standard xray-core JSON config file and extracts
// VLESS connection parameters into a Config struct.
// Supports the typical xray config with outbounds[].protocol == "vless".
func ParseXrayJSON(data []byte) (Config, error) {
	var raw struct {
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				Vnext []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
					Users   []struct {
						ID         string `json:"id"`
						Encryption string `json:"encryption"`
						Flow       string `json:"flow"`
					} `json:"users"`
				} `json:"vnext"`
			} `json:"settings"`
			StreamSettings struct {
				Network  string `json:"network"`
				Security string `json:"security"`
				RealitySettings struct {
					Fingerprint string `json:"fingerprint"`
					ServerName  string `json:"serverName"`
					PublicKey   string `json:"publicKey"`
					ShortID     string `json:"shortId"`
					SpiderX     string `json:"spiderX"`
				} `json:"realitySettings"`
				TLSSettings struct {
					ServerName    string `json:"serverName"`
					Fingerprint   string `json:"fingerprint"`
					AllowInsecure bool   `json:"allowInsecure"`
				} `json:"tlsSettings"`
				WSSettings struct {
					Path    string            `json:"path"`
					Headers map[string]string `json:"headers"`
				} `json:"wsSettings"`
				GRPCSettings struct {
					ServiceName string `json:"serviceName"`
				} `json:"grpcSettings"`
				XHTTPSettings struct {
					Path string `json:"path"`
					Host string `json:"host"`
					Mode string `json:"mode"`
				} `json:"xhttpSettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return Config{}, fmt.Errorf("parse xray JSON: %w", err)
	}

	// Find the first VLESS outbound.
	for _, ob := range raw.Outbounds {
		if ob.Protocol != "vless" {
			continue
		}
		if len(ob.Settings.Vnext) == 0 || len(ob.Settings.Vnext[0].Users) == 0 {
			return Config{}, fmt.Errorf("xray JSON: vless outbound has no vnext/users")
		}

		vnext := ob.Settings.Vnext[0]
		user := vnext.Users[0]
		ss := ob.StreamSettings

		cfg := Config{
			Address:    vnext.Address,
			Port:       vnext.Port,
			UUID:       user.ID,
			Flow:       user.Flow,
			Encryption: user.Encryption,
			Network:    ss.Network,
			Security:   ss.Security,
		}

		// Defaults.
		if cfg.Encryption == "" {
			cfg.Encryption = "none"
		}
		if cfg.Network == "" {
			cfg.Network = "tcp"
		}

		// Reality settings.
		if ss.Security == "reality" {
			cfg.Reality = RealityConfig{
				PublicKey:   ss.RealitySettings.PublicKey,
				ShortID:     ss.RealitySettings.ShortID,
				ServerName:  ss.RealitySettings.ServerName,
				Fingerprint: ss.RealitySettings.Fingerprint,
				SpiderX:     ss.RealitySettings.SpiderX,
			}
		}

		// TLS settings.
		if ss.Security == "tls" {
			cfg.TLS = TLSConfig{
				ServerName:    ss.TLSSettings.ServerName,
				Fingerprint:   ss.TLSSettings.Fingerprint,
				AllowInsecure: ss.TLSSettings.AllowInsecure,
			}
		}

		// WebSocket settings.
		if ss.Network == "ws" {
			cfg.WebSocket = WSConfig{
				Path:    ss.WSSettings.Path,
				Headers: ss.WSSettings.Headers,
			}
		}

		// gRPC settings.
		if ss.Network == "grpc" {
			cfg.GRPC = GRPCConfig{
				ServiceName: ss.GRPCSettings.ServiceName,
			}
		}

		// XHTTP settings.
		if ss.Network == "xhttp" || ss.Network == "splithttp" {
			cfg.Network = "xhttp"
			cfg.XHTTP = XHTTPConfig{
				Path: ss.XHTTPSettings.Path,
				Host: ss.XHTTPSettings.Host,
				Mode: ss.XHTTPSettings.Mode,
			}
		}

		return cfg, nil
	}

	return Config{}, fmt.Errorf("xray JSON: no vless outbound found")
}

// ParseVLESSURI parses a vless:// share link into a Config and a display name.
// Format: vless://UUID@host:port?params#name
// Standard query params:
//
//	type      → network (tcp, ws, grpc, h2)
//	encryption→ encryption (none)
//	security  → security (reality, tls, none)
//	flow      → flow (xtls-rprx-vision)
//	pbk       → reality.public_key
//	fp        → fingerprint (reality or tls)
//	sni       → server_name (reality or tls)
//	sid       → reality.short_id
//	spx       → reality.spider_x
//	path      → ws.path
//	host      → ws host header
//	serviceName → grpc.service_name
//	allowInsecure → tls.allow_insecure
func ParseVLESSURI(uri string) (Config, string, error) {
	if !strings.HasPrefix(uri, "vless://") {
		return Config{}, "", fmt.Errorf("not a vless:// URI")
	}

	// Parse as URL. Replace "vless" scheme with "https" for standard parsing.
	u, err := url.Parse("https" + uri[5:])
	if err != nil {
		return Config{}, "", fmt.Errorf("parse vless URI: %w", err)
	}

	uuid := u.User.Username()
	if uuid == "" {
		return Config{}, "", fmt.Errorf("vless URI: missing UUID")
	}

	host := u.Hostname()
	if host == "" {
		return Config{}, "", fmt.Errorf("vless URI: missing host")
	}

	port := 443
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}

	q := u.Query()

	cfg := Config{
		Address:    host,
		Port:       port,
		UUID:       uuid,
		Flow:       q.Get("flow"),
		Encryption: q.Get("encryption"),
		Network:    q.Get("type"),
		Security:   q.Get("security"),
	}

	if cfg.Encryption == "" {
		cfg.Encryption = "none"
	}
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}

	fp := q.Get("fp")
	sni := q.Get("sni")

	switch cfg.Security {
	case "reality":
		cfg.Reality = RealityConfig{
			PublicKey:   q.Get("pbk"),
			ShortID:     q.Get("sid"),
			ServerName:  sni,
			Fingerprint: fp,
			SpiderX:     q.Get("spx"),
		}
	case "tls":
		cfg.TLS = TLSConfig{
			ServerName:    sni,
			Fingerprint:   fp,
			AllowInsecure: q.Get("allowInsecure") == "1" || q.Get("allowInsecure") == "true",
		}
	}

	switch cfg.Network {
	case "ws":
		cfg.WebSocket = WSConfig{
			Path: q.Get("path"),
		}
		if h := q.Get("host"); h != "" {
			cfg.WebSocket.Headers = map[string]string{"Host": h}
		}
	case "grpc":
		cfg.GRPC = GRPCConfig{
			ServiceName: q.Get("serviceName"),
		}
	case "xhttp", "splithttp":
		cfg.Network = "xhttp"
		cfg.XHTTP = XHTTPConfig{
			Path: q.Get("path"),
			Host: q.Get("host"),
			Mode: q.Get("mode"),
		}
	}

	// Fragment is the display name.
	name := u.Fragment

	return cfg, name, nil
}
