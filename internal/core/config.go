//go:build windows

package core

import (
	"fmt"
	"log"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// TunnelState represents the lifecycle state of a VPN tunnel.
type TunnelState int

const (
	TunnelStateDown       TunnelState = iota
	TunnelStateConnecting
	TunnelStateUp
	TunnelStateError
)

func (s TunnelState) String() string {
	switch s {
	case TunnelStateDown:
		return "down"
	case TunnelStateConnecting:
		return "connecting"
	case TunnelStateUp:
		return "up"
	case TunnelStateError:
		return "error"
	default:
		return "unknown"
	}
}

// FallbackPolicy defines what happens when a tunnel is unavailable.
type FallbackPolicy int

const (
	// PolicyAllowDirect lets traffic go directly if tunnel is down.
	PolicyAllowDirect FallbackPolicy = iota
	// PolicyBlock drops traffic if tunnel is down (per-app kill switch).
	PolicyBlock
	// PolicyDrop always drops traffic regardless of tunnel state.
	PolicyDrop
)

func (p FallbackPolicy) String() string {
	switch p {
	case PolicyAllowDirect:
		return "allow_direct"
	case PolicyBlock:
		return "block"
	case PolicyDrop:
		return "drop"
	default:
		return "unknown"
	}
}

func ParseFallbackPolicy(s string) (FallbackPolicy, error) {
	switch s {
	case "allow_direct", "allow", "direct":
		return PolicyAllowDirect, nil
	case "block":
		return PolicyBlock, nil
	case "drop":
		return PolicyDrop, nil
	default:
		return PolicyAllowDirect, fmt.Errorf("unknown fallback policy: %q", s)
	}
}

// Rule maps a process pattern to a tunnel with a fallback policy.
type Rule struct {
	// Pattern is the matching expression: "firefox.exe", "chrome", "C:\Games\*"
	Pattern string `yaml:"pattern"`
	// TunnelID identifies which tunnel to route through. Empty for drop-only rules.
	TunnelID string `yaml:"tunnel_id,omitempty"`
	// Fallback defines behavior when the tunnel is unavailable.
	Fallback FallbackPolicy `yaml:"fallback"`
}

// TunnelConfig holds the configuration for a single VPN tunnel.
type TunnelConfig struct {
	ID       string `yaml:"id"`
	Protocol string `yaml:"protocol"` // "amneziawg", "wireguard", "httpproxy", "socks5"
	Name     string `yaml:"name"`

	// Protocol-specific configuration stored as a generic map.
	// Parsed by the corresponding provider.
	Settings map[string]any `yaml:"settings,omitempty"`

	// Per-tunnel IP/app filtering (optional overrides).
	AllowedIPs     []string `yaml:"allowed_ips,omitempty"`
	DisallowedIPs  []string `yaml:"disallowed_ips,omitempty"`
	DisallowedApps []string `yaml:"disallowed_apps,omitempty"`
}

// DNSRouteConfig configures per-process DNS routing.
type DNSRouteConfig struct {
	// FallbackTunnelID is the tunnel used for system DNS (svchost.exe) queries.
	// Empty means use direct (no tunnel).
	FallbackTunnelID string `yaml:"tunnel_id,omitempty"`
	// Servers are DNS server addresses for fallback queries.
	Servers []string `yaml:"servers,omitempty"`
}

// GlobalFilterConfig holds IP and app filters applied to all tunnels.
type GlobalFilterConfig struct {
	AllowedIPs     []string `yaml:"allowed_ips,omitempty"`
	DisallowedIPs  []string `yaml:"disallowed_ips,omitempty"`
	DisallowedApps []string `yaml:"disallowed_apps,omitempty"`
	DisableLocal   bool     `yaml:"disable_local,omitempty"`
}

// Config is the top-level application configuration.
type Config struct {
	Global  GlobalFilterConfig `yaml:"global,omitempty"`
	Tunnels []TunnelConfig     `yaml:"tunnels"`
	Rules   []Rule             `yaml:"rules"`
	DNS     DNSRouteConfig     `yaml:"dns,omitempty"`
}

// ConfigManager handles loading, saving, and hot-reloading configuration.
type ConfigManager struct {
	mu       sync.RWMutex
	config   Config
	filePath string
	bus      *EventBus
}

// NewConfigManager creates a config manager that reads from the given file.
func NewConfigManager(filePath string, bus *EventBus) *ConfigManager {
	return &ConfigManager{
		filePath: filePath,
		bus:      bus,
	}
}

// defaultConfig returns an empty but valid configuration.
func defaultConfig() Config {
	return Config{}
}

// Load reads and parses the configuration from disk.
// If the config file does not exist, it creates one with default values.
func (cm *ConfigManager) Load() error {
	data, err := os.ReadFile(cm.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[Core] Config %s not found, creating default config", cm.filePath)
			cm.mu.Lock()
			cm.config = defaultConfig()
			cm.mu.Unlock()
			if saveErr := cm.Save(); saveErr != nil {
				return fmt.Errorf("[Core] failed to create default config: %w", saveErr)
			}
			return nil
		}
		return fmt.Errorf("[Core] failed to read config %s: %w", cm.filePath, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("[Core] failed to parse config: %w", err)
	}

	cm.mu.Lock()
	cm.config = cfg
	cm.mu.Unlock()

	if cm.bus != nil {
		cm.bus.Publish(Event{Type: EventConfigReloaded})
	}

	return nil
}

// Save writes the current configuration to disk.
func (cm *ConfigManager) Save() error {
	cm.mu.RLock()
	data, err := yaml.Marshal(&cm.config)
	cm.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("[Core] failed to marshal config: %w", err)
	}

	if err := os.WriteFile(cm.filePath, data, 0644); err != nil {
		return fmt.Errorf("[Core] failed to write config %s: %w", cm.filePath, err)
	}

	return nil
}

// Get returns a copy of the current configuration.
func (cm *ConfigManager) Get() Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}

// GetTunnels returns tunnel configurations.
func (cm *ConfigManager) GetTunnels() []TunnelConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	result := make([]TunnelConfig, len(cm.config.Tunnels))
	copy(result, cm.config.Tunnels)
	return result
}

// GetRules returns routing rules.
func (cm *ConfigManager) GetRules() []Rule {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	result := make([]Rule, len(cm.config.Rules))
	copy(result, cm.config.Rules)
	return result
}

// SetRules replaces the routing rules.
func (cm *ConfigManager) SetRules(rules []Rule) {
	cm.mu.Lock()
	cm.config.Rules = rules
	cm.mu.Unlock()

	if cm.bus != nil {
		cm.bus.Publish(Event{Type: EventConfigReloaded})
	}
}

// UnmarshalFallbackPolicy implements yaml.Unmarshaler for FallbackPolicy.
func (p *FallbackPolicy) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := ParseFallbackPolicy(s)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// MarshalYAML implements yaml.Marshaler for FallbackPolicy.
func (p FallbackPolicy) MarshalYAML() (any, error) {
	return p.String(), nil
}
