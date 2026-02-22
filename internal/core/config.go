//go:build windows

package core

import (
	"fmt"
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

// Protocol identifiers for tunnel providers.
const (
	ProtocolAmneziaWG = "amneziawg"
	ProtocolWireGuard = "wireguard"
	ProtocolSOCKS5    = "socks5"
	ProtocolHTTPProxy = "httpproxy"
	ProtocolVLESS     = "vless"
)

// FallbackPolicy defines what happens when a tunnel is unavailable.
type FallbackPolicy int

const (
	// PolicyAllowDirect lets traffic go directly if tunnel is down.
	PolicyAllowDirect FallbackPolicy = iota
	// PolicyBlock drops traffic if tunnel is down (per-app kill switch).
	PolicyBlock
	// PolicyDrop always drops traffic regardless of tunnel state.
	PolicyDrop
	// PolicyFailover tries the next matching rule; drops if none match.
	PolicyFailover
)

func (p FallbackPolicy) String() string {
	switch p {
	case PolicyAllowDirect:
		return "allow_direct"
	case PolicyBlock:
		return "block"
	case PolicyDrop:
		return "drop"
	case PolicyFailover:
		return "failover"
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
	case "failover":
		return PolicyFailover, nil
	default:
		return PolicyAllowDirect, fmt.Errorf("unknown fallback policy: %q", s)
	}
}

// RulePriority defines packet scheduling priority for a rule.
type RulePriority int

const (
	// PriorityAuto classifies packets by their characteristics (default).
	PriorityAuto RulePriority = iota
	// PriorityRealtime forces all packets to high priority queue.
	PriorityRealtime
	// PriorityNormal forces all packets to normal priority queue.
	PriorityNormal
	// PriorityLow forces all packets to low priority queue.
	PriorityLow
)

func (p RulePriority) String() string {
	switch p {
	case PriorityAuto:
		return "auto"
	case PriorityRealtime:
		return "realtime"
	case PriorityNormal:
		return "normal"
	case PriorityLow:
		return "low"
	default:
		return "unknown"
	}
}

// ParseRulePriority parses a string into a RulePriority.
func ParseRulePriority(s string) (RulePriority, error) {
	switch s {
	case "auto", "":
		return PriorityAuto, nil
	case "realtime", "high":
		return PriorityRealtime, nil
	case "normal":
		return PriorityNormal, nil
	case "low", "bulk":
		return PriorityLow, nil
	default:
		return PriorityAuto, fmt.Errorf("unknown rule priority: %q", s)
	}
}

// DomainAction defines what happens when a domain rule matches.
type DomainAction int

const (
	// DomainRoute routes traffic through a specific tunnel.
	DomainRoute DomainAction = iota
	// DomainDirect bypasses VPN for matching domains.
	DomainDirect
	// DomainBlock drops DNS queries for matching domains.
	DomainBlock
)

func (a DomainAction) String() string {
	switch a {
	case DomainRoute:
		return "route"
	case DomainDirect:
		return "direct"
	case DomainBlock:
		return "block"
	default:
		return "unknown"
	}
}

// ParseDomainAction parses a string into a DomainAction.
func ParseDomainAction(s string) (DomainAction, error) {
	switch s {
	case "route", "":
		return DomainRoute, nil
	case "direct":
		return DomainDirect, nil
	case "block":
		return DomainBlock, nil
	default:
		return DomainRoute, fmt.Errorf("unknown domain action: %q", s)
	}
}

// DomainRule maps a domain pattern to a routing action.
type DomainRule struct {
	// Pattern is the matching expression: "domain:vk.com", "full:example.com", "keyword:google", "geosite:ru"
	Pattern string `yaml:"pattern"`
	// TunnelID identifies which tunnel to route through (only for DomainRoute).
	TunnelID string `yaml:"tunnel_id,omitempty"`
	// Action defines the routing behavior.
	Action DomainAction `yaml:"action"`
}

// Rule maps a process pattern to a tunnel with a fallback policy.
type Rule struct {
	// Pattern is the matching expression: "firefox.exe", "chrome", "C:\Games\*"
	Pattern string `yaml:"pattern"`
	// TunnelID identifies which tunnel to route through. Empty for drop-only rules.
	TunnelID string `yaml:"tunnel_id,omitempty"`
	// Fallback defines behavior when the tunnel is unavailable.
	Fallback FallbackPolicy `yaml:"fallback"`
	// Priority defines packet scheduling priority: auto (default), realtime, normal, low.
	Priority RulePriority `yaml:"priority,omitempty"`
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
	// Cache configures DNS response caching.
	Cache DNSCacheYAMLConfig `yaml:"cache,omitempty"`
}

// DNSCacheYAMLConfig holds DNS cache settings from YAML config.
type DNSCacheYAMLConfig struct {
	// Enabled controls whether DNS caching is active (default true).
	Enabled *bool `yaml:"enabled,omitempty"`
	// MaxSize is the maximum number of cache entries (default 10000).
	MaxSize int `yaml:"max_size,omitempty"`
	// MinTTL is the minimum TTL floor, e.g. "30s" (default 30s).
	MinTTL string `yaml:"min_ttl,omitempty"`
	// MaxTTL is the maximum TTL cap, e.g. "5m" (default 5m).
	MaxTTL string `yaml:"max_ttl,omitempty"`
	// NegTTL is the NXDOMAIN cache TTL, e.g. "60s" (default 60s).
	NegTTL string `yaml:"neg_ttl,omitempty"`
}

// GlobalFilterConfig holds IP and app filters applied to all tunnels.
type GlobalFilterConfig struct {
	AllowedIPs     []string `yaml:"allowed_ips,omitempty"`
	DisallowedIPs  []string `yaml:"disallowed_ips,omitempty"`
	DisallowedApps []string `yaml:"disallowed_apps,omitempty"`
	DisableLocal   bool     `yaml:"disable_local,omitempty"`
}

// UpdateConfig holds auto-update settings.
type UpdateConfig struct {
	// Enabled controls whether periodic update checks run (default true).
	Enabled *bool `yaml:"enabled,omitempty"`
	// CheckInterval is how often to check for updates (e.g. "24h"). Default "24h".
	CheckInterval string `yaml:"check_interval,omitempty"`
}

// IsEnabled returns whether auto-update checks are enabled (default true).
func (u UpdateConfig) IsEnabled() bool {
	if u.Enabled == nil {
		return true
	}
	return *u.Enabled
}

// GUIConfig holds GUI-specific settings.
type GUIConfig struct {
	RestoreConnections bool     `yaml:"restore_connections,omitempty"`
	ActiveTunnels      []string `yaml:"active_tunnels,omitempty"`
}

// SubscriptionConfig holds configuration for a VLESS subscription URL.
type SubscriptionConfig struct {
	// URL is the subscription endpoint that returns base64-encoded proxy URIs.
	URL string `yaml:"url"`
	// RefreshInterval is how often to auto-refresh (e.g. "6h", "24h"). Zero disables auto-refresh.
	RefreshInterval string `yaml:"refresh_interval,omitempty"`
	// UserAgent is the HTTP User-Agent header for subscription requests.
	UserAgent string `yaml:"user_agent,omitempty"`
	// Prefix is prepended to generated tunnel IDs (default: subscription name).
	Prefix string `yaml:"prefix,omitempty"`
}

// Config is the top-level application configuration.
type Config struct {
	Global        GlobalFilterConfig            `yaml:"global,omitempty"`
	Tunnels       []TunnelConfig                `yaml:"tunnels"`
	Subscriptions map[string]SubscriptionConfig `yaml:"subscriptions,omitempty"`
	Rules         []Rule                        `yaml:"rules"`
	DomainRules   []DomainRule                  `yaml:"domain_rules,omitempty"`
	DNS           DNSRouteConfig                `yaml:"dns,omitempty"`
	Logging       LogConfig                     `yaml:"logging,omitempty"`
	GUI           GUIConfig                     `yaml:"gui,omitempty"`
	Update        UpdateConfig                  `yaml:"update,omitempty"`
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
			Log.Infof("Core", "Config %s not found, creating default config", cm.filePath)
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

// GetDomainRules returns domain routing rules.
func (cm *ConfigManager) GetDomainRules() []DomainRule {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	result := make([]DomainRule, len(cm.config.DomainRules))
	copy(result, cm.config.DomainRules)
	return result
}

// SetDomainRules replaces the domain routing rules.
func (cm *ConfigManager) SetDomainRules(rules []DomainRule) {
	cm.mu.Lock()
	cm.config.DomainRules = rules
	cm.mu.Unlock()

	if cm.bus != nil {
		cm.bus.Publish(Event{Type: EventConfigReloaded})
	}
}

// SetFromGUI replaces the entire config with values from the GUI.
// Publishes EventConfigReloaded.
func (cm *ConfigManager) SetFromGUI(cfg Config) {
	cm.mu.Lock()
	cm.config = cfg
	cm.mu.Unlock()

	if cm.bus != nil {
		cm.bus.Publish(Event{Type: EventConfigReloaded})
	}
}

// GetSubscriptions returns subscription configurations.
func (cm *ConfigManager) GetSubscriptions() map[string]SubscriptionConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	result := make(map[string]SubscriptionConfig, len(cm.config.Subscriptions))
	for k, v := range cm.config.Subscriptions {
		result[k] = v
	}
	return result
}

// SetSubscriptions replaces subscription configurations.
func (cm *ConfigManager) SetSubscriptions(subs map[string]SubscriptionConfig) {
	cm.mu.Lock()
	cm.config.Subscriptions = subs
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

// UnmarshalYAML implements yaml.Unmarshaler for RulePriority.
func (p *RulePriority) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := ParseRulePriority(s)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// MarshalYAML implements yaml.Marshaler for RulePriority.
func (p RulePriority) MarshalYAML() (any, error) {
	if p == PriorityAuto {
		return nil, nil // omit default
	}
	return p.String(), nil
}

// UnmarshalYAML implements yaml.Unmarshaler for DomainAction.
func (a *DomainAction) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := ParseDomainAction(s)
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// MarshalYAML implements yaml.Marshaler for DomainAction.
func (a DomainAction) MarshalYAML() (any, error) {
	return a.String(), nil
}
