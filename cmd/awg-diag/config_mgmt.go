//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/ipc"

	"google.golang.org/protobuf/types/known/emptypb"
	"gopkg.in/yaml.v3"
)

// loadConfig reads the YAML config file into a core.Config.
func loadConfig() (*core.Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg core.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// saveConfig writes the config back to the YAML file.
func saveConfig(cfg *core.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// runConfigAddRule adds a new rule to the config.
func runConfigAddRule(args []string) {
	var pattern, tunnelID, fallbackStr, priorityStr string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--pattern":
			if i+1 < len(args) {
				pattern = args[i+1]
				i++
			}
		case "--tunnel":
			if i+1 < len(args) {
				tunnelID = args[i+1]
				i++
			}
		case "--fallback":
			if i+1 < len(args) {
				fallbackStr = args[i+1]
				i++
			}
		case "--priority":
			if i+1 < len(args) {
				priorityStr = args[i+1]
				i++
			}
		}
	}

	if pattern == "" || tunnelID == "" {
		fatal("usage: config add-rule --pattern <pattern> --tunnel <tunnel_id> [--fallback <policy>] [--priority <level>]")
	}

	cfg, err := loadConfig()
	if err != nil {
		fatal("load config: %v", err)
	}

	// Check for duplicate.
	for _, r := range cfg.Rules {
		if strings.EqualFold(r.Pattern, pattern) {
			fatal("rule for pattern %q already exists", pattern)
		}
	}

	rule := core.Rule{
		Pattern:  pattern,
		TunnelID: tunnelID,
	}

	if fallbackStr != "" {
		fb, err := core.ParseFallbackPolicy(fallbackStr)
		if err != nil {
			fatal("invalid fallback: %v", err)
		}
		rule.Fallback = fb
	}

	if priorityStr != "" {
		pr, err := core.ParseRulePriority(priorityStr)
		if err != nil {
			fatal("invalid priority: %v", err)
		}
		rule.Priority = pr
	}

	cfg.Rules = append(cfg.Rules, rule)

	if err := saveConfig(cfg); err != nil {
		fatal("save config: %v", err)
	}

	diagLog.Printf("Added rule: %s -> %s", pattern, tunnelID)
}

// runConfigRemoveRule removes a rule by pattern (case-insensitive).
func runConfigRemoveRule(args []string) {
	var pattern string
	for i := 0; i < len(args); i++ {
		if args[i] == "--pattern" && i+1 < len(args) {
			pattern = args[i+1]
			i++
		}
	}

	if pattern == "" {
		fatal("usage: config remove-rule --pattern <pattern>")
	}

	cfg, err := loadConfig()
	if err != nil {
		fatal("load config: %v", err)
	}

	found := false
	var filtered []core.Rule
	for _, r := range cfg.Rules {
		if strings.EqualFold(r.Pattern, pattern) {
			found = true
			continue
		}
		filtered = append(filtered, r)
	}

	if !found {
		fatal("no rule found for pattern %q", pattern)
	}

	cfg.Rules = filtered
	if err := saveConfig(cfg); err != nil {
		fatal("save config: %v", err)
	}

	diagLog.Printf("Removed rule: %s", pattern)
}

// runConfigShowRules displays the current rules.
func runConfigShowRules() {
	cfg, err := loadConfig()
	if err != nil {
		fatal("load config: %v", err)
	}

	if jsonOutput {
		outputJSON(cfg.Rules)
		return
	}

	if len(cfg.Rules) == 0 {
		diagLog.Printf("No rules configured.")
		return
	}

	diagLog.Printf("%-30s %-20s %-15s %-10s", "PATTERN", "TUNNEL", "FALLBACK", "PRIORITY")
	diagLog.Printf("%s", strings.Repeat("-", 75))
	for _, r := range cfg.Rules {
		diagLog.Printf("%-30s %-20s %-15s %-10s",
			r.Pattern, r.TunnelID, r.Fallback.String(), r.Priority.String())
	}
}

// runConfigListTunnels shows tunnels from config + optional live status via IPC.
func runConfigListTunnels() {
	cfg, err := loadConfig()
	if err != nil {
		fatal("load config: %v", err)
	}

	type tunnelInfo struct {
		ID       string `json:"id"`
		Protocol string `json:"protocol"`
		Name     string `json:"name"`
		Status   string `json:"status,omitempty"`
	}

	tunnels := make([]tunnelInfo, 0, len(cfg.Tunnels))
	seen := make(map[string]bool)
	for _, t := range cfg.Tunnels {
		if seen[t.ID] {
			continue
		}
		seen[t.ID] = true
		tunnels = append(tunnels, tunnelInfo{
			ID:       t.ID,
			Protocol: t.Protocol,
			Name:     t.Name,
			Status:   "unknown",
		})
	}

	// Try IPC for live status (best-effort).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := ipc.DialWithTimeout(ctx, 3*time.Second)
	if err == nil {
		defer client.Close()
		resp, err := client.Service.ListTunnels(ctx, &emptypb.Empty{})
		if err == nil {
			statusMap := make(map[string]string)
			for _, t := range resp.GetTunnels() {
				statusMap[t.GetId()] = t.GetState().String()
			}
			for i := range tunnels {
				if s, ok := statusMap[tunnels[i].ID]; ok {
					tunnels[i].Status = s
				}
			}
		}
	}

	if jsonOutput {
		outputJSON(tunnels)
		return
	}

	if len(tunnels) == 0 {
		diagLog.Printf("No tunnels configured.")
		return
	}

	diagLog.Printf("%-20s %-15s %-25s %-10s", "ID", "PROTOCOL", "NAME", "STATUS")
	diagLog.Printf("%s", strings.Repeat("-", 70))
	for _, t := range tunnels {
		diagLog.Printf("%-20s %-15s %-25s %-10s", t.ID, t.Protocol, t.Name, t.Status)
	}
}
