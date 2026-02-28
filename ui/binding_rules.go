//go:build windows || darwin

package main

import (
	"context"
	"errors"

	vpnapi "awg-split-tunnel/api/gen"

	"google.golang.org/protobuf/types/known/emptypb"
)

// ─── Process rules ──────────────────────────────────────────────────

type RuleInfo struct {
	Pattern  string `json:"pattern"`
	TunnelID string `json:"tunnelId"`
	Fallback string `json:"fallback"` // "allow_direct", "block", "drop", "failover"
	Priority string `json:"priority"` // "auto", "realtime", "normal", "low"
	Active   bool   `json:"active"`   // tunnel is connected, rule is active
}

func fallbackStr(f vpnapi.FallbackPolicy) string {
	switch f {
	case vpnapi.FallbackPolicy_FALLBACK_ALLOW_DIRECT:
		return "allow_direct"
	case vpnapi.FallbackPolicy_FALLBACK_BLOCK:
		return "block"
	case vpnapi.FallbackPolicy_FALLBACK_DROP:
		return "drop"
	case vpnapi.FallbackPolicy_FALLBACK_FAILOVER:
		return "failover"
	default:
		return "allow_direct"
	}
}

func fallbackFromStr(s string) vpnapi.FallbackPolicy {
	switch s {
	case "block":
		return vpnapi.FallbackPolicy_FALLBACK_BLOCK
	case "drop":
		return vpnapi.FallbackPolicy_FALLBACK_DROP
	case "failover":
		return vpnapi.FallbackPolicy_FALLBACK_FAILOVER
	default:
		return vpnapi.FallbackPolicy_FALLBACK_ALLOW_DIRECT
	}
}

func (b *BindingService) ListRules() ([]RuleInfo, error) {
	resp, err := b.client.Service.ListRules(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	rules := make([]RuleInfo, 0, len(resp.Rules))
	for _, r := range resp.Rules {
		prio := r.Priority
		if prio == "" {
			prio = "auto"
		}
		rules = append(rules, RuleInfo{
			Pattern:  r.Pattern,
			TunnelID: r.TunnelId,
			Fallback: fallbackStr(r.Fallback),
			Priority: prio,
			Active:   r.Active,
		})
	}
	return rules, nil
}

func (b *BindingService) SaveRules(rules []RuleInfo) error {
	protoRules := make([]*vpnapi.Rule, 0, len(rules))
	for _, r := range rules {
		prio := r.Priority
		if prio == "auto" {
			prio = ""
		}
		protoRules = append(protoRules, &vpnapi.Rule{
			Pattern:  r.Pattern,
			TunnelId: r.TunnelID,
			Fallback: fallbackFromStr(r.Fallback),
			Priority: prio,
		})
	}
	resp, err := b.client.Service.SaveRules(context.Background(), &vpnapi.SaveRulesRequest{Rules: protoRules})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

// ─── Domain rules ───────────────────────────────────────────────────

type DomainRuleInfo struct {
	Pattern  string `json:"pattern"`
	TunnelID string `json:"tunnelId"`
	Action   string `json:"action"` // "route", "direct", "block"
	Active   bool   `json:"active"`
}

func domainActionStr(a vpnapi.DomainAction) string {
	switch a {
	case vpnapi.DomainAction_DOMAIN_ACTION_ROUTE:
		return "route"
	case vpnapi.DomainAction_DOMAIN_ACTION_DIRECT:
		return "direct"
	case vpnapi.DomainAction_DOMAIN_ACTION_BLOCK:
		return "block"
	default:
		return "route"
	}
}

func domainActionFromStr(s string) vpnapi.DomainAction {
	switch s {
	case "direct":
		return vpnapi.DomainAction_DOMAIN_ACTION_DIRECT
	case "block":
		return vpnapi.DomainAction_DOMAIN_ACTION_BLOCK
	default:
		return vpnapi.DomainAction_DOMAIN_ACTION_ROUTE
	}
}

func (b *BindingService) ListDomainRules() ([]DomainRuleInfo, error) {
	resp, err := b.client.Service.ListDomainRules(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	rules := make([]DomainRuleInfo, 0, len(resp.Rules))
	for _, r := range resp.Rules {
		rules = append(rules, DomainRuleInfo{
			Pattern:  r.Pattern,
			TunnelID: r.TunnelId,
			Action:   domainActionStr(r.Action),
			Active:   r.Active,
		})
	}
	return rules, nil
}

func (b *BindingService) SaveDomainRules(rules []DomainRuleInfo) error {
	protoRules := make([]*vpnapi.DomainRule, 0, len(rules))
	for _, r := range rules {
		protoRules = append(protoRules, &vpnapi.DomainRule{
			Pattern:  r.Pattern,
			TunnelId: r.TunnelID,
			Action:   domainActionFromStr(r.Action),
		})
	}
	resp, err := b.client.Service.SaveDomainRules(context.Background(), &vpnapi.SaveDomainRulesRequest{Rules: protoRules})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

func (b *BindingService) ListGeositeCategories() ([]string, error) {
	resp, err := b.client.Service.ListGeositeCategories(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return resp.Categories, nil
}

func (b *BindingService) ListGeoIPCategories() ([]string, error) {
	resp, err := b.client.Service.ListGeoIPCategories(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return resp.Categories, nil
}

func (b *BindingService) UpdateGeosite() error {
	resp, err := b.client.Service.UpdateGeosite(context.Background(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}
