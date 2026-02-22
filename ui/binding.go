//go:build windows

package main

import (
	"context"
	"errors"
	"log"
	"os"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/ipc"

	"google.golang.org/protobuf/types/known/emptypb"
)

// BindingService is exposed to the Svelte frontend via Wails bindings.
// Each public method becomes callable from JavaScript.
type BindingService struct {
	client          *ipc.Client
	logStreamOnce   sync.Once
	statsStreamOnce sync.Once
}

// NewBindingService creates a BindingService wrapping the IPC client.
func NewBindingService(client *ipc.Client) *BindingService {
	return &BindingService{client: client}
}

// ─── Service status ─────────────────────────────────────────────────

type ServiceStatusResult struct {
	Running       bool   `json:"running"`
	ActiveTunnels int32  `json:"activeTunnels"`
	TotalTunnels  int32  `json:"totalTunnels"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
}

func (b *BindingService) GetStatus() (*ServiceStatusResult, error) {
	resp, err := b.client.Service.GetStatus(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return &ServiceStatusResult{
		Running:       resp.Running,
		ActiveTunnels: resp.ActiveTunnels,
		TotalTunnels:  resp.TotalTunnels,
		Version:       resp.Version,
		UptimeSeconds: resp.UptimeSeconds,
	}, nil
}

// ─── Tunnel management ──────────────────────────────────────────────

type TunnelInfo struct {
	ID         string `json:"id"`
	Protocol   string `json:"protocol"`
	Name       string `json:"name"`
	State      string `json:"state"` // "down", "connecting", "up", "error"
	Error      string `json:"error"`
	AdapterIP  string `json:"adapterIp"`
}

func tunnelStateStr(s vpnapi.TunnelState) string {
	switch s {
	case vpnapi.TunnelState_TUNNEL_STATE_DOWN:
		return "down"
	case vpnapi.TunnelState_TUNNEL_STATE_CONNECTING:
		return "connecting"
	case vpnapi.TunnelState_TUNNEL_STATE_UP:
		return "up"
	case vpnapi.TunnelState_TUNNEL_STATE_ERROR:
		return "error"
	default:
		return "unknown"
	}
}

func (b *BindingService) ListTunnels() ([]TunnelInfo, error) {
	resp, err := b.client.Service.ListTunnels(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	tunnels := make([]TunnelInfo, 0, len(resp.Tunnels))
	for _, t := range resp.Tunnels {
		info := TunnelInfo{
			ID:        t.Id,
			State:     tunnelStateStr(t.State),
			Error:     t.Error,
			AdapterIP: t.AdapterIp,
		}
		if t.Config != nil {
			info.Protocol = t.Config.Protocol
			info.Name = t.Config.Name
		}
		tunnels = append(tunnels, info)
	}
	return tunnels, nil
}

func (b *BindingService) ConnectTunnel(tunnelID string) error {
	resp, err := b.client.Service.Connect(context.Background(), &vpnapi.ConnectRequest{TunnelId: tunnelID})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

func (b *BindingService) DisconnectTunnel(tunnelID string) error {
	resp, err := b.client.Service.Disconnect(context.Background(), &vpnapi.DisconnectRequest{TunnelId: tunnelID})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

func (b *BindingService) RestartTunnel(tunnelID string) error {
	resp, err := b.client.Service.RestartTunnel(context.Background(), &vpnapi.ConnectRequest{TunnelId: tunnelID})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

func (b *BindingService) ConnectAll() error {
	resp, err := b.client.Service.Connect(context.Background(), &vpnapi.ConnectRequest{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

func (b *BindingService) DisconnectAll() error {
	resp, err := b.client.Service.Disconnect(context.Background(), &vpnapi.DisconnectRequest{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

type AddTunnelParams struct {
	ID             string            `json:"id"`
	Protocol       string            `json:"protocol"`
	Name           string            `json:"name"`
	Settings       map[string]string `json:"settings"`
	ConfigFileData []byte            `json:"configFileData"`
}

func (b *BindingService) AddTunnel(params AddTunnelParams) error {
	resp, err := b.client.Service.AddTunnel(context.Background(), &vpnapi.AddTunnelRequest{
		Config: &vpnapi.TunnelConfig{
			Id:       params.ID,
			Protocol: params.Protocol,
			Name:     params.Name,
			Settings: params.Settings,
		},
		ConfigFileData: params.ConfigFileData,
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

func (b *BindingService) RemoveTunnel(tunnelID string) error {
	resp, err := b.client.Service.RemoveTunnel(context.Background(), &vpnapi.RemoveTunnelRequest{TunnelId: tunnelID})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

// ─── Rules ──────────────────────────────────────────────────────────

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

// ─── Processes ──────────────────────────────────────────────────────

type ProcessInfo struct {
	PID  uint32 `json:"pid"`
	Name string `json:"name"`
	Path string `json:"path"`
}

func (b *BindingService) ListProcesses(nameFilter string) ([]ProcessInfo, error) {
	resp, err := b.client.Service.ListProcesses(context.Background(), &vpnapi.ProcessListRequest{NameFilter: nameFilter})
	if err != nil {
		return nil, err
	}
	procs := make([]ProcessInfo, 0, len(resp.Processes))
	for _, p := range resp.Processes {
		procs = append(procs, ProcessInfo{
			PID:  p.Pid,
			Name: p.Name,
			Path: p.Path,
		})
	}
	return procs, nil
}

// ─── Config ─────────────────────────────────────────────────────────

func (b *BindingService) GetConfig() (*vpnapi.AppConfig, error) {
	return b.client.Service.GetConfig(context.Background(), &emptypb.Empty{})
}

func (b *BindingService) SaveConfig(config *vpnapi.AppConfig, restartIfConnected bool) (bool, error) {
	resp, err := b.client.Service.SaveConfig(context.Background(), &vpnapi.SaveConfigRequest{
		Config:             config,
		RestartIfConnected: restartIfConnected,
	})
	if err != nil {
		return false, err
	}
	if !resp.Success {
		return false, errors.New(resp.Error)
	}
	return resp.Restarted, nil
}

// ─── Autostart ──────────────────────────────────────────────────────

type AutostartInfo struct {
	Enabled            bool `json:"enabled"`
	RestoreConnections bool `json:"restoreConnections"`
}

func (b *BindingService) GetAutostart() (*AutostartInfo, error) {
	resp, err := b.client.Service.GetAutostart(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return &AutostartInfo{
		Enabled:            resp.Enabled,
		RestoreConnections: resp.RestoreConnections,
	}, nil
}

func (b *BindingService) SetAutostart(enabled bool, restoreConnections bool) error {
	resp, err := b.client.Service.SetAutostart(context.Background(), &vpnapi.SetAutostartRequest{
		Config: &vpnapi.AutostartConfig{
			Enabled:            enabled,
			RestoreConnections: restoreConnections,
		},
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

func (b *BindingService) RestoreConnections() error {
	resp, err := b.client.Service.RestoreConnections(context.Background(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

// ─── Log streaming ──────────────────────────────────────────────────

// StartLogStream begins streaming logs from the VPN service and emitting
// them as Wails "log-entry" events. Safe to call multiple times; only the
// first call starts the stream. Called by the frontend when the log store
// is initialized, guaranteeing no events are lost.
func (b *BindingService) StartLogStream() {
	b.logStreamOnce.Do(func() {
		go b.runLogStream()
	})
}

func (b *BindingService) runLogStream() {
	app := application.Get()
	ctx := context.Background()

	stream, err := b.client.Service.StreamLogs(ctx, &vpnapi.LogStreamRequest{
		MinLevel:  vpnapi.LogLevel_LOG_LEVEL_DEBUG,
		TailLines: 1000,
	})
	if err != nil {
		log.Printf("[UI] Failed to start log stream: %v", err)
		return
	}

	for {
		entry, err := stream.Recv()
		if err != nil {
			return
		}

		var ts string
		if entry.Timestamp != nil {
			ts = entry.Timestamp.AsTime().Format(time.RFC3339Nano)
		}

		app.Event.Emit("log-entry", map[string]interface{}{
			"timestamp": ts,
			"level":     logLevelStr(entry.Level),
			"tag":       entry.Tag,
			"message":   entry.Message,
		})
	}
}

// ─── Stats streaming ─────────────────────────────────────────────

// StartStatsStream begins streaming stats from the VPN service and emitting
// them as Wails "stats-update" events. Safe to call multiple times; only the
// first call starts the stream.
func (b *BindingService) StartStatsStream() {
	b.statsStreamOnce.Do(func() {
		go b.runStatsStream()
	})
}

func (b *BindingService) runStatsStream() {
	app := application.Get()
	ctx := context.Background()

	stream, err := b.client.Service.StreamStats(ctx, &vpnapi.StatsStreamRequest{
		IntervalMs: 2000,
	})
	if err != nil {
		log.Printf("[UI] Failed to start stats stream: %v", err)
		return
	}

	for {
		snap, err := stream.Recv()
		if err != nil {
			return
		}

		tunnels := make([]map[string]interface{}, 0, len(snap.Tunnels))
		for _, t := range snap.Tunnels {
			tunnels = append(tunnels, map[string]interface{}{
				"tunnelId":   t.TunnelId,
				"state":      tunnelStateStr(t.State),
				"speedTx":    t.SpeedTx,
				"speedRx":    t.SpeedRx,
				"packetLoss": t.PacketLoss,
				"latencyMs":  t.LatencyMs,
				"jitterMs":   t.JitterMs,
			})
		}

		app.Event.Emit("stats-update", map[string]interface{}{
			"tunnels": tunnels,
		})
	}
}

func logLevelStr(l vpnapi.LogLevel) string {
	switch l {
	case vpnapi.LogLevel_LOG_LEVEL_DEBUG:
		return "DEBUG"
	case vpnapi.LogLevel_LOG_LEVEL_INFO:
		return "INFO"
	case vpnapi.LogLevel_LOG_LEVEL_WARN:
		return "WARN"
	case vpnapi.LogLevel_LOG_LEVEL_ERROR:
		return "ERROR"
	default:
		return "INFO"
	}
}

// SaveLogsToFile writes log content to the specified file path.
func (b *BindingService) SaveLogsToFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

// ─── Subscriptions ──────────────────────────────────────────────────

type SubscriptionInfo struct {
	Name            string `json:"name"`
	URL             string `json:"url"`
	RefreshInterval string `json:"refreshInterval"`
	UserAgent       string `json:"userAgent"`
	Prefix          string `json:"prefix"`
	TunnelCount     int32  `json:"tunnelCount"`
	LastError       string `json:"lastError"`
}

func (b *BindingService) ListSubscriptions() ([]SubscriptionInfo, error) {
	resp, err := b.client.Service.ListSubscriptions(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	subs := make([]SubscriptionInfo, 0, len(resp.Subscriptions))
	for _, s := range resp.Subscriptions {
		info := SubscriptionInfo{
			TunnelCount: s.TunnelCount,
			LastError:   s.LastError,
		}
		if s.Config != nil {
			info.Name = s.Config.Name
			info.URL = s.Config.Url
			info.RefreshInterval = s.Config.RefreshInterval
			info.UserAgent = s.Config.UserAgent
			info.Prefix = s.Config.Prefix
		}
		subs = append(subs, info)
	}
	return subs, nil
}

type AddSubscriptionParams struct {
	Name            string `json:"name"`
	URL             string `json:"url"`
	RefreshInterval string `json:"refreshInterval"`
	UserAgent       string `json:"userAgent"`
	Prefix          string `json:"prefix"`
}

type AddSubscriptionResult struct {
	TunnelCount int32  `json:"tunnelCount"`
	Error       string `json:"error"`
}

func (b *BindingService) AddSubscription(params AddSubscriptionParams) (*AddSubscriptionResult, error) {
	resp, err := b.client.Service.AddSubscription(context.Background(), &vpnapi.AddSubscriptionRequest{
		Config: &vpnapi.SubscriptionConfig{
			Name:            params.Name,
			Url:             params.URL,
			RefreshInterval: params.RefreshInterval,
			UserAgent:       params.UserAgent,
			Prefix:          params.Prefix,
		},
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return &AddSubscriptionResult{Error: resp.Error}, errors.New(resp.Error)
	}
	return &AddSubscriptionResult{TunnelCount: resp.TunnelCount}, nil
}

func (b *BindingService) RemoveSubscription(name string) error {
	resp, err := b.client.Service.RemoveSubscription(context.Background(), &vpnapi.RemoveSubscriptionRequest{Name: name})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

type RefreshResult struct {
	TunnelCount int32 `json:"tunnelCount"`
}

func (b *BindingService) RefreshSubscription(name string) (*RefreshResult, error) {
	resp, err := b.client.Service.RefreshSubscription(context.Background(), &vpnapi.RefreshSubscriptionRequest{Name: name})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return &RefreshResult{TunnelCount: resp.TunnelCount}, errors.New(resp.Error)
	}
	return &RefreshResult{TunnelCount: resp.TunnelCount}, nil
}

func (b *BindingService) RefreshAllSubscriptions() (*RefreshResult, error) {
	resp, err := b.client.Service.RefreshSubscription(context.Background(), &vpnapi.RefreshSubscriptionRequest{})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return &RefreshResult{TunnelCount: resp.TunnelCount}, errors.New(resp.Error)
	}
	return &RefreshResult{TunnelCount: resp.TunnelCount}, nil
}
