//go:build windows

package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/gateway"
	"awg-split-tunnel/internal/update"
)

// Ensure Service implements VPNServiceServer.
var _ vpnapi.VPNServiceServer = (*Service)(nil)

// ─── Service lifecycle ──────────────────────────────────────────────

func (s *Service) GetStatus(_ context.Context, _ *emptypb.Empty) (*vpnapi.ServiceStatus, error) {
	tunnels := s.registry.All()
	active := 0
	for _, t := range tunnels {
		if t.State == core.TunnelStateUp {
			active++
		}
	}
	return &vpnapi.ServiceStatus{
		Running:       true,
		ActiveTunnels: int32(active),
		TotalTunnels:  int32(len(tunnels)),
		Version:       s.version,
		UptimeSeconds: int64(time.Since(s.startTime).Seconds()),
	}, nil
}

func (s *Service) Shutdown(_ context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	// Signal the main process to shut down. The caller (main.go) should
	// listen for this and trigger graceful shutdown.
	s.bus.PublishAsync(core.Event{Type: core.EventConfigReloaded, Payload: "shutdown"})
	return &emptypb.Empty{}, nil
}

// ─── Tunnel management ──────────────────────────────────────────────

func (s *Service) ListTunnels(_ context.Context, _ *emptypb.Empty) (*vpnapi.TunnelListResponse, error) {
	entries := s.registry.All()
	tunnels := make([]*vpnapi.TunnelStatus, 0, len(entries))
	for _, e := range entries {
		tunnels = append(tunnels, tunnelEntryToProto(e, s.ctrl))
	}
	return &vpnapi.TunnelListResponse{Tunnels: tunnels}, nil
}

func (s *Service) GetTunnel(_ context.Context, req *vpnapi.GetTunnelRequest) (*vpnapi.TunnelStatus, error) {
	e, ok := s.registry.Get(req.TunnelId)
	if !ok {
		return nil, errNotFound("tunnel", req.TunnelId)
	}
	return tunnelEntryToProto(&e, s.ctrl), nil
}

func (s *Service) AddTunnel(ctx context.Context, req *vpnapi.AddTunnelRequest) (*vpnapi.AddTunnelResponse, error) {
	cfg := tunnelConfigFromProto(req.Config)
	if err := s.ctrl.AddTunnel(ctx, cfg, req.ConfigFileData); err != nil {
		return &vpnapi.AddTunnelResponse{Success: false, Error: err.Error()}, nil
	}
	return &vpnapi.AddTunnelResponse{Success: true}, nil
}

func (s *Service) RemoveTunnel(_ context.Context, req *vpnapi.RemoveTunnelRequest) (*vpnapi.RemoveTunnelResponse, error) {
	if err := s.ctrl.RemoveTunnel(req.TunnelId); err != nil {
		return &vpnapi.RemoveTunnelResponse{Success: false, Error: err.Error()}, nil
	}
	return &vpnapi.RemoveTunnelResponse{Success: true}, nil
}

func (s *Service) UpdateTunnel(_ context.Context, req *vpnapi.UpdateTunnelRequest) (*vpnapi.UpdateTunnelResponse, error) {
	// Update is remove + add without connect.
	cfg := tunnelConfigFromProto(req.Config)
	if err := s.ctrl.RemoveTunnel(cfg.ID); err != nil {
		return &vpnapi.UpdateTunnelResponse{Success: false, Error: err.Error()}, nil
	}
	if err := s.ctrl.AddTunnel(context.Background(), cfg, nil); err != nil {
		return &vpnapi.UpdateTunnelResponse{Success: false, Error: err.Error()}, nil
	}
	return &vpnapi.UpdateTunnelResponse{Success: true}, nil
}

func (s *Service) Connect(ctx context.Context, req *vpnapi.ConnectRequest) (*vpnapi.ConnectResponse, error) {
	var err error
	if req.TunnelId == "" {
		err = s.ctrl.ConnectAll(ctx)
	} else {
		err = s.ctrl.ConnectTunnel(ctx, req.TunnelId)
	}
	if err != nil {
		return &vpnapi.ConnectResponse{Success: false, Error: err.Error()}, nil
	}
	return &vpnapi.ConnectResponse{Success: true}, nil
}

func (s *Service) Disconnect(_ context.Context, req *vpnapi.DisconnectRequest) (*vpnapi.DisconnectResponse, error) {
	var err error
	if req.TunnelId == "" {
		err = s.ctrl.DisconnectAll()
	} else {
		err = s.ctrl.DisconnectTunnel(req.TunnelId)
	}
	if err != nil {
		return &vpnapi.DisconnectResponse{Success: false, Error: err.Error()}, nil
	}
	return &vpnapi.DisconnectResponse{Success: true}, nil
}

func (s *Service) RestartTunnel(ctx context.Context, req *vpnapi.ConnectRequest) (*vpnapi.ConnectResponse, error) {
	if err := s.ctrl.RestartTunnel(ctx, req.TunnelId); err != nil {
		return &vpnapi.ConnectResponse{Success: false, Error: err.Error()}, nil
	}
	return &vpnapi.ConnectResponse{Success: true}, nil
}

// ─── Rules ──────────────────────────────────────────────────────────

func (s *Service) ListRules(_ context.Context, _ *emptypb.Empty) (*vpnapi.RuleListResponse, error) {
	rules := s.rules.GetRules()
	protoRules := make([]*vpnapi.Rule, 0, len(rules))
	for _, r := range rules {
		pr := ruleToProto(r)
		// Mark rule as active if its tunnel is connected (or if it's a direct/drop rule).
		if r.TunnelID == "" || r.TunnelID == "__direct__" {
			pr.Active = true
		} else {
			pr.Active = s.rules.IsTunnelActive(r.TunnelID)
		}
		protoRules = append(protoRules, pr)
	}
	return &vpnapi.RuleListResponse{Rules: protoRules}, nil
}

func (s *Service) SaveRules(_ context.Context, req *vpnapi.SaveRulesRequest) (*vpnapi.SaveRulesResponse, error) {
	rules := make([]core.Rule, 0, len(req.Rules))
	for _, pr := range req.Rules {
		rules = append(rules, ruleFromProto(pr))
	}
	s.rules.SetRules(rules)
	s.cfg.SetRules(rules)
	if err := s.cfg.Save(); err != nil {
		return &vpnapi.SaveRulesResponse{Success: false, Error: err.Error()}, nil
	}
	return &vpnapi.SaveRulesResponse{Success: true}, nil
}

// ─── Domain rules ───────────────────────────────────────────────────

func (s *Service) ListDomainRules(_ context.Context, _ *emptypb.Empty) (*vpnapi.DomainRuleListResponse, error) {
	rules := s.cfg.GetDomainRules()
	protoRules := make([]*vpnapi.DomainRule, 0, len(rules))
	for _, r := range rules {
		pr := domainRuleToProto(r)
		// Mark rule as active if its tunnel is connected (or non-route action).
		if r.Action != core.DomainRoute || r.TunnelID == "" {
			pr.Active = true
		} else {
			pr.Active = s.rules.IsTunnelActive(r.TunnelID)
		}
		protoRules = append(protoRules, pr)
	}
	return &vpnapi.DomainRuleListResponse{Rules: protoRules}, nil
}

func (s *Service) SaveDomainRules(_ context.Context, req *vpnapi.SaveDomainRulesRequest) (*vpnapi.SaveDomainRulesResponse, error) {
	rules := make([]core.DomainRule, 0, len(req.Rules))
	for _, pr := range req.Rules {
		rules = append(rules, domainRuleFromProto(pr))
	}
	s.cfg.SetDomainRules(rules)
	if err := s.cfg.Save(); err != nil {
		return &vpnapi.SaveDomainRulesResponse{Success: false, Error: err.Error()}, nil
	}
	// Rebuild domain matcher with new rules.
	if s.domainReloader != nil {
		if err := s.domainReloader(rules); err != nil {
			core.Log.Warnf("Core", "Domain reloader failed: %v", err)
			return &vpnapi.SaveDomainRulesResponse{Success: false, Error: err.Error()}, nil
		}
	}
	return &vpnapi.SaveDomainRulesResponse{Success: true}, nil
}

func (s *Service) ListGeositeCategories(_ context.Context, _ *emptypb.Empty) (*vpnapi.GeositeCategoriesResponse, error) {
	if s.geositeFilePath == "" {
		return &vpnapi.GeositeCategoriesResponse{}, nil
	}
	categories, err := gateway.ListGeositeCategories(s.geositeFilePath)
	if err != nil {
		return &vpnapi.GeositeCategoriesResponse{}, nil // return empty on error
	}
	return &vpnapi.GeositeCategoriesResponse{Categories: categories}, nil
}

func (s *Service) UpdateGeosite(_ context.Context, _ *emptypb.Empty) (*vpnapi.UpdateGeositeResponse, error) {
	if s.geositeFilePath == "" {
		return &vpnapi.UpdateGeositeResponse{Success: false, Error: "geosite file path not configured"}, nil
	}
	if err := gateway.DownloadGeositeFile(s.geositeFilePath, s.httpClient); err != nil {
		return &vpnapi.UpdateGeositeResponse{Success: false, Error: err.Error()}, nil
	}
	// Rebuild domain matcher with updated geosite data.
	if s.domainReloader != nil {
		rules := s.cfg.GetDomainRules()
		if err := s.domainReloader(rules); err != nil {
			return &vpnapi.UpdateGeositeResponse{Success: false, Error: err.Error()}, nil
		}
	}
	return &vpnapi.UpdateGeositeResponse{Success: true}, nil
}

// ─── Config ─────────────────────────────────────────────────────────

func (s *Service) GetConfig(_ context.Context, _ *emptypb.Empty) (*vpnapi.AppConfig, error) {
	cfg := s.cfg.Get()
	return configToProto(cfg), nil
}

func (s *Service) SaveConfig(ctx context.Context, req *vpnapi.SaveConfigRequest) (*vpnapi.SaveConfigResponse, error) {
	newCfg := configFromProto(req.Config)

	// Preserve fields not exposed via proto.
	oldCfg := s.cfg.Get()
	newCfg.Version = core.CurrentConfigVersion
	newCfg.GUI = oldCfg.GUI
	newCfg.Update = oldCfg.Update
	// Subscriptions are now part of AppConfig proto, but if the client sends
	// an empty list we preserve the existing subscriptions (backward compat).
	if len(newCfg.Subscriptions) == 0 && len(oldCfg.Subscriptions) > 0 {
		newCfg.Subscriptions = oldCfg.Subscriptions
	}

	// Check if VPN is connected before saving.
	wasConnected := false
	if req.RestartIfConnected {
		for _, t := range s.registry.All() {
			if t.State == core.TunnelStateUp {
				wasConnected = true
				break
			}
		}
	}

	// Apply and save config.
	// Use SetQuiet to avoid publishing EventConfigReloaded before Save writes
	// the file — otherwise the main loop's reload handler calls Load() and reads
	// the stale file, overwriting the new in-memory config.
	s.cfg.SetQuiet(newCfg)
	if err := s.cfg.Save(); err != nil {
		return &vpnapi.SaveConfigResponse{Success: false, Error: err.Error()}, nil
	}
	// Now that the file is persisted, notify listeners to reload.
	s.bus.Publish(core.Event{Type: core.EventConfigReloaded})

	// Restart if needed.
	restarted := false
	if wasConnected && req.RestartIfConnected {
		_ = s.ctrl.DisconnectAll()
		_ = s.ctrl.ConnectAll(ctx)
		restarted = true
	}

	return &vpnapi.SaveConfigResponse{Success: true, Restarted: restarted}, nil
}

// ─── Streaming ──────────────────────────────────────────────────────

func (s *Service) StreamLogs(req *vpnapi.LogStreamRequest, stream vpnapi.VPNService_StreamLogsServer) error {
	minLevel := logLevelFromProto(req.MinLevel)
	sub := s.logs.Subscribe(minLevel, req.TagFilter, int(req.TailLines))
	defer s.logs.Unsubscribe(sub)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case entry, ok := <-sub.C:
			if !ok {
				return nil
			}
			if err := stream.Send(&vpnapi.LogEntry{
				Timestamp: timestamppb.New(entry.Timestamp),
				Level:     logLevelToProto(entry.Level),
				Tag:       entry.Tag,
				Message:   entry.Message,
			}); err != nil {
				return err
			}
		}
	}
}

func (s *Service) StreamStats(req *vpnapi.StatsStreamRequest, stream vpnapi.VPNService_StreamStatsServer) error {
	ch := s.stats.Subscribe()
	defer s.stats.Unsubscribe(ch)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case snap, ok := <-ch:
			if !ok {
				return nil
			}
			protoSnap := &vpnapi.StatsSnapshot{
				Timestamp: timestamppb.New(snap.Timestamp),
			}
			for _, ts := range snap.Tunnels {
				protoSnap.Tunnels = append(protoSnap.Tunnels, &vpnapi.TunnelStats{
					TunnelId: ts.TunnelID,
					State:    vpnapi.TunnelState(ts.State),
					BytesTx:  ts.BytesTx,
					BytesRx:  ts.BytesRx,
					SpeedTx:    ts.SpeedTx,
					SpeedRx:    ts.SpeedRx,
					PacketLoss: ts.PacketLoss,
					LatencyMs:  ts.LatencyMs,
					JitterMs:   ts.JitterMs,
				})
			}
			if err := stream.Send(protoSnap); err != nil {
				return err
			}
		}
	}
}

// ─── Processes ──────────────────────────────────────────────────────

func (s *Service) ListProcesses(_ context.Context, req *vpnapi.ProcessListRequest) (*vpnapi.ProcessListResponse, error) {
	procs, err := listRunningProcesses(req.NameFilter)
	if err != nil {
		return nil, err
	}
	return &vpnapi.ProcessListResponse{Processes: procs}, nil
}

// ─── Autostart ──────────────────────────────────────────────────────

func (s *Service) GetAutostart(_ context.Context, _ *emptypb.Empty) (*vpnapi.AutostartConfig, error) {
	enabled, _ := isAutostartEnabled()
	return &vpnapi.AutostartConfig{
		Enabled:            enabled,
		RestoreConnections: s.cfg.Get().GUI.RestoreConnections,
	}, nil
}

func (s *Service) SetAutostart(_ context.Context, req *vpnapi.SetAutostartRequest) (*vpnapi.SetAutostartResponse, error) {
	if err := setAutostartEnabled(req.Config.Enabled, req.Config.GuiExePath); err != nil {
		return &vpnapi.SetAutostartResponse{Success: false, Error: err.Error()}, nil
	}

	// Persist restore_connections in config.
	cfg := s.cfg.Get()
	cfg.GUI.RestoreConnections = req.Config.RestoreConnections
	s.cfg.SetFromGUI(cfg)
	if err := s.cfg.Save(); err != nil {
		return &vpnapi.SetAutostartResponse{Success: false, Error: err.Error()}, nil
	}

	return &vpnapi.SetAutostartResponse{Success: true}, nil
}

func (s *Service) RestoreConnections(ctx context.Context, _ *emptypb.Empty) (*vpnapi.ConnectResponse, error) {
	cfg := s.cfg.Get()
	if !cfg.GUI.RestoreConnections {
		return &vpnapi.ConnectResponse{Success: true}, nil
	}

	activeTunnels := cfg.GUI.ActiveTunnels
	if len(activeTunnels) == 0 {
		return &vpnapi.ConnectResponse{Success: true}, nil
	}

	var lastErr error
	for _, tunnelID := range activeTunnels {
		if err := s.ctrl.ConnectTunnel(ctx, tunnelID); err != nil {
			core.Log.Warnf("Core", "RestoreConnections: failed to connect %q: %v", tunnelID, err)
			lastErr = err
		}
	}
	if lastErr != nil {
		return &vpnapi.ConnectResponse{Success: false, Error: lastErr.Error()}, nil
	}
	return &vpnapi.ConnectResponse{Success: true}, nil
}

// ─── Subscriptions ──────────────────────────────────────────────────

func (s *Service) ListSubscriptions(_ context.Context, _ *emptypb.Empty) (*vpnapi.SubscriptionListResponse, error) {
	cfg := s.cfg.Get()
	result := make([]*vpnapi.SubscriptionStatus, 0, len(cfg.Subscriptions))
	for name, sub := range cfg.Subscriptions {
		status := &vpnapi.SubscriptionStatus{
			Config: subscriptionConfigToProto(name, sub),
		}
		if s.subMgr != nil {
			cached := s.subMgr.GetCached(name)
			status.TunnelCount = int32(len(cached))
		}
		result = append(result, status)
	}
	return &vpnapi.SubscriptionListResponse{Subscriptions: result}, nil
}

func (s *Service) AddSubscription(ctx context.Context, req *vpnapi.AddSubscriptionRequest) (*vpnapi.AddSubscriptionResponse, error) {
	if req.Config == nil || req.Config.Name == "" || req.Config.Url == "" {
		return &vpnapi.AddSubscriptionResponse{Success: false, Error: "name and url are required"}, nil
	}

	name, sub := subscriptionConfigFromProto(req.Config)

	// Add to config.
	subs := s.cfg.GetSubscriptions()
	if subs == nil {
		subs = make(map[string]core.SubscriptionConfig)
	}
	subs[name] = sub
	s.cfg.SetSubscriptions(subs)
	if err := s.cfg.Save(); err != nil {
		return &vpnapi.AddSubscriptionResponse{Success: false, Error: err.Error()}, nil
	}

	// Initial refresh.
	var tunnelCount int32
	if s.subMgr != nil {
		tunnels, err := s.subMgr.Refresh(ctx, name, sub)
		if err != nil {
			return &vpnapi.AddSubscriptionResponse{Success: true, Error: "saved but refresh failed: " + err.Error()}, nil
		}
		tunnelCount = int32(len(tunnels))
		// Sync tunnels into the controller so they appear in the GUI.
		s.syncSubscriptionTunnels(ctx, name, tunnels)
	}

	return &vpnapi.AddSubscriptionResponse{Success: true, TunnelCount: tunnelCount}, nil
}

func (s *Service) RemoveSubscription(_ context.Context, req *vpnapi.RemoveSubscriptionRequest) (*vpnapi.RemoveSubscriptionResponse, error) {
	if req.Name == "" {
		return &vpnapi.RemoveSubscriptionResponse{Success: false, Error: "name is required"}, nil
	}

	subs := s.cfg.GetSubscriptions()
	if _, ok := subs[req.Name]; !ok {
		return &vpnapi.RemoveSubscriptionResponse{Success: false, Error: "subscription not found"}, nil
	}
	delete(subs, req.Name)
	s.cfg.SetSubscriptions(subs)
	if err := s.cfg.Save(); err != nil {
		return &vpnapi.RemoveSubscriptionResponse{Success: false, Error: err.Error()}, nil
	}

	// Remove all tunnels belonging to this subscription.
	s.removeSubscriptionTunnels(req.Name)

	return &vpnapi.RemoveSubscriptionResponse{Success: true}, nil
}

func (s *Service) RefreshSubscription(ctx context.Context, req *vpnapi.RefreshSubscriptionRequest) (*vpnapi.RefreshSubscriptionResponse, error) {
	if s.subMgr == nil {
		return &vpnapi.RefreshSubscriptionResponse{Success: false, Error: "subscription manager not initialized"}, nil
	}

	if req.Name == "" {
		// Refresh all subscriptions and sync tunnels.
		tunnels, err := s.subMgr.RefreshAll(ctx)
		if err != nil {
			// Still sync whatever was fetched successfully.
			s.syncAllSubscriptionTunnels(ctx)
			return &vpnapi.RefreshSubscriptionResponse{Success: false, Error: err.Error(), TunnelCount: int32(len(tunnels))}, nil
		}
		s.syncAllSubscriptionTunnels(ctx)
		return &vpnapi.RefreshSubscriptionResponse{Success: true, TunnelCount: int32(len(tunnels))}, nil
	}

	// Refresh specific subscription and sync its tunnels.
	cfg := s.cfg.Get()
	sub, ok := cfg.Subscriptions[req.Name]
	if !ok {
		return &vpnapi.RefreshSubscriptionResponse{Success: false, Error: "subscription not found"}, nil
	}
	tunnels, err := s.subMgr.Refresh(ctx, req.Name, sub)
	if err != nil {
		return &vpnapi.RefreshSubscriptionResponse{Success: false, Error: err.Error()}, nil
	}
	s.syncSubscriptionTunnels(ctx, req.Name, tunnels)
	return &vpnapi.RefreshSubscriptionResponse{Success: true, TunnelCount: int32(len(tunnels))}, nil
}

// ─── Subscription tunnel sync ──────────────────────────────────────

// syncSubscriptionTunnels reconciles the running tunnels for a single
// subscription with the freshly-fetched list. New tunnels are added via
// TunnelController; stale ones are removed.
func (s *Service) syncSubscriptionTunnels(ctx context.Context, subName string, wanted []core.TunnelConfig) {
	wantedIDs := make(map[string]struct{}, len(wanted))
	for _, tc := range wanted {
		wantedIDs[tc.ID] = struct{}{}
	}

	// Remove tunnels that no longer appear in the subscription.
	for _, entry := range s.registry.All() {
		sub, ok := entry.Config.Settings["_subscription"]
		if !ok {
			continue
		}
		if subStr, _ := sub.(string); subStr == subName {
			if _, keep := wantedIDs[entry.ID]; !keep {
				if err := s.ctrl.RemoveTunnel(entry.ID); err != nil {
					core.Log.Warnf("Core", "Failed to remove stale subscription tunnel %q: %v", entry.ID, err)
				}
			}
		}
	}

	// Add tunnels that are not yet registered.
	for _, tc := range wanted {
		if _, exists := s.registry.Get(tc.ID); exists {
			continue
		}
		if err := s.ctrl.AddTunnel(ctx, tc, nil); err != nil {
			core.Log.Warnf("Core", "Failed to add subscription tunnel %q: %v", tc.ID, err)
		}
	}
}

// syncAllSubscriptionTunnels refreshes tunnels for every configured
// subscription using the current cache.
func (s *Service) syncAllSubscriptionTunnels(ctx context.Context) {
	subs := s.cfg.GetSubscriptions()
	for name := range subs {
		cached := s.subMgr.GetCached(name)
		s.syncSubscriptionTunnels(ctx, name, cached)
	}
}

// removeSubscriptionTunnels removes all running tunnels that belong to
// the given subscription.
func (s *Service) removeSubscriptionTunnels(subName string) {
	for _, entry := range s.registry.All() {
		sub, ok := entry.Config.Settings["_subscription"]
		if !ok {
			continue
		}
		if subStr, _ := sub.(string); subStr == subName {
			if err := s.ctrl.RemoveTunnel(entry.ID); err != nil {
				core.Log.Warnf("Core", "Failed to remove subscription tunnel %q: %v", entry.ID, err)
			}
		}
	}
}

// ─── Updates ─────────────────────────────────────────────────────────

func (s *Service) CheckUpdate(ctx context.Context, _ *emptypb.Empty) (*vpnapi.CheckUpdateResponse, error) {
	if s.updateChecker == nil {
		return &vpnapi.CheckUpdateResponse{Available: false}, nil
	}

	info, err := s.updateChecker.CheckNow(ctx)
	if err != nil {
		return &vpnapi.CheckUpdateResponse{Available: false}, nil
	}
	if info == nil {
		return &vpnapi.CheckUpdateResponse{Available: false}, nil
	}

	return &vpnapi.CheckUpdateResponse{
		Available: true,
		Info: &vpnapi.UpdateInfo{
			Version:      info.Version,
			ReleaseNotes: info.ReleaseNotes,
			AssetUrl:     info.AssetURL,
			AssetSize:    info.AssetSize,
		},
	}, nil
}

func (s *Service) ApplyUpdate(ctx context.Context, _ *emptypb.Empty) (*vpnapi.ApplyUpdateResponse, error) {
	if s.updateChecker == nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: "update checker not initialized"}, nil
	}

	info := s.updateChecker.GetLatestInfo()
	if info == nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: "no update available"}, nil
	}

	// Download the update.
	extractDir, err := update.Download(ctx, info, s.httpClient, nil)
	if err != nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: fmt.Sprintf("download failed: %v", err)}, nil
	}

	// Find updater binary in the current install directory.
	exe, err := os.Executable()
	if err != nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: fmt.Sprintf("cannot determine install dir: %v", err)}, nil
	}
	installDir := filepath.Dir(exe)
	updaterPath := filepath.Join(installDir, "awg-split-tunnel-updater.exe")

	if _, err := os.Stat(updaterPath); err != nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: "updater binary not found"}, nil
	}

	// Launch updater process.
	core.Log.Infof("Update", "Launching updater: %s", updaterPath)
	attr := &os.ProcAttr{
		Dir:   installDir,
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	}
	_, err = os.StartProcess(updaterPath, []string{
		updaterPath,
		"--install-dir", installDir,
		"--temp-dir", extractDir,
		"--start-service",
		"--launch-gui",
	}, attr)
	if err != nil {
		return &vpnapi.ApplyUpdateResponse{Success: false, Error: fmt.Sprintf("failed to launch updater: %v", err)}, nil
	}

	// Signal shutdown after a short delay so the response gets sent first.
	go func() {
		time.Sleep(500 * time.Millisecond)
		s.bus.PublishAsync(core.Event{Type: core.EventConfigReloaded, Payload: "shutdown"})
	}()

	return &vpnapi.ApplyUpdateResponse{Success: true}, nil
}
