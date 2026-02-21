//go:build windows

package service

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/core"
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

// ─── Config ─────────────────────────────────────────────────────────

func (s *Service) GetConfig(_ context.Context, _ *emptypb.Empty) (*vpnapi.AppConfig, error) {
	cfg := s.cfg.Get()
	return configToProto(cfg), nil
}

func (s *Service) SaveConfig(ctx context.Context, req *vpnapi.SaveConfigRequest) (*vpnapi.SaveConfigResponse, error) {
	newCfg := configFromProto(req.Config)

	// Preserve GUI-only fields not present in the proto AppConfig.
	oldCfg := s.cfg.Get()
	newCfg.GUI = oldCfg.GUI

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
	s.cfg.SetFromGUI(newCfg)
	if err := s.cfg.Save(); err != nil {
		return &vpnapi.SaveConfigResponse{Success: false, Error: err.Error()}, nil
	}

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
	if err := setAutostartEnabled(req.Config.Enabled); err != nil {
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
