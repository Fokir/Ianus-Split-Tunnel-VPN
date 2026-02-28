package service

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/dpi"
)

// GetDPIEnabled returns whether DPI bypass is currently active.
func (s *Service) GetDPIEnabled(_ context.Context, _ *emptypb.Empty) (*vpnapi.GetDPIEnabledResponse, error) {
	return &vpnapi.GetDPIEnabledResponse{Enabled: s.dpiMgr != nil}, nil
}

// SetDPIEnabled dynamically enables or disables DPI bypass.
func (s *Service) SetDPIEnabled(ctx context.Context, req *vpnapi.SetDPIEnabledRequest) (*vpnapi.SetDPIEnabledResponse, error) {
	const dpiTunnelID = "dpi-bypass"

	if req.Enabled {
		// Already enabled — nothing to do.
		if s.dpiMgr != nil {
			return &vpnapi.SetDPIEnabledResponse{Success: true}, nil
		}
		if s.dpiMgrFactory == nil {
			return &vpnapi.SetDPIEnabledResponse{Success: false, Error: "DPI manager factory not configured"}, nil
		}
		mgr, err := s.dpiMgrFactory()
		if err != nil {
			return &vpnapi.SetDPIEnabledResponse{Success: false, Error: err.Error()}, nil
		}
		s.dpiMgr = mgr

		// Add ephemeral DPI bypass tunnel (not persisted to config).
		dpiCfg := core.TunnelConfig{
			ID:       dpiTunnelID,
			Protocol: core.ProtocolDPIBypass,
			Name:     "DPI Bypass",
		}
		if err := s.ctrl.AddTunnel(ctx, dpiCfg, nil); err != nil {
			core.Log.Warnf("DPI", "Failed to add DPI tunnel: %v", err)
		} else {
			_ = s.ctrl.ConnectTunnel(ctx, dpiTunnelID)
		}

		// Persist enabled state in config.
		cfg := s.cfg.Get()
		cfg.DPIBypass.Enabled = true
		s.cfg.SetQuiet(cfg)
		_ = s.cfg.Save()
	} else {
		// Already disabled — nothing to do.
		if s.dpiMgr == nil {
			return &vpnapi.SetDPIEnabledResponse{Success: true}, nil
		}

		// Remove DPI bypass tunnel.
		_ = s.ctrl.DisconnectTunnel(dpiTunnelID)
		_ = s.ctrl.RemoveTunnel(dpiTunnelID)

		s.dpiMgr.Stop()
		s.dpiMgr = nil

		// Persist disabled state in config.
		cfg := s.cfg.Get()
		cfg.DPIBypass.Enabled = false
		s.cfg.SetQuiet(cfg)
		_ = s.cfg.Save()
	}
	return &vpnapi.SetDPIEnabledResponse{Success: true}, nil
}

// ListDPIStrategies returns all known DPI bypass strategies.
func (s *Service) ListDPIStrategies(_ context.Context, _ *emptypb.Empty) (*vpnapi.ListDPIStrategiesResponse, error) {
	if s.dpiMgr == nil {
		return &vpnapi.ListDPIStrategiesResponse{}, nil
	}

	strategies := s.dpiMgr.ListStrategies()
	protos := make([]*vpnapi.DPIStrategy, 0, len(strategies))
	for _, st := range strategies {
		protos = append(protos, dpiStrategyToProto(st))
	}
	return &vpnapi.ListDPIStrategiesResponse{Strategies: protos}, nil
}

// FetchDPIStrategies downloads strategies from the zapret GitHub repository.
func (s *Service) FetchDPIStrategies(ctx context.Context, _ *emptypb.Empty) (*vpnapi.FetchDPIStrategiesResponse, error) {
	if s.dpiMgr == nil {
		return &vpnapi.FetchDPIStrategiesResponse{Success: false, Error: "DPI bypass not enabled"}, nil
	}

	strategies, err := s.dpiMgr.FetchStrategies(ctx)
	if err != nil {
		return &vpnapi.FetchDPIStrategiesResponse{Success: false, Error: err.Error()}, nil
	}

	protos := make([]*vpnapi.DPIStrategy, 0, len(strategies))
	for _, st := range strategies {
		protos = append(protos, dpiStrategyToProto(st))
	}
	return &vpnapi.FetchDPIStrategiesResponse{Success: true, Strategies: protos}, nil
}

// SelectDPIStrategy activates a named strategy.
func (s *Service) SelectDPIStrategy(_ context.Context, req *vpnapi.SelectDPIStrategyRequest) (*vpnapi.SelectDPIStrategyResponse, error) {
	if s.dpiMgr == nil {
		return &vpnapi.SelectDPIStrategyResponse{Success: false, Error: "DPI bypass not enabled"}, nil
	}

	if err := s.dpiMgr.SelectStrategy(req.Name); err != nil {
		return &vpnapi.SelectDPIStrategyResponse{Success: false, Error: err.Error()}, nil
	}
	return &vpnapi.SelectDPIStrategyResponse{Success: true}, nil
}

// StartDPISearch begins parameter search for a working strategy.
func (s *Service) StartDPISearch(ctx context.Context, req *vpnapi.StartDPISearchRequest) (*vpnapi.StartDPISearchResponse, error) {
	if s.dpiMgr == nil {
		return &vpnapi.StartDPISearchResponse{Success: false, Error: "DPI bypass not enabled"}, nil
	}

	if err := s.dpiMgr.StartSearch(ctx, req.BaseStrategy); err != nil {
		return &vpnapi.StartDPISearchResponse{Success: false, Error: err.Error()}, nil
	}
	return &vpnapi.StartDPISearchResponse{Success: true}, nil
}

// StopDPISearch stops a running parameter search.
func (s *Service) StopDPISearch(_ context.Context, _ *emptypb.Empty) (*vpnapi.StopDPISearchResponse, error) {
	if s.dpiMgr == nil {
		return &vpnapi.StopDPISearchResponse{Success: false, Error: "DPI bypass not enabled"}, nil
	}

	s.dpiMgr.StopSearch()
	return &vpnapi.StopDPISearchResponse{Success: true}, nil
}

// StreamDPISearchProgress streams search progress events to the client.
func (s *Service) StreamDPISearchProgress(_ *emptypb.Empty, stream vpnapi.VPNService_StreamDPISearchProgressServer) error {
	if s.dpiMgr == nil {
		return fmt.Errorf("DPI bypass not enabled")
	}

	// Create a channel to receive events.
	ch := make(chan core.Event, 16)
	handler := func(e core.Event) {
		select {
		case ch <- e:
		default:
			// Drop if buffer full.
		}
	}

	s.bus.Subscribe(core.EventDPISearchProgress, handler)
	s.bus.Subscribe(core.EventDPISearchComplete, handler)
	defer s.bus.Unsubscribe(core.EventDPISearchProgress, handler)
	defer s.bus.Unsubscribe(core.EventDPISearchComplete, handler)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case e := <-ch:
			msg := &vpnapi.DPISearchProgress{}
			switch p := e.Payload.(type) {
			case core.DPISearchProgressPayload:
				msg.Phase = int32(p.Phase)
				msg.Tested = int32(p.Tested)
				msg.Total = int32(p.Total)
				msg.CurrentDesc = p.CurrentDesc
			case core.DPISearchCompletePayload:
				msg.Complete = true
				msg.Found = p.Success
				msg.StrategyName = p.StrategyName
				msg.Error = p.Error
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
			// If search is complete, end the stream.
			if msg.Complete {
				return nil
			}
		}
	}
}

// ProbeDPI tests connectivity to a domain with optional DPI bypass strategy.
func (s *Service) ProbeDPI(ctx context.Context, req *vpnapi.DPIProbeRequest) (*vpnapi.DPIProbeResponse, error) {
	if s.dpiMgr == nil {
		return &vpnapi.DPIProbeResponse{Success: false, Error: "DPI bypass not enabled"}, nil
	}

	result := s.dpiMgr.Probe(ctx, req.Domain, req.StrategyName)
	return &vpnapi.DPIProbeResponse{
		Success:   result.Success,
		LatencyMs: result.Latency.Milliseconds(),
		Error:     result.Error,
	}, nil
}

// dpiStrategyToProto converts a dpi.Strategy to a proto DPIStrategy.
func dpiStrategyToProto(s *dpi.Strategy) *vpnapi.DPIStrategy {
	ps := &vpnapi.DPIStrategy{
		Name:      s.Name,
		Source:    s.Source,
		NetworkId: s.NetworkID,
	}
	if !s.LastTested.IsZero() {
		ps.LastTested = timestamppb.New(s.LastTested)
	}
	for _, op := range s.Ops {
		pop := &vpnapi.DPIDesyncOp{
			Mode:           string(op.Mode),
			FilterProtocol: op.FilterProtocol,
			FakeTtl:        int32(op.FakeTTL),
			Repeats:        int32(op.Repeats),
			SplitSeqOvl:    int32(op.SplitSeqOvl),
			Cutoff:         op.Cutoff,
		}
		for _, p := range op.FilterPorts {
			pop.FilterPorts = append(pop.FilterPorts, int32(p))
		}
		for _, f := range op.Fool {
			pop.Fool = append(pop.Fool, string(f))
		}
		for _, sp := range op.SplitPos {
			pop.SplitPos = append(pop.SplitPos, int32(sp))
		}
		ps.Ops = append(ps.Ops, pop)
	}
	return ps
}
