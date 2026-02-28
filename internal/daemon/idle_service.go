//go:build darwin

package daemon

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	vpnapi "awg-split-tunnel/api/gen"
)

// IdleService handles gRPC RPCs when the daemon is in idle state
// (no VPN stack running). Only lifecycle and config RPCs are functional;
// all VPN-related RPCs return FailedPrecondition.
type IdleService struct {
	vpnapi.UnimplementedVPNServiceServer

	ctrl      *Controller
	version   string
	startTime time.Time
}

// NewIdleService creates an IdleService bound to the given controller.
func NewIdleService(ctrl *Controller, version string) *IdleService {
	return &IdleService{
		ctrl:      ctrl,
		version:   version,
		startTime: time.Now(),
	}
}

var errIdle = status.Error(codes.FailedPrecondition, "daemon is idle; call Activate first")

// --- Lifecycle RPCs (functional in idle) ---

func (s *IdleService) GetStatus(_ context.Context, _ *emptypb.Empty) (*vpnapi.ServiceStatus, error) {
	return &vpnapi.ServiceStatus{
		Running:       true,
		ActiveTunnels: 0,
		TotalTunnels:  0,
		Version:       s.version,
		UptimeSeconds: int64(time.Since(s.startTime).Seconds()),
		DaemonState:   vpnapi.DaemonState_DAEMON_STATE_IDLE,
	}, nil
}

func (s *IdleService) Activate(_ context.Context, _ *vpnapi.ActivateRequest) (*vpnapi.ActivateResponse, error) {
	if err := s.ctrl.Activate(); err != nil {
		return &vpnapi.ActivateResponse{Success: false, Error: err.Error()}, nil
	}
	return &vpnapi.ActivateResponse{Success: true}, nil
}

func (s *IdleService) Deactivate(_ context.Context, _ *vpnapi.DeactivateRequest) (*vpnapi.DeactivateResponse, error) {
	return &vpnapi.DeactivateResponse{Success: true}, nil // already idle
}

func (s *IdleService) Shutdown(_ context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	s.ctrl.Shutdown()
	return &emptypb.Empty{}, nil
}

// --- All other RPCs unavailable in idle (GUI must Activate first) ---

func (s *IdleService) GetConfig(_ context.Context, _ *emptypb.Empty) (*vpnapi.AppConfig, error) {
	return nil, errIdle
}

func (s *IdleService) SaveConfig(_ context.Context, _ *vpnapi.SaveConfigRequest) (*vpnapi.SaveConfigResponse, error) {
	return nil, errIdle
}

func (s *IdleService) ListTunnels(_ context.Context, _ *emptypb.Empty) (*vpnapi.TunnelListResponse, error) {
	return nil, errIdle
}

func (s *IdleService) GetTunnel(_ context.Context, _ *vpnapi.GetTunnelRequest) (*vpnapi.TunnelStatus, error) {
	return nil, errIdle
}

func (s *IdleService) AddTunnel(_ context.Context, _ *vpnapi.AddTunnelRequest) (*vpnapi.AddTunnelResponse, error) {
	return nil, errIdle
}

func (s *IdleService) RemoveTunnel(_ context.Context, _ *vpnapi.RemoveTunnelRequest) (*vpnapi.RemoveTunnelResponse, error) {
	return nil, errIdle
}

func (s *IdleService) UpdateTunnel(_ context.Context, _ *vpnapi.UpdateTunnelRequest) (*vpnapi.UpdateTunnelResponse, error) {
	return nil, errIdle
}

func (s *IdleService) Connect(_ context.Context, _ *vpnapi.ConnectRequest) (*vpnapi.ConnectResponse, error) {
	return nil, errIdle
}

func (s *IdleService) Disconnect(_ context.Context, _ *vpnapi.DisconnectRequest) (*vpnapi.DisconnectResponse, error) {
	return nil, errIdle
}

func (s *IdleService) RestartTunnel(_ context.Context, _ *vpnapi.ConnectRequest) (*vpnapi.ConnectResponse, error) {
	return nil, errIdle
}

func (s *IdleService) SaveTunnelOrder(_ context.Context, _ *vpnapi.SaveTunnelOrderRequest) (*vpnapi.SaveTunnelOrderResponse, error) {
	return nil, errIdle
}

func (s *IdleService) RenameTunnel(_ context.Context, _ *vpnapi.RenameTunnelRequest) (*vpnapi.RenameTunnelResponse, error) {
	return nil, errIdle
}

func (s *IdleService) ListRules(_ context.Context, _ *emptypb.Empty) (*vpnapi.RuleListResponse, error) {
	return nil, errIdle
}

func (s *IdleService) SaveRules(_ context.Context, _ *vpnapi.SaveRulesRequest) (*vpnapi.SaveRulesResponse, error) {
	return nil, errIdle
}

func (s *IdleService) ListDomainRules(_ context.Context, _ *emptypb.Empty) (*vpnapi.DomainRuleListResponse, error) {
	return nil, errIdle
}

func (s *IdleService) SaveDomainRules(_ context.Context, _ *vpnapi.SaveDomainRulesRequest) (*vpnapi.SaveDomainRulesResponse, error) {
	return nil, errIdle
}

func (s *IdleService) ListGeositeCategories(_ context.Context, _ *emptypb.Empty) (*vpnapi.GeositeCategoriesResponse, error) {
	return nil, errIdle
}

func (s *IdleService) ListGeoIPCategories(_ context.Context, _ *emptypb.Empty) (*vpnapi.GeositeCategoriesResponse, error) {
	return nil, errIdle
}

func (s *IdleService) UpdateGeosite(_ context.Context, _ *emptypb.Empty) (*vpnapi.UpdateGeositeResponse, error) {
	return nil, errIdle
}

func (s *IdleService) StreamLogs(_ *vpnapi.LogStreamRequest, _ vpnapi.VPNService_StreamLogsServer) error {
	return errIdle
}

func (s *IdleService) StreamStats(_ *vpnapi.StatsStreamRequest, _ vpnapi.VPNService_StreamStatsServer) error {
	return errIdle
}

func (s *IdleService) ListProcesses(_ context.Context, _ *vpnapi.ProcessListRequest) (*vpnapi.ProcessListResponse, error) {
	return nil, errIdle
}

func (s *IdleService) GetAutostart(_ context.Context, _ *emptypb.Empty) (*vpnapi.AutostartConfig, error) {
	return nil, errIdle
}

func (s *IdleService) SetAutostart(_ context.Context, _ *vpnapi.SetAutostartRequest) (*vpnapi.SetAutostartResponse, error) {
	return nil, errIdle
}

func (s *IdleService) ListSubscriptions(_ context.Context, _ *emptypb.Empty) (*vpnapi.SubscriptionListResponse, error) {
	return nil, errIdle
}

func (s *IdleService) AddSubscription(_ context.Context, _ *vpnapi.AddSubscriptionRequest) (*vpnapi.AddSubscriptionResponse, error) {
	return nil, errIdle
}

func (s *IdleService) RemoveSubscription(_ context.Context, _ *vpnapi.RemoveSubscriptionRequest) (*vpnapi.RemoveSubscriptionResponse, error) {
	return nil, errIdle
}

func (s *IdleService) RefreshSubscription(_ context.Context, _ *vpnapi.RefreshSubscriptionRequest) (*vpnapi.RefreshSubscriptionResponse, error) {
	return nil, errIdle
}

func (s *IdleService) UpdateSubscription(_ context.Context, _ *vpnapi.UpdateSubscriptionRequest) (*vpnapi.UpdateSubscriptionResponse, error) {
	return nil, errIdle
}

func (s *IdleService) RestoreConnections(_ context.Context, _ *emptypb.Empty) (*vpnapi.ConnectResponse, error) {
	return nil, errIdle
}

func (s *IdleService) FlushDNS(_ context.Context, _ *emptypb.Empty) (*vpnapi.ConnectResponse, error) {
	return nil, errIdle
}

func (s *IdleService) CheckUpdate(_ context.Context, _ *emptypb.Empty) (*vpnapi.CheckUpdateResponse, error) {
	return nil, errIdle
}

func (s *IdleService) ApplyUpdate(_ context.Context, _ *emptypb.Empty) (*vpnapi.ApplyUpdateResponse, error) {
	return nil, errIdle
}

func (s *IdleService) CheckConflictingServices(_ context.Context, _ *emptypb.Empty) (*vpnapi.ConflictingServicesResponse, error) {
	return nil, errIdle
}

func (s *IdleService) StopConflictingServices(_ context.Context, _ *vpnapi.StopConflictingServicesRequest) (*vpnapi.StopConflictingServicesResponse, error) {
	return nil, errIdle
}
