//go:build darwin

package daemon

import (
	"context"
	"sync"

	"google.golang.org/protobuf/types/known/emptypb"

	vpnapi "awg-split-tunnel/api/gen"
)

// ServiceDelegator implements VPNServiceServer by forwarding every RPC
// to either the IdleService (when VPN is not running) or the active
// Service (when VPN stack is up). Switching happens atomically via
// SetActiveService / ClearActiveService.
type ServiceDelegator struct {
	vpnapi.UnimplementedVPNServiceServer

	mu     sync.RWMutex
	idle   *IdleService
	active vpnapi.VPNServiceServer // nil when idle
}

// NewServiceDelegator creates a delegator with the given idle service.
func NewServiceDelegator(idle *IdleService) *ServiceDelegator {
	return &ServiceDelegator{idle: idle}
}

// SetActiveService switches all RPCs to the active VPN service.
func (d *ServiceDelegator) SetActiveService(svc vpnapi.VPNServiceServer) {
	d.mu.Lock()
	d.active = svc
	d.mu.Unlock()
}

// ClearActiveService reverts all RPCs back to the idle service.
func (d *ServiceDelegator) ClearActiveService() {
	d.mu.Lock()
	d.active = nil
	d.mu.Unlock()
}

// current returns the active service if set, otherwise the idle service.
func (d *ServiceDelegator) current() vpnapi.VPNServiceServer {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.active != nil {
		return d.active
	}
	return d.idle
}

// isActive returns true if VPN stack is running.
func (d *ServiceDelegator) isActive() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.active != nil
}

// --- Service lifecycle ---

func (d *ServiceDelegator) GetStatus(ctx context.Context, req *emptypb.Empty) (*vpnapi.ServiceStatus, error) {
	resp, err := d.current().GetStatus(ctx, req)
	if err != nil {
		return nil, err
	}
	// Inject DaemonState based on current mode.
	if d.isActive() {
		resp.DaemonState = vpnapi.DaemonState_DAEMON_STATE_ACTIVE
	}
	// else: idle service already sets DAEMON_STATE_IDLE
	return resp, nil
}

func (d *ServiceDelegator) Shutdown(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	return d.current().Shutdown(ctx, req)
}

func (d *ServiceDelegator) Activate(ctx context.Context, req *vpnapi.ActivateRequest) (*vpnapi.ActivateResponse, error) {
	// Always route to idle service — it knows how to trigger activation.
	return d.idle.Activate(ctx, req)
}

func (d *ServiceDelegator) Deactivate(ctx context.Context, req *vpnapi.DeactivateRequest) (*vpnapi.DeactivateResponse, error) {
	return d.idle.Deactivate(ctx, req)
}

// --- Tunnel management ---

func (d *ServiceDelegator) ListTunnels(ctx context.Context, req *emptypb.Empty) (*vpnapi.TunnelListResponse, error) {
	return d.current().ListTunnels(ctx, req)
}

func (d *ServiceDelegator) GetTunnel(ctx context.Context, req *vpnapi.GetTunnelRequest) (*vpnapi.TunnelStatus, error) {
	return d.current().GetTunnel(ctx, req)
}

func (d *ServiceDelegator) AddTunnel(ctx context.Context, req *vpnapi.AddTunnelRequest) (*vpnapi.AddTunnelResponse, error) {
	return d.current().AddTunnel(ctx, req)
}

func (d *ServiceDelegator) RemoveTunnel(ctx context.Context, req *vpnapi.RemoveTunnelRequest) (*vpnapi.RemoveTunnelResponse, error) {
	return d.current().RemoveTunnel(ctx, req)
}

func (d *ServiceDelegator) UpdateTunnel(ctx context.Context, req *vpnapi.UpdateTunnelRequest) (*vpnapi.UpdateTunnelResponse, error) {
	return d.current().UpdateTunnel(ctx, req)
}

func (d *ServiceDelegator) Connect(ctx context.Context, req *vpnapi.ConnectRequest) (*vpnapi.ConnectResponse, error) {
	return d.current().Connect(ctx, req)
}

func (d *ServiceDelegator) Disconnect(ctx context.Context, req *vpnapi.DisconnectRequest) (*vpnapi.DisconnectResponse, error) {
	return d.current().Disconnect(ctx, req)
}

func (d *ServiceDelegator) RestartTunnel(ctx context.Context, req *vpnapi.ConnectRequest) (*vpnapi.ConnectResponse, error) {
	return d.current().RestartTunnel(ctx, req)
}

func (d *ServiceDelegator) SaveTunnelOrder(ctx context.Context, req *vpnapi.SaveTunnelOrderRequest) (*vpnapi.SaveTunnelOrderResponse, error) {
	return d.current().SaveTunnelOrder(ctx, req)
}

func (d *ServiceDelegator) RenameTunnel(ctx context.Context, req *vpnapi.RenameTunnelRequest) (*vpnapi.RenameTunnelResponse, error) {
	return d.current().RenameTunnel(ctx, req)
}

// --- Rules ---

func (d *ServiceDelegator) ListRules(ctx context.Context, req *emptypb.Empty) (*vpnapi.RuleListResponse, error) {
	return d.current().ListRules(ctx, req)
}

func (d *ServiceDelegator) SaveRules(ctx context.Context, req *vpnapi.SaveRulesRequest) (*vpnapi.SaveRulesResponse, error) {
	return d.current().SaveRules(ctx, req)
}

// --- Domain rules ---

func (d *ServiceDelegator) ListDomainRules(ctx context.Context, req *emptypb.Empty) (*vpnapi.DomainRuleListResponse, error) {
	return d.current().ListDomainRules(ctx, req)
}

func (d *ServiceDelegator) SaveDomainRules(ctx context.Context, req *vpnapi.SaveDomainRulesRequest) (*vpnapi.SaveDomainRulesResponse, error) {
	return d.current().SaveDomainRules(ctx, req)
}

func (d *ServiceDelegator) ListGeositeCategories(ctx context.Context, req *emptypb.Empty) (*vpnapi.GeositeCategoriesResponse, error) {
	return d.current().ListGeositeCategories(ctx, req)
}

func (d *ServiceDelegator) ListGeoIPCategories(ctx context.Context, req *emptypb.Empty) (*vpnapi.GeositeCategoriesResponse, error) {
	return d.current().ListGeoIPCategories(ctx, req)
}

func (d *ServiceDelegator) UpdateGeosite(ctx context.Context, req *emptypb.Empty) (*vpnapi.UpdateGeositeResponse, error) {
	return d.current().UpdateGeosite(ctx, req)
}

// --- Config ---

func (d *ServiceDelegator) GetConfig(ctx context.Context, req *emptypb.Empty) (*vpnapi.AppConfig, error) {
	return d.current().GetConfig(ctx, req)
}

func (d *ServiceDelegator) SaveConfig(ctx context.Context, req *vpnapi.SaveConfigRequest) (*vpnapi.SaveConfigResponse, error) {
	return d.current().SaveConfig(ctx, req)
}

// --- Streaming ---

func (d *ServiceDelegator) StreamLogs(req *vpnapi.LogStreamRequest, stream vpnapi.VPNService_StreamLogsServer) error {
	return d.current().StreamLogs(req, stream)
}

func (d *ServiceDelegator) StreamStats(req *vpnapi.StatsStreamRequest, stream vpnapi.VPNService_StreamStatsServer) error {
	return d.current().StreamStats(req, stream)
}

// --- Processes ---

func (d *ServiceDelegator) ListProcesses(ctx context.Context, req *vpnapi.ProcessListRequest) (*vpnapi.ProcessListResponse, error) {
	return d.current().ListProcesses(ctx, req)
}

// --- Autostart ---

func (d *ServiceDelegator) GetAutostart(ctx context.Context, req *emptypb.Empty) (*vpnapi.AutostartConfig, error) {
	return d.current().GetAutostart(ctx, req)
}

func (d *ServiceDelegator) SetAutostart(ctx context.Context, req *vpnapi.SetAutostartRequest) (*vpnapi.SetAutostartResponse, error) {
	return d.current().SetAutostart(ctx, req)
}

// --- Subscriptions ---

func (d *ServiceDelegator) ListSubscriptions(ctx context.Context, req *emptypb.Empty) (*vpnapi.SubscriptionListResponse, error) {
	return d.current().ListSubscriptions(ctx, req)
}

func (d *ServiceDelegator) AddSubscription(ctx context.Context, req *vpnapi.AddSubscriptionRequest) (*vpnapi.AddSubscriptionResponse, error) {
	return d.current().AddSubscription(ctx, req)
}

func (d *ServiceDelegator) RemoveSubscription(ctx context.Context, req *vpnapi.RemoveSubscriptionRequest) (*vpnapi.RemoveSubscriptionResponse, error) {
	return d.current().RemoveSubscription(ctx, req)
}

func (d *ServiceDelegator) RefreshSubscription(ctx context.Context, req *vpnapi.RefreshSubscriptionRequest) (*vpnapi.RefreshSubscriptionResponse, error) {
	return d.current().RefreshSubscription(ctx, req)
}

func (d *ServiceDelegator) UpdateSubscription(ctx context.Context, req *vpnapi.UpdateSubscriptionRequest) (*vpnapi.UpdateSubscriptionResponse, error) {
	return d.current().UpdateSubscription(ctx, req)
}

// --- Connection restore ---

func (d *ServiceDelegator) RestoreConnections(ctx context.Context, req *emptypb.Empty) (*vpnapi.ConnectResponse, error) {
	return d.current().RestoreConnections(ctx, req)
}

// --- DNS ---

func (d *ServiceDelegator) FlushDNS(ctx context.Context, req *emptypb.Empty) (*vpnapi.ConnectResponse, error) {
	return d.current().FlushDNS(ctx, req)
}

// --- Updates ---

func (d *ServiceDelegator) CheckUpdate(ctx context.Context, req *emptypb.Empty) (*vpnapi.CheckUpdateResponse, error) {
	return d.current().CheckUpdate(ctx, req)
}

func (d *ServiceDelegator) ApplyUpdate(ctx context.Context, req *emptypb.Empty) (*vpnapi.ApplyUpdateResponse, error) {
	return d.current().ApplyUpdate(ctx, req)
}

// --- Conflicting services ---

func (d *ServiceDelegator) CheckConflictingServices(ctx context.Context, req *emptypb.Empty) (*vpnapi.ConflictingServicesResponse, error) {
	return d.current().CheckConflictingServices(ctx, req)
}

func (d *ServiceDelegator) StopConflictingServices(ctx context.Context, req *vpnapi.StopConflictingServicesRequest) (*vpnapi.StopConflictingServicesResponse, error) {
	return d.current().StopConflictingServices(ctx, req)
}
