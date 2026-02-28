//go:build windows || darwin

package main

import (
	"context"
	"errors"

	"github.com/wailsapp/wails/v3/pkg/application"

	vpnapi "awg-split-tunnel/api/gen"

	"google.golang.org/protobuf/types/known/emptypb"
)

// ─── Tunnel management ──────────────────────────────────────────────

type TunnelInfo struct {
	ID          string `json:"id"`
	Protocol    string `json:"protocol"`
	Name        string `json:"name"`
	State       string `json:"state"` // "down", "connecting", "up", "error"
	Error       string `json:"error"`
	AdapterIP   string `json:"adapterIp"`
	ExternalIP  string `json:"externalIp"`
	CountryCode string `json:"countryCode"`
	SortIndex   int    `json:"sortIndex"`
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
			ID:          t.Id,
			State:       tunnelStateStr(t.State),
			Error:       t.Error,
			AdapterIP:   t.AdapterIp,
			ExternalIP:  t.ExternalIp,
			CountryCode: t.CountryCode,
			SortIndex:   int(t.SortIndex),
		}
		if t.Config != nil {
			info.Protocol = t.Config.Protocol
			info.Name = t.Config.Name
		}
		tunnels = append(tunnels, info)
	}
	return tunnels, nil
}

func (b *BindingService) emitTunnelsChanged() {
	if app := application.Get(); app != nil {
		app.Event.Emit("tunnels-changed", nil)
	}
}

func (b *BindingService) ConnectTunnel(tunnelID string) error {
	resp, err := b.client.Service.Connect(context.Background(), &vpnapi.ConnectRequest{TunnelId: tunnelID})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	b.emitTunnelsChanged()
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
	b.emitTunnelsChanged()
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
	b.emitTunnelsChanged()
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
	b.emitTunnelsChanged()
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
	b.emitTunnelsChanged()
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
	b.emitTunnelsChanged()
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
	b.emitTunnelsChanged()
	return nil
}

// SaveTunnelOrder persists the display order of tunnels.
func (b *BindingService) SaveTunnelOrder(tunnelIDs []string) error {
	resp, err := b.client.Service.SaveTunnelOrder(context.Background(), &vpnapi.SaveTunnelOrderRequest{TunnelIds: tunnelIDs})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	return nil
}

// RenameTunnel sets a custom display name for a tunnel.
func (b *BindingService) RenameTunnel(tunnelID, name string) error {
	resp, err := b.client.Service.RenameTunnel(context.Background(), &vpnapi.RenameTunnelRequest{
		TunnelId: tunnelID,
		Name:     name,
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return errors.New(resp.Error)
	}
	b.emitTunnelsChanged()
	return nil
}
