//go:build windows || darwin

package main

import (
	"context"
	"errors"

	vpnapi "awg-split-tunnel/api/gen"

	"google.golang.org/protobuf/types/known/emptypb"
)

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

type UpdateSubscriptionParams struct {
	Name            string `json:"name"`
	URL             string `json:"url"`
	RefreshInterval string `json:"refreshInterval"`
	UserAgent       string `json:"userAgent"`
	Prefix          string `json:"prefix"`
}

// UpdateSubscription updates an existing subscription's configuration.
func (b *BindingService) UpdateSubscription(params UpdateSubscriptionParams) error {
	resp, err := b.client.Service.UpdateSubscription(context.Background(), &vpnapi.UpdateSubscriptionRequest{
		Config: &vpnapi.SubscriptionConfig{
			Name:            params.Name,
			Url:             params.URL,
			RefreshInterval: params.RefreshInterval,
			UserAgent:       params.UserAgent,
			Prefix:          params.Prefix,
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
