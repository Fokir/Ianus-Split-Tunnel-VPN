//go:build windows || darwin

package main

import (
	"context"

	vpnapi "awg-split-tunnel/api/gen"

	"google.golang.org/protobuf/types/known/emptypb"
)

// ─── Conflicting services ──────────────────────────────────────────

type ConflictingServiceResult struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Type        string `json:"type"`
	Running     bool   `json:"running"`
	Description string `json:"description"`
}

func (b *BindingService) CheckConflictingServices() ([]ConflictingServiceResult, error) {
	resp, err := b.client.Service.CheckConflictingServices(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	result := make([]ConflictingServiceResult, 0, len(resp.Services))
	for _, s := range resp.Services {
		result = append(result, ConflictingServiceResult{
			Name:        s.Name,
			DisplayName: s.DisplayName,
			Type:        s.Type,
			Running:     s.Running,
			Description: s.Description,
		})
	}
	return result, nil
}

func (b *BindingService) StopConflictingServices(names []string) (map[string]interface{}, error) {
	resp, err := b.client.Service.StopConflictingServices(context.Background(), &vpnapi.StopConflictingServicesRequest{
		Names: names,
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"success": resp.Success,
		"error":   resp.Error,
		"stopped": resp.Stopped,
		"failed":  resp.Failed,
	}, nil
}
