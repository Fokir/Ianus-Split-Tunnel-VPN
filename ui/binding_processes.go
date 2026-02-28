//go:build windows || darwin

package main

import (
	"context"

	vpnapi "awg-split-tunnel/api/gen"
)

// ─── Processes ──────────────────────────────────────────────────────

type ProcessInfo struct {
	PID       uint32 `json:"pid"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	Icon      string `json:"icon"`      // base64 PNG data URL (populated for windowed processes)
	HasWindow bool   `json:"hasWindow"` // process has a visible window
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
	return enrichProcessList(procs), nil
}
