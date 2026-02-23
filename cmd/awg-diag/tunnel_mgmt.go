//go:build windows

package main

import (
	"context"
	"strings"
	"time"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/ipc"

	"google.golang.org/protobuf/types/known/emptypb"
)

// runTunnelConnect connects a specific tunnel (or all if empty).
func runTunnelConnect(tunnelID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := ipc.DialWithTimeout(ctx, 5*time.Second)
	if err != nil {
		fatal("connect to service: %v", err)
	}
	defer client.Close()

	target := tunnelID
	if target == "" {
		target = "all tunnels"
	}

	diagLog.Printf("Connecting %s...", target)
	resp, err := client.Service.Connect(ctx, &vpnapi.ConnectRequest{
		TunnelId: tunnelID,
	})
	if err != nil {
		fatal("RPC Connect: %v", err)
	}

	if jsonOutput {
		outputJSON(resp)
		return
	}

	if resp.GetSuccess() {
		diagLog.Printf("Connected: %s", target)
	} else {
		fatal("connect failed: %s", resp.GetError())
	}
}

// runTunnelDisconnect disconnects a specific tunnel (or all if empty).
func runTunnelDisconnect(tunnelID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := ipc.DialWithTimeout(ctx, 5*time.Second)
	if err != nil {
		fatal("connect to service: %v", err)
	}
	defer client.Close()

	target := tunnelID
	if target == "" {
		target = "all tunnels"
	}

	diagLog.Printf("Disconnecting %s...", target)
	resp, err := client.Service.Disconnect(ctx, &vpnapi.DisconnectRequest{
		TunnelId: tunnelID,
	})
	if err != nil {
		fatal("RPC Disconnect: %v", err)
	}

	if jsonOutput {
		outputJSON(resp)
		return
	}

	if resp.GetSuccess() {
		diagLog.Printf("Disconnected: %s", target)
	} else {
		fatal("disconnect failed: %s", resp.GetError())
	}
}

// runTunnelList shows tunnels with live status.
func runTunnelList() {
	cfg, err := loadConfig()
	if err != nil {
		fatal("load config: %v", err)
	}

	type tunnelInfo struct {
		ID       string `json:"id"`
		Protocol string `json:"protocol"`
		Name     string `json:"name"`
		Status   string `json:"status"`
	}

	// Deduplicate tunnels by ID.
	seen := make(map[string]bool)
	var tunnels []tunnelInfo
	for _, t := range cfg.Tunnels {
		if seen[t.ID] {
			continue
		}
		seen[t.ID] = true
		tunnels = append(tunnels, tunnelInfo{
			ID:       t.ID,
			Protocol: t.Protocol,
			Name:     t.Name,
			Status:   "unknown",
		})
	}

	// Try IPC for live status.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := ipc.DialWithTimeout(ctx, 3*time.Second)
	if err == nil {
		defer client.Close()
		resp, err := client.Service.ListTunnels(ctx, &emptypb.Empty{})
		if err == nil {
			statusMap := make(map[string]string)
			for _, t := range resp.GetTunnels() {
				statusMap[t.GetId()] = t.GetState().String()
			}
			for i := range tunnels {
				if s, ok := statusMap[tunnels[i].ID]; ok {
					tunnels[i].Status = s
				}
			}
		}
	}

	if jsonOutput {
		outputJSON(tunnels)
		return
	}

	if len(tunnels) == 0 {
		diagLog.Printf("No tunnels configured.")
		return
	}

	diagLog.Printf("%-25s %-15s %-25s %-12s", "ID", "PROTOCOL", "NAME", "STATUS")
	diagLog.Printf("%s", strings.Repeat("-", 77))
	for _, t := range tunnels {
		diagLog.Printf("%-25s %-15s %-25s %-12s", t.ID, t.Protocol, t.Name, t.Status)
	}
}

// runTunnelStatus shows status of a specific tunnel.
func runTunnelStatus(tunnelID string) {
	type tunnelStatus struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Found  bool   `json:"found"`
	}

	result := tunnelStatus{ID: tunnelID, Status: "unknown"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := ipc.DialWithTimeout(ctx, 3*time.Second)
	if err != nil {
		fatal("connect to service: %v", err)
	}
	defer client.Close()

	resp, err := client.Service.ListTunnels(ctx, &emptypb.Empty{})
	if err != nil {
		fatal("list tunnels: %v", err)
	}

	for _, t := range resp.GetTunnels() {
		if t.GetId() == tunnelID {
			result.Status = t.GetState().String()
			result.Found = true
			break
		}
	}

	if jsonOutput {
		outputJSON(result)
		return
	}

	if !result.Found {
		diagLog.Printf("Tunnel %q not found in service.", tunnelID)
	} else {
		diagLog.Printf("Tunnel: %s  Status: %s", tunnelID, result.Status)
	}
}
