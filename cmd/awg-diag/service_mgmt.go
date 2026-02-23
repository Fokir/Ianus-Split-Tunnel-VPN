//go:build windows

package main

import (
	"context"
	"fmt"
	"time"

	"awg-split-tunnel/internal/ipc"
	"awg-split-tunnel/internal/winsvc"

	"google.golang.org/protobuf/types/known/emptypb"
)

// runServiceStart starts the Windows service and verifies it's running.
func runServiceStart() {
	if !winsvc.IsServiceInstalled() {
		fatal("service %q is not installed", winsvc.ServiceName)
	}

	if winsvc.IsServiceRunning() {
		diagLog.Printf("Service is already running.")
		return
	}

	diagLog.Printf("Starting service %s...", winsvc.ServiceName)
	if err := winsvc.StartService(); err != nil {
		fatal("start service: %v", err)
	}

	// Verify the service is reachable via IPC.
	diagLog.Printf("Service started. Verifying IPC connection...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := ipc.DialWithTimeout(ctx, 15*time.Second)
	if err != nil {
		diagLog.Printf("Warning: service started but IPC not reachable: %v", err)
		return
	}
	defer client.Close()

	diagLog.Printf("Service is running and IPC is reachable.")
}

// runServiceStop stops the Windows service.
func runServiceStop() {
	if !winsvc.IsServiceInstalled() {
		fatal("service %q is not installed", winsvc.ServiceName)
	}

	if !winsvc.IsServiceRunning() {
		diagLog.Printf("Service is not running.")
		return
	}

	diagLog.Printf("Stopping service %s...", winsvc.ServiceName)
	if err := winsvc.StopService(); err != nil {
		fatal("stop service: %v", err)
	}

	diagLog.Printf("Service stopped.")
}

// runServiceStatus shows the current service status.
func runServiceStatus() {
	type statusInfo struct {
		Installed     bool   `json:"installed"`
		Running       bool   `json:"running"`
		Version       string `json:"version,omitempty"`
		ActiveTunnels int32  `json:"active_tunnels,omitempty"`
		TotalTunnels  int32  `json:"total_tunnels,omitempty"`
		UptimeSeconds int64  `json:"uptime_seconds,omitempty"`
	}

	info := statusInfo{
		Installed: winsvc.IsServiceInstalled(),
		Running:   winsvc.IsServiceRunning(),
	}

	// Try gRPC for detailed status.
	if info.Running {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		client, err := ipc.DialWithTimeout(ctx, 5*time.Second)
		if err == nil {
			defer client.Close()
			status, err := client.Service.GetStatus(ctx, &emptypb.Empty{})
			if err == nil {
				info.Version = status.GetVersion()
				info.ActiveTunnels = status.GetActiveTunnels()
				info.TotalTunnels = status.GetTotalTunnels()
				info.UptimeSeconds = status.GetUptimeSeconds()
			}
		}
	}

	if jsonOutput {
		outputJSON(info)
		return
	}

	diagLog.Printf("Service: %s", winsvc.ServiceName)
	diagLog.Printf("  Installed: %v", info.Installed)
	diagLog.Printf("  Running:   %v", info.Running)
	if info.Running {
		if info.Version != "" {
			diagLog.Printf("  Version:   %s", info.Version)
		}
		diagLog.Printf("  Tunnels:   %d active / %d total", info.ActiveTunnels, info.TotalTunnels)
		if info.UptimeSeconds > 0 {
			diagLog.Printf("  Uptime:    %s", formatDuration(time.Duration(info.UptimeSeconds)*time.Second))
		}
	}
}

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
