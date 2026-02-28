//go:build windows || darwin

package main

import (
	"log"
	"os"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	vpnapi "awg-split-tunnel/api/gen"
)

// ─── Log streaming ──────────────────────────────────────────────────

// StartLogStream begins streaming logs from the VPN service and emitting
// them as Wails "log-entry" events. Safe to call multiple times; only the
// first call starts the stream. Called by the frontend when the log store
// is initialized, guaranteeing no events are lost.
func (b *BindingService) StartLogStream() {
	b.logStreamOnce.Do(func() {
		go b.runLogStream()
	})
}

func (b *BindingService) runLogStream() {
	app := application.Get()

	stream, err := b.client.Service.StreamLogs(b.ctx, &vpnapi.LogStreamRequest{
		MinLevel:  vpnapi.LogLevel_LOG_LEVEL_DEBUG,
		TailLines: 1000,
	})
	if err != nil {
		log.Printf("[UI] Failed to start log stream: %v", err)
		return
	}

	for {
		entry, err := stream.Recv()
		if err != nil {
			return
		}

		var ts string
		if entry.Timestamp != nil {
			ts = entry.Timestamp.AsTime().Format(time.RFC3339Nano)
		}

		app.Event.Emit("log-entry", map[string]interface{}{
			"timestamp": ts,
			"level":     logLevelStr(entry.Level),
			"tag":       entry.Tag,
			"message":   entry.Message,
		})
	}
}

// ─── Stats streaming ─────────────────────────────────────────────

// StartStatsStream begins streaming stats from the VPN service and emitting
// them as Wails "stats-update" events. Safe to call multiple times; only the
// first call starts the stream.
func (b *BindingService) StartStatsStream() {
	b.statsStreamOnce.Do(func() {
		go b.runStatsStream()
	})
}

func (b *BindingService) runStatsStream() {
	app := application.Get()

	stream, err := b.client.Service.StreamStats(b.ctx, &vpnapi.StatsStreamRequest{
		IntervalMs: 2000,
	})
	if err != nil {
		log.Printf("[UI] Failed to start stats stream: %v", err)
		return
	}

	// Track previous tunnel states for transition detection.
	prevStates := make(map[string]vpnapi.TunnelState)

	for {
		snap, err := stream.Recv()
		if err != nil {
			return
		}

		tunnels := make([]map[string]interface{}, 0, len(snap.Tunnels))
		for _, t := range snap.Tunnels {
			tunnels = append(tunnels, map[string]interface{}{
				"tunnelId":   t.TunnelId,
				"state":      tunnelStateStr(t.State),
				"speedTx":    t.SpeedTx,
				"speedRx":    t.SpeedRx,
				"bytesTx":    t.BytesTx,
				"bytesRx":    t.BytesRx,
				"packetLoss": t.PacketLoss,
				"latencyMs":  t.LatencyMs,
				"jitterMs":   t.JitterMs,
			})

			// Detect state transitions for notifications.
			prev, hasPrev := prevStates[t.TunnelId]
			if hasPrev {
				if prev == vpnapi.TunnelState_TUNNEL_STATE_UP && t.State == vpnapi.TunnelState_TUNNEL_STATE_ERROR {
					b.notifMgr.NotifyTunnelError(t.TunnelId, "Connection lost")
				}
				if prev == vpnapi.TunnelState_TUNNEL_STATE_ERROR && t.State == vpnapi.TunnelState_TUNNEL_STATE_UP {
					b.notifMgr.NotifyReconnected(t.TunnelId)
				}
			}
			prevStates[t.TunnelId] = t.State
		}

		app.Event.Emit("stats-update", map[string]interface{}{
			"tunnels": tunnels,
		})
	}
}

func logLevelStr(l vpnapi.LogLevel) string {
	switch l {
	case vpnapi.LogLevel_LOG_LEVEL_DEBUG:
		return "DEBUG"
	case vpnapi.LogLevel_LOG_LEVEL_INFO:
		return "INFO"
	case vpnapi.LogLevel_LOG_LEVEL_WARN:
		return "WARN"
	case vpnapi.LogLevel_LOG_LEVEL_ERROR:
		return "ERROR"
	default:
		return "INFO"
	}
}

// SaveLogsToFile writes log content to the specified file path.
func (b *BindingService) SaveLogsToFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
