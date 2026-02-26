package service

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/gateway"
)

const (
	statsInterval = 1 * time.Second
)

// TunnelStats holds traffic statistics for a single tunnel.
type TunnelStats struct {
	TunnelID   string
	State      core.TunnelState
	BytesTx    int64
	BytesRx    int64
	SpeedTx    int64   // bytes/sec
	SpeedRx    int64   // bytes/sec
	PacketLoss float64 // 0.0-1.0
	LatencyMs  int64   // avg RTT ms
	JitterMs   int64   // max-min RTT ms
}

// StatsSnapshot is a point-in-time snapshot of all tunnel stats.
type StatsSnapshot struct {
	Tunnels   []TunnelStats
	Timestamp time.Time
}

// StatsCollector periodically gathers per-tunnel traffic statistics.
type StatsCollector struct {
	registry *core.TunnelRegistry
	bus      *core.EventBus

	cancel context.CancelFunc
	done   chan struct{}

	mu        sync.RWMutex
	latest    StatsSnapshot
	listeners []chan StatsSnapshot

	// Per-tunnel byte counters (updated externally).
	counters sync.Map // tunnelID -> *tunnelCounters

	// Diagnostics providers (jitter probes).
	diagMu    sync.RWMutex
	diagProvs map[string]gateway.DiagnosticsProvider
}

type tunnelCounters struct {
	bytesTx atomic.Int64
	bytesRx atomic.Int64
}

// NewStatsCollector creates a StatsCollector.
func NewStatsCollector(registry *core.TunnelRegistry, bus *core.EventBus) *StatsCollector {
	return &StatsCollector{
		registry:  registry,
		bus:       bus,
		done:      make(chan struct{}),
		diagProvs: make(map[string]gateway.DiagnosticsProvider),
	}
}

// Start begins periodic stats collection.
func (sc *StatsCollector) Start(ctx context.Context) {
	ctx, sc.cancel = context.WithCancel(ctx)
	go sc.loop(ctx)
}

// Stop halts stats collection and closes all listener channels.
func (sc *StatsCollector) Stop() {
	if sc.cancel != nil {
		sc.cancel()
	}
	<-sc.done

	sc.mu.Lock()
	defer sc.mu.Unlock()
	for _, ch := range sc.listeners {
		close(ch)
	}
	sc.listeners = nil
}

// Subscribe returns a channel that receives stats snapshots at each interval.
func (sc *StatsCollector) Subscribe() chan StatsSnapshot {
	ch := make(chan StatsSnapshot, 4)
	sc.mu.Lock()
	sc.listeners = append(sc.listeners, ch)
	sc.mu.Unlock()
	return ch
}

// Unsubscribe removes a listener channel.
func (sc *StatsCollector) Unsubscribe(ch chan StatsSnapshot) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for i, l := range sc.listeners {
		if l == ch {
			close(l)
			sc.listeners = append(sc.listeners[:i], sc.listeners[i+1:]...)
			return
		}
	}
}

// AddBytes records transmitted/received bytes for a tunnel.
// Called from the packet processing path.
func (sc *StatsCollector) AddBytes(tunnelID string, tx, rx int64) {
	val, _ := sc.counters.LoadOrStore(tunnelID, &tunnelCounters{})
	c := val.(*tunnelCounters)
	if tx > 0 {
		c.bytesTx.Add(tx)
	}
	if rx > 0 {
		c.bytesRx.Add(rx)
	}
}

// RegisterDiagnostics adds a diagnostics provider (e.g. JitterProbe) for a tunnel.
func (sc *StatsCollector) RegisterDiagnostics(dp gateway.DiagnosticsProvider) {
	sc.diagMu.Lock()
	sc.diagProvs[dp.TunnelID()] = dp
	sc.diagMu.Unlock()
}

// UnregisterDiagnostics removes a diagnostics provider by tunnel ID.
func (sc *StatsCollector) UnregisterDiagnostics(tunnelID string) {
	sc.diagMu.Lock()
	delete(sc.diagProvs, tunnelID)
	sc.diagMu.Unlock()
}

// Latest returns the most recent stats snapshot.
func (sc *StatsCollector) Latest() StatsSnapshot {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.latest
}

func (sc *StatsCollector) loop(ctx context.Context) {
	defer close(sc.done)
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()

	// Previous totals for speed calculation.
	prevTx := make(map[string]int64)
	prevRx := make(map[string]int64)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := sc.collect(prevTx, prevRx)

			sc.mu.Lock()
			sc.latest = snap
			listeners := make([]chan StatsSnapshot, len(sc.listeners))
			copy(listeners, sc.listeners)
			sc.mu.Unlock()

			for _, ch := range listeners {
				select {
				case ch <- snap:
				default:
				}
			}
		}
	}
}

func (sc *StatsCollector) collect(prevTx, prevRx map[string]int64) StatsSnapshot {
	tunnels := sc.registry.All()
	stats := make([]TunnelStats, 0, len(tunnels))

	// Snapshot diagnostics providers under read lock.
	sc.diagMu.RLock()
	diagSnaps := make(map[string]gateway.DiagnosticsSnapshot, len(sc.diagProvs))
	for id, dp := range sc.diagProvs {
		diagSnaps[id] = dp.Snapshot()
	}
	sc.diagMu.RUnlock()

	for _, t := range tunnels {
		var tx, rx int64
		if val, ok := sc.counters.Load(t.ID); ok {
			c := val.(*tunnelCounters)
			tx = c.bytesTx.Load()
			rx = c.bytesRx.Load()
		}

		speedTx := tx - prevTx[t.ID]
		speedRx := rx - prevRx[t.ID]
		if speedTx < 0 {
			speedTx = 0
		}
		if speedRx < 0 {
			speedRx = 0
		}
		prevTx[t.ID] = tx
		prevRx[t.ID] = rx

		ts := TunnelStats{
			TunnelID: t.ID,
			State:    t.State,
			BytesTx:  tx,
			BytesRx:  rx,
			SpeedTx:  speedTx,
			SpeedRx:  speedRx,
		}

		if ds, ok := diagSnaps[t.ID]; ok && ds.SampleCount > 0 {
			ts.PacketLoss = ds.PacketLoss
			ts.LatencyMs = ds.AvgRTT.Milliseconds()
			ts.JitterMs = ds.Jitter.Milliseconds()
		}

		stats = append(stats, ts)
	}

	return StatsSnapshot{
		Tunnels:   stats,
		Timestamp: time.Now(),
	}
}
