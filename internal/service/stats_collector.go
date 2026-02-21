//go:build windows

package service

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"awg-split-tunnel/internal/core"
)

const (
	statsInterval = 1 * time.Second
)

// TunnelStats holds traffic statistics for a single tunnel.
type TunnelStats struct {
	TunnelID  string
	State     core.TunnelState
	BytesTx   int64
	BytesRx   int64
	SpeedTx   int64 // bytes/sec
	SpeedRx   int64 // bytes/sec
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
}

type tunnelCounters struct {
	bytesTx atomic.Int64
	bytesRx atomic.Int64
}

// NewStatsCollector creates a StatsCollector.
func NewStatsCollector(registry *core.TunnelRegistry, bus *core.EventBus) *StatsCollector {
	return &StatsCollector{
		registry: registry,
		bus:      bus,
		done:     make(chan struct{}),
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

		stats = append(stats, TunnelStats{
			TunnelID: t.ID,
			State:    t.State,
			BytesTx:  tx,
			BytesRx:  rx,
			SpeedTx:  speedTx,
			SpeedRx:  speedRx,
		})
	}

	return StatsSnapshot{
		Tunnels:   stats,
		Timestamp: time.Now(),
	}
}
