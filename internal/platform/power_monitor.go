package platform

import (
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
)

// PowerMonitor detects system sleep/wake events using a heartbeat approach:
// a goroutine ticks at a regular interval and measures the wall-clock gap
// between ticks. A gap significantly larger than the tick period indicates
// the process was frozen (system sleep/hibernation/AppNap), after which
// OnWake is invoked on a fresh goroutine.
//
// Works uniformly on macOS and Windows without platform APIs. Does NOT fire
// on garbage collection pauses or scheduler stalls — wake gaps are measured
// in seconds, not milliseconds.
type PowerMonitor struct {
	tick      time.Duration
	threshold time.Duration
	onWake    func(gap time.Duration)

	mu     sync.Mutex
	done   chan struct{}
	closed bool
}

// NewPowerMonitor creates a heartbeat-based sleep/wake detector.
// A gap > threshold between ticks triggers onWake(gap).
// Recommended defaults: tick=2s, threshold=10s.
func NewPowerMonitor(tick, threshold time.Duration, onWake func(gap time.Duration)) *PowerMonitor {
	if tick <= 0 {
		tick = 2 * time.Second
	}
	if threshold <= 0 {
		threshold = 10 * time.Second
	}
	return &PowerMonitor{
		tick:      tick,
		threshold: threshold,
		onWake:    onWake,
		done:      make(chan struct{}),
	}
}

// Start begins the heartbeat loop.
func (pm *PowerMonitor) Start() {
	go pm.loop()
	core.Log.Infof("Core", "Power monitor started (tick=%s, threshold=%s)", pm.tick, pm.threshold)
}

// Stop terminates the heartbeat loop.
func (pm *PowerMonitor) Stop() {
	pm.mu.Lock()
	if pm.closed {
		pm.mu.Unlock()
		return
	}
	pm.closed = true
	close(pm.done)
	pm.mu.Unlock()
}

func (pm *PowerMonitor) loop() {
	ticker := time.NewTicker(pm.tick)
	defer ticker.Stop()

	// Strip the monotonic clock reading so Sub uses wall-clock subtraction.
	// macOS freezes the monotonic clock during system sleep, so monotonic
	// gaps never exceed the tick interval and we'd miss every wake event.
	last := time.Now().Round(0)
	for {
		select {
		case <-pm.done:
			return
		case now := <-ticker.C:
			now = now.Round(0)
			gap := now.Sub(last)
			last = now
			if gap < pm.threshold {
				continue
			}
			core.Log.Warnf("Core", "Power monitor: detected wake (gap=%s, threshold=%s)", gap.Round(time.Second), pm.threshold)
			if pm.onWake != nil {
				go pm.onWake(gap)
			}
		}
	}
}
