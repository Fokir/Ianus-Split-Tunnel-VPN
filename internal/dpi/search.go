package dpi

import (
	"context"
	"fmt"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
)

// SearchState represents the current state of a parameter search.
type SearchState int

const (
	SearchIdle     SearchState = iota
	SearchRunning
	SearchStopped
	SearchComplete
)

// ParameterSearcher performs directed parameter search to find working
// DPI bypass strategies. It modifies one parameter at a time from a base
// strategy and tests each variation against the target domains.
type ParameterSearcher struct {
	probe  *ProbeRunner
	bus    *core.EventBus
	cache  *CacheManager

	mu      sync.Mutex
	state   SearchState
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// NewParameterSearcher creates a parameter searcher.
func NewParameterSearcher(probe *ProbeRunner, bus *core.EventBus, cache *CacheManager) *ParameterSearcher {
	return &ParameterSearcher{
		probe: probe,
		bus:   bus,
		cache: cache,
		state: SearchIdle,
	}
}

// State returns the current search state.
func (ps *ParameterSearcher) State() SearchState {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.state
}

// Start begins a parameter search using the given base strategy and test domains.
// The search runs in a goroutine and publishes progress events.
func (ps *ParameterSearcher) Start(ctx context.Context, base *Strategy, testDomains []string, networkID string) error {
	ps.mu.Lock()
	if ps.state == SearchRunning {
		ps.mu.Unlock()
		return fmt.Errorf("search already running")
	}
	ps.state = SearchRunning
	ps.stopCh = make(chan struct{})
	ps.doneCh = make(chan struct{})
	ps.mu.Unlock()

	go ps.run(ctx, base, testDomains, networkID)
	return nil
}

// Stop requests the running search to stop gracefully.
func (ps *ParameterSearcher) Stop() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.state == SearchRunning && ps.stopCh != nil {
		close(ps.stopCh)
		ps.state = SearchStopped
	}
}

// Wait blocks until the search completes or is stopped.
func (ps *ParameterSearcher) Wait() {
	ps.mu.Lock()
	ch := ps.doneCh
	ps.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

func (ps *ParameterSearcher) run(ctx context.Context, base *Strategy, testDomains []string, networkID string) {
	defer func() {
		ps.mu.Lock()
		if ps.state == SearchRunning {
			ps.state = SearchComplete
		}
		close(ps.doneCh)
		ps.mu.Unlock()
	}()

	if len(testDomains) == 0 {
		testDomains = []string{"youtube.com", "discord.com"}
	}

	testDomain := testDomains[0]

	// Phase 0: Baseline — test the base strategy as-is.
	ps.publishProgress(0, 0, 1, "Testing base strategy")
	if ps.isStopped() {
		return
	}

	if base != nil && len(base.Ops) > 0 {
		result := ps.probe.TestWithStrategy(ctx, testDomain, base)
		if result.Success {
			core.Log.Infof("DPI", "Search: base strategy works! (%s, %v)", testDomain, result.Latency)
			ps.publishComplete(true, base.Name, "")
			ps.saveResult(base, networkID)
			return
		}
		core.Log.Infof("DPI", "Search: base strategy failed: %s", result.Error)
	}

	// Phase 1: Single parameter variation.
	variations := ps.generatePhase1Variations(base)
	total := len(variations)
	core.Log.Infof("DPI", "Search Phase 1: %d variations to test", total)

	var bestStrategy *Strategy
	for i, v := range variations {
		if ps.isStopped() {
			return
		}

		ps.publishProgress(1, i, total, v.desc)
		result := ps.probe.TestWithStrategy(ctx, testDomain, v.strategy)
		if result.Success {
			core.Log.Infof("DPI", "Search: found working strategy at Phase 1 step %d: %s (%v)", i, v.desc, result.Latency)
			bestStrategy = v.strategy
			bestStrategy.Name = fmt.Sprintf("search_%s", v.desc)
			bestStrategy.Source = "search"
			ps.publishComplete(true, bestStrategy.Name, "")
			ps.saveResult(bestStrategy, networkID)
			return
		}
	}

	// Phase 2: Double parameter variation (top pairs).
	pairs := ps.generatePhase2Variations(base)
	total2 := len(pairs)
	core.Log.Infof("DPI", "Search Phase 2: %d variations to test", total2)

	for i, v := range pairs {
		if ps.isStopped() {
			return
		}

		ps.publishProgress(2, i, total2, v.desc)
		result := ps.probe.TestWithStrategy(ctx, testDomain, v.strategy)
		if result.Success {
			core.Log.Infof("DPI", "Search: found working strategy at Phase 2 step %d: %s (%v)", i, v.desc, result.Latency)
			bestStrategy = v.strategy
			bestStrategy.Name = fmt.Sprintf("search_%s", v.desc)
			bestStrategy.Source = "search"
			ps.publishComplete(true, bestStrategy.Name, "")
			ps.saveResult(bestStrategy, networkID)
			return
		}
	}

	core.Log.Warnf("DPI", "Search: no working strategy found after %d tests", total+total2)
	ps.publishComplete(false, "", "no working strategy found")
}

type searchVariation struct {
	strategy *Strategy
	desc     string
}

// generatePhase1Variations creates single-parameter variations of the base strategy.
func (ps *ParameterSearcher) generatePhase1Variations(base *Strategy) []searchVariation {
	var variations []searchVariation

	// Mode variations.
	modes := []DesyncMode{DesyncFake, DesyncMultisplit, DesyncFakedsplit, DesyncMultidisorder, DesyncNone}
	for _, mode := range modes {
		s := ps.cloneWithOp(base, func(op *DesyncOp) { op.Mode = mode })
		variations = append(variations, searchVariation{s, fmt.Sprintf("mode_%s", mode)})
	}

	// SplitPos variations.
	splitPositions := [][]int{{1}, {2}, {3}, {5}, {10}, {50}, {100}, {SplitPosAutoSNI}, {-5}}
	for _, pos := range splitPositions {
		s := ps.cloneWithOp(base, func(op *DesyncOp) { op.SplitPos = pos })
		desc := fmt.Sprintf("split_%v", pos)
		variations = append(variations, searchVariation{s, desc})
	}

	// FakeTTL variations.
	ttls := []int{1, 2, 3, 4, 5, 8, 11}
	for _, ttl := range ttls {
		s := ps.cloneWithOp(base, func(op *DesyncOp) { op.FakeTTL = ttl })
		variations = append(variations, searchVariation{s, fmt.Sprintf("ttl_%d", ttl)})
	}

	// Repeats variations.
	repeats := []int{1, 3, 6, 12}
	for _, r := range repeats {
		s := ps.cloneWithOp(base, func(op *DesyncOp) { op.Repeats = r })
		variations = append(variations, searchVariation{s, fmt.Sprintf("repeats_%d", r)})
	}

	// SplitSeqOvl variations.
	ovls := []int{0, 1, 2, 568, 681, 1024}
	for _, o := range ovls {
		s := ps.cloneWithOp(base, func(op *DesyncOp) { op.SplitSeqOvl = o })
		variations = append(variations, searchVariation{s, fmt.Sprintf("seqovl_%d", o)})
	}

	// Fool method variations.
	fools := [][]FoolMethod{{FoolTTL}, {FoolBadSeq}, {FoolBadSum}, {FoolTTL, FoolBadSeq}}
	for _, f := range fools {
		s := ps.cloneWithOp(base, func(op *DesyncOp) { op.Fool = f })
		desc := fmt.Sprintf("fool_%v", f)
		variations = append(variations, searchVariation{s, desc})
	}

	return variations
}

// generatePhase2Variations creates double-parameter variations (top pairs).
func (ps *ParameterSearcher) generatePhase2Variations(base *Strategy) []searchVariation {
	var variations []searchVariation

	// Mode × SplitPos.
	modes := []DesyncMode{DesyncMultisplit, DesyncFakedsplit, DesyncMultidisorder}
	positions := [][]int{{1}, {3}, {SplitPosAutoSNI}, {-5}}
	for _, mode := range modes {
		for _, pos := range positions {
			s := ps.cloneWithOp(base, func(op *DesyncOp) {
				op.Mode = mode
				op.SplitPos = pos
			})
			desc := fmt.Sprintf("mode_%s_split_%v", mode, pos)
			variations = append(variations, searchVariation{s, desc})
		}
	}

	// Mode × FakeTTL.
	ttls := []int{1, 3, 5, 8}
	for _, mode := range []DesyncMode{DesyncFake, DesyncFakedsplit} {
		for _, ttl := range ttls {
			s := ps.cloneWithOp(base, func(op *DesyncOp) {
				op.Mode = mode
				op.FakeTTL = ttl
			})
			desc := fmt.Sprintf("mode_%s_ttl_%d", mode, ttl)
			variations = append(variations, searchVariation{s, desc})
		}
	}

	// SplitPos × Repeats.
	repValues := []int{3, 6}
	for _, pos := range positions {
		for _, r := range repValues {
			s := ps.cloneWithOp(base, func(op *DesyncOp) {
				op.SplitPos = pos
				op.Repeats = r
			})
			desc := fmt.Sprintf("split_%v_repeats_%d", pos, r)
			variations = append(variations, searchVariation{s, desc})
		}
	}

	return variations
}

// cloneWithOp creates a clone of the base strategy with a modifier applied
// to the first op (or creates a new op if base is nil/empty).
func (ps *ParameterSearcher) cloneWithOp(base *Strategy, modify func(*DesyncOp)) *Strategy {
	s := &Strategy{
		Name:   "search_variation",
		Source: "search",
	}

	if base != nil && len(base.Ops) > 0 {
		s.Ops = make([]DesyncOp, len(base.Ops))
		copy(s.Ops, base.Ops)
	} else {
		// Default base op.
		s.Ops = []DesyncOp{{
			Mode:           DesyncMultisplit,
			FilterProtocol: "tcp",
			FilterPorts:    []int{443},
			FakeTTL:        1,
			Repeats:        1,
			SplitPos:       []int{SplitPosAutoSNI},
		}}
	}

	modify(&s.Ops[0])
	return s
}

func (ps *ParameterSearcher) isStopped() bool {
	select {
	case <-ps.stopCh:
		return true
	default:
		return false
	}
}

func (ps *ParameterSearcher) publishProgress(phase, tested, total int, desc string) {
	if ps.bus != nil {
		ps.bus.PublishAsync(core.Event{
			Type: core.EventDPISearchProgress,
			Payload: core.DPISearchProgressPayload{
				Phase:       phase,
				Tested:      tested,
				Total:       total,
				CurrentDesc: desc,
			},
		})
	}
}

func (ps *ParameterSearcher) publishComplete(success bool, name, errStr string) {
	if ps.bus != nil {
		ps.bus.PublishAsync(core.Event{
			Type: core.EventDPISearchComplete,
			Payload: core.DPISearchCompletePayload{
				Success:      success,
				StrategyName: name,
				Error:        errStr,
			},
		})
	}
}

func (ps *ParameterSearcher) saveResult(s *Strategy, networkID string) {
	s.LastTested = time.Now()
	if ps.cache != nil {
		if err := ps.cache.SetNetworkStrategy(networkID, s); err != nil {
			core.Log.Warnf("DPI", "Failed to cache search result: %v", err)
		}
		if err := ps.cache.AddSearchResult(s); err != nil {
			core.Log.Warnf("DPI", "Failed to add search result: %v", err)
		}
	}
}
