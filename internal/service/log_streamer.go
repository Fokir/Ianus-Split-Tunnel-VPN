package service

import (
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
)

const (
	// logRingSize is the max number of log entries kept in the ring buffer.
	logRingSize = 5000
	// logChannelSize is the buffer size for each subscriber channel.
	logChannelSize = 256
)

// LogEntry represents a single log line.
type LogEntry struct {
	Timestamp time.Time
	Level     core.LogLevel
	Tag       string
	Message   string
}

// LogSubscriber receives log entries via a channel.
type LogSubscriber struct {
	C        <-chan LogEntry
	ch       chan LogEntry
	minLevel core.LogLevel
	tagFilter string
	id       uint64
}

// LogStreamer captures log output and distributes it to subscribers.
type LogStreamer struct {
	bus *core.EventBus

	mu          sync.RWMutex
	ring        []LogEntry
	ringPos     int
	ringFull    bool
	subscribers map[uint64]*LogSubscriber
	nextID      uint64
	stopped     bool
}

// NewLogStreamer creates a LogStreamer.
func NewLogStreamer(bus *core.EventBus) *LogStreamer {
	return &LogStreamer{
		bus:         bus,
		ring:        make([]LogEntry, logRingSize),
		subscribers: make(map[uint64]*LogSubscriber),
	}
}

// Start begins capturing logs. Must be called after core.Log is initialized.
// It installs a hook into the core logger.
func (ls *LogStreamer) Start() {
	core.Log.SetHook(ls.onLogEntry)
}

// Stop removes the log hook and closes all subscribers.
func (ls *LogStreamer) Stop() {
	core.Log.SetHook(nil)
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.stopped = true
	for id, sub := range ls.subscribers {
		close(sub.ch)
		delete(ls.subscribers, id)
	}
}

// Subscribe creates a new log subscriber with optional filters.
// tailLines sends the last N entries from the ring buffer first.
func (ls *LogStreamer) Subscribe(minLevel core.LogLevel, tagFilter string, tailLines int) *LogSubscriber {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	ch := make(chan LogEntry, logChannelSize)
	id := ls.nextID
	ls.nextID++

	sub := &LogSubscriber{
		C:         ch,
		ch:        ch,
		minLevel:  minLevel,
		tagFilter: tagFilter,
		id:        id,
	}
	ls.subscribers[id] = sub

	// Send tail from ring buffer.
	if tailLines > 0 {
		entries := ls.tail(tailLines)
		for _, e := range entries {
			if matchesFilter(e, minLevel, tagFilter) {
				select {
				case ch <- e:
				default:
				}
			}
		}
	}

	return sub
}

// Unsubscribe removes a subscriber and closes its channel.
func (ls *LogStreamer) Unsubscribe(sub *LogSubscriber) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if _, ok := ls.subscribers[sub.id]; ok {
		close(sub.ch)
		delete(ls.subscribers, sub.id)
	}
}

// onLogEntry is the hook called by core.Logger for each log line.
func (ls *LogStreamer) onLogEntry(level core.LogLevel, tag, msg string) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Tag:       tag,
		Message:   msg,
	}

	ls.mu.Lock()
	// Write to ring buffer.
	ls.ring[ls.ringPos] = entry
	ls.ringPos++
	if ls.ringPos >= logRingSize {
		ls.ringPos = 0
		ls.ringFull = true
	}

	// Copy subscribers slice under lock to avoid holding lock during send.
	subs := make([]*LogSubscriber, 0, len(ls.subscribers))
	for _, sub := range ls.subscribers {
		subs = append(subs, sub)
	}
	ls.mu.Unlock()

	// Dispatch to subscribers (non-blocking).
	for _, sub := range subs {
		if matchesFilter(entry, sub.minLevel, sub.tagFilter) {
			select {
			case sub.ch <- entry:
			default:
				// Drop entry if subscriber is slow.
			}
		}
	}
}

// tail returns the last n entries from the ring buffer.
func (ls *LogStreamer) tail(n int) []LogEntry {
	total := ls.ringPos
	if ls.ringFull {
		total = logRingSize
	}
	if n > total {
		n = total
	}
	if n == 0 {
		return nil
	}

	result := make([]LogEntry, n)
	start := ls.ringPos - n
	if start < 0 {
		start += logRingSize
	}
	for i := range n {
		idx := (start + i) % logRingSize
		result[i] = ls.ring[idx]
	}
	return result
}

func matchesFilter(e LogEntry, minLevel core.LogLevel, tagFilter string) bool {
	if e.Level < minLevel {
		return false
	}
	if tagFilter != "" && e.Tag != tagFilter {
		return false
	}
	return true
}
