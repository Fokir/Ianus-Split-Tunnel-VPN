package core

import (
	"reflect"
	"sync"
)

// EventType identifies the kind of event fired on the bus.
type EventType int

const (
	EventTunnelStateChanged EventType = iota
	EventRuleAdded
	EventRuleRemoved
	EventRuleUpdated
	EventConfigReloaded
	EventSubscriptionUpdated
	EventUpdateAvailable
	EventDPISearchProgress
	EventDPISearchComplete
	EventDPIStrategyChanged
)

// Event carries data about something that happened in the system.
type Event struct {
	Type    EventType
	Payload any
}

// TunnelStatePayload is the payload for EventTunnelStateChanged.
type TunnelStatePayload struct {
	TunnelID string
	OldState TunnelState
	NewState TunnelState
}

// RulePayload is the payload for rule-related events.
type RulePayload struct {
	Rule Rule
}

// SubscriptionPayload is the payload for EventSubscriptionUpdated.
type SubscriptionPayload struct {
	Name    string
	Tunnels []TunnelConfig
	Error   error
}

// UpdatePayload is the payload for EventUpdateAvailable.
type UpdatePayload struct {
	Version      string
	ReleaseNotes string
	AssetURL     string
	AssetSize    int64
}

// DPISearchProgressPayload is the payload for EventDPISearchProgress.
type DPISearchProgressPayload struct {
	Phase       int    // current search phase (0-2)
	Tested      int    // number of configurations tested so far
	Total       int    // estimated total configurations
	CurrentDesc string // human-readable description of current test
}

// DPISearchCompletePayload is the payload for EventDPISearchComplete.
type DPISearchCompletePayload struct {
	Success      bool
	StrategyName string
	Error        string
}

// DPIStrategyChangedPayload is the payload for EventDPIStrategyChanged.
type DPIStrategyChangedPayload struct {
	StrategyName string
	Source       string // "zapret", "user", "search"
}

// Handler is a callback for bus subscribers.
type Handler func(Event)

// EventBus provides pub/sub between system components.
type EventBus struct {
	mu       sync.RWMutex
	handlers map[EventType][]Handler
}

// NewEventBus creates a ready-to-use event bus.
func NewEventBus() *EventBus {
	return &EventBus{
		handlers: make(map[EventType][]Handler),
	}
}

// Subscribe registers a handler for a given event type.
func (eb *EventBus) Subscribe(t EventType, h Handler) {
	eb.mu.Lock()
	eb.handlers[t] = append(eb.handlers[t], h)
	eb.mu.Unlock()
}

// Unsubscribe removes a previously registered handler for a given event type.
// Handlers are compared by function pointer identity.
func (eb *EventBus) Unsubscribe(t EventType, h Handler) {
	target := reflect.ValueOf(h).Pointer()
	eb.mu.Lock()
	handlers := eb.handlers[t]
	for i, existing := range handlers {
		if reflect.ValueOf(existing).Pointer() == target {
			eb.handlers[t] = append(handlers[:i], handlers[i+1:]...)
			break
		}
	}
	eb.mu.Unlock()
}

// Publish fires an event to all subscribed handlers synchronously.
func (eb *EventBus) Publish(e Event) {
	eb.mu.RLock()
	handlers := eb.handlers[e.Type]
	eb.mu.RUnlock()

	for _, h := range handlers {
		h(e)
	}
}

// PublishAsync fires an event to all subscribed handlers in goroutines.
func (eb *EventBus) PublishAsync(e Event) {
	eb.mu.RLock()
	handlers := eb.handlers[e.Type]
	eb.mu.RUnlock()

	for _, h := range handlers {
		go h(e)
	}
}
