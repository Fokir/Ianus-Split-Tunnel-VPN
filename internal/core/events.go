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
	EventAuthRequired    // Tunnel needs interactive re-authentication (OTP/MFA)
	EventTunnelBanner    // Server sent a banner/MOTD message
	EventTunnelResuming  // Tunnel is attempting session resumption
	EventTunnelTimeout   // Tunnel idle or session timeout

	EventSupervisorRestarted  // A supervised goroutine recovered from panic and restarted
	EventSupervisorCircuitOpen // A supervisor exceeded max restarts and stopped
)

// AuthRequiredPayload is the payload for EventAuthRequired.
type AuthRequiredPayload struct {
	TunnelID string
	Reason   string
}

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

// BannerPayload is the payload for EventTunnelBanner.
type BannerPayload struct {
	TunnelID string
	Banner   string
}

// TimeoutPayload is the payload for EventTunnelTimeout.
type TimeoutPayload struct {
	TunnelID string
	Kind     string // "idle" or "session"
}

// SupervisorRestartPayload is the payload for EventSupervisorRestarted.
type SupervisorRestartPayload struct {
	Name       string
	Attempt    int
	PanicValue any
}

// SupervisorCircuitPayload is the payload for EventSupervisorCircuitOpen.
type SupervisorCircuitPayload struct {
	Name        string
	TotalPanics int
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
