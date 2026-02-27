package core

import (
	"fmt"
	"sync"
)

// TunnelEntry holds runtime information about an active tunnel.
type TunnelEntry struct {
	ID           string
	Config       TunnelConfig
	State        TunnelState
	ProxyPort    uint16 // Local port where the TCP tunnel proxy listens
	UDPProxyPort uint16 // Local port where the UDP tunnel proxy listens
	Error        error  // Last error if state == TunnelStateError
}

// TunnelRegistry manages active tunnels and their states.
type TunnelRegistry struct {
	mu      sync.RWMutex
	tunnels map[string]*TunnelEntry
	bus     *EventBus
}

// NewTunnelRegistry creates a ready-to-use registry.
func NewTunnelRegistry(bus *EventBus) *TunnelRegistry {
	return &TunnelRegistry{
		tunnels: make(map[string]*TunnelEntry),
		bus:     bus,
	}
}

// Register adds a new tunnel to the registry in Down state.
func (tr *TunnelRegistry) Register(cfg TunnelConfig, proxyPort, udpProxyPort uint16) error {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	if _, exists := tr.tunnels[cfg.ID]; exists {
		return fmt.Errorf("[Core] tunnel %q already registered", cfg.ID)
	}

	tr.tunnels[cfg.ID] = &TunnelEntry{
		ID:           cfg.ID,
		Config:       cfg,
		State:        TunnelStateDown,
		ProxyPort:    proxyPort,
		UDPProxyPort: udpProxyPort,
	}

	Log.Infof("Core", "Registered tunnel %q (protocol=%s, tcp=:%d, udp=:%d)", cfg.ID, cfg.Protocol, proxyPort, udpProxyPort)
	return nil
}

// Unregister removes a tunnel from the registry.
func (tr *TunnelRegistry) Unregister(id string) {
	tr.mu.Lock()
	delete(tr.tunnels, id)
	tr.mu.Unlock()

	Log.Infof("Core", "Unregistered tunnel %q", id)
}

// Get returns a snapshot copy of the tunnel entry for the given ID.
// Returns a value (not pointer) to avoid data races — callers can safely
// read fields after the lock is released.
func (tr *TunnelRegistry) Get(id string) (TunnelEntry, bool) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	entry, ok := tr.tunnels[id]
	if !ok {
		return TunnelEntry{}, false
	}
	return *entry, true
}

// SetState updates the tunnel state and publishes an event if changed.
func (tr *TunnelRegistry) SetState(id string, state TunnelState, err error) {
	tr.mu.Lock()
	entry, ok := tr.tunnels[id]
	if !ok {
		tr.mu.Unlock()
		return
	}

	old := entry.State
	entry.State = state
	entry.Error = err
	tr.mu.Unlock()

	if old != state {
		Log.Infof("Core", "Tunnel %q: %s → %s", id, old, state)
		if tr.bus != nil {
			tr.bus.Publish(Event{
				Type: EventTunnelStateChanged,
				Payload: TunnelStatePayload{
					TunnelID: id,
					OldState: old,
					NewState: state,
				},
			})
		}
	}
}

// SetName updates the display name of the tunnel in-place. Returns false if tunnel not found.
func (tr *TunnelRegistry) SetName(id, name string) bool {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	entry, ok := tr.tunnels[id]
	if !ok {
		return false
	}
	entry.Config.Name = name
	return true
}

// GetState returns the current state of a tunnel.
func (tr *TunnelRegistry) GetState(id string) TunnelState {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	if entry, ok := tr.tunnels[id]; ok {
		return entry.State
	}
	return TunnelStateDown
}

// GetProxyPort returns the local TCP proxy port for a tunnel.
func (tr *TunnelRegistry) GetProxyPort(id string) (uint16, bool) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	if entry, ok := tr.tunnels[id]; ok {
		return entry.ProxyPort, true
	}
	return 0, false
}

// GetUDPProxyPort returns the local UDP proxy port for a tunnel.
func (tr *TunnelRegistry) GetUDPProxyPort(id string) (uint16, bool) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	if entry, ok := tr.tunnels[id]; ok {
		return entry.UDPProxyPort, true
	}
	return 0, false
}

// All returns a snapshot of all registered tunnels.
func (tr *TunnelRegistry) All() []*TunnelEntry {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	result := make([]*TunnelEntry, 0, len(tr.tunnels))
	for _, entry := range tr.tunnels {
		// Return a copy to avoid races.
		e := *entry
		result = append(result, &e)
	}
	return result
}
