//go:build darwin

package darwin

import (
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"awg-split-tunnel/internal/core"
)

// Route message types we care about (from <net/route.h>).
const (
	rtmNewAddr = 0xC  // RTM_NEWADDR — address added
	rtmDelAddr = 0xD  // RTM_DELADDR — address removed
	rtmIfInfo  = 0xE  // RTM_IFINFO — interface state change
	rtmAdd     = 0x1  // RTM_ADD — route added
	rtmDelete  = 0x2  // RTM_DELETE — route deleted
	rtmChange  = 0x3  // RTM_CHANGE — route changed
)

// rtMsghdr is the header of a routing socket message (macOS version 5).
// Only the first 4 bytes (msglen uint16, version uint8, type uint8) are needed.
const rtMsghdrMinSize = 4

// NetworkMonitor monitors network changes via PF_ROUTE socket.
// Calls onChange when default route, addresses, or interface state changes.
type NetworkMonitor struct {
	routeFD  int
	onChange func()
	done     chan struct{}
	stopped  chan struct{}

	// Debounce: collapse rapid events into one callback via timer reset.
	mu    sync.Mutex
	timer *time.Timer
}

// NewNetworkMonitor creates a network change monitor.
// onChange is called (debounced, ~2s) when routing/address changes are detected.
func NewNetworkMonitor(onChange func()) (*NetworkMonitor, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}

	return &NetworkMonitor{
		routeFD:  fd,
		onChange: onChange,
		done:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}, nil
}

// Start begins listening for route socket events in a goroutine.
func (nm *NetworkMonitor) Start() error {
	go nm.loop()
	core.Log.Infof("Gateway", "Network monitor started (PF_ROUTE socket)")
	return nil
}

// Stop closes the route socket and stops the monitor goroutine.
func (nm *NetworkMonitor) Stop() error {
	close(nm.done)
	// Stop debounce timer to prevent callback after shutdown.
	nm.mu.Lock()
	if nm.timer != nil {
		nm.timer.Stop()
	}
	nm.mu.Unlock()
	// Closing the fd unblocks the Read in the loop goroutine.
	err := unix.Close(nm.routeFD)
	<-nm.stopped
	core.Log.Infof("Gateway", "Network monitor stopped")
	return err
}

// loop reads routing messages and fires debounced callbacks.
func (nm *NetworkMonitor) loop() {
	defer close(nm.stopped)

	buf := make([]byte, 4096)
	for {
		select {
		case <-nm.done:
			return
		default:
		}

		n, err := unix.Read(nm.routeFD, buf)
		if err != nil {
			select {
			case <-nm.done:
				return // expected: fd closed during shutdown
			default:
				core.Log.Warnf("Gateway", "Route socket read error: %v", err)
				return
			}
		}
		if n < rtMsghdrMinSize {
			continue
		}

		msgType := buf[3]
		if nm.isRelevant(msgType) {
			nm.fireDebounced()
		}
	}
}

// isRelevant returns true for routing message types that indicate network changes.
func (nm *NetworkMonitor) isRelevant(msgType byte) bool {
	switch msgType {
	case rtmNewAddr, rtmDelAddr, rtmIfInfo, rtmAdd, rtmDelete, rtmChange:
		return true
	default:
		return false
	}
}

const debounceDuration = 2 * time.Second

// fireDebounced schedules the onChange callback with a 2-second debounce.
// Uses time.AfterFunc + Reset to guarantee exactly one callback fires
// debounceDuration after the LAST event in a burst.
func (nm *NetworkMonitor) fireDebounced() {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if nm.timer == nil {
		nm.timer = time.AfterFunc(debounceDuration, func() {
			select {
			case <-nm.done:
				return
			default:
				core.Log.Debugf("Gateway", "Network change detected, firing callback")
				nm.onChange()
			}
		})
	} else {
		nm.timer.Reset(debounceDuration)
	}
}
