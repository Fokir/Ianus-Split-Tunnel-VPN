//go:build windows

package windows

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"awg-split-tunnel/internal/core"
)

// iphlpapi procs for network change notifications.
var (
	modIPHlpAPI                      = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyRouteChange2           = modIPHlpAPI.NewProc("NotifyRouteChange2")
	procNotifyIpInterfaceChange      = modIPHlpAPI.NewProc("NotifyIpInterfaceChange")
	procNotifyUnicastIpAddressChange = modIPHlpAPI.NewProc("NotifyUnicastIpAddressChange")
	procCancelMibChangeNotify2       = modIPHlpAPI.NewProc("CancelMibChangeNotify2")
)

const debounceDuration = 2 * time.Second

// NetworkMonitor detects network changes via Windows iphlpapi notification
// callbacks: route changes, interface state changes, and IP address changes.
// Calls onChange (debounced, ~2s) when any network topology change is detected.
type NetworkMonitor struct {
	onChange func()
	done    chan struct{}

	// Debounce: collapse rapid events into one callback via timer reset.
	mu    sync.Mutex
	timer *time.Timer

	// Suppress prevents callbacks while we modify routes ourselves.
	suppressed atomic.Bool

	routeHandle windows.Handle
	ifaceHandle windows.Handle
	addrHandle  windows.Handle
}

// activeMonitor holds a reference to the currently active NetworkMonitor.
// Used by Windows callbacks which cannot have Go method receivers.
var activeMonitor atomic.Pointer[NetworkMonitor]

// NewNetworkMonitor creates a network change monitor.
// onChange is called (debounced, ~2s) when routing/interface/address changes are detected.
func NewNetworkMonitor(onChange func()) (*NetworkMonitor, error) {
	return &NetworkMonitor{
		onChange: onChange,
		done:    make(chan struct{}),
	}, nil
}

// Start registers Windows notification callbacks for route, interface,
// and unicast address changes. All three use AF_UNSPEC for dual-stack monitoring.
func (nm *NetworkMonitor) Start() error {
	activeMonitor.Store(nm)

	// Register route change notifications (default gateway changes, metric updates).
	err := notifyRouteChange2(
		windows.AF_UNSPEC,
		windows.NewCallback(routeChangedCB),
		0, false, &nm.routeHandle,
	)
	if err != nil {
		activeMonitor.Store(nil)
		return fmt.Errorf("NotifyRouteChange2: %w", err)
	}

	// Register interface change notifications (up/down, WiFi disconnect).
	err = notifyIpInterfaceChange(
		windows.AF_UNSPEC,
		windows.NewCallback(ifaceChangedCB),
		0, false, &nm.ifaceHandle,
	)
	if err != nil {
		cancelMibChangeNotify2(nm.routeHandle)
		activeMonitor.Store(nil)
		return fmt.Errorf("NotifyIpInterfaceChange: %w", err)
	}

	// Register unicast address change notifications (DHCP renewal, new IP).
	err = notifyUnicastIpAddressChange(
		windows.AF_UNSPEC,
		windows.NewCallback(addrChangedCB),
		0, false, &nm.addrHandle,
	)
	if err != nil {
		cancelMibChangeNotify2(nm.routeHandle)
		cancelMibChangeNotify2(nm.ifaceHandle)
		activeMonitor.Store(nil)
		return fmt.Errorf("NotifyUnicastIpAddressChange: %w", err)
	}

	core.Log.Infof("Gateway", "Network monitor started (iphlpapi notifications)")
	return nil
}

// Stop unregisters all notification callbacks and stops the debounce timer.
func (nm *NetworkMonitor) Stop() error {
	close(nm.done)

	// Stop debounce timer to prevent callback after shutdown.
	nm.mu.Lock()
	if nm.timer != nil {
		nm.timer.Stop()
	}
	nm.mu.Unlock()

	var firstErr error
	if nm.routeHandle != 0 {
		if err := cancelMibChangeNotify2(nm.routeHandle); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if nm.ifaceHandle != 0 {
		if err := cancelMibChangeNotify2(nm.ifaceHandle); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if nm.addrHandle != 0 {
		if err := cancelMibChangeNotify2(nm.addrHandle); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	activeMonitor.CompareAndSwap(nm, nil)

	core.Log.Infof("Gateway", "Network monitor stopped")
	return firstErr
}

// Suppress prevents onChange callbacks from firing. Used during gateway
// activation/deactivation to avoid feedback loops from our own route changes.
func (nm *NetworkMonitor) Suppress() { nm.suppressed.Store(true) }

// Resume re-enables onChange callbacks after a Suppress call.
func (nm *NetworkMonitor) Resume() { nm.suppressed.Store(false) }

// fireDebounced schedules the onChange callback with a 2-second debounce.
// Collapses rapid network change events into a single callback.
func (nm *NetworkMonitor) fireDebounced() {
	if nm.suppressed.Load() {
		return
	}

	nm.mu.Lock()
	defer nm.mu.Unlock()

	if nm.timer == nil {
		nm.timer = time.AfterFunc(debounceDuration, func() {
			select {
			case <-nm.done:
				return
			default:
				if nm.suppressed.Load() {
					return
				}
				core.Log.Debugf("Gateway", "Network change detected, firing callback")
				nm.onChange()
			}
		})
	} else {
		nm.timer.Reset(debounceDuration)
	}
}

// ---------------------------------------------------------------------------
// Windows notification callbacks.
// Called from Windows on an arbitrary OS thread. Must be package-level functions
// (windows.NewCallback doesn't support method values). The activeMonitor
// atomic pointer dispatches to the current NetworkMonitor instance.
// Signatures: (callerContext, row, notificationType) → uintptr, matching
// the PIPFORWARD_CHANGE_CALLBACK / PIPINTERFACE_CHANGE_CALLBACK /
// PUNICAST_IPADDRESS_CHANGE_CALLBACK prototypes.
// ---------------------------------------------------------------------------

func routeChangedCB(callerContext, row, notificationType uintptr) uintptr {
	if nm := activeMonitor.Load(); nm != nil {
		nm.fireDebounced()
	}
	return 0
}

func ifaceChangedCB(callerContext, row, notificationType uintptr) uintptr {
	if nm := activeMonitor.Load(); nm != nil {
		nm.fireDebounced()
	}
	return 0
}

func addrChangedCB(callerContext, row, notificationType uintptr) uintptr {
	if nm := activeMonitor.Load(); nm != nil {
		nm.fireDebounced()
	}
	return 0
}

// ---------------------------------------------------------------------------
// Low-level wrappers for iphlpapi notification APIs.
// Follow the proc.Call() pattern used in gateway/adapter.go and gateway/route.go.
// ---------------------------------------------------------------------------

func notifyRouteChange2(family uint32, callback uintptr, callerContext uintptr, initialNotification bool, handle *windows.Handle) error {
	var initial uintptr
	if initialNotification {
		initial = 1
	}
	r, _, _ := procNotifyRouteChange2.Call(
		uintptr(family), callback, callerContext, initial,
		uintptr(unsafe.Pointer(handle)),
	)
	if r != 0 {
		return fmt.Errorf("error %d", r)
	}
	return nil
}

func notifyIpInterfaceChange(family uint32, callback uintptr, callerContext uintptr, initialNotification bool, handle *windows.Handle) error {
	var initial uintptr
	if initialNotification {
		initial = 1
	}
	r, _, _ := procNotifyIpInterfaceChange.Call(
		uintptr(family), callback, callerContext, initial,
		uintptr(unsafe.Pointer(handle)),
	)
	if r != 0 {
		return fmt.Errorf("error %d", r)
	}
	return nil
}

func notifyUnicastIpAddressChange(family uint32, callback uintptr, callerContext uintptr, initialNotification bool, handle *windows.Handle) error {
	var initial uintptr
	if initialNotification {
		initial = 1
	}
	r, _, _ := procNotifyUnicastIpAddressChange.Call(
		uintptr(family), callback, callerContext, initial,
		uintptr(unsafe.Pointer(handle)),
	)
	if r != 0 {
		return fmt.Errorf("error %d", r)
	}
	return nil
}

func cancelMibChangeNotify2(handle windows.Handle) error {
	r, _, _ := procCancelMibChangeNotify2.Call(uintptr(handle))
	if r != 0 {
		return fmt.Errorf("CancelMibChangeNotify2: error %d", r)
	}
	return nil
}
