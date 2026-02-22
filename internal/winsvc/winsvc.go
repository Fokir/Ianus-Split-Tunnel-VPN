//go:build windows

package winsvc

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
)

const (
	ServiceName        = "AWGSplitTunnel"
	ServiceDisplayName = "AWG Split Tunnel VPN Service"
	ServiceDescription = "Multi-tunnel VPN client with per-process split tunneling"
)

// IsWindowsService reports whether the current process is running as a Windows Service.
func IsWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isSvc
}

// RunService runs the process as a Windows Service, calling runFunc to start
// the VPN and stopFunc to signal graceful shutdown.
// This function blocks until the service is stopped.
func RunService(runFunc func() error, stopFunc func()) error {
	h := &serviceHandler{
		runFunc:  runFunc,
		stopFunc: stopFunc,
		done:     make(chan struct{}),
	}
	return svc.Run(ServiceName, h)
}

// serviceHandler implements svc.Handler for the Windows Service Control Manager.
type serviceHandler struct {
	runFunc  func() error
	stopFunc func()
	done     chan struct{}
	once     sync.Once
}

// Execute is called by the Windows SCM. It must respond to service control commands.
func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	// Report that we are starting.
	s <- svc.Status{State: svc.StartPending}

	// Accepted commands while running.
	accepted := svc.AcceptStop | svc.AcceptShutdown

	// Start the VPN in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- h.runFunc()
	}()

	// Give the service a moment to initialize, then report running.
	// The runFunc is async (it runs until stopFunc is called), so we
	// report Running immediately.
	s <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case cr := <-r:
			switch cr.Cmd {
			case svc.Interrogate:
				s <- cr.CurrentStatus
				// Resend after short delay per Windows docs.
				time.Sleep(100 * time.Millisecond)
				s <- cr.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				h.once.Do(func() {
					h.stopFunc()
				})
				// Wait for runFunc to finish.
				<-errCh
				return false, 0
			default:
				// Ignore unknown commands.
			}
		case err := <-errCh:
			// runFunc exited on its own (unexpected or graceful).
			if err != nil {
				// Return a non-zero exit code to signal failure.
				return true, 1
			}
			return false, 0
		}
	}
}

// ServiceError wraps service-related errors with context.
type ServiceError struct {
	Op  string
	Err error
}

func (e *ServiceError) Error() string {
	return fmt.Sprintf("winsvc: %s: %v", e.Op, e.Err)
}

func (e *ServiceError) Unwrap() error {
	return e.Err
}
