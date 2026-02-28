//go:build darwin

package daemon

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/ipc"
	"awg-split-tunnel/internal/platform"
)

// State represents the daemon lifecycle state.
type State int

const (
	StateIdle         State = iota // gRPC server running, no VPN stack
	StateActivating                // runVPN is starting up
	StateActive                    // VPN stack fully running
	StateDeactivating              // VPN stack shutting down
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateActivating:
		return "activating"
	case StateActive:
		return "active"
	case StateDeactivating:
		return "deactivating"
	default:
		return "unknown"
	}
}

// RunVPNFunc is the signature of the runVPN function.
type RunVPNFunc func(configPath string, plat *platform.Platform, stopCh <-chan struct{}, opts ...RunConfig) error

// Controller orchestrates the daemon lifecycle:
//
//	launchd spawn → IDLE (gRPC only) → Activate → ACTIVE (full VPN)
//	                                 ← Deactivate ← GUI disconnect
//	                                 → os.Exit(0) → launchd holds socket
type Controller struct {
	mu    sync.Mutex
	state State

	configPath  string
	plat        *platform.Platform
	version     string
	runVPN      RunVPNFunc
	keepAlive   bool // KeepAliveOnDisconnect from config
	gracePeriod time.Duration

	listener    net.Listener
	grpcServer  *grpc.Server
	connTracker *ipc.ConnTracker
	delegator   *ServiceDelegator
	idleSvc     *IdleService

	vpnStopCh  chan struct{} // signals runVPN to stop
	vpnDoneCh  chan error    // receives runVPN result
	shutdownCh chan struct{} // signals Run() to exit
}

// ControllerConfig holds parameters for creating a Controller.
type ControllerConfig struct {
	ConfigPath  string
	Platform    *platform.Platform
	Version     string
	RunVPN      RunVPNFunc
	KeepAlive   bool          // from config: gui.keep_alive_on_disconnect
	GracePeriod time.Duration // 0 = 30s default
	Listener    net.Listener  // inherited from launchd (or created manually)
}

// NewController creates a new daemon controller.
func NewController(cfg ControllerConfig) *Controller {
	grace := cfg.GracePeriod
	if grace == 0 {
		grace = 30 * time.Second
	}

	ctrl := &Controller{
		state:       StateIdle,
		configPath:  cfg.ConfigPath,
		plat:        cfg.Platform,
		version:     cfg.Version,
		runVPN:      cfg.RunVPN,
		keepAlive:   cfg.KeepAlive,
		gracePeriod: grace,
		listener:    cfg.Listener,
		shutdownCh:  make(chan struct{}),
	}

	ctrl.idleSvc = NewIdleService(ctrl, cfg.Version)
	ctrl.delegator = NewServiceDelegator(ctrl.idleSvc)

	ctrl.connTracker = ipc.NewConnTracker(grace, func() {
		ctrl.onAllClientsDisconnected()
	})

	return ctrl
}

// Run starts the gRPC server and blocks until Shutdown is called or the
// daemon decides to exit (grace period expired after all clients disconnect).
// Returns nil on clean exit.
func (c *Controller) Run() error {
	c.grpcServer = grpc.NewServer(
		grpc.ChainUnaryInterceptor(c.connTracker.UnaryInterceptor()),
		grpc.ChainStreamInterceptor(c.connTracker.StreamInterceptor()),
	)
	vpnapi.RegisterVPNServiceServer(c.grpcServer, c.delegator)

	log.Printf("[Daemon] Starting gRPC server on %s (idle mode)", c.listener.Addr())

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.grpcServer.Serve(c.listener)
	}()

	// Block until shutdown signal or gRPC server error.
	select {
	case <-c.shutdownCh:
		log.Printf("[Daemon] Shutdown signal received")
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("gRPC server error: %w", err)
		}
	}

	// Deactivate VPN if running.
	c.mu.Lock()
	if c.state == StateActive || c.state == StateActivating {
		c.mu.Unlock()
		c.deactivate()
	} else {
		c.mu.Unlock()
	}

	// Stop gRPC server.
	c.grpcServer.GracefulStop()

	log.Printf("[Daemon] Controller exiting")
	return nil
}

// Activate starts the full VPN stack. Called by IdleService.Activate RPC.
func (c *Controller) Activate() error {
	c.mu.Lock()
	if c.state != StateIdle {
		st := c.state
		c.mu.Unlock()
		return fmt.Errorf("cannot activate: current state is %s", st)
	}
	c.state = StateActivating
	c.vpnStopCh = make(chan struct{})
	c.vpnDoneCh = make(chan error, 1)
	c.mu.Unlock()

	log.Printf("[Daemon] Activating VPN stack...")

	// Launch runVPN in a goroutine.
	go func() {
		err := c.runVPN(c.configPath, c.plat, c.vpnStopCh, RunConfig{
			RegisterService: func(svc vpnapi.VPNServiceServer) func() {
				c.delegator.SetActiveService(svc)
				c.mu.Lock()
				c.state = StateActive
				c.mu.Unlock()
				log.Printf("[Daemon] VPN stack active, service registered")
				return func() {
					c.delegator.ClearActiveService()
					log.Printf("[Daemon] VPN service deregistered")
				}
			},
		})
		c.vpnDoneCh <- err

		c.mu.Lock()
		c.delegator.ClearActiveService()
		c.state = StateIdle
		c.mu.Unlock()

		if err != nil {
			log.Printf("[Daemon] runVPN exited with error: %v", err)
		} else {
			log.Printf("[Daemon] runVPN exited cleanly")
		}
	}()

	// Wait for VPN to become active (up to 30s).
	deadline := time.After(30 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			st := c.state
			c.mu.Unlock()
			if st == StateActive {
				return nil
			}
			if st == StateIdle {
				// runVPN already exited with error.
				select {
				case err := <-c.vpnDoneCh:
					if err != nil {
						return fmt.Errorf("VPN failed to start: %w", err)
					}
					return fmt.Errorf("VPN exited unexpectedly")
				default:
					return fmt.Errorf("VPN failed to activate")
				}
			}
		case <-deadline:
			return fmt.Errorf("VPN activation timed out (30s)")
		}
	}
}

// deactivate stops the VPN stack.
func (c *Controller) deactivate() {
	c.mu.Lock()
	if c.state != StateActive && c.state != StateActivating {
		c.mu.Unlock()
		return
	}
	c.state = StateDeactivating
	stopCh := c.vpnStopCh
	doneCh := c.vpnDoneCh
	c.mu.Unlock()

	log.Printf("[Daemon] Deactivating VPN stack...")
	close(stopCh)

	// Wait for runVPN to finish (with timeout).
	select {
	case <-doneCh:
		log.Printf("[Daemon] VPN stack deactivated")
	case <-time.After(15 * time.Second):
		log.Printf("[Daemon] VPN deactivation timed out (15s)")
	}

	c.mu.Lock()
	c.state = StateIdle
	c.mu.Unlock()
}

// onAllClientsDisconnected is called by ConnTracker when all gRPC clients
// have disconnected and the grace period has elapsed.
func (c *Controller) onAllClientsDisconnected() {
	if c.keepAlive {
		log.Printf("[Daemon] All clients disconnected, but keep_alive_on_disconnect is set — staying active")
		return
	}

	log.Printf("[Daemon] All clients disconnected and grace period expired — shutting down")
	c.deactivate()
	close(c.shutdownCh)
}

// Shutdown initiates a clean shutdown. Called by Shutdown RPC.
func (c *Controller) Shutdown() {
	c.connTracker.CancelGrace()
	select {
	case <-c.shutdownCh:
		// Already closed.
	default:
		close(c.shutdownCh)
	}
}

// State returns the current daemon state.
func (c *Controller) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}
