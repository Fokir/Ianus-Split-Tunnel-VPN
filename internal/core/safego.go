package core

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"time"
)

// SafeGo launches a goroutine with panic recovery and logging.
// The goroutine is NOT restarted after a panic.
func SafeGo(name string, fn func()) {
	go func() {
		defer func() {
			if v := recover(); v != nil {
				stack := debug.Stack()
				msg := fmt.Sprintf("PANIC in goroutine %q: %v\n%s", name, v, stack)
				if Log != nil {
					Log.Errorf("Supervisor", "%s", msg)
				} else {
					log.Print(msg)
				}
			}
		}()
		fn()
	}()
}

// SafeGoWG is like SafeGo but calls wg.Done() when the goroutine exits.
func SafeGoWG(wg *sync.WaitGroup, name string, fn func()) {
	go func() {
		defer wg.Done()
		defer func() {
			if v := recover(); v != nil {
				stack := debug.Stack()
				msg := fmt.Sprintf("PANIC in goroutine %q: %v\n%s", name, v, stack)
				if Log != nil {
					Log.Errorf("Supervisor", "%s", msg)
				} else {
					log.Print(msg)
				}
			}
		}()
		fn()
	}()
}

// SupervisorConfig controls the behavior of Supervise.
type SupervisorConfig struct {
	Name           string
	InitialBackoff time.Duration // default 1s
	MaxBackoff     time.Duration // default 30s
	MaxRestarts    int           // default 5 per ResetWindow
	ResetWindow    time.Duration // default 2min; counter resets after stable run
	EventBus       *EventBus    // optional; emits restart/circuit events
}

func (c *SupervisorConfig) defaults() {
	if c.InitialBackoff == 0 {
		c.InitialBackoff = 1 * time.Second
	}
	if c.MaxBackoff == 0 {
		c.MaxBackoff = 30 * time.Second
	}
	if c.MaxRestarts == 0 {
		c.MaxRestarts = 5
	}
	if c.ResetWindow == 0 {
		c.ResetWindow = 2 * time.Minute
	}
}

// Supervise runs fn in a loop, restarting it with exponential backoff on panic.
// Stops when ctx is cancelled or circuit breaker opens (MaxRestarts exceeded within ResetWindow).
func Supervise(ctx context.Context, cfg SupervisorConfig, fn func(ctx context.Context)) {
	cfg.defaults()
	go func() {
		backoff := cfg.InitialBackoff
		restarts := 0

		for {
			startedAt := time.Now()
			panicked := false
			var panicVal any

			func() {
				defer func() {
					if v := recover(); v != nil {
						panicked = true
						panicVal = v
						stack := debug.Stack()
						msg := fmt.Sprintf("PANIC in supervised %q (restart #%d): %v\n%s",
							cfg.Name, restarts+1, v, stack)
						if Log != nil {
							Log.Errorf("Supervisor", "%s", msg)
						} else {
							log.Print(msg)
						}
					}
				}()
				fn(ctx)
			}()

			// Clean exit (ctx cancelled or fn returned normally)
			if !panicked {
				return
			}

			restarts++

			// Reset backoff if fn ran long enough (stable run)
			if time.Since(startedAt) >= cfg.ResetWindow {
				backoff = cfg.InitialBackoff
				restarts = 1
			}

			// Emit restart event
			if cfg.EventBus != nil {
				cfg.EventBus.PublishAsync(Event{
					Type: EventSupervisorRestarted,
					Payload: SupervisorRestartPayload{
						Name:       cfg.Name,
						Attempt:    restarts,
						PanicValue: panicVal,
					},
				})
			}

			// Circuit breaker
			if restarts >= cfg.MaxRestarts {
				msg := fmt.Sprintf("supervisor %q: circuit open after %d restarts, giving up",
					cfg.Name, restarts)
				if Log != nil {
					Log.Errorf("Supervisor", "%s", msg)
				} else {
					log.Print(msg)
				}
				if cfg.EventBus != nil {
					cfg.EventBus.PublishAsync(Event{
						Type: EventSupervisorCircuitOpen,
						Payload: SupervisorCircuitPayload{
							Name:        cfg.Name,
							TotalPanics: restarts,
						},
					})
				}
				return
			}

			// Wait with backoff before restart
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, cfg.MaxBackoff)
		}
	}()
}

// SuperviseSimple is a convenience wrapper around Supervise with default config.
func SuperviseSimple(ctx context.Context, name string, fn func(ctx context.Context)) {
	Supervise(ctx, SupervisorConfig{Name: name}, fn)
}

// SuperviseWG is like Supervise but calls wg.Done() when the supervisor exits
// (either because ctx was cancelled or circuit breaker opened).
func SuperviseWG(ctx context.Context, wg *sync.WaitGroup, cfg SupervisorConfig, fn func(ctx context.Context)) {
	cfg.defaults()
	go func() {
		defer wg.Done()
		backoff := cfg.InitialBackoff
		restarts := 0

		for {
			startedAt := time.Now()
			panicked := false
			var panicVal any

			func() {
				defer func() {
					if v := recover(); v != nil {
						panicked = true
						panicVal = v
						stack := debug.Stack()
						msg := fmt.Sprintf("PANIC in supervised %q (restart #%d): %v\n%s",
							cfg.Name, restarts+1, v, stack)
						if Log != nil {
							Log.Errorf("Supervisor", "%s", msg)
						} else {
							log.Print(msg)
						}
					}
				}()
				fn(ctx)
			}()

			if !panicked {
				return
			}

			restarts++

			if time.Since(startedAt) >= cfg.ResetWindow {
				backoff = cfg.InitialBackoff
				restarts = 1
			}

			if cfg.EventBus != nil {
				cfg.EventBus.PublishAsync(Event{
					Type: EventSupervisorRestarted,
					Payload: SupervisorRestartPayload{
						Name:       cfg.Name,
						Attempt:    restarts,
						PanicValue: panicVal,
					},
				})
			}

			if restarts >= cfg.MaxRestarts {
				msg := fmt.Sprintf("supervisor %q: circuit open after %d restarts, giving up",
					cfg.Name, restarts)
				if Log != nil {
					Log.Errorf("Supervisor", "%s", msg)
				} else {
					log.Print(msg)
				}
				if cfg.EventBus != nil {
					cfg.EventBus.PublishAsync(Event{
						Type: EventSupervisorCircuitOpen,
						Payload: SupervisorCircuitPayload{
							Name:        cfg.Name,
							TotalPanics: restarts,
						},
					})
				}
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, cfg.MaxBackoff)
		}
	}()
}
