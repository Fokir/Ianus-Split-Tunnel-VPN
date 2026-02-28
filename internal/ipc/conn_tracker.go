package ipc

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
)

// ConnTracker tracks active gRPC connections (unary + streaming RPCs).
// When all clients disconnect, it starts a grace timer and calls the
// onAllDisconnected callback after the grace period expires.
type ConnTracker struct {
	active      atomic.Int64
	gracePeriod time.Duration
	onIdle      func() // called when grace period expires with no clients

	mu         sync.Mutex
	graceTimer *time.Timer
}

// NewConnTracker creates a ConnTracker with the given grace period.
// onIdle is called (in a separate goroutine) when all clients have
// disconnected and the grace period has elapsed without reconnection.
func NewConnTracker(gracePeriod time.Duration, onIdle func()) *ConnTracker {
	return &ConnTracker{
		gracePeriod: gracePeriod,
		onIdle:      onIdle,
	}
}

// ActiveCount returns the current number of active RPCs.
func (ct *ConnTracker) ActiveCount() int64 {
	return ct.active.Load()
}

// CancelGrace cancels any pending grace timer. Used during explicit shutdown
// to prevent the idle callback from firing.
func (ct *ConnTracker) CancelGrace() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.graceTimer != nil {
		ct.graceTimer.Stop()
		ct.graceTimer = nil
	}
}

func (ct *ConnTracker) inc() {
	n := ct.active.Add(1)
	if n == 1 {
		// Went from 0 → 1: cancel any pending grace timer.
		ct.mu.Lock()
		if ct.graceTimer != nil {
			ct.graceTimer.Stop()
			ct.graceTimer = nil
			log.Printf("[Daemon] Client reconnected, grace timer cancelled")
		}
		ct.mu.Unlock()
	}
}

func (ct *ConnTracker) dec() {
	n := ct.active.Add(-1)
	if n == 0 {
		// All clients gone — start grace timer.
		ct.mu.Lock()
		if ct.graceTimer != nil {
			ct.graceTimer.Stop()
		}
		log.Printf("[Daemon] All clients disconnected, starting %s grace timer", ct.gracePeriod)
		ct.graceTimer = time.AfterFunc(ct.gracePeriod, func() {
			ct.mu.Lock()
			ct.graceTimer = nil
			ct.mu.Unlock()
			if ct.onIdle != nil {
				ct.onIdle()
			}
		})
		ct.mu.Unlock()
	}
}

// UnaryInterceptor returns a gRPC unary server interceptor that tracks active RPCs.
func (ct *ConnTracker) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		ct.inc()
		defer ct.dec()
		return handler(ctx, req)
	}
}

// StreamInterceptor returns a gRPC stream server interceptor that tracks active streams.
func (ct *ConnTracker) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ct.inc()
		defer ct.dec()
		return handler(srv, ss)
	}
}
