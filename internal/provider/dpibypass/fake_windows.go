//go:build windows

package dpibypass

import (
	"syscall"
	"time"
)

// sendFakePacket temporarily sets TTL to a low value, sends the fake payload,
// then restores the original TTL. The fake packet expires before reaching
// the real server but is seen by the DPI middlebox.
func (dc *desyncConn) sendFakePacket(payload []byte, ttl int) error {
	if dc.rawConn == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = 1
	}

	var originalTTL int
	var controlErr error

	// Get original TTL.
	dc.rawConn.Control(func(fd uintptr) {
		originalTTL, controlErr = syscall.GetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
	})
	if controlErr != nil {
		return controlErr
	}

	// Set low TTL.
	dc.rawConn.Control(func(fd uintptr) {
		controlErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	})
	if controlErr != nil {
		return controlErr
	}

	// Send fake payload (ignore write errors — packet may be dropped).
	dc.Conn.Write(payload)

	// Tiny delay so the fake packet leaves before we restore TTL.
	time.Sleep(500 * time.Microsecond)

	// Restore original TTL.
	dc.rawConn.Control(func(fd uintptr) {
		controlErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, originalTTL)
	})
	return controlErr
}
