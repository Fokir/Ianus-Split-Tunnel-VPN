package dpibypass

import (
	"net"
	"sort"
	"sync"
	"syscall"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/dpi"
)

// desyncConn wraps a net.TCPConn and applies DPI desynchronization
// on the first Write containing a TLS ClientHello.
// After the first Write (or if the data isn't a ClientHello), all
// subsequent Writes pass through directly.
type desyncConn struct {
	net.Conn
	tcp      *net.TCPConn
	rawConn  syscall.RawConn // for TTL manipulation
	strategy *dpi.Strategy
	mu       sync.Mutex
	desyncDone bool
}

// newDesyncConn wraps an existing TCP connection for DPI desync.
// It enables TCP_NODELAY to prevent the OS from coalescing our split segments.
func newDesyncConn(conn *net.TCPConn, strategy *dpi.Strategy) *desyncConn {
	dc := &desyncConn{
		Conn:     conn,
		tcp:      conn,
		strategy: strategy,
	}
	// TCP_NODELAY ensures each Write() generates a separate TCP segment.
	if err := conn.SetNoDelay(true); err != nil {
		core.Log.Debugf("DPI", "SetNoDelay failed: %v", err)
	}
	// Get raw conn for TTL manipulation in fake packet injection.
	if rc, err := conn.SyscallConn(); err == nil {
		dc.rawConn = rc
	}
	return dc
}

// Write intercepts the first write. If it's a TLS ClientHello, applies
// desync operations; otherwise passes through. All subsequent writes
// go directly to the underlying connection.
func (dc *desyncConn) Write(b []byte) (int, error) {
	dc.mu.Lock()
	done := dc.desyncDone
	if !done {
		dc.desyncDone = true
	}
	dc.mu.Unlock()

	if done {
		return dc.Conn.Write(b)
	}

	if !dpi.IsTLSClientHello(b) {
		return dc.Conn.Write(b)
	}

	return dc.applyDesync(b)
}

// applyDesync applies all matching desync operations to the ClientHello payload.
func (dc *desyncConn) applyDesync(hello []byte) (int, error) {
	if dc.strategy == nil || len(dc.strategy.Ops) == 0 {
		return dc.Conn.Write(hello)
	}

	// Determine destination port from the connection's remote address.
	dstPort := 0
	if addr, ok := dc.Conn.RemoteAddr().(*net.TCPAddr); ok {
		dstPort = addr.Port
	}

	totalLen := len(hello)
	for _, op := range dc.strategy.Ops {
		if op.FilterProtocol != "" && op.FilterProtocol != "tcp" {
			continue
		}
		if !op.MatchesPort(dstPort) {
			continue
		}

		var err error
		switch op.Mode {
		case dpi.DesyncMultisplit:
			err = dc.applyMultisplit(hello, &op)
		case dpi.DesyncFake:
			err = dc.applyFake(hello, &op)
		case dpi.DesyncFakedsplit:
			err = dc.applyFakedsplit(hello, &op)
		case dpi.DesyncMultidisorder:
			err = dc.applyMultidisorder(hello, &op)
		case dpi.DesyncNone:
			_, err = dc.Conn.Write(hello)
		default:
			_, err = dc.Conn.Write(hello)
		}

		if err != nil {
			return 0, err
		}
		// First matching op handles the write; done.
		return totalLen, nil
	}

	// No matching ops — send as-is.
	return dc.Conn.Write(hello)
}

// applyMultisplit splits the ClientHello into multiple TCP segments
// at the specified positions, sending each as a separate Write.
func (dc *desyncConn) applyMultisplit(hello []byte, op *dpi.DesyncOp) error {
	positions := dc.resolveSplitPositions(hello, op.SplitPos)
	if len(positions) == 0 {
		_, err := dc.Conn.Write(hello)
		return err
	}

	chunks := splitAt(hello, positions)
	for i, chunk := range chunks {
		if _, err := dc.Conn.Write(chunk); err != nil {
			return err
		}
		// Small delay between segments to reduce OS coalescence.
		if i < len(chunks)-1 {
			time.Sleep(1 * time.Millisecond)
		}
	}
	return nil
}

// applyFake injects fake packets with short TTL before sending the real data.
// The fake packets are seen by DPI middleboxes but expire before reaching
// the destination server.
func (dc *desyncConn) applyFake(hello []byte, op *dpi.DesyncOp) error {
	fakePayload := op.FakeTLS
	if len(fakePayload) == 0 {
		fakePayload = defaultFakeClientHello()
	}

	for i := 0; i < op.Repeats; i++ {
		if err := dc.sendFakePacket(fakePayload, op.FakeTTL); err != nil {
			core.Log.Debugf("DPI", "fake packet send failed: %v", err)
			// Continue even if fake injection fails.
		}
	}

	// Send real ClientHello.
	_, err := dc.Conn.Write(hello)
	return err
}

// applyFakedsplit combines fake injection with multisplit:
// injects fake packet(s), then sends split real ClientHello segments.
func (dc *desyncConn) applyFakedsplit(hello []byte, op *dpi.DesyncOp) error {
	fakePayload := op.FakeTLS
	if len(fakePayload) == 0 {
		fakePayload = defaultFakeClientHello()
	}

	positions := dc.resolveSplitPositions(hello, op.SplitPos)
	chunks := splitAt(hello, positions)

	for i, chunk := range chunks {
		// Inject fake before each chunk.
		for r := 0; r < op.Repeats; r++ {
			if err := dc.sendFakePacket(fakePayload, op.FakeTTL); err != nil {
				core.Log.Debugf("DPI", "fakedsplit: fake send failed: %v", err)
			}
		}
		if _, err := dc.Conn.Write(chunk); err != nil {
			return err
		}
		if i < len(chunks)-1 {
			time.Sleep(1 * time.Millisecond)
		}
	}
	return nil
}

// applyMultidisorder sends split segments in reverse order.
func (dc *desyncConn) applyMultidisorder(hello []byte, op *dpi.DesyncOp) error {
	positions := dc.resolveSplitPositions(hello, op.SplitPos)
	if len(positions) == 0 {
		_, err := dc.Conn.Write(hello)
		return err
	}

	chunks := splitAt(hello, positions)
	// Send in reverse order (disorder).
	for i := len(chunks) - 1; i >= 0; i-- {
		if _, err := dc.Conn.Write(chunks[i]); err != nil {
			return err
		}
		if i > 0 {
			time.Sleep(1 * time.Millisecond)
		}
	}
	return nil
}

// resolveSplitPositions converts op split positions into concrete byte offsets
// within the hello payload. SplitPosAutoSNI (0) is resolved to the SNI offset.
// Negative values count from the end of the payload.
func (dc *desyncConn) resolveSplitPositions(hello []byte, splitPos []int) []int {
	if len(splitPos) == 0 {
		// Default: split at SNI.
		sniOff := dpi.FindSNIOffset(hello)
		if sniOff > 0 {
			return []int{sniOff}
		}
		return nil
	}

	sniOffset := -1 // lazy-computed
	var result []int

	for _, pos := range splitPos {
		switch {
		case pos == dpi.SplitPosAutoSNI:
			if sniOffset < 0 {
				sniOffset = dpi.FindSNIOffset(hello)
			}
			if sniOffset > 0 && sniOffset < len(hello) {
				result = append(result, sniOffset)
			}
		case pos < 0:
			actual := len(hello) + pos
			if actual > 0 && actual < len(hello) {
				result = append(result, actual)
			}
		default:
			if pos > 0 && pos < len(hello) {
				result = append(result, pos)
			}
		}
	}

	return result
}

// splitAt splits data into chunks at the given sorted byte offsets.
func splitAt(data []byte, positions []int) [][]byte {
	if len(positions) == 0 {
		return [][]byte{data}
	}

	// Deduplicate and sort positions.
	sort.Ints(positions)
	unique := positions[:0]
	prev := -1
	for _, p := range positions {
		if p != prev && p > 0 && p < len(data) {
			unique = append(unique, p)
			prev = p
		}
	}
	positions = unique

	if len(positions) == 0 {
		return [][]byte{data}
	}

	chunks := make([][]byte, 0, len(positions)+1)
	start := 0
	for _, pos := range positions {
		if pos > start {
			chunks = append(chunks, data[start:pos])
			start = pos
		}
	}
	if start < len(data) {
		chunks = append(chunks, data[start:])
	}
	return chunks
}

// defaultFakeClientHello returns a minimal fake TLS ClientHello payload.
func defaultFakeClientHello() []byte {
	return []byte{
		0x16, 0x03, 0x01, 0x00, 0x2F,
		0x01, 0x00, 0x00, 0x2B, 0x03, 0x03,
		0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE,
		0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE,
		0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE,
		0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE,
		0x00, 0x00, 0x02, 0x00, 0xFF, 0x01, 0x00,
	}
}
