//go:build linux

package dpibypass

// sendFakePacket is a no-op stub on Linux.
// Fake packet injection with TTL manipulation requires platform-specific
// raw socket syscalls (implemented for Windows and Darwin).
func (dc *desyncConn) sendFakePacket(payload []byte, ttl int) error {
	return nil
}
