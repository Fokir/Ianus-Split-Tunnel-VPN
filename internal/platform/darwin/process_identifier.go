//go:build darwin

package darwin

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// pcbStructSize is the per-entry size in pcblist_n output (xinpcb_n + xsocket_n + sockbufs).
// Varies by macOS version: 408 on macOS 13+ (Darwin 22.x), 384 on macOS 12 and earlier.
// Reference: mihomo (Clash Meta) and sing-box use identical size detection.
var pcbStructSize = func() int {
	release, _ := unix.Sysctl("kern.osrelease")
	major, _, _ := strings.Cut(release, ".")
	n, _ := strconv.ParseInt(major, 10, 64)
	if n >= 22 { // macOS 13 Ventura+ (Darwin 22.x)
		return 408
	}
	return 384 // macOS 12 and earlier
}()

// pcblist_n parsing constants (from XNU kernel headers, verified against mihomo/sing-box).
const (
	xinpgenSize   = 24  // sizeof(xinpgen) — header/trailer
	tcpEntryExtra = 208 // sizeof(xtcpcb_n) — appended to each TCP entry
	offInpLport   = 18  // inp_lport in xinpcb_n (big-endian uint16)
	offSoBase     = 104 // xsocket_n starts at this offset within each entry
	offSoLastPID  = 68  // so_last_pid within xsocket_n (native-endian int32)
)

// portKey identifies a network port + protocol pair.
type portKey struct {
	port  uint16
	isUDP bool
}

// ProcessIdentifier implements platform.ProcessIdentifier using macOS
// sysctl("net.inet.{tcp,udp}.pcblist_n") — a single atomic kernel snapshot
// per protocol, O(1) syscalls + O(S) linear scan. Cached for 300ms.
type ProcessIdentifier struct {
	mu       sync.RWMutex
	cache    map[portKey]uint32
	cacheAge time.Time
}

const pidCacheTTL = 300 * time.Millisecond

// NewProcessIdentifier creates a macOS process identifier.
func NewProcessIdentifier() *ProcessIdentifier {
	return &ProcessIdentifier{
		cache: make(map[portKey]uint32),
	}
}

// FindPIDByPort finds the PID owning a connection with the given local port.
// Uses a cached full-system scan (300ms TTL) for performance.
func (pi *ProcessIdentifier) FindPIDByPort(srcPort uint16, isUDP bool) (uint32, error) {
	key := portKey{srcPort, isUDP}

	// Fast path: read from cache.
	pi.mu.RLock()
	if pid, ok := pi.cache[key]; ok && time.Since(pi.cacheAge) < pidCacheTTL {
		pi.mu.RUnlock()
		return pid, nil
	}
	pi.mu.RUnlock()

	// Cache expired or miss — full scan.
	newCache, err := scanPortPIDs()
	if err != nil {
		return 0, err
	}

	pi.mu.Lock()
	pi.cache = newCache
	pi.cacheAge = time.Now()
	pi.mu.Unlock()

	if pid, ok := newCache[key]; ok {
		return pid, nil
	}

	return 0, fmt.Errorf("no PID for port %d (UDP=%v)", srcPort, isUDP)
}

// scanPortPIDs builds a port->PID map from kernel pcblist_n snapshots for TCP and UDP.
func scanPortPIDs() (map[portKey]uint32, error) {
	result := make(map[portKey]uint32, 256)

	tcpBuf, err := unix.SysctlRaw("net.inet.tcp.pcblist_n")
	if err != nil {
		return nil, fmt.Errorf("sysctl tcp.pcblist_n: %w", err)
	}
	parsePCBList(tcpBuf, false, result)

	udpBuf, err := unix.SysctlRaw("net.inet.udp.pcblist_n")
	if err != nil {
		return nil, fmt.Errorf("sysctl udp.pcblist_n: %w", err)
	}
	parsePCBList(udpBuf, true, result)

	return result, nil
}

// parsePCBList parses a pcblist_n sysctl buffer into port->PID entries.
//
// Buffer layout: xinpgen (24B) | fixed-size entries | xinpgen trailer (24B).
// Each entry is a monolithic block: xinpcb_n + xsocket_n + sockbufs (pcbStructSize bytes),
// plus xtcpcb_n (208 bytes) for TCP. Stride is constant for a given protocol and macOS version.
//
// Offsets within each entry (verified against mihomo and sing-box):
//   - inp_lport:   byte 18  (big-endian uint16)
//   - xsocket_n:   byte 104 (start of embedded socket structure)
//   - so_last_pid: byte 104+68 = 172 (native-endian int32)
func parsePCBList(buf []byte, isUDP bool, result map[portKey]uint32) {
	entrySize := pcbStructSize
	if !isUDP {
		entrySize += tcpEntryExtra
	}

	pidOff := offSoBase + offSoLastPID // 104 + 68 = 172

	// Skip xinpgen header; stop when remaining bytes can't fit a full entry
	// (the 24-byte trailer is always smaller than any entry).
	for pos := xinpgenSize; pos+entrySize <= len(buf); pos += entrySize {
		localPort := binary.BigEndian.Uint16(buf[pos+offInpLport : pos+offInpLport+2])
		pid := binary.LittleEndian.Uint32(buf[pos+pidOff : pos+pidOff+4])

		if localPort != 0 && pid != 0 {
			result[portKey{localPort, isUDP}] = pid
		}
	}
}
