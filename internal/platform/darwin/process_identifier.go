//go:build darwin

package darwin

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// pcblist_n item kinds (from XNU bsd/sys/socketvar.h).
const (
	xsoSocket = 0x001 // XSO_SOCKET — contains PID
	xsoInpcb  = 0x010 // XSO_INPCB — contains port numbers
)

// pcblist_n parsing offsets (from XNU kernel headers).
const (
	xinpgenSize  = 24 // sizeof(xinpgen) — header/trailer marker
	offInpLport  = 18 // inp_lport in xinpcb_n (big-endian uint16)
	offSoLastPID = 68 // so_last_pid in xsocket_n (native-endian int32)
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
// Buffer layout: xinpgen header | (xinpcb_n, xsocket_n, [xtcpcb_n])* | xinpgen trailer.
// Each sub-item starts with xi_len (uint32) and xi_kind (uint32), allowing
// kind-based iteration that works across all macOS versions without hardcoded struct sizes.
func parsePCBList(buf []byte, isUDP bool, result map[portKey]uint32) {
	// Skip xinpgen header.
	pos := xinpgenSize
	if pos >= len(buf) {
		return
	}

	var currentPort uint16

	for pos+8 <= len(buf) {
		itemLen := int(binary.LittleEndian.Uint32(buf[pos : pos+4]))
		itemKind := binary.LittleEndian.Uint32(buf[pos+4 : pos+8])

		if itemLen < 8 || pos+itemLen > len(buf) {
			break
		}
		// Trailer: xinpgen is 24 bytes; no data struct is that small.
		if itemLen <= xinpgenSize {
			break
		}

		switch itemKind {
		case xsoInpcb: // xinpcb_n — extract local port.
			if itemLen >= offInpLport+2 {
				currentPort = binary.BigEndian.Uint16(buf[pos+offInpLport : pos+offInpLport+2])
			}
		case xsoSocket: // xsocket_n — extract PID, pair with preceding port.
			if currentPort != 0 && itemLen >= offSoLastPID+4 {
				pid := binary.LittleEndian.Uint32(buf[pos+offSoLastPID : pos+offSoLastPID+4])
				if pid != 0 {
					result[portKey{currentPort, isUDP}] = pid
				}
			}
			currentPort = 0
		}

		pos += itemLen
	}
}
