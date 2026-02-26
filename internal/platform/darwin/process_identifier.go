//go:build darwin

package darwin

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// proc_info syscall constants (from XNU bsd/sys/proc_info.h).
const (
	sysProcInfo = 336 // SYS_PROC_INFO

	procInfoCallListPIDs  = 1 // PROC_INFO_CALL_LISTPIDS
	procInfoCallPIDInfo   = 2 // PROC_INFO_CALL_PIDINFO
	procInfoCallPIDFDInfo = 3 // PROC_INFO_CALL_PIDFDINFO

	procAllPIDs         = 1 // PROC_ALL_PIDS
	procPIDListFDs      = 1 // PROC_PIDLISTFDS
	procPIDFDSocketInfo = 3 // PROC_PIDFDSOCKETINFO

	procFDTypeSocket = 2 // PROX_FDTYPE_SOCKET
)

// struct proc_fdinfo layout (8 bytes).
const (
	procFDInfoSize    = 8
	procFDFieldFD     = 0 // int32: file descriptor
	procFDFieldFDType = 4 // uint32: descriptor type
)

// struct socket_fdinfo offsets (from XNU kernel headers).
// Layout: proc_fileinfo(24) + socket_info(vinfo_stat(136) + fields(48) + union).
const (
	sockProtocolOff  = 180 // socket_info.soi_protocol (int32)
	sockFamilyOff    = 184 // socket_info.soi_family (int32)
	sockLocalPortOff = 212 // socket_info.soi_proto.pri_in.insi_lport (int32, network byte order)
	sockFDInfoBufSz  = 1024
)

// portKey identifies a network port + protocol pair.
type portKey struct {
	port  uint16
	isUDP bool
}

// ProcessIdentifier implements platform.ProcessIdentifier using macOS proc_info
// raw syscall (SYS_PROC_INFO 336). Scans all processes and their socket FDs to
// build a port→PID map, cached for 300ms.
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

// scanPortPIDs iterates all processes and their socket FDs to build port→PID map.
func scanPortPIDs() (map[portKey]uint32, error) {
	result := make(map[portKey]uint32, 256)

	pids, err := listAllPIDs()
	if err != nil {
		return nil, err
	}

	fdBuf := make([]byte, 64*1024) // handles ~8000 FDs per process
	sockBuf := make([]byte, sockFDInfoBufSz)

	for _, pid := range pids {
		// List file descriptors for this process.
		n, err := callPIDInfo(pid, procPIDListFDs, 0, fdBuf)
		if err != nil || n < procFDInfoSize {
			continue // permission denied or zombie — skip
		}

		numFDs := n / procFDInfoSize
		for i := 0; i < numFDs; i++ {
			off := i * procFDInfoSize

			// Only inspect socket FDs.
			fdType := binary.LittleEndian.Uint32(fdBuf[off+procFDFieldFDType : off+procFDFieldFDType+4])
			if fdType != procFDTypeSocket {
				continue
			}

			fd := int(int32(binary.LittleEndian.Uint32(fdBuf[off+procFDFieldFD : off+procFDFieldFD+4])))
			if fd < 0 {
				continue
			}

			// Get socket info for this FD.
			sn, err := callPIDFDInfo(pid, fd, procPIDFDSocketInfo, sockBuf)
			if err != nil || sn < sockLocalPortOff+4 {
				continue
			}

			// Filter: only AF_INET (2) and AF_INET6 (30).
			family := int32(binary.LittleEndian.Uint32(sockBuf[sockFamilyOff : sockFamilyOff+4]))
			if family != 2 && family != 30 {
				continue
			}

			// Filter: only TCP (6) and UDP (17).
			proto := int32(binary.LittleEndian.Uint32(sockBuf[sockProtocolOff : sockProtocolOff+4]))
			var isUDP bool
			switch proto {
			case 6: // IPPROTO_TCP
				isUDP = false
			case 17: // IPPROTO_UDP
				isUDP = true
			default:
				continue
			}

			// Local port is stored in network byte order (big endian) in the first 2 bytes.
			localPort := binary.BigEndian.Uint16(sockBuf[sockLocalPortOff : sockLocalPortOff+2])
			if localPort == 0 {
				continue
			}

			result[portKey{localPort, isUDP}] = uint32(pid)
		}
	}

	return result, nil
}

// listAllPIDs returns all process IDs on the system.
func listAllPIDs() ([]int, error) {
	// First call: get required buffer size.
	n, err := sysCallProcInfo(procInfoCallListPIDs, 0, procAllPIDs, 0, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("list PIDs: %w", err)
	}
	if n <= 0 {
		return nil, fmt.Errorf("proc_info returned 0 PIDs")
	}

	// Allocate 2x to handle race with new processes.
	bufSize := n * 2
	buf := make([]byte, bufSize)
	n, err = sysCallProcInfo(procInfoCallListPIDs, 0, procAllPIDs, 0, unsafe.Pointer(&buf[0]), bufSize)
	if err != nil {
		return nil, fmt.Errorf("list PIDs: %w", err)
	}

	numPIDs := n / 4
	pids := make([]int, 0, numPIDs)
	for i := 0; i < numPIDs; i++ {
		pid := int32(binary.LittleEndian.Uint32(buf[i*4 : i*4+4]))
		if pid > 0 {
			pids = append(pids, int(pid))
		}
	}
	return pids, nil
}

// callPIDInfo calls proc_info(PROC_INFO_CALL_PIDINFO, pid, flavor, arg, buf, bufsize).
func callPIDInfo(pid, flavor int, arg uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	return sysCallProcInfo(procInfoCallPIDInfo, pid, flavor, arg, unsafe.Pointer(&buf[0]), len(buf))
}

// callPIDFDInfo calls proc_info(PROC_INFO_CALL_PIDFDINFO, pid, fd, fdInfoFlavor, buf, bufsize).
// Note: for PIDFDINFO, the "flavor" param = fd number, "arg" = fdinfo flavor.
func callPIDFDInfo(pid, fd, fdInfoFlavor int, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	return sysCallProcInfo(procInfoCallPIDFDInfo, pid, fd, uint64(fdInfoFlavor), unsafe.Pointer(&buf[0]), len(buf))
}

// sysCallProcInfo invokes the proc_info(2) syscall (SYS_PROC_INFO = 336).
func sysCallProcInfo(callnum, pid, flavor int, arg uint64, buf unsafe.Pointer, bufsize int) (int, error) {
	r1, _, errno := unix.Syscall6(
		sysProcInfo,
		uintptr(callnum),
		uintptr(pid),
		uintptr(flavor),
		uintptr(arg),
		uintptr(buf),
		uintptr(bufsize),
	)
	if errno != 0 {
		return 0, errno
	}
	return int(r1), nil
}
