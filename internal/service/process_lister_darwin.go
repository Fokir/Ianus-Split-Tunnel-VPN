//go:build darwin

package service

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"

	vpnapi "awg-split-tunnel/api/gen"
)

// proc_info syscall constants (from XNU bsd/sys/proc_info.h).
const (
	sysProcInfo         = 336 // SYS_PROC_INFO
	procInfoCallList    = 1   // PROC_INFO_CALL_LISTPIDS
	procInfoCallPIDInfo = 2   // PROC_INFO_CALL_PIDINFO
	procAllPIDs         = 1   // PROC_ALL_PIDS
	procPIDPathInfo     = 11  // PROC_PIDPATHINFO
	procPIDPathMaxSz    = 4096
)

// listRunningProcesses enumerates running processes, optionally filtered by name substring.
// Uses raw proc_info syscalls — no CGO required.
func listRunningProcesses(nameFilter string) ([]*vpnapi.ProcessInfo, error) {
	pids, err := listAllPIDsForLister()
	if err != nil {
		return nil, err
	}

	filterLower := strings.ToLower(nameFilter)
	pathBuf := make([]byte, procPIDPathMaxSz)
	var result []*vpnapi.ProcessInfo

	for _, pid := range pids {
		path := pidPath(uint32(pid), pathBuf)
		if path == "" {
			continue
		}

		name := filepath.Base(path)
		if nameFilter != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			continue
		}

		result = append(result, &vpnapi.ProcessInfo{
			Pid:  uint32(pid),
			Name: name,
			Path: path,
		})
	}

	return result, nil
}

// pidPath retrieves the executable path for a PID via proc_pidpath syscall.
// Returns empty string on error (permission denied, zombie, etc.).
func pidPath(pid uint32, buf []byte) string {
	n, _, errno := unix.Syscall6(
		sysProcInfo,
		uintptr(procInfoCallPIDInfo),
		uintptr(pid),
		uintptr(procPIDPathInfo),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if errno != 0 || n == 0 {
		return ""
	}
	return unix.ByteSliceToString(buf[:n])
}

// listAllPIDsForLister returns all process IDs on the system.
func listAllPIDsForLister() ([]int, error) {
	// First call: determine buffer size.
	n, _, errno := unix.Syscall6(
		sysProcInfo,
		uintptr(procInfoCallList),
		uintptr(procAllPIDs),
		0, 0, 0, 0,
	)
	if errno != 0 {
		return nil, errno
	}
	if n <= 0 {
		return nil, unix.ESRCH
	}

	// Allocate 2x to handle race with new processes.
	bufSize := int(n) * 2
	buf := make([]byte, bufSize)
	n, _, errno = unix.Syscall6(
		sysProcInfo,
		uintptr(procInfoCallList),
		uintptr(procAllPIDs),
		0, 0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(bufSize),
	)
	if errno != 0 {
		return nil, errno
	}

	numPIDs := int(n) / 4
	pids := make([]int, 0, numPIDs)
	for i := 0; i < numPIDs; i++ {
		pid := int32(binary.LittleEndian.Uint32(buf[i*4 : i*4+4]))
		if pid > 0 {
			pids = append(pids, int(pid))
		}
	}
	return pids, nil
}
