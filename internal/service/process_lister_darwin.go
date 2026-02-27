//go:build darwin

package service

import (
	"log"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	vpnapi "awg-split-tunnel/api/gen"
)

// proc_info syscall constants (from XNU bsd/sys/proc_info.h).
// Buffer size 1024 = PROC_PIDPATHINFO_SIZE (MAXPATHLEN), matching sing-box and mihomo.
const (
	procInfoCallPIDInfoSvc = 2    // PROC_INFO_CALL_PIDINFO
	procPIDPathInfoSvc     = 0xb  // PROC_PIDPATHINFO
	procPIDPathBufSize     = 1024 // PROC_PIDPATHINFO_SIZE = MAXPATHLEN
)

// listRunningProcesses enumerates running processes, optionally filtered by name substring.
// Uses sysctl("kern.proc.all") for PID enumeration (proven approach from gopsutil)
// and proc_pidpath syscall for executable path resolution.
func listRunningProcesses(nameFilter string) ([]*vpnapi.ProcessInfo, error) {
	pids, err := listAllPIDsForLister()
	if err != nil {
		log.Printf("[ProcessLister] listAllPIDsForLister failed: %v", err)
		return nil, err
	}
	log.Printf("[ProcessLister] enumerated %d PIDs", len(pids))

	filterLower := strings.ToLower(nameFilter)
	pathBuf := make([]byte, procPIDPathBufSize)
	var result []*vpnapi.ProcessInfo
	pathFails := 0

	for _, pid := range pids {
		path := pidPath(uint32(pid), pathBuf)
		if path == "" {
			pathFails++
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

	log.Printf("[ProcessLister] resolved %d processes (%d PIDs had no path)", len(result), pathFails)
	return result, nil
}

// pidPath retrieves the executable path for a PID via proc_pidpath syscall.
// Returns empty string on error (permission denied, zombie, etc.).
func pidPath(pid uint32, buf []byte) string {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		procInfoCallPIDInfoSvc,
		uintptr(pid),
		procPIDPathInfoSvc,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return ""
	}
	return unix.ByteSliceToString(buf)
}

// listAllPIDsForLister returns all process IDs on the system using
// sysctl("kern.proc.all"). This is the standard approach used by gopsutil
// and other tools — it returns typed KinfoProc structures and handles
// buffer management automatically via golang.org/x/sys/unix.
func listAllPIDsForLister() ([]int, error) {
	kprocs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}

	pids := make([]int, 0, len(kprocs))
	for i := range kprocs {
		pid := int32(kprocs[i].Proc.P_pid)
		if pid > 0 {
			pids = append(pids, int(pid))
		}
	}
	return pids, nil
}
