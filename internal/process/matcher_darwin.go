//go:build darwin

package process

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// proc_pidpath syscall constants (from XNU bsd/sys/proc_info.h).
const (
	sysProcInfo          = 336 // SYS_PROC_INFO
	procInfoCallPIDInfo  = 2   // PROC_INFO_CALL_PIDINFO
	procPIDPathInfo      = 11  // PROC_PIDPATHINFO
	procPIDPathInfoMaxSz = 4096
)

// queryProcessPath retrieves the executable path for a PID using the
// proc_pidpath equivalent via raw syscall (no CGO required).
//
// Calls: syscall6(SYS_PROC_INFO=336, PROC_INFO_CALL_PIDINFO=2, pid, PROC_PIDPATHINFO=11, 0, buf, 4096)
func queryProcessPath(pid uint32) (string, error) {
	buf := make([]byte, procPIDPathInfoMaxSz)
	n, _, errno := unix.Syscall6(
		sysProcInfo,
		uintptr(procInfoCallPIDInfo),
		uintptr(pid),
		uintptr(procPIDPathInfo),
		0, // arg
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(procPIDPathInfoMaxSz),
	)
	if errno != 0 {
		return "", errno
	}
	if n == 0 {
		return "", unix.ESRCH
	}
	// n = bytes written; result is a null-terminated C string.
	return unix.ByteSliceToString(buf[:n]), nil
}
