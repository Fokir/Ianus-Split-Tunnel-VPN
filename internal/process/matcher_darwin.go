//go:build darwin

package process

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// proc_pidpath syscall constants (from XNU bsd/sys/proc_info.h).
// Buffer size 1024 = PROC_PIDPATHINFO_SIZE (MAXPATHLEN), matching sing-box and mihomo.
const (
	procInfoCallPIDInfo  = 2    // PROC_INFO_CALL_PIDINFO
	procPIDPathInfo      = 0xb  // PROC_PIDPATHINFO
	procPIDPathInfoSize  = 1024 // PROC_PIDPATHINFO_SIZE = MAXPATHLEN
)

// queryProcessPath retrieves the executable path for a PID using the
// proc_pidpath equivalent via raw syscall (no CGO required).
//
// Implementation matches sing-box/mihomo: uses syscall.SYS_PROC_INFO,
// 1024-byte buffer, and reads the path from the buffer directly
// (ignoring the syscall return value, relying on null-terminated string).
func queryProcessPath(pid uint32) (string, error) {
	buf := make([]byte, procPIDPathInfoSize)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		procInfoCallPIDInfo,
		uintptr(pid),
		procPIDPathInfo,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		procPIDPathInfoSize,
	)
	if errno != 0 {
		return "", errno
	}
	// Path is null-terminated in the buffer; ByteSliceToString finds the null.
	path := unix.ByteSliceToString(buf)
	if path == "" {
		return "", unix.ESRCH
	}
	return path, nil
}
