//go:build windows

package process

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// queryProcessPath uses Windows API to get the executable path from a PID.
func queryProcessPath(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
	if err != nil {
		return "", err
	}

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&buf[0]))), nil
}
