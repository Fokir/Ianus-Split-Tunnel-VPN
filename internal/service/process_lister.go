//go:build windows

package service

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	vpnapi "awg-split-tunnel/api/gen"
)

// listRunningProcesses enumerates running processes, optionally filtered by name substring.
func listRunningProcesses(nameFilter string) ([]*vpnapi.ProcessInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = windows.Process32First(snapshot, &pe)
	if err != nil {
		return nil, err
	}

	filterLower := strings.ToLower(nameFilter)
	var result []*vpnapi.ProcessInfo

	for {
		name := windows.UTF16ToString(pe.ExeFile[:])
		if nameFilter == "" || strings.Contains(strings.ToLower(name), filterLower) {
			info := &vpnapi.ProcessInfo{
				Pid:  pe.ProcessID,
				Name: name,
			}
			// Try to get full path.
			if path := getProcessPath(pe.ProcessID); path != "" {
				info.Path = path
			}
			result = append(result, info)
		}

		err = windows.Process32Next(snapshot, &pe)
		if err != nil {
			break
		}
	}

	return result, nil
}

// getProcessPath attempts to retrieve the full exe path for a PID.
func getProcessPath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	err = windows.QueryFullProcessImageName(h, 0, &buf[0], &size)
	if err != nil {
		return ""
	}
	return filepath.Clean(windows.UTF16ToString(buf[:size]))
}
