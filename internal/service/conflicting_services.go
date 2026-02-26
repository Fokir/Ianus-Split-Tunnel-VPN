//go:build windows

package service

import (
	"fmt"
	"strings"
	"unsafe"

	"awg-split-tunnel/internal/core"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ConflictingServiceInfo describes a detected conflicting service or process.
type ConflictingServiceInfo struct {
	Name        string // service or process name (key for stopping)
	DisplayName string // human-readable display name
	Type        string // "service" or "process"
	Running     bool   // true if currently active
	Description string // why it conflicts with our client
}

// knownConflictingServices lists Windows services that conflict with WFP/TUN routing.
// WinDivert registers under different names depending on the version.
var knownConflictingServices = []struct {
	Name        string
	DisplayName string
	Description string
}{
	{"WinDivert", "WinDivert Driver", "WinDivert kernel driver intercepts network packets and conflicts with WFP rules"},
	{"WinDivert14", "WinDivert 1.4 Driver", "WinDivert 1.4 kernel driver intercepts network packets and conflicts with WFP rules"},
	{"WinDivert1.4", "WinDivert 1.4 Driver", "WinDivert 1.4 kernel driver intercepts network packets and conflicts with WFP rules"},
}

// knownConflictingProcesses lists user-space processes that use WinDivert or
// otherwise manipulate traffic in ways that conflict with our TUN gateway.
var knownConflictingProcesses = []struct {
	ExeName     string
	DisplayName string
	Description string
}{
	{"winws.exe", "Zapret (winws)", "Zapret DPI bypass tool uses WinDivert to modify packets"},
	{"goodbyedpi.exe", "GoodbyeDPI", "DPI bypass tool uses WinDivert to modify packets"},
	{"blockcheck.exe", "Zapret BlockCheck", "Zapret diagnostics tool uses WinDivert"},
}

// CheckConflictingServices detects running third-party services and processes
// that are known to conflict with our WFP rules and TUN routing.
func CheckConflictingServices() []ConflictingServiceInfo {
	var result []ConflictingServiceInfo

	// Check Windows services (WinDivert driver, etc.)
	for _, s := range knownConflictingServices {
		if running, err := isServiceRunning(s.Name); err == nil && running {
			result = append(result, ConflictingServiceInfo{
				Name:        s.Name,
				DisplayName: s.DisplayName,
				Type:        "service",
				Running:     true,
				Description: s.Description,
			})
		}
	}

	// Check running processes (winws.exe, goodbyedpi.exe, etc.)
	runningProcs := getRunningProcessNames()
	for _, p := range knownConflictingProcesses {
		if _, found := runningProcs[strings.ToLower(p.ExeName)]; found {
			result = append(result, ConflictingServiceInfo{
				Name:        p.ExeName,
				DisplayName: p.DisplayName,
				Type:        "process",
				Running:     true,
				Description: p.Description,
			})
		}
	}

	return result
}

// StopConflictingService stops a conflicting service or kills a process by name.
// Returns nil on success.
func StopConflictingService(name string) error {
	// Try as Windows service first.
	for _, s := range knownConflictingServices {
		if strings.EqualFold(s.Name, name) {
			return stopWindowsService(name)
		}
	}

	// Try as process.
	for _, p := range knownConflictingProcesses {
		if strings.EqualFold(p.ExeName, name) {
			return killProcessByName(name)
		}
	}

	return fmt.Errorf("unknown conflicting service: %s", name)
}

// isServiceRunning checks if a Windows service exists and is running.
func isServiceRunning(serviceName string) (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return false, nil // service doesn't exist
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return false, err
	}

	return status.State == svc.Running, nil
}

// stopWindowsService stops and deletes a Windows driver service via SCM.
// This is the equivalent of `sc stop <name>` followed by `sc delete <name>`.
// Deletion prevents the driver from auto-loading again. The application that
// installed it (e.g. zapret) will reinstall it on next launch if needed.
func stopWindowsService(serviceName string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", serviceName, err)
	}
	defer s.Close()

	// Stop the service first.
	status, err := s.Control(svc.Stop)
	if err != nil {
		// If already stopped, continue to delete.
		core.Log.Warnf("Core", "Stop service %q: %v (continuing to delete)", serviceName, err)
	} else {
		core.Log.Infof("Core", "Stopped conflicting service %q (state=%d)", serviceName, status.State)
	}

	// Delete the service registration to prevent it from loading again.
	if err := s.Delete(); err != nil {
		core.Log.Warnf("Core", "Delete service %q: %v", serviceName, err)
		// Non-fatal — stop alone may be sufficient for this session.
	} else {
		core.Log.Infof("Core", "Deleted conflicting service %q", serviceName)
	}

	return nil
}

// killProcessByName terminates all processes matching the given executable name.
func killProcessByName(exeName string) error {
	pids, err := findProcessesByName(exeName)
	if err != nil {
		return err
	}

	if len(pids) == 0 {
		return nil // already not running
	}

	var lastErr error
	for _, pid := range pids {
		handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
		if err != nil {
			lastErr = fmt.Errorf("open process %d: %w", pid, err)
			continue
		}
		if err := windows.TerminateProcess(handle, 1); err != nil {
			lastErr = fmt.Errorf("terminate process %d: %w", pid, err)
		}
		windows.CloseHandle(handle)
	}

	if lastErr != nil {
		return lastErr
	}
	core.Log.Infof("Core", "Killed conflicting process %q (%d instances)", exeName, len(pids))
	return nil
}

// findProcessesByName returns PIDs of all processes with the given executable name.
func findProcessesByName(exeName string) ([]uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("create process snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	if err := windows.Process32First(snapshot, &pe); err != nil {
		return nil, err
	}

	target := strings.ToLower(exeName)
	var pids []uint32

	for {
		name := windows.UTF16ToString(pe.ExeFile[:])
		if strings.EqualFold(name, target) {
			pids = append(pids, pe.ProcessID)
		}
		if err := windows.Process32Next(snapshot, &pe); err != nil {
			break
		}
	}

	return pids, nil
}

// getRunningProcessNames returns a set of lowercase process names currently running.
func getRunningProcessNames() map[string]struct{} {
	result := make(map[string]struct{})

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return result
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	if err := windows.Process32First(snapshot, &pe); err != nil {
		return result
	}

	for {
		name := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
		result[name] = struct{}{}
		if err := windows.Process32Next(snapshot, &pe); err != nil {
			break
		}
	}

	return result
}
