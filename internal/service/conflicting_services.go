//go:build windows

package service

import (
	"fmt"
	"strings"
	"time"
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
// Also detects WinDivert driver services in non-stopped states (e.g. registered
// but not yet started) because the kernel driver may still be loaded.
func CheckConflictingServices() []ConflictingServiceInfo {
	var result []ConflictingServiceInfo

	// Check Windows services (WinDivert driver, etc.)
	// Detect any non-deleted service — even if it reports as "stopped," the kernel
	// driver may still be loaded if handles were not properly closed.
	for _, s := range knownConflictingServices {
		state, err := getServiceState(s.Name)
		if err != nil {
			continue // service doesn't exist
		}
		result = append(result, ConflictingServiceInfo{
			Name:        s.Name,
			DisplayName: s.DisplayName,
			Type:        "service",
			Running:     state == svc.Running || state == svc.StartPending || state == svc.StopPending,
			Description: s.Description,
		})
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

// getServiceState returns the current state of a Windows service.
// Returns an error if the service doesn't exist.
func getServiceState(serviceName string) (svc.State, error) {
	m, err := mgr.Connect()
	if err != nil {
		return 0, err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return 0, err // service doesn't exist
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return 0, err
	}
	return status.State, nil
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
// Waits for the service to fully stop before deleting to ensure the kernel
// driver is completely unloaded. Deletion prevents the driver from auto-loading
// again. The application that installed it (e.g. zapret) will reinstall it on
// next launch if needed.
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

	// Stop the service.
	status, err := s.Control(svc.Stop)
	if err != nil {
		// If already stopped, continue to delete.
		core.Log.Warnf("Core", "Stop service %q: %v (continuing to delete)", serviceName, err)
	} else {
		// Wait for the service to fully stop (up to 15 seconds).
		// This is critical for kernel drivers like WinDivert — the driver must
		// be completely unloaded before we can safely proceed.
		for i := 0; i < 30; i++ {
			if status.State == svc.Stopped {
				core.Log.Infof("Core", "Conflicting service %q stopped", serviceName)
				break
			}
			time.Sleep(500 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				core.Log.Warnf("Core", "Query service %q: %v", serviceName, err)
				break
			}
		}
		if status.State != svc.Stopped {
			core.Log.Warnf("Core", "Service %q did not stop in time (state=%d)", serviceName, status.State)
		}
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

// killProcessByName terminates all processes matching the given executable name
// and waits for them to fully exit. Waiting is important because the process may
// hold handles to kernel drivers (e.g. WinDivert) that prevent the driver from
// unloading until the handle is released.
func killProcessByName(exeName string) error {
	pids, err := findProcessesByName(exeName)
	if err != nil {
		return err
	}

	if len(pids) == 0 {
		return nil // already not running
	}

	// Terminate and collect handles to wait on.
	var handles []windows.Handle
	var lastErr error
	for _, pid := range pids {
		// Open with TERMINATE + SYNCHRONIZE so we can wait for exit.
		handle, err := windows.OpenProcess(
			windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid,
		)
		if err != nil {
			lastErr = fmt.Errorf("open process %d: %w", pid, err)
			continue
		}
		if err := windows.TerminateProcess(handle, 1); err != nil {
			lastErr = fmt.Errorf("terminate process %d: %w", pid, err)
			windows.CloseHandle(handle)
			continue
		}
		handles = append(handles, handle)
	}

	// Wait for all terminated processes to fully exit (up to 5 seconds each).
	// This ensures handles to kernel drivers are released before we try to
	// stop the driver service.
	for _, h := range handles {
		windows.WaitForSingleObject(h, 5000) // 5s timeout
		windows.CloseHandle(h)
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
