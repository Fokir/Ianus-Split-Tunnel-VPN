//go:build windows

package winsvc

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// InstallService registers the Windows Service with the SCM.
// exePath is the full path to the service executable.
// configPath is the path to config.yaml (passed as --config flag).
func InstallService(exePath, configPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return &ServiceError{Op: "connect to SCM", Err: err}
	}
	defer m.Disconnect()

	// Check if already installed.
	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		return &ServiceError{Op: "install", Err: fmt.Errorf("service %q already exists", ServiceName)}
	}

	args := []string{"--service"}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}

	s, err = m.CreateService(ServiceName, exePath, mgr.Config{
		DisplayName:  ServiceDisplayName,
		Description:  ServiceDescription,
		StartType:    mgr.StartAutomatic,
		ServiceStartName: "LocalSystem",
	}, args...)
	if err != nil {
		return &ServiceError{Op: "create service", Err: err}
	}
	defer s.Close()

	// Set recovery actions: restart after 5 seconds on first 3 failures.
	err = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400) // Reset failure count after 24h.
	if err != nil {
		// Non-fatal: service is installed but without recovery actions.
		return nil
	}

	return nil
}

// UninstallService stops and removes the Windows Service.
func UninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return &ServiceError{Op: "connect to SCM", Err: err}
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return &ServiceError{Op: "open service", Err: fmt.Errorf("service %q not found: %w", ServiceName, err)}
	}
	defer s.Close()

	// Try to stop the service first.
	status, err := s.Control(svc.Stop)
	if err == nil {
		// Wait for stop.
		for i := 0; i < 30; i++ {
			if status.State == svc.Stopped {
				break
			}
			time.Sleep(500 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				break
			}
		}
	}

	if err := s.Delete(); err != nil {
		return &ServiceError{Op: "delete service", Err: err}
	}
	return nil
}

// StartService starts the Windows Service via SCM.
func StartService() error {
	m, err := mgr.Connect()
	if err != nil {
		return &ServiceError{Op: "connect to SCM", Err: err}
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return &ServiceError{Op: "open service", Err: err}
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return &ServiceError{Op: "start service", Err: err}
	}

	// Wait until the service is running.
	for i := 0; i < 30; i++ {
		time.Sleep(500 * time.Millisecond)
		status, err := s.Query()
		if err != nil {
			return &ServiceError{Op: "query service status", Err: err}
		}
		if status.State == svc.Running {
			return nil
		}
		if status.State == svc.Stopped {
			return &ServiceError{Op: "start service", Err: fmt.Errorf("service stopped unexpectedly")}
		}
	}
	return &ServiceError{Op: "start service", Err: fmt.Errorf("timeout waiting for service to start")}
}

// StopService stops the Windows Service via SCM.
func StopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return &ServiceError{Op: "connect to SCM", Err: err}
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return &ServiceError{Op: "open service", Err: err}
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return &ServiceError{Op: "stop service", Err: err}
	}

	for i := 0; i < 30; i++ {
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return &ServiceError{Op: "query service status", Err: err}
		}
	}
	return &ServiceError{Op: "stop service", Err: fmt.Errorf("timeout waiting for service to stop")}
}

// IsServiceInstalled checks if the service is registered in the SCM.
func IsServiceInstalled() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// IsServiceRunning checks if the service is currently running.
func IsServiceRunning() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return false
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return false
	}
	return status.State == svc.Running
}

// SetStartType changes the service start type (Automatic, Manual, Disabled).
func SetStartType(startType uint32) error {
	m, err := mgr.Connect()
	if err != nil {
		return &ServiceError{Op: "connect to SCM", Err: err}
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return &ServiceError{Op: "open service", Err: err}
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return &ServiceError{Op: "query config", Err: err}
	}

	cfg.StartType = startType
	if err := s.UpdateConfig(cfg); err != nil {
		return &ServiceError{Op: "update config", Err: err}
	}
	return nil
}
