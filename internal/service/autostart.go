//go:build windows

package service

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

const (
	autostartRegKey  = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	autostartRegName = "AWGSplitTunnel"
)

// isAutostartEnabled checks if the application is registered for Windows autostart.
func isAutostartEnabled() (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, autostartRegKey, registry.QUERY_VALUE)
	if err != nil {
		return false, err
	}
	defer k.Close()

	_, _, err = k.GetStringValue(autostartRegName)
	if err == registry.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// setAutostartEnabled adds or removes the application from Windows autostart.
func setAutostartEnabled(enabled bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, autostartRegKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if enabled {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		return k.SetStringValue(autostartRegName, `"`+exe+`" --minimized`)
	}

	err = k.DeleteValue(autostartRegName)
	if err == registry.ErrNotExist {
		return nil
	}
	return err
}
