//go:build !windows && !darwin

package service

// TriggerGUILaunch is a no-op on unsupported platforms.
func TriggerGUILaunch() bool {
	return false
}
