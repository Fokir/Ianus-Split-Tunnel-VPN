//go:build !windows && !darwin

package process

import "errors"

// queryProcessPath is a stub for non-Windows platforms.
// Will be replaced with platform-specific implementation (e.g. proc_pidpath on macOS).
func queryProcessPath(pid uint32) (string, error) {
	return "", errors.New("process path query not implemented on this platform")
}
