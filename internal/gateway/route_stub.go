//go:build !windows

package gateway

// CleanupOrphanedRoutes is a no-op on non-Windows platforms.
func CleanupOrphanedRoutes() error {
	return nil
}
