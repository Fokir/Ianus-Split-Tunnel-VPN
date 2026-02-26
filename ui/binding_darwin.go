//go:build darwin

package main

// removeLegacyGUIRegistryEntries is a no-op on macOS (no Windows registry).
func removeLegacyGUIRegistryEntries() {}
