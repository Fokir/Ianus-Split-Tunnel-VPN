//go:build !windows && !darwin

package update

// Stub constants for unsupported platforms (allows go test on Linux CI).
const AssetPattern = "awg-split-tunnel-v"
const AssetSuffix = "-unsupported"
