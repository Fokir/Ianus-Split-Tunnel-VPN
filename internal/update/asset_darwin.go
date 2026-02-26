//go:build darwin

package update

import "runtime"

// AssetPattern matches release assets for macOS.
const AssetPattern = "awg-split-tunnel-v"

// AssetSuffix selects the correct architecture-specific tarball.
// Prefers universal binary; falls back to arch-specific if not available.
var AssetSuffix = darwinAssetSuffix()

func darwinAssetSuffix() string {
	switch runtime.GOARCH {
	case "arm64":
		return "-darwin-arm64.tar.gz"
	case "amd64":
		return "-darwin-amd64.tar.gz"
	default:
		return "-darwin-arm64.tar.gz"
	}
}
