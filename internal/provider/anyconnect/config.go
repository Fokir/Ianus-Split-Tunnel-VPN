//go:build windows

package anyconnect

// Config holds AnyConnect provider configuration parsed from TunnelConfig.Settings.
// OTP codes are NOT stored here — they are passed at connect time via SetAuthParams.
type Config struct {
	Server        string // VPN server hostname or IP
	Port          int    // Server port (default 443)
	Username      string // Login username
	Password      string // Login password
	Group         string // Connection profile/group (optional)
	TLSSkipVerify bool   // Skip TLS certificate verification
}
