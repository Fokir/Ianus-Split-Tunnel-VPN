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
	UserAgent     string // Custom User-Agent override (empty = auto-detect)

	// Client certificate for mutual TLS authentication.
	// Supported values:
	//   ""      — no client certificate
	//   "auto"  — auto-detect from system certificate store (Windows/macOS)
	//   path    — file path to certificate; supported formats:
	//             * .p12/.pfx  — PKCS12 bundle (cert+key, password via ClientCertPassword)
	//             * .cer/.crt/.der — certificate only, private key looked up in system store
	//             * .pem       — PEM file; if ClientKey is empty, must contain both cert and key blocks
	ClientCert         string // Certificate path or "auto"
	ClientKey          string // Path to PEM private key (only for separate PEM cert+key files)
	ClientCertPassword string // Password for PKCS12 (.p12/.pfx) files

	// Proxy settings for connecting through HTTP CONNECT proxy.
	ProxyURL      string // HTTP proxy URL (e.g. "http://proxy:8080")
	ProxyUsername string // Proxy auth username (optional)
	ProxyPassword string // Proxy auth password (optional)

	// DTLS enables UDP transport for lower-latency forwarding.
	// Falls back to CSTP if DTLS handshake fails.
	DTLS bool
}
