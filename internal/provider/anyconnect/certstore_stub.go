//go:build !windows && !darwin

package anyconnect

import "crypto/tls"

// enumerateSystemClientCerts is a no-op on unsupported platforms.
func enumerateSystemClientCerts() ([]tls.Certificate, error) {
	return nil, nil
}
