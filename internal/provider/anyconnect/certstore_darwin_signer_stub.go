//go:build darwin && !cgo

package anyconnect

import (
	"crypto"
	"fmt"
)

// loadKeychainSigner is a stub when CGo is not available.
// Falls back to PKCS12 export (private key temporarily in memory).
func loadKeychainSigner(certDER []byte, keychain string) (crypto.Signer, error) {
	return nil, fmt.Errorf("native Keychain signer requires CGo; falling back to PKCS12 export")
}
