package anyconnect

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"awg-split-tunnel/internal/core"
)

// findSystemCertificate searches the OS certificate store for a client
// certificate whose issuer matches one of the acceptable CAs provided
// by the TLS server during handshake.
// Returns nil (no cert) when no match is found — this lets TLS proceed
// without a client certificate (the server may fall back to password auth).
func findSystemCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	certs, err := enumerateSystemClientCerts()
	if err != nil {
		core.Log.Warnf("AnyConnect", "System cert store enumeration failed: %v", err)
		return &tls.Certificate{}, nil
	}
	if len(certs) == 0 {
		core.Log.Warnf("AnyConnect", "No client certificates found in system store")
		return &tls.Certificate{}, nil
	}

	core.Log.Infof("AnyConnect", "Found %d client certificate(s) in system store", len(certs))

	// If the server specified acceptable CAs, filter by issuer.
	if len(info.AcceptableCAs) > 0 {
		acceptableSet := make(map[string]struct{}, len(info.AcceptableCAs))
		for _, ca := range info.AcceptableCAs {
			acceptableSet[string(ca)] = struct{}{}
		}

		for i := range certs {
			leaf, err := x509.ParseCertificate(certs[i].Certificate[0])
			if err != nil {
				continue
			}
			if _, ok := acceptableSet[string(leaf.RawIssuer)]; ok {
				core.Log.Infof("AnyConnect", "Auto-selected client certificate: subject=%q issuer=%q",
					leaf.Subject.CommonName, leaf.Issuer.CommonName)
				return &certs[i], nil
			}
		}
		core.Log.Warnf("AnyConnect", "No client certificate matches server's acceptable CAs (%d CAs)", len(info.AcceptableCAs))
		return &tls.Certificate{}, nil
	}

	// No CA filter — use the first available client cert.
	if len(certs) > 0 {
		leaf, _ := x509.ParseCertificate(certs[0].Certificate[0])
		if leaf != nil {
			core.Log.Infof("AnyConnect", "Auto-selected first client certificate: subject=%q issuer=%q",
				leaf.Subject.CommonName, leaf.Issuer.CommonName)
		}
		return &certs[0], nil
	}

	return &tls.Certificate{}, nil
}

// enumerateSystemClientCerts is implemented per-platform:
//   - certstore_windows.go: Windows Certificate Store ("MY") via crypt32.dll
//   - certstore_darwin.go:  macOS Keychain via security(1) CLI
//   - certstore_stub.go:    returns empty on unsupported platforms
//
// Each returned tls.Certificate must have a valid PrivateKey (crypto.Signer).

// certStoreError wraps platform-specific cert store errors.
type certStoreError struct {
	Op  string
	Err error
}

func (e *certStoreError) Error() string {
	return fmt.Sprintf("certstore: %s: %v", e.Op, e.Err)
}

func (e *certStoreError) Unwrap() error { return e.Err }

// findSystemKeyForCert finds the private key for the given certificate in the
// system certificate store. This handles the common Cisco AnyConnect scenario
// where the user has a .cer file and the private key was generated on-device.
func findSystemKeyForCert(certDER []byte) (crypto.Signer, error) {
	signer, _, err := findSystemKeyAndChain(certDER)
	return signer, err
}

// findSystemKeyAndChain finds the private key and full certificate chain
// (leaf + intermediate CAs) for the given certificate in the system store.
func findSystemKeyAndChain(certDER []byte) (crypto.Signer, [][]byte, error) {
	certs, err := enumerateSystemClientCerts()
	if err != nil {
		return nil, nil, fmt.Errorf("enumerate system certs: %w", err)
	}

	for _, c := range certs {
		if len(c.Certificate) > 0 && bytes.Equal(c.Certificate[0], certDER) {
			signer, ok := c.PrivateKey.(crypto.Signer)
			if !ok {
				return nil, nil, fmt.Errorf("private key does not implement crypto.Signer")
			}
			// enumerateSystemClientCerts already builds the chain on Windows/macOS.
			return signer, c.Certificate, nil
		}
	}

	return nil, nil, fmt.Errorf("no matching private key found in system certificate store; " +
		"ensure the certificate is imported and the private key exists (e.g. via enrollment or PKCS12 import)")
}
