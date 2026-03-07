//go:build darwin

package anyconnect

import (
	"crypto"
	"crypto/x509"

	"golang.org/x/crypto/pkcs12"
)

// decodePKCS12 decodes a PKCS12 bundle and returns the private key and leaf certificate.
func decodePKCS12(data []byte, password string) (crypto.PrivateKey, *x509.Certificate, error) {
	privKey, cert, err := pkcs12.Decode(data, password)
	if err != nil {
		return nil, nil, err
	}
	return privKey, cert, nil
}
