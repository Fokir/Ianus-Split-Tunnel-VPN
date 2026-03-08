//go:build darwin

package anyconnect

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	"golang.org/x/crypto/pkcs12"
)

// decodePKCS12Chain decodes a PKCS12 bundle and returns a tls.Certificate
// with the full certificate chain (leaf + intermediate CAs).
func decodePKCS12Chain(data []byte, password string) (*tls.Certificate, error) {
	// ToPEM extracts all items: private key, leaf cert, and CA certs.
	pemBlocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, err
	}

	var pemData []byte
	for _, block := range pemBlocks {
		pemData = append(pemData, pem.EncodeToMemory(block)...)
	}

	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		return nil, err
	}

	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	return &cert, nil
}
