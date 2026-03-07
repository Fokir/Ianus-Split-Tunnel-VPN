//go:build darwin

package anyconnect

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"awg-split-tunnel/internal/core"
)

// reIdentity matches lines like:
//
//	1) ABCDEF1234567890ABCDEF1234567890ABCDEF12 "Common Name"
var reIdentity = regexp.MustCompile(`^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"(.+)"`)

// enumerateSystemClientCerts searches the macOS Keychain for SSL client
// identities (certificate + private key pairs) using the security(1) CLI.
func enumerateSystemClientCerts() ([]tls.Certificate, error) {
	// Step 1: List all SSL client identities.
	out, err := exec.Command("security", "find-identity", "-v", "-p", "ssl-client").Output()
	if err != nil {
		return nil, &certStoreError{Op: "find-identity", Err: err}
	}

	lines := strings.Split(string(out), "\n")
	type identity struct {
		sha1Hash string
		name     string
	}
	var identities []identity
	for _, line := range lines {
		m := reIdentity.FindStringSubmatch(line)
		if m != nil {
			identities = append(identities, identity{sha1Hash: m[1], name: m[2]})
		}
	}

	if len(identities) == 0 {
		return nil, nil
	}

	core.Log.Debugf("AnyConnect", "Keychain: found %d SSL client identity(ies)", len(identities))

	// Step 2: Export each identity's certificate as PEM to check issuer,
	// then export matching identity as PKCS12 for the private key.
	var result []tls.Certificate
	for _, id := range identities {
		cert, err := exportIdentity(id.sha1Hash, id.name)
		if err != nil {
			core.Log.Debugf("AnyConnect", "Keychain: skip %q (%s): %v", id.name, id.sha1Hash[:8], err)
			continue
		}
		result = append(result, *cert)
	}

	return result, nil
}

// exportIdentity exports a single identity (cert+key) from the Keychain.
func exportIdentity(sha1Hash, name string) (*tls.Certificate, error) {
	// Get the certificate PEM via find-certificate.
	hashBytes, err := hex.DecodeString(sha1Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %w", err)
	}
	_ = hashBytes

	// Export the certificate by SHA-1 hash.
	certPEM, err := exec.Command("security", "find-certificate", "-Z", sha1Hash, "-p").Output()
	if err != nil {
		return nil, fmt.Errorf("find-certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in certificate output")
	}

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	// Export the identity (cert+key) as PKCS12.
	// Generate a random password for the temporary export.
	pwBytes := make([]byte, 16)
	if _, err := rand.Read(pwBytes); err != nil {
		return nil, fmt.Errorf("generate password: %w", err)
	}
	tempPW := hex.EncodeToString(pwBytes)

	tmpDir, err := os.MkdirTemp("", "awg-cert-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	p12File := filepath.Join(tmpDir, "identity.p12")

	// Use security export with the identity name to export as PKCS12.
	// -t identities exports cert+key pairs.
	cmd := exec.Command("security", "export",
		"-c", name,
		"-t", "identities",
		"-f", "pkcs12",
		"-P", tempPW,
		"-o", p12File,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("export identity: %w (%s)", err, stderr.String())
	}

	p12Data, err := os.ReadFile(p12File)
	if err != nil {
		return nil, fmt.Errorf("read p12: %w", err)
	}

	// Parse PKCS12.
	cert, err := parsePKCS12(p12Data, tempPW, leaf)
	if err != nil {
		return nil, fmt.Errorf("parse p12: %w", err)
	}

	return cert, nil
}

// parsePKCS12 decodes a PKCS12 file and finds the entry matching the target leaf.
func parsePKCS12(data []byte, password string, targetLeaf *x509.Certificate) (*tls.Certificate, error) {
	// Go 1.23+ has crypto/tls helpers; use x509 PKCS12 parsing.
	// For older Go, use golang.org/x/crypto/pkcs12.
	// We use a simple approach: try tls.X509KeyPair-style parsing via pkcs12.

	// Use the legacy approach with golang.org/x/crypto/pkcs12 if available.
	// Since this project may or may not have it, use the standard library approach.
	// Go's crypto/x509 can parse PKCS12 natively since Go 1.23 via ParsePKCS12.
	// For broader compatibility, we attempt both.
	privKey, leafCert, err := decodePKCS12(data, password)
	if err != nil {
		return nil, err
	}

	// Verify this is the cert we expected.
	if targetLeaf != nil && !bytes.Equal(leafCert.Raw, targetLeaf.Raw) {
		return nil, fmt.Errorf("exported cert does not match target")
	}

	return &tls.Certificate{
		Certificate: [][]byte{leafCert.Raw},
		PrivateKey:  privKey,
		Leaf:        leafCert,
	}, nil
}
