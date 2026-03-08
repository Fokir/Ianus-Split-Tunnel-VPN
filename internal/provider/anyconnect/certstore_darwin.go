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
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"awg-split-tunnel/internal/core"
)

// reIdentity matches lines like:
//
//	1) ABCDEF1234567890ABCDEF1234567890ABCDEF12 "Common Name"
var reIdentity = regexp.MustCompile(`^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"(.+)"`)

// keychainPaths returns the list of keychains to search for client certificates.
// When running as root (daemon), we need to explicitly include:
//   - System Keychain (/Library/Keychains/System.keychain) — machine certs
//   - Console user's Login Keychain — user certs
//
// When running as a regular user, the default search list already includes
// the user's login keychain, but we add System explicitly for completeness.
func keychainPaths() []string {
	var paths []string

	// Always include System Keychain (machine certificates, accessible by root).
	systemKC := "/Library/Keychains/System.keychain"
	if _, err := os.Stat(systemKC); err == nil {
		paths = append(paths, systemKC)
	}

	// Try to find the console (GUI) user's login keychain.
	// When running as root daemon, os.UserHomeDir() returns /var/root,
	// so we use stat /dev/console to find the actual logged-in user.
	if loginKC := consoleUserLoginKeychain(); loginKC != "" {
		paths = append(paths, loginKC)
	}

	return paths
}

// consoleUserLoginKeychain returns the login keychain path for the
// currently logged-in console user, or empty string if not found.
func consoleUserLoginKeychain() string {
	// Method 1: stat /dev/console to find the GUI user (works when running as root).
	if fi, err := os.Stat("/dev/console"); err == nil {
		if stat, ok := fi.Sys().(interface{ Uid() int }); ok {
			uid := fmt.Sprintf("%d", stat.Uid())
			if u, err := user.LookupId(uid); err == nil && u.HomeDir != "" {
				kc := filepath.Join(u.HomeDir, "Library", "Keychains", "login.keychain-db")
				if _, err := os.Stat(kc); err == nil {
					core.Log.Debugf("AnyConnect", "Console user keychain (via /dev/console): %s", kc)
					return kc
				}
			}
		}
	}

	// Method 2: scutil --get ConsoleUser.
	if out, err := exec.Command("scutil", "--get", "ConsoleUser").Output(); err == nil {
		username := strings.TrimSpace(string(out))
		if username != "" && username != "loginwindow" {
			if u, err := user.Lookup(username); err == nil && u.HomeDir != "" {
				kc := filepath.Join(u.HomeDir, "Library", "Keychains", "login.keychain-db")
				if _, err := os.Stat(kc); err == nil {
					core.Log.Debugf("AnyConnect", "Console user keychain (via scutil): %s", kc)
					return kc
				}
			}
		}
	}

	// Method 3: if we're not root, use current user's home.
	if os.Getuid() != 0 {
		if home, err := os.UserHomeDir(); err == nil {
			kc := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
			if _, err := os.Stat(kc); err == nil {
				return kc
			}
		}
	}

	return ""
}

// enumerateSystemClientCerts searches macOS Keychains for SSL client
// identities (certificate + private key pairs) using the security(1) CLI.
// When running as root (daemon), it searches both the System Keychain
// and the console user's Login Keychain.
func enumerateSystemClientCerts() ([]tls.Certificate, error) {
	keychains := keychainPaths()

	type identity struct {
		sha1Hash string
		name     string
		keychain string // which keychain this identity was found in
	}
	seen := make(map[string]struct{}) // deduplicate by SHA-1 hash
	var identities []identity

	// Search each keychain for SSL client identities.
	for _, kc := range keychains {
		args := []string{"find-identity", "-v", "-p", "ssl-client", kc}
		out, err := exec.Command("security", args...).Output()
		if err != nil {
			core.Log.Debugf("AnyConnect", "Keychain %s: find-identity failed: %v", kc, err)
			continue
		}

		for _, line := range strings.Split(string(out), "\n") {
			m := reIdentity.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			hash := strings.ToUpper(m[1])
			if _, dup := seen[hash]; dup {
				continue
			}
			seen[hash] = struct{}{}
			identities = append(identities, identity{sha1Hash: m[1], name: m[2], keychain: kc})
		}
	}

	// Fallback: search without specifying keychain (default search list).
	if len(identities) == 0 {
		out, err := exec.Command("security", "find-identity", "-v", "-p", "ssl-client").Output()
		if err != nil {
			return nil, &certStoreError{Op: "find-identity", Err: err}
		}
		for _, line := range strings.Split(string(out), "\n") {
			m := reIdentity.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			hash := strings.ToUpper(m[1])
			if _, dup := seen[hash]; dup {
				continue
			}
			seen[hash] = struct{}{}
			identities = append(identities, identity{sha1Hash: m[1], name: m[2]})
		}
	}

	if len(identities) == 0 {
		return nil, nil
	}

	core.Log.Infof("AnyConnect", "Keychain: found %d SSL client identity(ies)", len(identities))

	var result []tls.Certificate
	for _, id := range identities {
		cert, err := exportIdentity(id.sha1Hash, id.name, id.keychain)
		if err != nil {
			core.Log.Debugf("AnyConnect", "Keychain: skip %q (%s): %v", id.name, id.sha1Hash[:8], err)
			continue
		}
		result = append(result, *cert)
	}

	return result, nil
}

// exportIdentity exports a single identity (cert+key) from the Keychain.
// If keychain is non-empty, the certificate lookup and export are scoped to that keychain.
func exportIdentity(sha1Hash, name, keychain string) (*tls.Certificate, error) {
	// Export the certificate by SHA-1 hash.
	findCertArgs := []string{"find-certificate", "-Z", sha1Hash, "-p"}
	if keychain != "" {
		findCertArgs = append(findCertArgs, keychain)
	}
	certPEM, err := exec.Command("security", findCertArgs...).Output()
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

	exportArgs := []string{"export",
		"-c", name,
		"-t", "identities",
		"-f", "pkcs12",
		"-P", tempPW,
		"-o", p12File,
	}
	if keychain != "" {
		exportArgs = append(exportArgs, "-k", keychain)
	}
	cmd := exec.Command("security", exportArgs...)
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
