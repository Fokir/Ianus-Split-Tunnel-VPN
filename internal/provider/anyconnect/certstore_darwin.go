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
	core.Log.Infof("AnyConnect", "Keychain search: keychains=%v, uid=%d", keychains, os.Getuid())

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
		core.Log.Debugf("AnyConnect", "Running: security %s", strings.Join(args, " "))
		out, err := exec.Command("security", args...).Output()
		if err != nil {
			core.Log.Warnf("AnyConnect", "Keychain %s: find-identity -p ssl-client failed: %v", kc, err)
			continue
		}
		core.Log.Debugf("AnyConnect", "Keychain %s (ssl-client) output:\n%s", kc, string(out))

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
			core.Log.Infof("AnyConnect", "Keychain: found identity %q (hash=%s, keychain=%s, policy=ssl-client)", m[2], hash[:8], kc)
			identities = append(identities, identity{sha1Hash: m[1], name: m[2], keychain: kc})
		}
	}

	// Fallback 1: search without specifying keychain (default search list).
	if len(identities) == 0 {
		out, err := exec.Command("security", "find-identity", "-v", "-p", "ssl-client").Output()
		if err != nil {
			core.Log.Debugf("AnyConnect", "find-identity (default keychains, ssl-client): %v", err)
		} else {
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
	}

	// Fallback 2: search WITHOUT policy filter. Some corporate certificates
	// (e.g. machine/host certs enrolled via SCEP) lack the ssl-client policy
	// but are still valid for TLS client authentication. The TLS handshake's
	// AcceptableCAs filter will select the correct certificate.
	if len(identities) == 0 {
		core.Log.Infof("AnyConnect", "No ssl-client identities found; searching without policy filter")
		searches := [][]string{{"find-identity", "-v"}}
		for _, kc := range keychains {
			searches = append(searches, []string{"find-identity", "-v", kc})
		}
		for _, args := range searches {
			core.Log.Debugf("AnyConnect", "Running: security %s", strings.Join(args, " "))
			out, err := exec.Command("security", args...).Output()
			if err != nil {
				core.Log.Warnf("AnyConnect", "find-identity (no policy) failed: %v", err)
				continue
			}
			core.Log.Debugf("AnyConnect", "find-identity (no policy) output:\n%s", string(out))
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
				core.Log.Infof("AnyConnect", "Keychain: found identity %q (hash=%s, policy=any)", m[2], hash[:8])
				identities = append(identities, identity{sha1Hash: m[1], name: m[2]})
			}
		}
	}

	if len(identities) == 0 {
		core.Log.Warnf("AnyConnect", "No identities found in any keychain (searched %d keychains + default list)", len(keychains))
		return nil, nil
	}

	core.Log.Infof("AnyConnect", "Keychain: found %d identity(ies) total, loading certificates...", len(identities))

	var result []tls.Certificate
	for _, id := range identities {
		core.Log.Infof("AnyConnect", "Keychain: loading identity %q (hash=%s, keychain=%q)...", id.name, id.sha1Hash[:8], id.keychain)
		cert, err := exportIdentity(id.sha1Hash, id.name, id.keychain)
		if err != nil {
			core.Log.Warnf("AnyConnect", "Keychain: failed to load %q (%s): %v", id.name, id.sha1Hash[:8], err)
			continue
		}
		if cert.Leaf != nil {
			core.Log.Infof("AnyConnect", "Keychain: loaded %q — subject=%q issuer=%q notAfter=%s EKUs=%v",
				id.name, cert.Leaf.Subject.CommonName, cert.Leaf.Issuer.CommonName,
				cert.Leaf.NotAfter.Format("2006-01-02"), cert.Leaf.ExtKeyUsage)
		}
		result = append(result, *cert)
	}

	core.Log.Infof("AnyConnect", "Keychain: %d/%d identities loaded successfully", len(result), len(identities))
	return result, nil
}

// exportIdentity loads a single identity (cert+key) from the Keychain.
// It first tries the native Security Framework signer (private key stays in Keychain,
// analogous to NCrypt on Windows). If that fails, it falls back to PKCS12 export.
func exportIdentity(sha1Hash, name, keychain string) (*tls.Certificate, error) {
	// Export the certificate (public part only) by SHA-1 hash.
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

	// Try native Keychain signer first (private key never leaves the Keychain).
	signer, err := loadKeychainSigner(block.Bytes, keychain)
	if err == nil {
		core.Log.Infof("AnyConnect", "Keychain: using native signer for %q (private key stays in Keychain)", name)
		chain := buildCertChainDarwin(leaf)
		return &tls.Certificate{
			Certificate: chain,
			PrivateKey:  signer,
			Leaf:        leaf,
		}, nil
	}
	core.Log.Debugf("AnyConnect", "Keychain: native signer unavailable for %q: %v; falling back to PKCS12 export", name, err)

	// Fallback: export identity as PKCS12 (private key temporarily in process memory).
	return exportIdentityPKCS12(name, keychain, leaf)
}

// exportIdentityPKCS12 exports an identity via `security export` as PKCS12.
// The private key is temporarily extracted into process memory.
func exportIdentityPKCS12(name, keychain string, leaf *x509.Certificate) (*tls.Certificate, error) {
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

	cert, err := parsePKCS12(p12Data, tempPW, leaf)
	if err != nil {
		return nil, fmt.Errorf("parse p12: %w", err)
	}

	return cert, nil
}

// parsePKCS12 decodes a PKCS12 file and returns a tls.Certificate with the
// full chain (leaf + intermediate CAs). Verifies the leaf matches targetLeaf.
func parsePKCS12(data []byte, password string, targetLeaf *x509.Certificate) (*tls.Certificate, error) {
	cert, err := decodePKCS12Chain(data, password)
	if err != nil {
		return nil, err
	}

	// Verify this is the cert we expected.
	if targetLeaf != nil && cert.Leaf != nil && !bytes.Equal(cert.Leaf.Raw, targetLeaf.Raw) {
		return nil, fmt.Errorf("exported cert does not match target")
	}

	return cert, nil
}

// buildCertChainDarwin attempts to build a certificate chain from the leaf
// by searching the System Keychain for intermediate CA certificates.
// Uses `security find-certificate` to look up issuers by common name.
func buildCertChainDarwin(leaf *x509.Certificate) [][]byte {
	chain := [][]byte{leaf.Raw}

	if isSelfSignedDarwin(leaf) {
		return chain
	}

	// Walk up the issuer chain (max 5 intermediates to prevent loops).
	current := leaf
	for i := 0; i < 5; i++ {
		issuerCN := current.Issuer.CommonName
		if issuerCN == "" {
			break
		}

		// Search all keychains for a certificate with this CN.
		out, err := exec.Command("security", "find-certificate", "-c", issuerCN, "-p").Output()
		if err != nil {
			break
		}

		block, _ := pem.Decode(out)
		if block == nil {
			break
		}

		issuer, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			break
		}

		// Verify this is actually the issuer (subject matches current cert's issuer).
		if string(issuer.RawSubject) != string(current.RawIssuer) {
			break
		}

		// Don't include root CAs — servers should have them.
		if isSelfSignedDarwin(issuer) {
			break
		}

		chain = append(chain, issuer.Raw)
		current = issuer
	}

	if len(chain) > 1 {
		core.Log.Infof("AnyConnect", "Keychain: built certificate chain with %d certs", len(chain))
	}
	return chain
}

func isSelfSignedDarwin(cert *x509.Certificate) bool {
	return string(cert.RawIssuer) == string(cert.RawSubject)
}
