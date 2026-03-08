//go:build darwin && cgo

package anyconnect

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

// keychainSigner implements crypto.Signer for a key stored in macOS Keychain.
// The private key never leaves the Keychain; all signing operations are
// performed via Security Framework's SecKeyCreateSignature.
// This is analogous to ncryptSigner on Windows.
type keychainSigner struct {
	keyRef C.SecKeyRef
	pub    crypto.PublicKey
}

func (s *keychainSigner) Public() crypto.PublicKey { return s.pub }

func (s *keychainSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	algorithm, err := secKeyAlgorithm(s.pub, opts)
	if err != nil {
		return nil, err
	}

	digestCF := C.CFDataCreate(C.kCFAllocatorDefault,
		(*C.UInt8)(unsafe.Pointer(&digest[0])), C.CFIndex(len(digest)))
	if digestCF == 0 {
		return nil, fmt.Errorf("CFDataCreate failed for digest")
	}
	defer C.CFRelease(C.CFTypeRef(digestCF))

	var cfErr C.CFErrorRef
	sig := C.SecKeyCreateSignature(s.keyRef, algorithm, digestCF, &cfErr)
	if sig == 0 {
		return nil, cfErrorToGo(cfErr, "SecKeyCreateSignature")
	}
	defer C.CFRelease(C.CFTypeRef(sig))

	return cfDataToBytes(sig), nil
}

func (s *keychainSigner) close() {
	if s.keyRef != 0 {
		C.CFRelease(C.CFTypeRef(s.keyRef))
		s.keyRef = 0
	}
}

// secKeyAlgorithm maps Go's crypto.SignerOpts to Security Framework algorithm constants.
func secKeyAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (C.SecKeyAlgorithm, error) {
	h := opts.HashFunc()

	switch pub.(type) {
	case *rsa.PublicKey:
		if _, ok := opts.(*rsa.PSSOptions); ok {
			switch h {
			case crypto.SHA1:
				return C.kSecKeyAlgorithmRSASignatureDigestPSSSHA1, nil
			case crypto.SHA256:
				return C.kSecKeyAlgorithmRSASignatureDigestPSSSHA256, nil
			case crypto.SHA384:
				return C.kSecKeyAlgorithmRSASignatureDigestPSSSHA384, nil
			case crypto.SHA512:
				return C.kSecKeyAlgorithmRSASignatureDigestPSSSHA512, nil
			}
		} else {
			switch h {
			case crypto.SHA1:
				return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1, nil
			case crypto.SHA256:
				return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256, nil
			case crypto.SHA384:
				return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384, nil
			case crypto.SHA512:
				return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512, nil
			}
		}
	case *ecdsa.PublicKey:
		switch h {
		case crypto.SHA1:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA1, nil
		case crypto.SHA256:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256, nil
		case crypto.SHA384:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384, nil
		case crypto.SHA512:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512, nil
		}
	}

	return 0, fmt.Errorf("unsupported key type %T with hash %v", pub, h)
}

// loadKeychainSigner creates a crypto.Signer backed by the macOS Keychain.
// The certificate DER data is used to find the matching identity (cert + private key).
// The private key remains in the Keychain; signing is performed via SecKeyCreateSignature.
func loadKeychainSigner(certDER []byte, keychain string) (crypto.Signer, error) {
	// Create SecCertificateRef from the DER-encoded certificate.
	certData := C.CFDataCreate(C.kCFAllocatorDefault,
		(*C.UInt8)(unsafe.Pointer(&certDER[0])), C.CFIndex(len(certDER)))
	if certData == 0 {
		return nil, fmt.Errorf("CFDataCreate failed for certificate")
	}
	defer C.CFRelease(C.CFTypeRef(certData))

	certRef := C.SecCertificateCreateWithData(C.kCFAllocatorDefault, certData)
	if certRef == 0 {
		return nil, fmt.Errorf("SecCertificateCreateWithData failed")
	}
	defer C.CFRelease(C.CFTypeRef(certRef))

	// Find the identity (cert + matching private key) in the Keychain.
	// SecIdentityCreateWithCertificate searches all keychains in the default search list.
	var identityRef C.SecIdentityRef
	status := C.SecIdentityCreateWithCertificate(0, certRef, &identityRef)
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("SecIdentityCreateWithCertificate: OSStatus %d (no matching private key in Keychain)", status)
	}
	defer C.CFRelease(C.CFTypeRef(identityRef))

	// Extract the private key reference. The key stays in the Keychain;
	// we only get a reference for signing operations.
	var keyRef C.SecKeyRef
	status = C.SecIdentityCopyPrivateKey(identityRef, &keyRef)
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("SecIdentityCopyPrivateKey: OSStatus %d", status)
	}

	// Parse the certificate to extract the public key.
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		C.CFRelease(C.CFTypeRef(keyRef))
		return nil, fmt.Errorf("parse cert for public key: %w", err)
	}

	signer := &keychainSigner{
		keyRef: keyRef,
		pub:    cert.PublicKey,
	}

	// Release the key reference when the signer is garbage collected.
	runtime.SetFinalizer(signer, (*keychainSigner).close)

	return signer, nil
}

// cfDataToBytes converts a CFDataRef to a Go byte slice.
func cfDataToBytes(data C.CFDataRef) []byte {
	length := C.CFDataGetLength(data)
	if length == 0 {
		return nil
	}
	ptr := C.CFDataGetBytePtr(data)
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length))
}

// cfErrorToGo converts a CFErrorRef to a Go error.
func cfErrorToGo(cfErr C.CFErrorRef, context string) error {
	if cfErr == 0 {
		return fmt.Errorf("%s failed", context)
	}
	defer C.CFRelease(C.CFTypeRef(cfErr))

	desc := C.CFErrorCopyDescription(cfErr)
	if desc == 0 {
		return fmt.Errorf("%s: error code %d", context, C.CFErrorGetCode(cfErr))
	}
	defer C.CFRelease(C.CFTypeRef(desc))

	length := C.CFStringGetLength(desc)
	maxSize := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8) + 1
	buf := C.malloc(C.size_t(maxSize))
	defer C.free(buf)

	if C.CFStringGetCString(desc, (*C.char)(buf), maxSize, C.kCFStringEncodingUTF8) != 0 {
		return fmt.Errorf("%s: %s", context, C.GoString((*C.char)(buf)))
	}
	return fmt.Errorf("%s: error code %d", context, C.CFErrorGetCode(cfErr))
}
