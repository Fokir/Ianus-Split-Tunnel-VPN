//go:build windows

package anyconnect

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modcrypt32 = windows.NewLazySystemDLL("crypt32.dll")
	modncrypt  = windows.NewLazySystemDLL("ncrypt.dll")

	procCertOpenSystemStoreW          = modcrypt32.NewProc("CertOpenSystemStoreW")
	procCertCloseStore                = modcrypt32.NewProc("CertCloseStore")
	procCertEnumCertificatesInStore   = modcrypt32.NewProc("CertEnumCertificatesInStore")
	procCertFreeCertificateContext    = modcrypt32.NewProc("CertFreeCertificateContext")
	procCryptAcquireCertPrivateKey    = modcrypt32.NewProc("CryptAcquireCertificatePrivateKey2")
	procCryptAcquireCertPrivateKeyOld = modcrypt32.NewProc("CryptAcquireCertificatePrivateKey")

	procNCryptSignHash   = modncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject = modncrypt.NewProc("NCryptFreeObject")
	procNCryptGetProperty = modncrypt.NewProc("NCryptGetProperty")
)

// Windows constants.
const (
	certStoreProvSystem        = 10
	certStoreOpenExistingFlag  = 0x00004000
	certStoreLocalMachineID    = 0x00020000 // CERT_SYSTEM_STORE_LOCAL_MACHINE
	certStoreCurrentUserID     = 0x00010000 // CERT_SYSTEM_STORE_CURRENT_USER

	acquireOnlyNCryptKeyFlag   = 0x00040000 // CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
	acquireSilentFlag          = 0x00000040 // CRYPT_ACQUIRE_SILENT_FLAG

	ncryptPadPKCS1Flag         = 0x00000002 // NCRYPT_PAD_PKCS1_FLAG
	ncryptPadPSSFlag           = 0x00000008 // NCRYPT_PAD_PSS_FLAG
	ncryptSilentFlag           = 0x00000040 // NCRYPT_SILENT_FLAG
)

// CERT_CONTEXT from wincrypt.h.
type certContext struct {
	CertEncodingType uint32
	CertEncoded      *byte
	CertEncodedLen   uint32
	CertInfo         uintptr
	Store            uintptr
}

// BCRYPT_PKCS1_PADDING_INFO for RSA PKCS#1 v1.5 signing.
type bcryptPKCS1PaddingInfo struct {
	AlgID *uint16 // pointer to null-terminated UTF-16 algorithm name
}

// enumerateSystemClientCerts searches the Windows "MY" certificate store
// (current user) for certificates that have an associated private key.
func enumerateSystemClientCerts() ([]tls.Certificate, error) {
	// Open the "MY" (Personal) certificate store for the current user.
	storeName, _ := windows.UTF16PtrFromString("MY")
	storeHandle, _, err := procCertOpenSystemStoreW.Call(0, uintptr(unsafe.Pointer(storeName)))
	if storeHandle == 0 {
		return nil, &certStoreError{Op: "CertOpenSystemStore", Err: err}
	}
	defer procCertCloseStore.Call(storeHandle, 0)

	var result []tls.Certificate
	var prev uintptr

	for {
		ctx, _, _ := procCertEnumCertificatesInStore.Call(storeHandle, prev)
		if ctx == 0 {
			break
		}
		prev = ctx

		cc := (*certContext)(unsafe.Pointer(ctx))
		certDER := unsafe.Slice(cc.CertEncoded, cc.CertEncodedLen)

		// Copy DER bytes (the context memory is owned by the store).
		derCopy := make([]byte, len(certDER))
		copy(derCopy, certDER)

		leaf, err := x509.ParseCertificate(derCopy)
		if err != nil {
			continue
		}

		// Skip certs without client auth key usage.
		if !hasClientAuthEKU(leaf) {
			continue
		}

		// Try to acquire the private key (CNG only, silent).
		signer, err := acquireNCryptKey(ctx)
		if err != nil {
			continue
		}

		result = append(result, tls.Certificate{
			Certificate: [][]byte{derCopy},
			PrivateKey:  signer,
			Leaf:        leaf,
		})
	}

	return result, nil
}

func hasClientAuthEKU(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 {
		// No EKU extension — treat as general purpose.
		return true
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth || eku == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// acquireNCryptKey gets a CNG key handle for the given cert context
// and returns a crypto.Signer wrapping it.
func acquireNCryptKey(certCtx uintptr) (crypto.Signer, error) {
	var keyHandle uintptr
	var keySpec uint32
	var callerFree int32

	r, _, err := procCryptAcquireCertPrivateKeyOld.Call(
		certCtx,
		acquireOnlyNCryptKeyFlag|acquireSilentFlag,
		0, // pvParameters
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(&keySpec)),
		uintptr(unsafe.Pointer(&callerFree)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptAcquireCertificatePrivateKey: %w", err)
	}

	// Determine key algorithm.
	algName, err := ncryptGetStringProperty(keyHandle, "Algorithm Name")
	if err != nil {
		if callerFree != 0 {
			procNCryptFreeObject.Call(keyHandle)
		}
		return nil, fmt.Errorf("get algorithm name: %w", err)
	}

	// Parse the public key from the cert context to get the correct public key.
	cc := (*certContext)(unsafe.Pointer(certCtx))
	certDER := unsafe.Slice(cc.CertEncoded, cc.CertEncodedLen)
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		if callerFree != 0 {
			procNCryptFreeObject.Call(keyHandle)
		}
		return nil, err
	}

	return &ncryptSigner{
		keyHandle:  keyHandle,
		algName:    algName,
		pub:        leaf.PublicKey,
		callerFree: callerFree != 0,
	}, nil
}

// ncryptSigner implements crypto.Signer using a Windows CNG key handle.
type ncryptSigner struct {
	keyHandle  uintptr
	algName    string // "RSA", "ECDSA_P256", "ECDSA_P384", "ECDSA_P521"
	pub        crypto.PublicKey
	callerFree bool
}

func (s *ncryptSigner) Public() crypto.PublicKey { return s.pub }

func (s *ncryptSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch s.algName {
	case "RSA":
		return s.signRSA(digest, opts)
	default:
		// ECDSA_P256, ECDSA_P384, ECDSA_P521, ECDH_P256 etc.
		return s.signECDSA(digest)
	}
}

func (s *ncryptSigner) signRSA(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashAlg := hashToNCryptAlg(opts.HashFunc())
	if hashAlg == "" {
		return nil, fmt.Errorf("unsupported hash: %v", opts.HashFunc())
	}

	algUTF16, _ := windows.UTF16PtrFromString(hashAlg)
	padInfo := bcryptPKCS1PaddingInfo{AlgID: algUTF16}

	flags := uintptr(ncryptPadPKCS1Flag | ncryptSilentFlag)
	if _, ok := opts.(*rsa.PSSOptions); ok {
		flags = uintptr(ncryptPadPSSFlag | ncryptSilentFlag)
	}

	// First call: get signature size.
	var sigLen uint32
	r, _, err := procNCryptSignHash.Call(
		s.keyHandle,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0, 0,
		uintptr(unsafe.Pointer(&sigLen)),
		flags,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash (size): 0x%x %w", r, err)
	}

	sig := make([]byte, sigLen)
	r, _, err = procNCryptSignHash.Call(
		s.keyHandle,
		uintptr(unsafe.Pointer(&padInfo)),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(sigLen),
		uintptr(unsafe.Pointer(&sigLen)),
		flags,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash (sign): 0x%x %w", r, err)
	}

	return sig[:sigLen], nil
}

func (s *ncryptSigner) signECDSA(digest []byte) ([]byte, error) {
	// ECDSA: no padding info needed.
	var sigLen uint32
	r, _, err := procNCryptSignHash.Call(
		s.keyHandle,
		0, // no padding
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0, 0,
		uintptr(unsafe.Pointer(&sigLen)),
		uintptr(ncryptSilentFlag),
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash ECDSA (size): 0x%x %w", r, err)
	}

	sig := make([]byte, sigLen)
	r, _, err = procNCryptSignHash.Call(
		s.keyHandle,
		0,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(sigLen),
		uintptr(unsafe.Pointer(&sigLen)),
		uintptr(ncryptSilentFlag),
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash ECDSA (sign): 0x%x %w", r, err)
	}

	// CNG returns r||s as raw big-endian integers. Convert to ASN.1 DER.
	return rawECDSAToASN1(sig[:sigLen], s.pub)
}

// rawECDSAToASN1 converts CNG's concatenated r||s to DER-encoded ECDSA-Sig-Value.
func rawECDSAToASN1(raw []byte, pub crypto.PublicKey) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("odd ECDSA signature length: %d", len(raw))
	}
	half := len(raw) / 2

	// Validate curve size matches if possible.
	if ecKey, ok := pub.(*ecdsa.PublicKey); ok {
		expectedSize := (ecKey.Curve.Params().BitSize + 7) / 8
		if half != expectedSize {
			// CNG may pad; use actual half.
			_ = expectedSize
		}
	}

	r := new(big.Int).SetBytes(raw[:half])
	sVal := new(big.Int).SetBytes(raw[half:])

	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, sVal})
}

// hashToNCryptAlg maps Go hash functions to CNG algorithm identifiers.
func hashToNCryptAlg(h crypto.Hash) string {
	switch h {
	case crypto.SHA1:
		return "SHA1"
	case crypto.SHA256:
		return "SHA256"
	case crypto.SHA384:
		return "SHA384"
	case crypto.SHA512:
		return "SHA512"
	default:
		return ""
	}
}

// ncryptGetStringProperty reads a string property from a CNG key handle.
func ncryptGetStringProperty(handle uintptr, name string) (string, error) {
	propName, _ := windows.UTF16PtrFromString(name)

	// Get size.
	var size uint32
	r, _, err := procNCryptGetProperty.Call(
		handle,
		uintptr(unsafe.Pointer(propName)),
		0, 0,
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		return "", fmt.Errorf("NCryptGetProperty (size): 0x%x %w", r, err)
	}
	if size == 0 {
		return "", nil
	}

	buf := make([]uint16, size/2)
	r, _, err = procNCryptGetProperty.Call(
		handle,
		uintptr(unsafe.Pointer(propName)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r != 0 {
		return "", fmt.Errorf("NCryptGetProperty (read): 0x%x %w", r, err)
	}

	return windows.UTF16ToString(buf), nil
}

// ecdsaCurveFromName returns the elliptic curve for a CNG algorithm name.
func ecdsaCurveFromName(algName string) elliptic.Curve {
	switch algName {
	case "ECDSA_P256":
		return elliptic.P256()
	case "ECDSA_P384":
		return elliptic.P384()
	case "ECDSA_P521":
		return elliptic.P521()
	default:
		return elliptic.P256()
	}
}
