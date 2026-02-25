//go:build windows

package proxy

// ExtractSNI parses a TLS ClientHello message and returns the SNI hostname.
// Returns empty string if the data is not a valid TLS ClientHello or has no SNI.
// Zero allocations on the fast path; ~1-5μs per call.
func ExtractSNI(data []byte) string {
	// Minimum TLS record header: 5 bytes
	if len(data) < 5 {
		return ""
	}

	// Check TLS record header: ContentType = Handshake (0x16)
	if data[0] != 0x16 {
		return ""
	}

	// Record length (2 bytes, big-endian)
	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return ""
	}

	// Start of handshake message
	hs := data[5 : 5+recordLen]

	// Handshake type = ClientHello (0x01)
	if len(hs) < 1 || hs[0] != 0x01 {
		return ""
	}

	// Handshake length (3 bytes)
	if len(hs) < 4 {
		return ""
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return ""
	}
	ch := hs[4 : 4+hsLen]

	// ClientHello:
	//   client_version: 2 bytes
	//   random: 32 bytes
	//   session_id_length: 1 byte + session_id
	//   cipher_suites_length: 2 bytes + cipher_suites
	//   compression_methods_length: 1 byte + compression_methods
	//   extensions_length: 2 bytes + extensions

	pos := 0

	// Skip version (2) + random (32)
	pos += 2 + 32
	if pos >= len(ch) {
		return ""
	}

	// Skip session ID
	sessionIDLen := int(ch[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(ch) {
		return ""
	}

	// Skip cipher suites
	cipherSuitesLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2 + cipherSuitesLen
	if pos+1 > len(ch) {
		return ""
	}

	// Skip compression methods
	compressionLen := int(ch[pos])
	pos += 1 + compressionLen
	if pos+2 > len(ch) {
		return ""
	}

	// Extensions length
	extensionsLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2
	if pos+extensionsLen > len(ch) {
		return ""
	}

	extensions := ch[pos : pos+extensionsLen]
	return parseSNIExtension(extensions)
}

// parseSNIExtension walks TLS extensions and extracts the SNI hostname.
func parseSNIExtension(data []byte) string {
	pos := 0
	for pos+4 <= len(data) {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extLen > len(data) {
			return ""
		}

		if extType == 0 { // SNI extension (type 0x0000)
			return parseSNIPayload(data[pos : pos+extLen])
		}

		pos += extLen
	}
	return ""
}

// parseSNIPayload extracts the hostname from the SNI extension payload.
func parseSNIPayload(data []byte) string {
	// ServerNameList: length (2 bytes) + entries
	if len(data) < 2 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return ""
	}
	list := data[2 : 2+listLen]

	pos := 0
	for pos+3 <= len(list) {
		nameType := list[pos]
		nameLen := int(list[pos+1])<<8 | int(list[pos+2])
		pos += 3

		if pos+nameLen > len(list) {
			return ""
		}

		if nameType == 0 { // host_name type
			return string(list[pos : pos+nameLen])
		}

		pos += nameLen
	}
	return ""
}
