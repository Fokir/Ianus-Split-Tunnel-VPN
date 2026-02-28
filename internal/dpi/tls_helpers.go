package dpi

import "encoding/binary"

// TLS record and handshake constants.
const (
	tlsRecordTypeHandshake  = 0x16
	tlsHandshakeClientHello = 0x01
	tlsExtSNI               = 0x0000 // Server Name Indication extension type
	sniHostNameType         = 0x00
)

// IsTLSClientHello reports whether data begins with a TLS ClientHello record.
// It checks the ContentType (0x16), protocol version (0x03, 0x01–0x03),
// and HandshakeType (0x01).
func IsTLSClientHello(data []byte) bool {
	// Minimum: 5 (record header) + 4 (handshake header) = 9 bytes.
	if len(data) < 9 {
		return false
	}
	// ContentType = Handshake (0x16).
	if data[0] != tlsRecordTypeHandshake {
		return false
	}
	// Protocol version: major=0x03, minor=0x01..0x03.
	if data[1] != 0x03 || data[2] < 0x01 || data[2] > 0x03 {
		return false
	}
	// HandshakeType = ClientHello (0x01) starts at byte 5.
	if data[5] != tlsHandshakeClientHello {
		return false
	}
	return true
}

// FindSNIOffset locates the SNI hostname within a TLS ClientHello and returns
// its byte offset relative to the start of data. Returns -1 if not found.
//
// The returned offset points to the first byte of the SNI hostname string,
// which is a good split point for DPI evasion.
func FindSNIOffset(data []byte) int {
	// Ensure we have at least a TLS record header.
	if !IsTLSClientHello(data) {
		return -1
	}

	// TLS record: [type(1) | version(2) | length(2)] = 5 bytes
	// Handshake:  [type(1) | length(3)]              = 4 bytes
	pos := 5 + 4 // skip record header + handshake header

	// ClientHello body:
	// [client_version(2) | random(32) = 34 bytes]
	pos += 34
	if pos >= len(data) {
		return -1
	}

	// Session ID: [length(1) | session_id(N)]
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(data) {
		return -1
	}

	// Cipher suites: [length(2) | suites(N)]
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > len(data) {
		return -1
	}

	// Compression methods: [length(1) | methods(N)]
	compressionLen := int(data[pos])
	pos += 1 + compressionLen
	if pos+2 > len(data) {
		return -1
	}

	// Extensions: [total_length(2) | extensions...]
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	// Walk extensions looking for SNI (type 0x0000).
	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == tlsExtSNI {
			// SNI extension data:
			// [server_name_list_length(2) | server_name_type(1) | host_name_length(2) | host_name(N)]
			if pos+5 > extensionsEnd {
				return -1
			}
			// Skip server_name_list_length (2 bytes).
			nameType := data[pos+2]
			if nameType != sniHostNameType {
				return -1
			}
			hostnameLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
			hostnameStart := pos + 5
			if hostnameStart+hostnameLen > extensionsEnd {
				return -1
			}
			return hostnameStart
		}

		pos += extLen
	}

	return -1
}

// ExtractSNI extracts the server name from a TLS ClientHello.
// Returns empty string if SNI is not found.
func ExtractSNI(data []byte) string {
	offset := FindSNIOffset(data)
	if offset < 0 {
		return ""
	}
	// Read the hostname length from the 2 bytes before the offset.
	if offset < 2 {
		return ""
	}
	hostnameLen := int(binary.BigEndian.Uint16(data[offset-2 : offset]))
	if offset+hostnameLen > len(data) {
		return ""
	}
	return string(data[offset : offset+hostnameLen])
}
