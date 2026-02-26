package gateway

// consumeTag reads a protobuf field tag and returns (fieldNumber, wireType, bytesConsumed).
func consumeTag(data []byte) (int, int, int) {
	v, n := consumeVarint(data)
	if n == 0 {
		return 0, 0, 0
	}
	return int(v >> 3), int(v & 0x7), n
}

// consumeVarint reads a base-128 varint and returns (value, bytesConsumed).
func consumeVarint(data []byte) (uint64, int) {
	var val uint64
	for i := 0; i < len(data) && i < 10; i++ {
		b := data[i]
		val |= uint64(b&0x7F) << (7 * i)
		if b < 0x80 {
			return val, i + 1
		}
	}
	return 0, 0
}

// skipField skips a protobuf field value based on wire type.
func skipField(data []byte, wireType int) []byte {
	switch wireType {
	case 0: // varint
		for i := 0; i < len(data); i++ {
			if data[i] < 0x80 {
				return data[i+1:]
			}
		}
		return nil
	case 1: // 64-bit
		if len(data) < 8 {
			return nil
		}
		return data[8:]
	case 2: // LEN
		length, n := consumeVarint(data)
		if n == 0 || int(length) > len(data[n:]) {
			return nil
		}
		return data[n+int(length):]
	case 5: // 32-bit
		if len(data) < 4 {
			return nil
		}
		return data[4:]
	default:
		return nil
	}
}
