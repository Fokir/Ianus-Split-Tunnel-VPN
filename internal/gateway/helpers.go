//go:build windows

package gateway

import "encoding/binary"

// ---------------------------------------------------------------------------
// In-place packet manipulation helpers for TUN (raw IP, no Ethernet header).
// Ported from packet_router.go with ethHdrLen=0.
// ---------------------------------------------------------------------------

const (
	minIPv4Hdr = 20
	minTCPHdr  = 20
	minUDPHdr  = 8

	protoICMP byte = 1
	protoTCP  byte = 6
	protoUDP  byte = 17

	minICMPHdr = 8

	icmpEchoReply   byte = 0
	icmpEchoRequest byte = 8

	tcpFIN byte = 0x01
	tcpSYN byte = 0x02
	tcpRST byte = 0x04
	tcpACK byte = 0x10
)

// pktMeta — stack-allocated packet metadata from direct buffer parsing.
// TUN version: offsets start at 0 (no Ethernet header).
type pktMeta struct {
	srcIP [4]byte
	dstIP [4]byte
	srcP  uint16
	dstP  uint16
	flags byte // TCP flags; 0 for UDP
	tpOff int  // transport header offset (ipHdrLen)
}

// checksumFold folds a 32-bit accumulator to a 16-bit one's complement value.
func checksumFold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(sum)
}

// checksumUpdate16 incrementally updates a one's complement checksum
// when a single 16-bit field changes from oldVal to newVal (RFC 1624).
func checksumUpdate16(oldCk, oldVal, newVal uint16) uint16 {
	sum := uint32(^oldCk) + uint32(^oldVal) + uint32(newVal)
	return ^checksumFold(sum)
}

// tunSwapIPs swaps IPv4 src/dst addresses in-place (raw IP packet).
// No checksum update needed: one's complement sum is commutative.
func tunSwapIPs(pkt []byte) {
	// srcIP at offset 12, dstIP at offset 16.
	var tmp [4]byte
	copy(tmp[:], pkt[12:16])
	copy(pkt[12:16], pkt[16:20])
	copy(pkt[16:20], tmp[:])
}

// tunOverwriteSrcIP sets a new IPv4 source address and incrementally updates
// both the IP header checksum and the transport checksum at transportCkOff.
// transportCkOff == 0 means skip transport checksum update.
func tunOverwriteSrcIP(pkt []byte, newSrc [4]byte, transportCkOff int) {
	off := 12 // srcIP offset in raw IP

	oldHi := binary.BigEndian.Uint16(pkt[off:])
	oldLo := binary.BigEndian.Uint16(pkt[off+2:])
	newHi := binary.BigEndian.Uint16(newSrc[:2])
	newLo := binary.BigEndian.Uint16(newSrc[2:])

	copy(pkt[off:off+4], newSrc[:])

	// IP header checksum at offset 10.
	ipCkOff := 10
	ipCk := binary.BigEndian.Uint16(pkt[ipCkOff:])
	ipCk = checksumUpdate16(ipCk, oldHi, newHi)
	ipCk = checksumUpdate16(ipCk, oldLo, newLo)
	binary.BigEndian.PutUint16(pkt[ipCkOff:], ipCk)

	// Transport checksum (pseudo-header includes srcIP).
	if transportCkOff > 0 {
		tCk := binary.BigEndian.Uint16(pkt[transportCkOff:])
		if tCk != 0 { // UDP checksum 0 means disabled
			tCk = checksumUpdate16(tCk, oldHi, newHi)
			tCk = checksumUpdate16(tCk, oldLo, newLo)
			binary.BigEndian.PutUint16(pkt[transportCkOff:], tCk)
		}
	}
}

// tunOverwriteDstIP sets a new IPv4 destination address and updates checksums.
func tunOverwriteDstIP(pkt []byte, newDst [4]byte, transportCkOff int) {
	off := 16 // dstIP offset in raw IP

	oldHi := binary.BigEndian.Uint16(pkt[off:])
	oldLo := binary.BigEndian.Uint16(pkt[off+2:])
	newHi := binary.BigEndian.Uint16(newDst[:2])
	newLo := binary.BigEndian.Uint16(newDst[2:])

	copy(pkt[off:off+4], newDst[:])

	// IP header checksum.
	ipCkOff := 10
	ipCk := binary.BigEndian.Uint16(pkt[ipCkOff:])
	ipCk = checksumUpdate16(ipCk, oldHi, newHi)
	ipCk = checksumUpdate16(ipCk, oldLo, newLo)
	binary.BigEndian.PutUint16(pkt[ipCkOff:], ipCk)

	// Transport checksum.
	if transportCkOff > 0 {
		tCk := binary.BigEndian.Uint16(pkt[transportCkOff:])
		if tCk != 0 {
			tCk = checksumUpdate16(tCk, oldHi, newHi)
			tCk = checksumUpdate16(tCk, oldLo, newLo)
			binary.BigEndian.PutUint16(pkt[transportCkOff:], tCk)
		}
	}
}

// tunSetTCPPort writes a new 16-bit value at portOff and updates the TCP checksum.
func tunSetTCPPort(pkt []byte, portOff int, newPort uint16, tcpCkOff int) {
	old := binary.BigEndian.Uint16(pkt[portOff:])
	binary.BigEndian.PutUint16(pkt[portOff:], newPort)
	ck := binary.BigEndian.Uint16(pkt[tcpCkOff:])
	binary.BigEndian.PutUint16(pkt[tcpCkOff:], checksumUpdate16(ck, old, newPort))
}

// tunSetUDPPort writes a new 16-bit value at portOff and updates the UDP checksum.
// Skips update if UDP checksum is 0 (disabled in IPv4).
func tunSetUDPPort(pkt []byte, portOff int, newPort uint16, udpCkOff int) {
	old := binary.BigEndian.Uint16(pkt[portOff:])
	binary.BigEndian.PutUint16(pkt[portOff:], newPort)
	ck := binary.BigEndian.Uint16(pkt[udpCkOff:])
	if ck == 0 {
		return
	}
	binary.BigEndian.PutUint16(pkt[udpCkOff:], checksumUpdate16(ck, old, newPort))
}

// rawMSSLimit is the maximum TCP MSS for raw-forwarded connections.
// Derived from TUN adapter MTU minus IP (20) + TCP (20) headers.
const rawMSSLimit = tunInterfaceMTU - 40 // 1360

// clampTCPMSS reduces the MSS option in a TCP SYN/SYN-ACK packet if it
// exceeds rawMSSLimit. This prevents the remote side from sending segments
// larger than the VPN tunnel can carry, avoiding silent drops due to MTU
// mismatch between the TUN adapter and the encrypted tunnel.
//
// tpOff is the offset of the TCP header within pkt.
func clampTCPMSS(pkt []byte, tpOff int) {
	// Only process packets with SYN flag set (SYN or SYN-ACK).
	if pkt[tpOff+13]&tcpSYN == 0 {
		return
	}

	// TCP data offset → header length in bytes.
	dataOff := int(pkt[tpOff+12]>>4) * 4
	if dataOff <= minTCPHdr {
		return // no options
	}

	optEnd := tpOff + dataOff
	if optEnd > len(pkt) {
		optEnd = len(pkt)
	}

	// Walk TCP options looking for MSS (kind=2, length=4).
	for pos := tpOff + minTCPHdr; pos < optEnd; {
		kind := pkt[pos]
		if kind == 0 { // End of Option List
			break
		}
		if kind == 1 { // NOP
			pos++
			continue
		}
		if pos+1 >= optEnd {
			break
		}
		optLen := int(pkt[pos+1])
		if optLen < 2 || pos+optLen > optEnd {
			break
		}

		if kind == 2 && optLen == 4 { // MSS option
			currentMSS := binary.BigEndian.Uint16(pkt[pos+2:])
			if currentMSS > rawMSSLimit {
				binary.BigEndian.PutUint16(pkt[pos+2:], rawMSSLimit)
				// Incrementally update TCP checksum.
				tcpCkOff := tpOff + 16
				ck := binary.BigEndian.Uint16(pkt[tcpCkOff:])
				ck = checksumUpdate16(ck, currentMSS, rawMSSLimit)
				binary.BigEndian.PutUint16(pkt[tcpCkOff:], ck)
			}
			return
		}

		pos += optLen
	}
}
