//go:build windows

package gateway

import (
	"encoding/binary"

	"awg-split-tunnel/internal/core"
)

// ---------------------------------------------------------------------------
// QoS: priority classification + DSCP marking for raw IP forwarding path
// ---------------------------------------------------------------------------

// Priority levels for packet scheduling. Lower value = higher priority.
const (
	PrioHigh   byte = 0 // realtime: voice, DNS, TCP control
	PrioNormal byte = 1 // default: web, streaming
	PrioLow    byte = 2 // bulk: torrent, backups
)

// DSCP code points (shifted left 2 to sit in the TOS/DSCP field bits 7-2).
const (
	dscpEF   byte = 0xB8 // Expedited Forwarding — voice
	dscpAF41 byte = 0x88 // Assured Forwarding 4/1 — video/control
)

// mapRulePriority converts a core.RulePriority to a gateway priority byte and
// an isAuto flag indicating whether per-packet classification should be used.
func mapRulePriority(rp core.RulePriority) (prio byte, isAuto bool) {
	switch rp {
	case core.PriorityRealtime:
		return PrioHigh, false
	case core.PriorityNormal:
		return PrioNormal, false
	case core.PriorityLow:
		return PrioLow, false
	default: // PriorityAuto
		return PrioNormal, true
	}
}

// classifyPacket determines priority for a new flow based on packet characteristics.
// Called once per new flow when the rule priority is "auto" (PrioNormal).
// Returns PrioHigh, PrioNormal, or PrioLow.
func classifyPacket(pkt []byte, proto byte, tpOff int, srcPort, dstPort uint16) byte {
	switch proto {
	case protoUDP:
		// DNS queries always high priority.
		if dstPort == 53 || srcPort == 53 {
			return PrioHigh
		}
		// Small UDP with both ephemeral ports — likely voice/game.
		payloadLen := len(pkt) - tpOff - minUDPHdr
		if payloadLen < 300 && srcPort >= 1024 && dstPort >= 1024 {
			return PrioHigh
		}
	case protoTCP:
		// TCP control packets (SYN/FIN/RST) get per-packet boost.
		if tpOff+13 < len(pkt) {
			flags := pkt[tpOff+13]
			if flags&(tcpSYN|tcpFIN|tcpRST) != 0 {
				return PrioHigh
			}
		}
	}
	return PrioNormal
}

// boostTCPControl returns PrioHigh if the packet is a TCP SYN/FIN/RST,
// regardless of cached flow priority. This is a per-packet boost for
// connection setup/teardown signals that must not be delayed.
func boostTCPControl(pkt []byte, tpOff int, cachedPrio byte) byte {
	if cachedPrio == PrioHigh {
		return PrioHigh
	}
	if tpOff+13 < len(pkt) {
		flags := pkt[tpOff+13]
		if flags&(tcpSYN|tcpFIN|tcpRST) != 0 {
			return PrioHigh
		}
	}
	return cachedPrio
}

// resolvePriority determines the effective priority for a packet.
// If the rule specifies an explicit priority (realtime/normal/low), use it directly.
// If the rule priority is "auto" (mapped to PrioNormal at config level),
// classify based on packet characteristics.
func resolvePriority(rulePrio byte, isAuto bool, pkt []byte, proto byte, tpOff int, srcPort, dstPort uint16) byte {
	if !isAuto {
		return rulePrio
	}
	return classifyPacket(pkt, proto, tpOff, srcPort, dstPort)
}

// markDSCP stamps the IPv4 TOS/DSCP field for high-priority packets.
// Only applied to PrioHigh traffic. Preserves ECN bits (low 2 bits of TOS).
// Updates IP header checksum incrementally (RFC 1624).
func markDSCP(pkt []byte, proto byte, tpOff int) {
	if len(pkt) < minIPv4Hdr {
		return
	}

	// Determine DSCP value: small UDP → EF (voice), otherwise AF41 (video/control).
	var dscp byte
	if proto == protoUDP {
		payloadLen := len(pkt) - tpOff - minUDPHdr
		if payloadLen < 300 {
			dscp = dscpEF
		} else {
			dscp = dscpAF41
		}
	} else {
		dscp = dscpAF41
	}

	oldTOS := pkt[1]
	newTOS := (dscp & 0xFC) | (oldTOS & 0x03) // preserve ECN bits
	if oldTOS == newTOS {
		return
	}

	// Incremental IP header checksum update (RFC 1624).
	// Must read oldWord BEFORE modifying pkt[1], otherwise oldWord == newWord
	// and the checksum update becomes a no-op despite TOS being changed.
	oldWord := binary.BigEndian.Uint16(pkt[0:2])
	pkt[1] = newTOS
	newWord := (uint16(pkt[0]) << 8) | uint16(newTOS)
	oldCk := binary.BigEndian.Uint16(pkt[10:12])
	newCk := checksumUpdate16(oldCk, oldWord, newWord)
	binary.BigEndian.PutUint16(pkt[10:12], newCk)
}
