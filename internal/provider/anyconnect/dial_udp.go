package anyconnect

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// rawUDPConn implements net.Conn for UDP-over-raw-IP through the CSTP tunnel.
// Used by the DNS resolver to forward queries through AnyConnect.
type rawUDPConn struct {
	p          *Provider
	srcIP      [4]byte
	dstIP      [4]byte
	localPort  uint16
	remotePort uint16
	respCh     chan []byte
	deadline   atomic.Value // stores time.Time
	closed     atomic.Bool
}

var (
	ephemeralPort atomic.Uint32
	ephemeralOnce sync.Once
)

func allocEphemeralPort() uint16 {
	ephemeralOnce.Do(func() { ephemeralPort.Store(49152) })
	for {
		p := ephemeralPort.Add(1)
		if p > 65000 {
			ephemeralPort.CompareAndSwap(p, 49153)
			continue
		}
		return uint16(p)
	}
}

// DialUDP creates a virtual UDP connection tunneled through CSTP at the raw IP level.
func (p *Provider) DialUDP(_ context.Context, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("anyconnect: parse addr %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("anyconnect: invalid port %q", portStr)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("anyconnect: invalid IP %q", host)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("anyconnect: IPv6 not supported")
	}

	p.mu.RLock()
	c := p.cstp
	adapterIP := p.adapterIP
	p.mu.RUnlock()

	if c == nil {
		return nil, fmt.Errorf("anyconnect: not connected")
	}
	if !adapterIP.IsValid() {
		return nil, fmt.Errorf("anyconnect: no adapter IP")
	}

	srcIP := adapterIP.As4()
	dstIP := [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
	localPort := allocEphemeralPort()

	conn := &rawUDPConn{
		p:          p,
		srcIP:      srcIP,
		dstIP:      dstIP,
		localPort:  localPort,
		remotePort: uint16(port),
		respCh:     make(chan []byte, 4),
	}

	p.pendingUDP.Store(localPort, conn)
	return conn, nil
}

func (c *rawUDPConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	pkt := buildRawUDPPacket(c.srcIP, c.dstIP, c.localPort, c.remotePort, b)

	c.p.mu.RLock()
	cstp := c.p.cstp
	c.p.mu.RUnlock()

	if cstp == nil {
		return 0, fmt.Errorf("anyconnect: not connected")
	}
	if !cstp.sendData(pkt) {
		return 0, fmt.Errorf("anyconnect: send failed")
	}
	return len(b), nil
}

func (c *rawUDPConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	if dl, ok := c.deadline.Load().(time.Time); ok && !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case resp, ok := <-c.respCh:
			if !ok {
				return 0, net.ErrClosed
			}
			return copy(b, resp), nil
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		}
	}

	// No deadline — block indefinitely.
	resp, ok := <-c.respCh
	if !ok {
		return 0, net.ErrClosed
	}
	return copy(b, resp), nil
}

func (c *rawUDPConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.p.pendingUDP.Delete(c.localPort)
	}
	return nil
}

func (c *rawUDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(c.srcIP[:]), Port: int(c.localPort)}
}

func (c *rawUDPConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(c.dstIP[:]), Port: int(c.remotePort)}
}

func (c *rawUDPConn) SetDeadline(t time.Time) error {
	c.deadline.Store(t)
	return nil
}

func (c *rawUDPConn) SetReadDeadline(t time.Time) error {
	c.deadline.Store(t)
	return nil
}

func (c *rawUDPConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

// interceptInbound checks if an inbound IP packet is a UDP response matching
// a pending DialUDP connection. Returns true if the packet was consumed.
func (p *Provider) interceptInbound(pkt []byte) bool {
	if len(pkt) < 28 { // min IP(20) + UDP(8)
		return false
	}
	if pkt[0]>>4 != 4 { // IPv4 only
		return false
	}
	if pkt[9] != 17 { // UDP
		return false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl+8 {
		return false
	}

	srcPort := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])

	val, ok := p.pendingUDP.Load(dstPort)
	if !ok {
		return false
	}

	conn := val.(*rawUDPConn)
	if srcPort != conn.remotePort {
		return false
	}

	// Extract UDP payload.
	udpLen := int(binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6]))
	if udpLen < 8 || ihl+udpLen > len(pkt) {
		return false
	}
	payload := make([]byte, udpLen-8)
	copy(payload, pkt[ihl+8:ihl+udpLen])

	select {
	case conn.respCh <- payload:
	default:
	}
	return true
}

// buildRawUDPPacket constructs a raw IPv4+UDP packet.
func buildRawUDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)

	// IP header.
	pkt[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])

	// IP header checksum.
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	// UDP header.
	udpLen := uint16(8 + len(payload))
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], udpLen)
	// UDP checksum = 0 (optional for IPv4).

	// Payload.
	copy(pkt[28:], payload)

	return pkt
}
