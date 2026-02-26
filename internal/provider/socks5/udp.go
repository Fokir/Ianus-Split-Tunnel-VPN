package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// socks5ReadBufPool reuses 64KB buffers for SOCKS5 UDP Read operations.
var socks5ReadBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

// SOCKS5 protocol constants.
const (
	socks5Version    = 0x05
	authNone         = 0x00
	authUserPassword = 0x02
	authNoAcceptable = 0xFF

	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded = 0x00

	userPassVersion  = 0x01
	userPassSucceeded = 0x00
)

// socks5Auth holds credentials for SOCKS5 username/password authentication.
type socks5Auth struct {
	username string
	password string
}

// udpAssociateConn wraps a UDP connection to a SOCKS5 UDP relay.
// It transparently adds/removes the SOCKS5 UDP request header (RFC 1928 §7).
// The TCP control connection is kept alive — closing it terminates the UDP relay.
type udpAssociateConn struct {
	udpConn  *net.UDPConn  // UDP socket to the relay
	tcpCtrl  net.Conn      // TCP control connection (must stay open)
	relayAddr *net.UDPAddr // UDP relay address from server
	targetAddr net.Addr    // original target address
	targetHost string      // target host for SOCKS5 header
	targetPort uint16      // target port for SOCKS5 header
}

// dialUDPAssociate performs SOCKS5 UDP ASSOCIATE handshake and returns a net.Conn
// that transparently encapsulates/decapsulates the SOCKS5 UDP header.
func dialUDPAssociate(ctx context.Context, serverAddr string, auth *socks5Auth, targetAddr string) (net.Conn, error) {
	// 1. Establish TCP control connection to SOCKS5 server.
	d := net.Dialer{Timeout: 10 * time.Second}
	tcpConn, err := d.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to SOCKS5 server: %w", err)
	}

	// 2. SOCKS5 handshake (auth negotiation).
	if err := socks5Handshake(tcpConn, auth); err != nil {
		tcpConn.Close()
		return nil, err
	}

	// 3. Send UDP ASSOCIATE request.
	// DST.ADDR = 0.0.0.0:0 — we don't know our source yet.
	req := []byte{
		socks5Version, cmdUDPAssociate, 0x00, // VER, CMD, RSV
		atypIPv4, 0, 0, 0, 0, // ATYP, DST.ADDR (0.0.0.0)
		0, 0, // DST.PORT (0)
	}
	if _, err := tcpConn.Write(req); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("send UDP ASSOCIATE: %w", err)
	}

	// 4. Read reply — get BND.ADDR:BND.PORT (the UDP relay address).
	relayAddr, err := readSocks5Reply(tcpConn)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE reply: %w", err)
	}

	// If server returns 0.0.0.0 as relay host, use the server's IP.
	if relayAddr.IP.IsUnspecified() {
		serverHost, _, _ := net.SplitHostPort(serverAddr)
		relayAddr.IP = net.ParseIP(serverHost)
	}

	// 5. Create local UDP socket and "connect" to the relay.
	udpConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("connect to UDP relay %s: %w", relayAddr, err)
	}

	// Parse target address.
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		udpConn.Close()
		tcpConn.Close()
		return nil, fmt.Errorf("invalid target %q: %w", targetAddr, err)
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	conn := &udpAssociateConn{
		udpConn:    udpConn,
		tcpCtrl:    tcpConn,
		relayAddr:  relayAddr,
		targetHost: host,
		targetPort: port,
	}

	// Keep TCP control connection alive (monitor in background).
	go conn.monitorTCPControl()

	return conn, nil
}

// socks5Handshake performs the SOCKS5 authentication negotiation.
func socks5Handshake(conn net.Conn, auth *socks5Auth) error {
	// Send greeting with supported auth methods.
	var methods []byte
	if auth != nil {
		methods = []byte{authNone, authUserPassword}
	} else {
		methods = []byte{authNone}
	}

	greeting := make([]byte, 2+len(methods))
	greeting[0] = socks5Version
	greeting[1] = byte(len(methods))
	copy(greeting[2:], methods)

	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("send greeting: %w", err)
	}

	// Read server's chosen method.
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("read auth method: %w", err)
	}
	if reply[0] != socks5Version {
		return fmt.Errorf("invalid SOCKS version %d", reply[0])
	}

	switch reply[1] {
	case authNone:
		return nil
	case authUserPassword:
		if auth == nil {
			return fmt.Errorf("server requires auth but no credentials provided")
		}
		return doUserPassAuth(conn, auth)
	case authNoAcceptable:
		return fmt.Errorf("no acceptable auth method")
	default:
		return fmt.Errorf("unsupported auth method %d", reply[1])
	}
}

// doUserPassAuth performs RFC 1929 username/password authentication.
func doUserPassAuth(conn net.Conn, auth *socks5Auth) error {
	uLen := len(auth.username)
	pLen := len(auth.password)
	if uLen > 255 || pLen > 255 {
		return fmt.Errorf("username or password too long")
	}

	msg := make([]byte, 3+uLen+pLen)
	msg[0] = userPassVersion
	msg[1] = byte(uLen)
	copy(msg[2:], auth.username)
	msg[2+uLen] = byte(pLen)
	copy(msg[3+uLen:], auth.password)

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("send user/pass: %w", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("read auth reply: %w", err)
	}
	if reply[1] != userPassSucceeded {
		return fmt.Errorf("authentication failed (status %d)", reply[1])
	}
	return nil
}

// readSocks5Reply reads a SOCKS5 reply and extracts BND.ADDR:BND.PORT.
func readSocks5Reply(conn net.Conn) (*net.UDPAddr, error) {
	// Read VER, REP, RSV, ATYP.
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read reply header: %w", err)
	}
	if header[1] != repSucceeded {
		return nil, fmt.Errorf("SOCKS5 error: reply code %d", header[1])
	}

	var ip net.IP
	switch header[3] {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		ip = net.IP(buf)
	case atypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		ip = net.IP(buf)
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		ips, err := net.ResolveIPAddr("ip", string(domain))
		if err != nil {
			return nil, fmt.Errorf("resolve relay domain %q: %w", domain, err)
		}
		ip = ips.IP
	default:
		return nil, fmt.Errorf("unsupported address type %d", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

// Write sends a datagram through the SOCKS5 UDP relay with the appropriate header.
func (c *udpAssociateConn) Write(b []byte) (int, error) {
	header := buildUDPHeader(c.targetHost, c.targetPort)
	pkt := make([]byte, len(header)+len(b))
	copy(pkt, header)
	copy(pkt[len(header):], b)

	_, err := c.udpConn.Write(pkt)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read receives a datagram from the SOCKS5 UDP relay, stripping the header.
func (c *udpAssociateConn) Read(b []byte) (int, error) {
	bp := socks5ReadBufPool.Get().(*[]byte)
	defer socks5ReadBufPool.Put(bp)
	buf := *bp
	n, err := c.udpConn.Read(buf)
	if err != nil {
		return 0, err
	}

	// Strip SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP(1) + ADDR(variable) + PORT(2).
	offset, err := udpHeaderLen(buf[:n])
	if err != nil {
		return 0, fmt.Errorf("parse UDP relay header: %w", err)
	}

	payload := buf[offset:n]
	copy(b, payload)
	if len(payload) > len(b) {
		return len(b), nil
	}
	return len(payload), nil
}

// Close closes both the UDP socket and the TCP control connection.
func (c *udpAssociateConn) Close() error {
	c.udpConn.Close()
	c.tcpCtrl.Close()
	return nil
}

// LocalAddr returns the local UDP address.
func (c *udpAssociateConn) LocalAddr() net.Addr {
	return c.udpConn.LocalAddr()
}

// RemoteAddr returns the target address.
func (c *udpAssociateConn) RemoteAddr() net.Addr {
	ap, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", c.targetHost, c.targetPort))
	if err != nil {
		return c.relayAddr
	}
	return net.UDPAddrFromAddrPort(ap)
}

// SetDeadline sets deadlines on the UDP connection.
func (c *udpAssociateConn) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the UDP connection.
func (c *udpAssociateConn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the UDP connection.
func (c *udpAssociateConn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}

// monitorTCPControl watches the TCP control connection. When it closes,
// the UDP relay is terminated (per RFC 1928).
func (c *udpAssociateConn) monitorTCPControl() {
	buf := make([]byte, 1)
	// Block until TCP connection closes or errors.
	c.tcpCtrl.Read(buf)
	// TCP closed — close UDP relay.
	c.udpConn.Close()
}

// buildUDPHeader constructs the SOCKS5 UDP request header for the target address.
// Format: RSV(2 bytes, 0x0000) + FRAG(1 byte, 0x00) + ATYP + DST.ADDR + DST.PORT
func buildUDPHeader(host string, port uint16) []byte {
	var header []byte

	// RSV + FRAG
	header = append(header, 0x00, 0x00, 0x00)

	// Try to parse as IP first.
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			header = append(header, atypIPv4)
			a4 := ip.As4()
			header = append(header, a4[:]...)
		} else {
			header = append(header, atypIPv6)
			a16 := ip.As16()
			header = append(header, a16[:]...)
		}
	} else {
		// Domain name.
		header = append(header, atypDomain)
		header = append(header, byte(len(host)))
		header = append(header, []byte(host)...)
	}

	// Port (big-endian).
	header = append(header, byte(port>>8), byte(port))

	return header
}

// udpHeaderLen returns the length of the SOCKS5 UDP header in the given packet.
func udpHeaderLen(pkt []byte) (int, error) {
	if len(pkt) < 4 {
		return 0, fmt.Errorf("packet too short")
	}

	// RSV(2) + FRAG(1) + ATYP(1)
	atyp := pkt[3]
	switch atyp {
	case atypIPv4:
		// 4 (header) + 4 (IPv4) + 2 (port) = 10
		if len(pkt) < 10 {
			return 0, fmt.Errorf("packet too short for IPv4")
		}
		return 10, nil
	case atypIPv6:
		// 4 (header) + 16 (IPv6) + 2 (port) = 22
		if len(pkt) < 22 {
			return 0, fmt.Errorf("packet too short for IPv6")
		}
		return 22, nil
	case atypDomain:
		if len(pkt) < 5 {
			return 0, fmt.Errorf("packet too short for domain")
		}
		domainLen := int(pkt[4])
		total := 4 + 1 + domainLen + 2 // header + len byte + domain + port
		if len(pkt) < total {
			return 0, fmt.Errorf("packet too short for domain name")
		}
		return total, nil
	default:
		return 0, fmt.Errorf("unsupported address type %d", atyp)
	}
}
