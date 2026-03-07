package anyconnect

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CSTP packet types.
const (
	pktData       byte = 0x00
	pktDPDReq     byte = 0x03
	pktDPDResp    byte = 0x04
	pktDisconnect byte = 0x05
	pktKeepalive  byte = 0x07
	pktTerminate  byte = 0x09
)

// cstpHeader is the 8-byte CSTP frame header template.
var cstpHeader = [8]byte{0x53, 0x54, 0x46, 0x01, 0x00, 0x00, 0x00, 0x00}

// tunnelParams holds parameters received from the server CONNECT response.
type tunnelParams struct {
	Address        netip.Addr
	Netmask        string
	DNS            []string
	MTU            int
	DPDInterval    int // seconds
	KeepaliveInt   int // seconds
	SplitInclude   []netip.Prefix
	SplitExclude   []netip.Prefix
	DTLSPort       int
	DTLSSessionID  string
	IdleTimeout    int
	SessionTimeout int
}

// cstpConn wraps a TLS connection with CSTP framing.
type cstpConn struct {
	conn   net.Conn
	br     *bufio.Reader
	writeMu sync.Mutex

	params tunnelParams

	inboundHandler atomic.Pointer[func(pkt []byte) bool]

	// onDisconnect is called when the CSTP readLoop exits (session drop, server terminate, I/O error).
	onDisconnect func(error)

	// cleanShutdown is set before stop() to suppress the onDisconnect callback
	// on intentional disconnect (avoids spurious session-drop events).
	cleanShutdown atomic.Bool

	cancel  func()
	stopped chan struct{}
}

// establishTunnel sends the CONNECT request and parses the response headers.
func establishTunnel(br *bufio.Reader, conn io.Writer, host, cookie string, cid clientID) (*tunnelParams, error) {
	reqStr := fmt.Sprintf("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: %s\r\n"+
		"Cookie: webvpn=%s\r\n"+
		"X-CSTP-Version: 1\r\n"+
		"X-CSTP-Hostname: %s\r\n"+
		"X-CSTP-Accept-Encoding: identity\r\n"+
		"X-CSTP-Address-Type: IPv4\r\n"+
		"X-CSTP-MTU: 1399\r\n"+
		"X-CSTP-Base-MTU: 1399\r\n"+
		"X-Transcend-Version: 1\r\n"+
		"X-Aggregate-Auth: 1\r\n"+
		"\r\n",
		host, cid.UserAgent, cookie, host)

	if _, err := io.WriteString(conn, reqStr); err != nil {
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	// Body is the raw CSTP stream; do NOT close it.

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CONNECT failed: HTTP %d", resp.StatusCode)
	}

	return parseTunnelHeaders(resp.Header)
}

func parseTunnelHeaders(h http.Header) (*tunnelParams, error) {
	p := &tunnelParams{
		MTU:          1399,
		DPDInterval:  30,
		KeepaliveInt: 20,
	}

	addrStr := h.Get("X-CSTP-Address")
	if addrStr == "" {
		return nil, fmt.Errorf("no X-CSTP-Address in response")
	}
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return nil, fmt.Errorf("parse X-CSTP-Address %q: %w", addrStr, err)
	}
	p.Address = addr
	p.Netmask = h.Get("X-CSTP-Netmask")

	if mtu := h.Get("X-CSTP-MTU"); mtu != "" {
		if v, err := strconv.Atoi(mtu); err == nil && v > 0 {
			p.MTU = v
		}
	}
	if dpd := h.Get("X-CSTP-DPD"); dpd != "" {
		if v, err := strconv.Atoi(dpd); err == nil && v > 0 {
			p.DPDInterval = v
		}
	}
	if ka := h.Get("X-CSTP-Keepalive"); ka != "" {
		if v, err := strconv.Atoi(ka); err == nil && v > 0 {
			p.KeepaliveInt = v
		}
	}

	p.DNS = h.Values("X-CSTP-DNS")
	p.DTLSPort, _ = strconv.Atoi(h.Get("X-DTLS-Port"))
	p.DTLSSessionID = h.Get("X-DTLS-Session-ID")

	for _, v := range h.Values("X-CSTP-Split-Include") {
		if pfx, ok := parseRouteEntry(v); ok {
			p.SplitInclude = append(p.SplitInclude, pfx)
		}
	}
	for _, v := range h.Values("X-CSTP-Split-Exclude") {
		if pfx, ok := parseRouteEntry(v); ok {
			p.SplitExclude = append(p.SplitExclude, pfx)
		}
	}

	return p, nil
}

// parseRouteEntry parses "ip/mask" where mask is dotted-decimal (e.g. "10.0.0.0/255.0.0.0")
// or CIDR notation (e.g. "10.0.0.0/8").
func parseRouteEntry(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)

	// Try CIDR first.
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx, true
	}

	// Try ip/dotted-mask.
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return netip.Prefix{}, false
	}

	ip, err := netip.ParseAddr(parts[0])
	if err != nil {
		return netip.Prefix{}, false
	}

	mask := net.ParseIP(parts[1])
	if mask == nil {
		return netip.Prefix{}, false
	}
	mask4 := mask.To4()
	if mask4 == nil {
		return netip.Prefix{}, false
	}

	ones, _ := net.IPv4Mask(mask4[0], mask4[1], mask4[2], mask4[3]).Size()
	return netip.PrefixFrom(ip, ones), true
}

// newCSTPConn wraps an existing TLS conn (after tunnel establishment) for CSTP I/O.
func newCSTPConn(conn net.Conn, br *bufio.Reader, params tunnelParams, cancelFn func()) *cstpConn {
	return &cstpConn{
		conn:    conn,
		br:      br,
		params:  params,
		cancel:  cancelFn,
		stopped: make(chan struct{}),
	}
}

// run starts the read loop, DPD and keepalive goroutines.
func (c *cstpConn) run() {
	go c.readLoop()
	go c.dpdLoop()
	go c.keepaliveLoop()
}

// stop closes the connection and waits for goroutines to finish.
func (c *cstpConn) stop() {
	c.sendControlPacket(pktDisconnect)
	c.cancel()
	c.conn.Close()
	<-c.stopped
}

func (c *cstpConn) readLoop() {
	defer close(c.stopped)

	var exitErr error
	defer func() {
		if c.onDisconnect != nil && !c.cleanShutdown.Load() {
			c.onDisconnect(exitErr)
		}
	}()

	hdr := make([]byte, 8)
	for {
		if c.params.DPDInterval > 0 {
			c.conn.SetReadDeadline(time.Now().Add(time.Duration(c.params.DPDInterval+5) * time.Second))
		}

		if _, err := io.ReadFull(c.br, hdr); err != nil {
			exitErr = fmt.Errorf("read header: %w", err)
			return
		}

		// Validate magic.
		if hdr[0] != 0x53 || hdr[1] != 0x54 || hdr[2] != 0x46 || hdr[3] != 0x01 {
			exitErr = fmt.Errorf("invalid CSTP magic")
			return
		}

		pktType := hdr[6]
		pktLen := binary.BigEndian.Uint16(hdr[4:6])

		switch pktType {
		case pktData:
			if pktLen == 0 {
				continue
			}
			buf := make([]byte, pktLen)
			if _, err := io.ReadFull(c.br, buf); err != nil {
				exitErr = fmt.Errorf("read data: %w", err)
				return
			}
			if hp := c.inboundHandler.Load(); hp != nil {
				(*hp)(buf)
			}

		case pktDPDReq:
			c.sendControlPacket(pktDPDResp)

		case pktDPDResp:
			// DPD response received; connection is alive.

		case pktKeepalive:
			// No action needed.

		case pktDisconnect:
			exitErr = fmt.Errorf("server sent disconnect")
			return

		case pktTerminate:
			exitErr = fmt.Errorf("session terminated by server")
			return

		default:
			// Skip unknown payload.
			if pktLen > 0 {
				io.CopyN(io.Discard, c.br, int64(pktLen))
			}
		}
	}
}

func (c *cstpConn) dpdLoop() {
	if c.params.DPDInterval <= 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(c.params.DPDInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.sendControlPacket(pktDPDReq)
		case <-c.stopped:
			return
		}
	}
}

func (c *cstpConn) keepaliveLoop() {
	if c.params.KeepaliveInt <= 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(c.params.KeepaliveInt) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.sendControlPacket(pktKeepalive)
		case <-c.stopped:
			return
		}
	}
}

func (c *cstpConn) sendControlPacket(pktType byte) {
	var frame [8]byte
	copy(frame[:], cstpHeader[:])
	frame[6] = pktType

	c.writeMu.Lock()
	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	c.conn.Write(frame[:])
	c.writeMu.Unlock()
}

// sendData sends an IP packet wrapped in a CSTP DATA frame.
func (c *cstpConn) sendData(pkt []byte) bool {
	l := len(pkt)
	if l == 0 || l > 65535 {
		return false
	}

	frame := make([]byte, 8+l)
	copy(frame[:4], cstpHeader[:4])
	binary.BigEndian.PutUint16(frame[4:6], uint16(l))
	frame[6] = pktData
	frame[7] = 0
	copy(frame[8:], pkt)

	c.writeMu.Lock()
	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.conn.Write(frame)
	c.writeMu.Unlock()
	return err == nil
}
