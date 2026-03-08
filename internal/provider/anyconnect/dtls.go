package anyconnect

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"awg-split-tunnel/internal/core"

	"github.com/pion/dtls/v3"
)

// dtlsConn wraps a DTLS connection for UDP-based data transport.
// Used alongside CSTP (which handles control: DPD, keepalive, disconnect).
type dtlsConn struct {
	conn    net.Conn
	writeMu sync.Mutex
	closed  atomic.Bool

	inboundHandler atomic.Pointer[func(pkt []byte) bool]
	onDisconnect   func(error)
	stopped        chan struct{}
}

// DTLS data packet types (1-byte header for AnyConnect DTLS framing).
const (
	dtlsPktData       byte = 0x00
	dtlsPktDPDReq     byte = 0x03
	dtlsPktDPDResp    byte = 0x04
	dtlsPktDisconnect byte = 0x05
	dtlsPktKeepalive  byte = 0x07
)

// dialDTLS establishes a DTLS connection to the AnyConnect server.
func dialDTLS(serverIP string, port int, sessionID string, insecureSkipVerify bool, serverName string) (*dtlsConn, error) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(serverIP),
		Port: port,
	}
	if addr.IP == nil {
		return nil, fmt.Errorf("invalid DTLS server IP: %s", serverIP)
	}

	core.Log.Infof("AnyConnect", "Attempting DTLS connection to %s:%d", serverIP, port)

	// AnyConnect DTLS typically uses AES-256-CBC-SHA or AES-128-GCM.
	// pion/dtls supports ECDHE variants which some AnyConnect servers accept.
	config := &dtls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		ServerName:         serverName,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		},
		MTU: 1400,
	}

	conn, err := dtls.Dial("udp4", addr, config)
	if err != nil {
		return nil, fmt.Errorf("DTLS dial: %w", err)
	}

	core.Log.Infof("AnyConnect", "DTLS connection established to %s:%d", serverIP, port)

	// Send session binding packet: the CSTP session ID tells the server
	// which CSTP session this DTLS connection belongs to.
	if sessionID != "" {
		bindPkt := buildDTLSConnectPacket(sessionID)
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(bindPkt); err != nil {
			conn.Close()
			return nil, fmt.Errorf("DTLS session bind: %w", err)
		}
		conn.SetWriteDeadline(time.Time{})
	}

	return &dtlsConn{
		conn:    conn,
		stopped: make(chan struct{}),
	}, nil
}

// run starts the read loop for receiving DTLS packets.
func (d *dtlsConn) run() {
	go d.readLoop()
}

func (d *dtlsConn) readLoop() {
	defer close(d.stopped)

	buf := make([]byte, 65536)
	for {
		n, err := d.conn.Read(buf)
		if err != nil {
			if !d.closed.Load() && d.onDisconnect != nil {
				d.onDisconnect(fmt.Errorf("DTLS read: %w", err))
			}
			return
		}
		if n < 1 {
			continue
		}

		pktType := buf[0]
		payload := buf[1:n]

		switch pktType {
		case dtlsPktData:
			if len(payload) > 0 {
				if hp := d.inboundHandler.Load(); hp != nil {
					pkt := make([]byte, len(payload))
					copy(pkt, payload)
					(*hp)(pkt)
				}
			}
		case dtlsPktDPDReq:
			d.sendControl(dtlsPktDPDResp)
		case dtlsPktDPDResp:
			// Connection alive.
		case dtlsPktKeepalive:
			// No action.
		case dtlsPktDisconnect:
			if d.onDisconnect != nil {
				d.onDisconnect(fmt.Errorf("DTLS server disconnect"))
			}
			return
		}
	}
}

// sendData sends an IP packet through the DTLS connection.
func (d *dtlsConn) sendData(pkt []byte) bool {
	if d.closed.Load() {
		return false
	}
	l := len(pkt)
	if l == 0 || l > 65535 {
		return false
	}

	frame := make([]byte, 1+l)
	frame[0] = dtlsPktData
	copy(frame[1:], pkt)

	d.writeMu.Lock()
	d.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := d.conn.Write(frame)
	d.writeMu.Unlock()
	return err == nil
}

func (d *dtlsConn) sendControl(pktType byte) {
	d.writeMu.Lock()
	d.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	d.conn.Write([]byte{pktType})
	d.writeMu.Unlock()
}

func (d *dtlsConn) close() {
	if d.closed.CompareAndSwap(false, true) {
		d.conn.Close()
		<-d.stopped
	}
}

// dtlsSendData sends data via DTLS (preferred) or falls back to CSTP.
func dtlsSendData(d *dtlsConn, c *cstpConn, pkt []byte) bool {
	if d != nil && !d.closed.Load() {
		return d.sendData(pkt)
	}
	if c != nil {
		return c.sendData(pkt)
	}
	return false
}

// buildDTLSConnectPacket constructs the session binding packet.
// AnyConnect sends "STF\x01\x00\x00\x00\x00" + session ID string in the first
// DTLS packet to bind this DTLS session to an existing CSTP session.
func buildDTLSConnectPacket(sessionID string) []byte {
	sessBytes := []byte(sessionID)
	pkt := make([]byte, 8+len(sessBytes))
	// CSTP magic header.
	pkt[0] = 0x53 // 'S'
	pkt[1] = 0x54 // 'T'
	pkt[2] = 0x46 // 'F'
	pkt[3] = 0x01
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(sessBytes)))
	pkt[6] = 0xF0 // Connect/bind packet type
	pkt[7] = 0x00
	copy(pkt[8:], sessBytes)
	return pkt
}
