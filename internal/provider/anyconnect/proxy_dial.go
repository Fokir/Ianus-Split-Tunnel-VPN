package anyconnect

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"awg-split-tunnel/internal/core"
)

// dialViaProxy establishes a TCP connection to target through an HTTP CONNECT proxy.
// Returns a raw net.Conn tunneled through the proxy, ready for TLS handshake.
func dialViaProxy(ctx context.Context, target string, proxyURL string, proxyUser, proxyPass string, controlFn func(string, string, net.Conn) error) (net.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL %q: %w", proxyURL, err)
	}

	proxyHost := u.Host
	if u.Port() == "" {
		proxyHost = net.JoinHostPort(u.Hostname(), "8080")
	}

	core.Log.Infof("AnyConnect", "Connecting via HTTP proxy %s", proxyHost)

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	proxyConn, err := dialer.DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyHost, err)
	}

	// Send HTTP CONNECT request.
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)

	// Add proxy authentication if provided.
	if proxyUser != "" || proxyPass != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(proxyUser + ":" + proxyPass))
		connectReq += "Proxy-Authorization: Basic " + auth + "\r\n"
	}

	// Use proxy credentials from URL if present.
	if u.User != nil && proxyUser == "" {
		pass, _ := u.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pass))
		connectReq += "Proxy-Authorization: Basic " + auth + "\r\n"
	}

	connectReq += "\r\n"

	proxyConn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(proxyConn, connectReq); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("write CONNECT to proxy: %w", err)
	}

	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("read proxy response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: HTTP %d %s", resp.StatusCode, resp.Status)
	}

	// Clear deadline for the tunneled connection.
	proxyConn.SetDeadline(time.Time{})

	core.Log.Infof("AnyConnect", "HTTP proxy tunnel established to %s", target)

	// If there's buffered data in br, wrap the connection.
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: proxyConn, br: br}, nil
	}
	return proxyConn, nil
}

// bufferedConn wraps a net.Conn with a bufio.Reader that may have leftover data.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}
