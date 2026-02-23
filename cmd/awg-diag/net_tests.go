//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// doCheckIP fetches the external IP address via HTTP.
func doCheckIP() TestResult {
	start := time.Now()
	result := TestResult{Name: "check-ip"}

	urls := []string{
		"https://ifconfig.me/ip",
		"https://api.ipify.org",
	}

	var lastErr error
	for _, url := range urls {
		client := &http.Client{Timeout: timeout}
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s returned %d", url, resp.StatusCode)
			continue
		}
		ip := strings.TrimSpace(string(body))
		result.Success = true
		result.LatencyMs = time.Since(start).Milliseconds()
		result.Details = ip
		return result
	}

	result.Error = lastErr.Error()
	result.LatencyMs = time.Since(start).Milliseconds()
	return result
}

// doDNS resolves a domain using the system resolver or a specific DNS server.
func doDNS(domain, server string) TestResult {
	start := time.Now()
	result := TestResult{Name: fmt.Sprintf("dns(%s)", domain)}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var resolver *net.Resolver
	if server != "" {
		// Use custom DNS server.
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				addr := server
				if !strings.Contains(addr, ":") {
					addr = addr + ":53"
				}
				return d.DialContext(ctx, "udp", addr)
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	addrs, err := resolver.LookupHost(ctx, domain)
	result.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Success = true
	result.Details = strings.Join(addrs, ", ")
	if server != "" {
		result.Details += fmt.Sprintf(" (server: %s)", server)
	}
	return result
}

// doTCP tests a TCP connection to the given address and measures latency.
func doTCP(addr string) TestResult {
	start := time.Now()
	result := TestResult{Name: fmt.Sprintf("tcp(%s)", addr)}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	result.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	conn.Close()

	result.Success = true
	result.Details = fmt.Sprintf("connected in %d ms", result.LatencyMs)
	return result
}

// doUDP sends a UDP packet and waits for a response.
// Default payload is a DNS root query if empty.
func doUDP(addr, payload string) TestResult {
	start := time.Now()
	result := TestResult{Name: fmt.Sprintf("udp(%s)", addr)}

	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		result.Error = err.Error()
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	var data []byte
	if payload != "" {
		data = []byte(payload)
	} else {
		// Minimal DNS query for "." (root) — type NS, class IN.
		data = []byte{
			0xAA, 0xBB, // Transaction ID
			0x01, 0x00, // Flags: standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answers: 0
			0x00, 0x00, // Authority: 0
			0x00, 0x00, // Additional: 0
			0x00,                   // Root domain
			0x00, 0x02, // Type: NS
			0x00, 0x01, // Class: IN
		}
	}

	_, err = conn.Write(data)
	if err != nil {
		result.Error = fmt.Sprintf("write: %v", err)
		result.LatencyMs = time.Since(start).Milliseconds()
		return result
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	result.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = fmt.Sprintf("read: %v", err)
		return result
	}

	result.Success = true
	result.Details = fmt.Sprintf("received %d bytes", n)
	return result
}

// doHTTP performs an HTTP GET request and reports status, latency, and headers.
func doHTTP(url string) TestResult {
	start := time.Now()
	result := TestResult{Name: fmt.Sprintf("http(%s)", truncateURL(url))}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	result.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 400
	result.Details = fmt.Sprintf("HTTP %d, %d bytes", resp.StatusCode, len(body))
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		result.Details += fmt.Sprintf(", %s", ct)
	}
	return result
}

// runFull executes all network tests sequentially and outputs a summary table.
func runFull() {
	diagLog.Printf("Running full diagnostic suite...")
	diagLog.Printf("")

	results := []TestResult{
		doCheckIP(),
		doDNS("google.com", ""),
		doDNS("google.com", "8.8.8.8"),
		doTCP("1.1.1.1:443"),
		doTCP("8.8.8.8:53"),
		doUDP("8.8.8.8:53", ""),
		doHTTP("https://httpbin.org/ip"),
	}

	outputResults(results)
}

// truncateURL shortens a URL for display.
func truncateURL(url string) string {
	if len(url) > 40 {
		return url[:37] + "..."
	}
	return url
}
