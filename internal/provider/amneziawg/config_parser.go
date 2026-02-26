package amneziawg

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

// ParsedConfig holds the result of parsing an AmneziaWG .conf file.
type ParsedConfig struct {
	// LocalAddresses are the IPs from the Interface Address field (for netstack).
	LocalAddresses []netip.Addr
	// DNSServers are the IPs from the Interface DNS field (for netstack).
	DNSServers []netip.Addr
	// MTU from the Interface section, default 1420.
	MTU int
	// UAPIConfig is the UAPI-formatted string ready for device.IpcSet().
	UAPIConfig string
	// PeerEndpoints are the server endpoints from [Peer] sections (for static filter bypass).
	PeerEndpoints []netip.AddrPort
}

// peerAccumulator buffers UAPI lines for a single [Peer] section
// so that public_key is always emitted first (required by UAPI protocol).
type peerAccumulator struct {
	publicKey string
	lines     []string
}

func (pa *peerAccumulator) flush(uapi *strings.Builder) error {
	if pa.publicKey == "" {
		if len(pa.lines) > 0 {
			return fmt.Errorf("peer section has no PublicKey but contains %d keys", len(pa.lines))
		}
		return nil
	}
	fmt.Fprintf(uapi, "public_key=%s\n", pa.publicKey)
	for _, line := range pa.lines {
		fmt.Fprint(uapi, line)
	}
	return nil
}

// ParseConfigFile reads an AmneziaWG .conf file and produces a ParsedConfig.
// Interface Address, DNS, and MTU are extracted for netstack.
// All other fields are converted to UAPI key=value format.
func ParseConfigFile(path string) (*ParsedConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	result := &ParsedConfig{MTU: 1420}
	var uapi strings.Builder
	section := ""
	peerSeen := false
	var currentPeer *peerAccumulator

	flushPeer := func() error {
		if currentPeer != nil {
			if err := currentPeer.flush(&uapi); err != nil {
				return err
			}
			currentPeer = nil
		}
		return nil
	}

	firstLine := true
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Strip UTF-8 BOM from the first line (common in Windows-exported configs).
		if firstLine {
			line = strings.TrimPrefix(line, "\xEF\xBB\xBF")
			firstLine = false
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Skip WireSock extension lines (e.g. @ws:AllowedApps = ...).
		if strings.HasPrefix(line, "@") {
			continue
		}

		if strings.HasPrefix(line, "[") {
			if err := flushPeer(); err != nil {
				return nil, err
			}
			section = strings.ToLower(strings.Trim(line, "[] "))
			if section == "peer" {
				if !peerSeen {
					peerSeen = true
					fmt.Fprint(&uapi, "replace_peers=true\n")
				}
				currentPeer = &peerAccumulator{}
			}
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch section {
		case "interface":
			if err := parseInterfaceKey(key, value, result, &uapi); err != nil {
				return nil, fmt.Errorf("[Interface] %s: %w", key, err)
			}
		case "peer":
			if err := parsePeerKey(key, value, result, currentPeer); err != nil {
				return nil, fmt.Errorf("[Peer] %s: %w", key, err)
			}
		}
	}

	if err := flushPeer(); err != nil {
		return nil, err
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	result.UAPIConfig = uapi.String()
	return result, nil
}

func parseInterfaceKey(key, value string, cfg *ParsedConfig, uapi *strings.Builder) error {
	switch strings.ToLower(key) {
	case "privatekey":
		h, err := base64ToHex(value)
		if err != nil {
			return err
		}
		fmt.Fprintf(uapi, "private_key=%s\n", h)
	case "listenport":
		fmt.Fprintf(uapi, "listen_port=%s\n", value)
	case "address":
		for _, s := range splitCSV(value) {
			prefix, err := netip.ParsePrefix(s)
			if err != nil {
				// Try as plain address without CIDR.
				ip, err2 := netip.ParseAddr(s)
				if err2 != nil {
					return fmt.Errorf("invalid address %q", s)
				}
				cfg.LocalAddresses = append(cfg.LocalAddresses, ip)
				continue
			}
			cfg.LocalAddresses = append(cfg.LocalAddresses, prefix.Addr())
		}
	case "dns":
		for _, s := range splitCSV(value) {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return fmt.Errorf("invalid DNS %q", s)
			}
			cfg.DNSServers = append(cfg.DNSServers, ip)
		}
	case "mtu":
		var mtu int
		if _, err := fmt.Sscanf(value, "%d", &mtu); err != nil {
			return fmt.Errorf("invalid MTU %q", value)
		}
		cfg.MTU = mtu
	// AmneziaWG obfuscation extensions — pass through to UAPI.
	case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4":
		fmt.Fprintf(uapi, "%s=%s\n", strings.ToLower(key), value)
	}
	return nil
}

func parsePeerKey(key, value string, cfg *ParsedConfig, peer *peerAccumulator) error {
	switch strings.ToLower(key) {
	case "publickey":
		h, err := base64ToHex(value)
		if err != nil {
			return err
		}
		peer.publicKey = h
	case "presharedkey":
		h, err := base64ToHex(value)
		if err != nil {
			return err
		}
		peer.lines = append(peer.lines, fmt.Sprintf("preshared_key=%s\n", h))
	case "endpoint":
		ep, err := resolveEndpoint(value)
		if err != nil {
			return fmt.Errorf("invalid endpoint %q: %w", value, err)
		}
		peer.lines = append(peer.lines, fmt.Sprintf("endpoint=%s\n", ep))
		// Store for static filter bypass.
		if ap, err := netip.ParseAddrPort(ep); err == nil {
			cfg.PeerEndpoints = append(cfg.PeerEndpoints, ap)
		}
	case "allowedips":
		for _, cidr := range splitCSV(value) {
			peer.lines = append(peer.lines, fmt.Sprintf("allowed_ip=%s\n", cidr))
		}
	case "persistentkeepalive":
		peer.lines = append(peer.lines, fmt.Sprintf("persistent_keepalive_interval=%s\n", value))
	}
	return nil
}

// resolveEndpoint resolves a hostname:port endpoint to IP:port.
// UAPI requires numeric IP addresses; hostnames are not accepted.
func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}
	// Already an IP — return as-is.
	if _, err := netip.ParseAddr(host); err == nil {
		return endpoint, nil
	}
	// Resolve hostname to IP.
	ips, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no addresses for %q", host)
	}
	return net.JoinHostPort(ips[0], port), nil
}

// base64ToHex decodes a base64-encoded key and returns its hex representation.
func base64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("invalid base64: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// splitCSV splits a comma-separated value string and trims whitespace.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
