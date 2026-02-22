//go:build windows

package wireguard

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// ParsedConfig holds the result of parsing a standard WireGuard .conf file.
type ParsedConfig struct {
	// LocalAddresses are the IPs from the Interface Address field (for netstack).
	LocalAddresses []netip.Addr
	// DNSServers are the IPs from the Interface DNS field (for netstack).
	DNSServers []netip.Addr
	// MTU from the Interface section, default 1420.
	MTU int
	// UAPIConfig is the UAPI-formatted string ready for device.IpcSet().
	UAPIConfig string
	// PeerEndpoints are the server endpoints from [Peer] sections (for bypass routes).
	PeerEndpoints []netip.AddrPort
}

// ParseConfigFile reads a standard WireGuard .conf file and produces a ParsedConfig.
// AmneziaWG obfuscation fields (Jc, Jmin, Jmax, S1-S4, H1-H4) are silently ignored.
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

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			if section == "peer" && !peerSeen {
				peerSeen = true
				fmt.Fprint(&uapi, "replace_peers=true\n")
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
			if err := parsePeerKey(key, value, result, &uapi); err != nil {
				return nil, fmt.Errorf("[Peer] %s: %w", key, err)
			}
		}
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
	// AmneziaWG obfuscation fields — silently ignored for standard WireGuard.
	case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4":
		// skip
	}
	return nil
}

func parsePeerKey(key, value string, cfg *ParsedConfig, uapi *strings.Builder) error {
	switch strings.ToLower(key) {
	case "publickey":
		h, err := base64ToHex(value)
		if err != nil {
			return err
		}
		fmt.Fprintf(uapi, "public_key=%s\n", h)
	case "presharedkey":
		h, err := base64ToHex(value)
		if err != nil {
			return err
		}
		fmt.Fprintf(uapi, "preshared_key=%s\n", h)
	case "endpoint":
		fmt.Fprintf(uapi, "endpoint=%s\n", value)
		if ap, err := netip.ParseAddrPort(value); err == nil {
			cfg.PeerEndpoints = append(cfg.PeerEndpoints, ap)
		}
	case "allowedips":
		for _, cidr := range splitCSV(value) {
			fmt.Fprintf(uapi, "allowed_ip=%s\n", cidr)
		}
	case "persistentkeepalive":
		fmt.Fprintf(uapi, "persistent_keepalive_interval=%s\n", value)
	}
	return nil
}

func base64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("invalid base64: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

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
