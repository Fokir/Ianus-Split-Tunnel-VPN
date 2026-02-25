//go:build windows

package gateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"awg-split-tunnel/internal/core"
)

const geoipDownloadURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"

// geoipRawCIDR is a raw parsed CIDR from geoip.dat.
type geoipRawCIDR struct {
	IP     []byte // 4 bytes for IPv4, 16 bytes for IPv6
	Prefix int    // prefix length
}

// geoipCategory groups CIDRs under a country code.
type geoipCategory struct {
	Code  string
	CIDRs []geoipRawCIDR
}

// GeoIPMatcher matches destination IPs against geoip rules.
type GeoIPMatcher struct {
	entries []geoipMatchEntry
}

type geoipMatchEntry struct {
	trie     *PrefixTrie
	tunnelID string
	action   core.DomainAction
}

// Match checks entries in order (first match wins).
func (m *GeoIPMatcher) Match(ip [4]byte) (tunnelID string, action core.DomainAction, matched bool) {
	for i := range m.entries {
		if m.entries[i].trie.Contains(ip) {
			return m.entries[i].tunnelID, m.entries[i].action, true
		}
	}
	return "", 0, false
}

// IsEmpty returns true if the matcher has no entries.
func (m *GeoIPMatcher) IsEmpty() bool {
	return len(m.entries) == 0
}

// NewGeoIPMatcher builds a matcher from geoip.dat for the requested categories.
// categories maps uppercase country code → DomainRule template.
func NewGeoIPMatcher(geoipFilePath string, categories map[string]core.DomainRule) (*GeoIPMatcher, error) {
	if len(categories) == 0 {
		return &GeoIPMatcher{}, nil
	}

	data, err := os.ReadFile(geoipFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read geoip.dat: %w", err)
	}

	// Normalize category names to uppercase.
	upperCats := make(map[string]core.DomainRule, len(categories))
	for k, v := range categories {
		upperCats[strings.ToUpper(k)] = v
	}

	cats := parseGeoIPList(data)

	// Build one PrefixTrie per requested category.
	// Multiple rules referencing the same category get merged.
	matcher := &GeoIPMatcher{}

	for _, cat := range cats {
		rule, ok := upperCats[strings.ToUpper(cat.Code)]
		if !ok {
			continue
		}

		trie := NewPrefixTrie()
		ipv4Count := 0
		for _, cidr := range cat.CIDRs {
			if len(cidr.IP) == 4 {
				var ip [4]byte
				copy(ip[:], cidr.IP)
				trie.Insert(ip, cidr.Prefix)
				ipv4Count++
			}
			// Skip IPv6 for now (our TUN stack is IPv4-only).
		}

		if ipv4Count > 0 {
			matcher.entries = append(matcher.entries, geoipMatchEntry{
				trie:     trie,
				tunnelID: rule.TunnelID,
				action:   rule.Action,
			})
		}
	}

	core.Log.Infof("DNS", "GeoIP matcher built: %d country entries", len(matcher.entries))
	return matcher, nil
}

// EnsureGeoIPFile checks if geoip.dat exists; downloads if missing.
func EnsureGeoIPFile(path string, httpClient *http.Client) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return DownloadGeoIPFile(path, httpClient)
}

// DownloadGeoIPFile downloads (or re-downloads) geoip.dat.
func DownloadGeoIPFile(path string, httpClient *http.Client) error {
	core.Log.Infof("DNS", "Downloading geoip.dat from %s", geoipDownloadURL)

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, geoipDownloadURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create geoip request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download geoip.dat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("geoip download returned HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read geoip response: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write geoip.dat: %w", err)
	}

	core.Log.Infof("DNS", "Downloaded geoip.dat (%d bytes)", len(data))
	return nil
}

// ListGeoIPCategories returns all country codes available in geoip.dat.
func ListGeoIPCategories(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read geoip.dat: %w", err)
	}

	cats := parseGeoIPList(data)
	codes := make([]string, 0, len(cats))
	for _, cat := range cats {
		codes = append(codes, cat.Code)
	}
	return codes, nil
}

// ─── GeoIPResolver — caching IP→country lookup ─────────────────────

// geoipResolverEntry maps a country code to its PrefixTrie.
type geoipResolverEntry struct {
	code string
	trie *PrefixTrie
}

// GeoIPResolver resolves IP addresses to country codes using geoip.dat.
type GeoIPResolver struct {
	entries []geoipResolverEntry
}

// NewGeoIPResolver parses geoip.dat and builds a PrefixTrie per country.
func NewGeoIPResolver(geoipPath string) (*GeoIPResolver, error) {
	data, err := os.ReadFile(geoipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read geoip.dat for resolver: %w", err)
	}

	cats := parseGeoIPList(data)
	resolver := &GeoIPResolver{}

	for _, cat := range cats {
		trie := NewPrefixTrie()
		count := 0
		for _, cidr := range cat.CIDRs {
			if len(cidr.IP) == 4 {
				var ip [4]byte
				copy(ip[:], cidr.IP)
				trie.Insert(ip, cidr.Prefix)
				count++
			}
		}
		if count > 0 {
			resolver.entries = append(resolver.entries, geoipResolverEntry{
				code: strings.ToUpper(cat.Code),
				trie: trie,
			})
		}
	}

	core.Log.Infof("Core", "GeoIP resolver built: %d countries", len(resolver.entries))
	return resolver, nil
}

// Lookup returns the 2-letter country code for the given IP address.
// Returns empty string if no match found.
func (r *GeoIPResolver) Lookup(addr netip.Addr) string {
	if r == nil || !addr.Is4() {
		return ""
	}
	ip4 := addr.As4()
	for i := range r.entries {
		if r.entries[i].trie.Contains(ip4) {
			return r.entries[i].code
		}
	}
	return ""
}

// --- Raw protobuf decoding for geoip.dat ---
//
// GeoIPList: field 1 = repeated GeoIP (LEN)
// GeoIP:     field 1 = string country_code (LEN), field 2 = repeated CIDR (LEN)
// CIDR:      field 1 = bytes ip (LEN), field 2 = int32 prefix (VARINT)

func parseGeoIPList(data []byte) []geoipCategory {
	var cats []geoipCategory
	for len(data) > 0 {
		fieldNum, wireType, n := consumeTag(data)
		if n == 0 {
			break
		}
		data = data[n:]

		if fieldNum == 1 && wireType == 2 { // LEN: GeoIP
			length, n := consumeVarint(data)
			if n == 0 || int(length) > len(data[n:]) {
				break
			}
			msgData := data[n : n+int(length)]
			data = data[n+int(length):]

			cat := parseGeoIP(msgData)
			if cat.Code != "" {
				cats = append(cats, cat)
			}
		} else {
			data = skipField(data, wireType)
			if data == nil {
				break
			}
		}
	}
	return cats
}

func parseGeoIP(data []byte) geoipCategory {
	var cat geoipCategory
	for len(data) > 0 {
		fieldNum, wireType, n := consumeTag(data)
		if n == 0 {
			break
		}
		data = data[n:]

		switch {
		case fieldNum == 1 && wireType == 2: // string country_code
			length, n := consumeVarint(data)
			if n == 0 || int(length) > len(data[n:]) {
				return cat
			}
			cat.Code = string(data[n : n+int(length)])
			data = data[n+int(length):]

		case fieldNum == 2 && wireType == 2: // LEN: CIDR
			length, n := consumeVarint(data)
			if n == 0 || int(length) > len(data[n:]) {
				return cat
			}
			cidrData := data[n : n+int(length)]
			data = data[n+int(length):]

			cidr := parseGeoIPCIDR(cidrData)
			if len(cidr.IP) > 0 {
				cat.CIDRs = append(cat.CIDRs, cidr)
			}

		default:
			data = skipField(data, wireType)
			if data == nil {
				return cat
			}
		}
	}
	return cat
}

func parseGeoIPCIDR(data []byte) geoipRawCIDR {
	var cidr geoipRawCIDR
	for len(data) > 0 {
		fieldNum, wireType, n := consumeTag(data)
		if n == 0 {
			break
		}
		data = data[n:]

		switch {
		case fieldNum == 1 && wireType == 2: // bytes ip
			length, n := consumeVarint(data)
			if n == 0 || int(length) > len(data[n:]) {
				return cidr
			}
			cidr.IP = make([]byte, length)
			copy(cidr.IP, data[n:n+int(length)])
			data = data[n+int(length):]

		case fieldNum == 2 && wireType == 0: // varint prefix
			val, n := consumeVarint(data)
			if n == 0 {
				return cidr
			}
			cidr.Prefix = int(val)
			data = data[n:]

		default:
			data = skipField(data, wireType)
			if data == nil {
				return cidr
			}
		}
	}
	return cidr
}
