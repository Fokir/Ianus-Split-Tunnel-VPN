package gateway

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/platform"
)

const geositeDownloadURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

// geositeRawEntry is a raw parsed domain from geosite.dat.
type geositeRawEntry struct {
	Type  int    // 0=Plain(keyword), 2=RootDomain(domain), 3=Full
	Value string
}

// geositeCategory groups entries under a country_code.
type geositeCategory struct {
	Code    string
	Entries []geositeRawEntry
}

// NewNICBoundHTTPClient creates an HTTP client that binds to the real NIC,
// bypassing the TUN adapter's default route. This prevents the service's own
// HTTP traffic from being captured and dropped by the TUN router (selfPID check).
func NewNICBoundHTTPClient(realNICIndex uint32, localIP netip.Addr, binder platform.InterfaceBinder) *http.Client {
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}
	if binder != nil {
		dialer.Control = binder.BindControl(realNICIndex)
	}
	if localIP.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP.AsSlice()}
	}
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}
}

// EnsureGeositeFile checks if geosite.dat exists at path; downloads if missing.
// httpClient may be nil — in that case, uses the default http.Client (which won't
// bypass TUN, but works when TUN is not yet active during early startup).
func EnsureGeositeFile(path string, httpClient *http.Client) error {
	if _, err := os.Stat(path); err == nil {
		return nil // file exists
	}
	return DownloadGeositeFile(path, httpClient)
}

// DownloadGeositeFile downloads (or re-downloads) geosite.dat from the upstream source.
// httpClient may be nil — falls back to http.DefaultClient.
func DownloadGeositeFile(path string, httpClient *http.Client) error {
	core.Log.Infof("DNS", "Downloading geosite.dat from %s", geositeDownloadURL)

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, geositeDownloadURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create geosite request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download geosite.dat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("geosite download returned HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read geosite response: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write geosite.dat: %w", err)
	}

	core.Log.Infof("DNS", "Downloaded geosite.dat (%d bytes)", len(data))
	return nil
}

// LoadGeosite parses geosite.dat and expands requested categories into matcher entries.
// categories maps category name (e.g. "ru") → DomainRule template (for TunnelID/Action).
func LoadGeosite(path string, categories map[string]core.DomainRule) ([]GeositeExpanded, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read geosite.dat: %w", err)
	}

	// Normalize category names to uppercase for matching.
	upperCats := make(map[string]core.DomainRule, len(categories))
	for k, v := range categories {
		upperCats[strings.ToUpper(k)] = v
	}

	var result []GeositeExpanded
	cats := parseGeoSiteList(data)

	for _, cat := range cats {
		rule, ok := upperCats[strings.ToUpper(cat.Code)]
		if !ok {
			continue
		}

		for _, entry := range cat.Entries {
			typ := geositeTypeToString(entry.Type)
			if typ == "" {
				continue
			}
			result = append(result, GeositeExpanded{
				Type:  typ,
				Value: entry.Value,
				Rule:  rule,
			})
		}
	}

	core.Log.Infof("DNS", "Loaded %d geosite entries from %d categories", len(result), len(categories))
	return result, nil
}

// ListGeositeCategories returns all category codes available in geosite.dat.
func ListGeositeCategories(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read geosite.dat: %w", err)
	}

	cats := parseGeoSiteList(data)
	codes := make([]string, 0, len(cats))
	for _, cat := range cats {
		codes = append(codes, cat.Code)
	}
	return codes, nil
}

// --- Raw protobuf decoding (no proto dependency) ---
//
// GeoSiteList: field 1 = repeated GeoSite (LEN)
// GeoSite:     field 1 = string country_code, field 2 = repeated Domain (LEN)
// Domain:      field 1 = varint type, field 2 = string value

// parseGeoSiteList decodes the top-level GeoSiteList message.
func parseGeoSiteList(data []byte) []geositeCategory {
	var cats []geositeCategory
	for len(data) > 0 {
		fieldNum, wireType, n := consumeTag(data)
		if n == 0 {
			break
		}
		data = data[n:]

		if fieldNum == 1 && wireType == 2 { // LEN: GeoSite
			length, n := consumeVarint(data)
			if n == 0 || int(length) > len(data[n:]) {
				break
			}
			msgData := data[n : n+int(length)]
			data = data[n+int(length):]

			cat := parseGeoSite(msgData)
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

// parseGeoSite decodes a GeoSite message.
func parseGeoSite(data []byte) geositeCategory {
	var cat geositeCategory
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

		case fieldNum == 2 && wireType == 2: // LEN: Domain
			length, n := consumeVarint(data)
			if n == 0 || int(length) > len(data[n:]) {
				return cat
			}
			domData := data[n : n+int(length)]
			data = data[n+int(length):]

			entry := parseDomain(domData)
			if entry.Value != "" {
				cat.Entries = append(cat.Entries, entry)
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

// parseDomain decodes a Domain message.
func parseDomain(data []byte) geositeRawEntry {
	var entry geositeRawEntry
	for len(data) > 0 {
		fieldNum, wireType, n := consumeTag(data)
		if n == 0 {
			break
		}
		data = data[n:]

		switch {
		case fieldNum == 1 && wireType == 0: // varint type
			val, n := consumeVarint(data)
			if n == 0 {
				return entry
			}
			entry.Type = int(val)
			data = data[n:]

		case fieldNum == 2 && wireType == 2: // string value
			length, n := consumeVarint(data)
			if n == 0 || int(length) > len(data[n:]) {
				return entry
			}
			entry.Value = string(data[n : n+int(length)])
			data = data[n+int(length):]

		default:
			data = skipField(data, wireType)
			if data == nil {
				return entry
			}
		}
	}
	return entry
}

// consumeTag, consumeVarint, skipField moved to proto_helpers.go (cross-platform).

// geositeTypeToString maps V2Ray Domain.Type to our pattern prefix.
func geositeTypeToString(t int) string {
	switch t {
	case 0: // Plain → keyword
		return "keyword"
	case 1: // Regex — not supported, skip
		return ""
	case 2: // RootDomain → domain
		return "domain"
	case 3: // Full → full
		return "full"
	default:
		return ""
	}
}

// GeositeFileSize returns the file size for UI display, or 0 if not found.
func GeositeFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

