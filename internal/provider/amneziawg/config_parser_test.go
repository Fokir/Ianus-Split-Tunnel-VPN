//go:build windows

package amneziawg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fake WireGuard keys (valid base64-encoded 32-byte values for testing only).
const (
	testPrivateKey   = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=" // 32x 0x61
	testPublicKey    = "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=" // 32x 0x62
	testPresharedKey = "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=" // 32x 0x63
)

// TestParseWireSockConfig verifies that a WireSock-exported AmneziaWG config
// (with WireSock extension comments and Endpoint before PublicKey in [Peer])
// produces valid UAPI output where public_key precedes endpoint.
func TestParseWireSockConfig(t *testing.T) {
	wireSockConf := `[Interface]
Address = 10.8.1.4/32
PrivateKey = ` + testPrivateKey + `
DNS = 198.51.100.53,208.67.222.222, 208.67.220.220

# [Interface] WireSock extensions
#@ws:BypassLanTraffic = true
#@ws:VirtualAdapterMode = true

# Amnezia WG extension

Jc = 3
Jmin = 15
Jmax = 60
S1 = 10
S2 = 20
H1 = 111111111
H2 = 222222222
H3 = 333333333
H4 = 444444444

[Peer]
Endpoint = 198.51.100.1:37298
PublicKey = ` + testPublicKey + `
PresharedKey = ` + testPresharedKey + `
PersistentKeepalive = 25
AllowedIPs = 0.0.0.0/0,::/0

# [Peer] WireSock extensions
#@ws:DisallowedIPs = 192.168.0.0/24,10.0.0.0/8
#@ws:AllowedApps = Discord,chrome
#@ws:DisallowedApps = C:\Program Files (x86)\SomeApp
`

	tmp := filepath.Join(t.TempDir(), "test.conf")
	if err := os.WriteFile(tmp, []byte(wireSockConf), 0600); err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseConfigFile(tmp)
	if err != nil {
		t.Fatalf("ParseConfigFile failed: %v", err)
	}

	uapi := parsed.UAPIConfig
	t.Logf("UAPI output:\n%s", uapi)

	// Verify public_key appears before endpoint in UAPI output.
	pkIdx := strings.Index(uapi, "public_key=")
	epIdx := strings.Index(uapi, "endpoint=")

	if pkIdx < 0 {
		t.Fatal("public_key not found in UAPI output")
	}
	if epIdx < 0 {
		t.Fatal("endpoint not found in UAPI output")
	}
	if epIdx < pkIdx {
		t.Errorf("endpoint (pos %d) appears before public_key (pos %d) in UAPI output", epIdx, pkIdx)
	}

	// Verify essential device keys are present.
	if !strings.Contains(uapi, "private_key=") {
		t.Error("private_key not found in UAPI output")
	}
	if !strings.Contains(uapi, "jc=3") {
		t.Error("jc=3 not found in UAPI output")
	}
	if !strings.Contains(uapi, "replace_peers=true") {
		t.Error("replace_peers not found in UAPI output")
	}

	// Verify parsed fields.
	if len(parsed.LocalAddresses) == 0 {
		t.Error("no local addresses parsed")
	}
	if len(parsed.DNSServers) != 3 {
		t.Errorf("expected 3 DNS servers, got %d", len(parsed.DNSServers))
	}
	if len(parsed.PeerEndpoints) == 0 {
		t.Error("no peer endpoints parsed")
	}
}

// TestParseWireSockConfigWithBOM verifies that a config file with UTF-8 BOM
// is parsed correctly.
func TestParseWireSockConfigWithBOM(t *testing.T) {
	confWithoutBOM := `[Interface]
Address = 10.8.1.4/32
PrivateKey = ` + testPrivateKey + `
DNS = 198.51.100.53

Jc = 3
Jmin = 15
Jmax = 60
S1 = 10
S2 = 20
H1 = 111111111
H2 = 222222222
H3 = 333333333
H4 = 444444444

[Peer]
Endpoint = 198.51.100.1:37298
PublicKey = ` + testPublicKey + `
PresharedKey = ` + testPresharedKey + `
AllowedIPs = 0.0.0.0/0
`
	// Prepend UTF-8 BOM.
	bom := []byte{0xEF, 0xBB, 0xBF}
	content := append(bom, []byte(confWithoutBOM)...)

	tmp := filepath.Join(t.TempDir(), "bom.conf")
	if err := os.WriteFile(tmp, content, 0600); err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseConfigFile(tmp)
	if err != nil {
		t.Fatalf("ParseConfigFile failed with BOM: %v", err)
	}

	uapi := parsed.UAPIConfig
	t.Logf("UAPI output (BOM):\n%s", uapi)

	if !strings.Contains(uapi, "private_key=") {
		t.Error("private_key not found in UAPI output (BOM file)")
	}
	if !strings.Contains(uapi, "public_key=") {
		t.Error("public_key not found in UAPI output (BOM file)")
	}
	if len(parsed.LocalAddresses) == 0 {
		t.Error("no local addresses parsed from BOM file")
	}
}

// TestParseConfigWithUncommentedWireSockExtensions verifies that uncommented
// WireSock @ws: extension lines are safely ignored.
func TestParseConfigWithUncommentedWireSockExtensions(t *testing.T) {
	conf := `[Interface]
Address = 10.8.1.4/32
PrivateKey = ` + testPrivateKey + `
DNS = 198.51.100.53
@ws:BypassLanTraffic = true
@ws:VirtualAdapterMode = true

[Peer]
PublicKey = ` + testPublicKey + `
Endpoint = 198.51.100.1:37298
AllowedIPs = 0.0.0.0/0
@ws:AllowedApps = Discord,chrome
`

	tmp := filepath.Join(t.TempDir(), "wsext.conf")
	if err := os.WriteFile(tmp, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseConfigFile(tmp)
	if err != nil {
		t.Fatalf("ParseConfigFile failed: %v", err)
	}

	uapi := parsed.UAPIConfig
	if !strings.Contains(uapi, "private_key=") {
		t.Error("private_key missing")
	}
	if !strings.Contains(uapi, "public_key=") {
		t.Error("public_key missing")
	}
	if strings.Contains(uapi, "ws:") {
		t.Error("WireSock extension leaked into UAPI")
	}
}

// TestPeerAccumulatorOrder verifies that the peerAccumulator always emits
// public_key before other peer keys regardless of input order.
func TestPeerAccumulatorOrder(t *testing.T) {
	var b strings.Builder
	pa := &peerAccumulator{
		publicKey: "abcdef1234567890abcdef1234567890",
		lines: []string{
			"endpoint=1.2.3.4:51820\n",
			"preshared_key=aabbccdd\n",
			"allowed_ip=0.0.0.0/0\n",
		},
	}
	if err := pa.flush(&b); err != nil {
		t.Fatalf("flush error: %v", err)
	}
	out := b.String()

	pkIdx := strings.Index(out, "public_key=")
	epIdx := strings.Index(out, "endpoint=")
	if pkIdx < 0 || epIdx < 0 {
		t.Fatalf("missing keys in output: %q", out)
	}
	if epIdx < pkIdx {
		t.Errorf("endpoint before public_key in: %q", out)
	}
}

// TestPeerAccumulatorNoPublicKey verifies that flushing a peer without
// PublicKey returns an error instead of writing orphaned lines.
func TestPeerAccumulatorNoPublicKey(t *testing.T) {
	var b strings.Builder
	pa := &peerAccumulator{
		lines: []string{
			"endpoint=1.2.3.4:51820\n",
		},
	}
	err := pa.flush(&b)
	if err == nil {
		t.Fatal("expected error for peer without PublicKey, got nil")
	}
	if b.Len() != 0 {
		t.Errorf("expected no UAPI output, got: %q", b.String())
	}
}
