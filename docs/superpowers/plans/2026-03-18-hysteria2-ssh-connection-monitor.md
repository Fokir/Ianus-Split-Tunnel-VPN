# Hysteria2, SSH Tunnel, Connection Monitor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Hysteria2 and SSH tunnel protocols + Connection Monitor GUI tab.

**Architecture:** Two new proxy-based TunnelProviders (Hysteria2 over QUIC, SSH over TCP) following SOCKS5/VLESS patterns. Connection Monitor: gRPC streaming RPC exposes flow table snapshots enriched with process/domain/GeoIP data to a new Svelte tab.

**Tech Stack:** Go (`apernet/hysteria/core/v2`, `golang.org/x/crypto/ssh`), protobuf, Svelte 4, TailwindCSS 4.

**Spec:** `docs/superpowers/specs/2026-03-18-hysteria2-ssh-connection-monitor-design.md`

---

## File Map

### New Files
| File | Responsibility |
|------|---------------|
| `internal/provider/hysteria2/provider.go` | Hysteria2 TunnelProvider + EndpointProvider |
| `internal/provider/ssh/provider.go` | SSH TunnelProvider + EndpointProvider |
| `internal/service/connection_monitor.go` | Snapshot collector + pub/sub for connection data |
| `internal/service/grpc_handler_connections.go` | StreamConnections gRPC handler |
| `ui/frontend/src/lib/tabs/ConnectionMonitorTab.svelte` | Connection Monitor GUI tab |
| `ui/frontend/src/lib/stores/connections.js` | Svelte store for connection snapshots |

### Modified Files
| File | Changes |
|------|---------|
| `internal/core/config.go:39-45,355-362` | Add ProtocolHysteria2, ProtocolSSH constants + validProtocols |
| `internal/service/tunnel_controller.go:561-698` | Add cases in CreateProvider switch |
| `internal/gateway/flow_table.go` | Add SnapshotNAT/SnapshotUDP/SnapshotRaw methods + snapshot structs |
| `internal/gateway/domain_table.go` | Add ReverseLookup method |
| `api/proto/vpn_service.proto:500-539` | Add ConnectionEntry, StreamConnections RPC |
| `api/gen/vpn_service.pb.go` | Regenerated |
| `api/gen/vpn_service_grpc.pb.go` | Regenerated |
| `internal/service/service.go` | Add connectionMonitor field |
| `ui/binding_streaming.go` | Add StartConnectionMonitorStream + runConnectionMonitorStream |
| `ui/frontend/src/App.svelte:20-28,133-147` | Add monitor tab definition + conditional render |
| `ui/frontend/src/lib/i18n/en.json` | Add monitor tab translations |
| `ui/frontend/src/lib/i18n/ru.json` | Add monitor tab translations |
| `config.example.yaml` | Add Hysteria2 + SSH tunnel examples |
| `go.mod` / `go.sum` | Add hysteria2 + ssh dependencies |

---

## Task 1: Protocol Constants & Dependencies

**Files:**
- Modify: `internal/core/config.go:39-45,355-362`
- Modify: `go.mod`

- [ ] **Step 1: Add protocol constants**

In `internal/core/config.go`, add to the constants block (after line 45):

```go
ProtocolHysteria2  = "hysteria2"
ProtocolSSH        = "ssh"
```

- [ ] **Step 2: Add to validProtocols map**

In `internal/core/config.go`, add to `validProtocols` map (after line 361):

```go
ProtocolHysteria2: true,
ProtocolSSH:       true,
```

- [ ] **Step 3: Add Go dependencies**

```bash
go get github.com/apernet/hysteria/core/v2@latest
go get golang.org/x/crypto/ssh@latest
```

- [ ] **Step 4: Verify build**

```bash
go build ./internal/core/...
```
Expected: SUCCESS

- [ ] **Step 5: Commit**

```bash
git add internal/core/config.go go.mod go.sum
git commit -m "feat: add Hysteria2 and SSH protocol constants + dependencies"
```

---

## Task 2: Hysteria2 Provider

**Files:**
- Create: `internal/provider/hysteria2/provider.go`

**Reference:** Study the actual hysteria2 client API before coding. Check `github.com/apernet/hysteria/core/v2` package exports. The API below is based on the spec but may need adjustment.

- [ ] **Step 1: Create provider file**

Create `internal/provider/hysteria2/provider.go`:

```go
package hysteria2

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"awg-split-tunnel/internal/core"
)

// Config holds Hysteria2 tunnel settings.
type Config struct {
	Server       string // server:port
	Password     string
	ObfsType     string // "" or "salamander"
	ObfsPassword string
	SNI          string
	Insecure     bool
	UpMbps       int
	DownMbps     int
}

// Provider implements provider.TunnelProvider and provider.EndpointProvider.
type Provider struct {
	mu       sync.RWMutex
	name     string
	config   Config
	state    core.TunnelState
	client   interface{} // hysteria2 client (typed after API verification)
	cancel   context.CancelFunc
	endpoint netip.AddrPort
}

// New creates a Hysteria2 provider.
func New(name string, cfg Config) (*Provider, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("[Hysteria2] server is required")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("[Hysteria2] password is required")
	}

	return &Provider{
		name:   name,
		config: cfg,
		state:  core.TunnelStateDown,
	}, nil
}

func (p *Provider) Name() string     { return p.name }
func (p *Provider) Protocol() string { return core.ProtocolHysteria2 }

func (p *Provider) State() core.TunnelState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

func (p *Provider) GetAdapterIP() netip.Addr {
	return netip.Addr{} // proxy-based, no adapter IP
}

func (p *Provider) GetServerEndpoints() []netip.AddrPort {
	p.mu.RLock()
	ep := p.endpoint
	p.mu.RUnlock()
	if ep.IsValid() {
		return []netip.AddrPort{ep}
	}
	return nil
}

// resolveEndpoint resolves server address to IP for bypass route (called during Connect).
func (p *Provider) resolveEndpoint() {
	host, port, err := net.SplitHostPort(p.config.Server)
	if err != nil {
		host = p.config.Server
		port = "443"
	}
	ips, _ := net.LookupIP(host)
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip.To4()); ok {
			portNum, _ := net.LookupPort("udp", port)
			p.endpoint = netip.AddrPortFrom(addr, uint16(portNum))
			return
		}
	}
}

func (p *Provider) Connect(ctx context.Context) error {
	p.mu.Lock()
	p.state = core.TunnelStateConnecting
	p.mu.Unlock()

	p.resolveEndpoint()

	core.Logger.Info("[Hysteria2] connecting to %s", p.config.Server)

	// TODO: Create hysteria2 client using the actual library API.
	// This requires verifying the exact API of github.com/apernet/hysteria/core/v2.
	//
	// Expected flow:
	// 1. Build TLS config (SNI, insecure)
	// 2. Build client config (server, auth, bandwidth, obfs)
	// 3. Call client constructor
	// 4. Store client reference
	//
	// Placeholder until API is verified:
	return fmt.Errorf("[Hysteria2] provider not yet implemented — verify library API first")
}

func (p *Provider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}

	// TODO: Close hysteria2 client.
	p.client = nil
	p.state = core.TunnelStateDown
	core.Logger.Info("[Hysteria2] disconnected")
	return nil
}

func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	client := p.client
	p.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("[Hysteria2] not connected")
	}

	// TODO: Call client.TCP(addr) or equivalent.
	return nil, fmt.Errorf("[Hysteria2] DialTCP not yet implemented")
}

func (p *Provider) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	client := p.client
	p.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("[Hysteria2] not connected")
	}

	// TODO: Call client.UDP() and wrap in net.Conn adapter.
	// The adapter needs to:
	// 1. Capture target addr from first Write
	// 2. Wrap ReadFrom/WriteTo into Read/Write
	// 3. Handle Close properly
	return nil, fmt.Errorf("[Hysteria2] DialUDP not yet implemented")
}
```

**Note:** The `Connect`, `DialTCP`, `DialUDP` methods have TODO placeholders. The implementer must:
1. Run `go doc github.com/apernet/hysteria/core/v2` to discover the actual API
2. Look at hysteria2 source code examples in the repo
3. Fill in the real client creation and dial methods
4. If the API is incompatible, fall back to subprocess approach

- [ ] **Step 2: Verify build**

```bash
go build ./internal/provider/hysteria2/...
```
Expected: SUCCESS (with TODOs)

- [ ] **Step 3: Commit**

```bash
git add internal/provider/hysteria2/
git commit -m "feat(hysteria2): add Hysteria2 provider skeleton with config + endpoints"
```

---

## Task 3: SSH Tunnel Provider

**Files:**
- Create: `internal/provider/ssh/provider.go`

- [ ] **Step 1: Create provider file**

Create `internal/provider/ssh/provider.go`:

```go
package ssh

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"

	gossh "golang.org/x/crypto/ssh"
)

// Config holds SSH tunnel settings.
type Config struct {
	Server               string
	Port                 int
	Username             string
	Password             string
	PrivateKeyPath       string
	PrivateKeyPassphrase string
	HostKey              string
	InsecureSkipHostKey  bool
	KeepaliveInterval    int // seconds
}

// Provider implements provider.TunnelProvider and provider.EndpointProvider.
type Provider struct {
	mu       sync.RWMutex
	name     string
	config   Config
	state    core.TunnelState
	client   *gossh.Client
	cancel   context.CancelFunc
	endpoint netip.AddrPort
}

// New creates an SSH tunnel provider.
func New(name string, cfg Config) (*Provider, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("[SSH] server is required")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("[SSH] username is required")
	}
	if cfg.Password == "" && cfg.PrivateKeyPath == "" {
		return nil, fmt.Errorf("[SSH] password or private_key_path is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.KeepaliveInterval == 0 {
		cfg.KeepaliveInterval = 30
	}
	if !cfg.InsecureSkipHostKey && cfg.HostKey == "" {
		return nil, fmt.Errorf("[SSH] host_key is required (or set insecure_skip_host_key: true)")
	}

	// Expand ~ in private key path.
	if cfg.PrivateKeyPath != "" && strings.HasPrefix(cfg.PrivateKeyPath, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			cfg.PrivateKeyPath = home + cfg.PrivateKeyPath[1:]
		}
	}

	return &Provider{
		name:   name,
		config: cfg,
		state:  core.TunnelStateDown,
	}, nil
}

func (p *Provider) Name() string     { return p.name }
func (p *Provider) Protocol() string { return core.ProtocolSSH }

func (p *Provider) State() core.TunnelState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

func (p *Provider) GetAdapterIP() netip.Addr {
	return netip.Addr{} // proxy-based
}

func (p *Provider) GetServerEndpoints() []netip.AddrPort {
	p.mu.RLock()
	ep := p.endpoint
	p.mu.RUnlock()
	if ep.IsValid() {
		return []netip.AddrPort{ep}
	}
	return nil
}

// resolveEndpoint resolves server address to IP for bypass route (called during Connect).
func (p *Provider) resolveEndpoint() {
	ips, _ := net.LookupIP(p.config.Server)
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip.To4()); ok {
			p.endpoint = netip.AddrPortFrom(addr, uint16(p.config.Port))
			return
		}
	}
}

// buildAuthMethods constructs SSH auth methods from config.
func (p *Provider) buildAuthMethods() ([]gossh.AuthMethod, error) {
	var methods []gossh.AuthMethod

	if p.config.Password != "" {
		methods = append(methods, gossh.Password(p.config.Password))
	}

	if p.config.PrivateKeyPath != "" {
		keyBytes, err := os.ReadFile(p.config.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("[SSH] read private key: %w", err)
		}
		var signer gossh.Signer
		if p.config.PrivateKeyPassphrase != "" {
			signer, err = gossh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(p.config.PrivateKeyPassphrase))
		} else {
			signer, err = gossh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("[SSH] parse private key: %w", err)
		}
		methods = append(methods, gossh.PublicKeys(signer))
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("[SSH] no auth method configured")
	}
	return methods, nil
}

// buildHostKeyCallback returns an SSH host key callback.
func (p *Provider) buildHostKeyCallback() (gossh.HostKeyCallback, error) {
	if p.config.HostKey != "" {
		pubKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(p.config.HostKey))
		if err != nil {
			return nil, fmt.Errorf("[SSH] parse host_key: %w", err)
		}
		return gossh.FixedHostKey(pubKey), nil
	}
	if p.config.InsecureSkipHostKey {
		core.Logger.Warn("[SSH] host key verification DISABLED — vulnerable to MITM attacks")
		return gossh.InsecureIgnoreHostKey(), nil
	}
	return nil, fmt.Errorf("[SSH] host_key is required")
}

func (p *Provider) Connect(ctx context.Context) error {
	p.mu.Lock()
	p.state = core.TunnelStateConnecting
	p.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", p.config.Server, p.config.Port)
	p.resolveEndpoint()

	core.Logger.Info("[SSH] connecting to %s@%s", p.config.Username, addr)

	authMethods, err := p.buildAuthMethods()
	if err != nil {
		p.mu.Lock()
		p.state = core.TunnelStateError
		p.mu.Unlock()
		return err
	}

	hostKeyCallback, err := p.buildHostKeyCallback()
	if err != nil {
		p.mu.Lock()
		p.state = core.TunnelStateError
		p.mu.Unlock()
		return err
	}

	sshConfig := &gossh.ClientConfig{
		User:            p.config.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}

	client, err := gossh.Dial("tcp", addr, sshConfig)
	if err != nil {
		p.mu.Lock()
		p.state = core.TunnelStateError
		p.mu.Unlock()
		return fmt.Errorf("[SSH] dial: %w", err)
	}

	connCtx, cancel := context.WithCancel(context.Background())

	p.mu.Lock()
	p.client = client
	p.cancel = cancel
	p.state = core.TunnelStateUp
	p.mu.Unlock()

	core.Logger.Info("[SSH] connected to %s", addr)

	// Start keepalive goroutine.
	go p.keepalive(connCtx, client)

	return nil
}

func (p *Provider) keepalive(ctx context.Context, client *gossh.Client) {
	interval := time.Duration(p.config.KeepaliveInterval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				core.Logger.Warn("[SSH] keepalive failed: %v", err)
				p.mu.Lock()
				p.state = core.TunnelStateError
				p.mu.Unlock()
				return
			}
		}
	}
}

func (p *Provider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}

	if p.client != nil {
		p.client.Close()
		p.client = nil
	}

	p.state = core.TunnelStateDown
	core.Logger.Info("[SSH] disconnected")
	return nil
}

func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	client := p.client
	p.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("[SSH] not connected")
	}

	conn, err := client.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("[SSH] dial %s: %w", addr, err)
	}
	return conn, nil
}

func (p *Provider) DialUDP(_ context.Context, _ string) (net.Conn, error) {
	return nil, fmt.Errorf("[SSH] UDP not supported")
}
```

- [ ] **Step 2: Verify build**

```bash
go build ./internal/provider/ssh/...
```
Expected: SUCCESS

- [ ] **Step 3: Commit**

```bash
git add internal/provider/ssh/
git commit -m "feat(ssh): add SSH tunnel provider with keepalive + host key verification"
```

---

## Task 4: Register Providers in Tunnel Controller

**Files:**
- Modify: `internal/service/tunnel_controller.go:696-698` (before default case)

- [ ] **Step 1: Add Hysteria2 case**

Add before the `default:` case in `CreateProvider()` (around line 696):

```go
case core.ProtocolHysteria2:
	hy2Cfg := hysteria2.Config{
		Server:       getStringSetting(cfg.Settings, "server", ""),
		Password:     getStringSetting(cfg.Settings, "password", ""),
		ObfsType:     getStringSetting(cfg.Settings, "obfs_type", ""),
		ObfsPassword: getStringSetting(cfg.Settings, "obfs_password", ""),
		SNI:          getStringSetting(cfg.Settings, "sni", ""),
		Insecure:     getBoolSetting(cfg.Settings, "insecure", false),
		UpMbps:       getIntSetting(cfg.Settings, "up_mbps", 0),
		DownMbps:     getIntSetting(cfg.Settings, "down_mbps", 0),
	}
	return hysteria2.New(cfg.Name, hy2Cfg)
```

- [ ] **Step 2: Add SSH case**

Add after the Hysteria2 case:

```go
case core.ProtocolSSH:
	sshCfg := ssh.Config{
		Server:               getStringSetting(cfg.Settings, "server", ""),
		Port:                 getIntSetting(cfg.Settings, "port", 22),
		Username:             getStringSetting(cfg.Settings, "username", ""),
		Password:             getStringSetting(cfg.Settings, "password", ""),
		PrivateKeyPath:       getStringSetting(cfg.Settings, "private_key_path", ""),
		PrivateKeyPassphrase: getStringSetting(cfg.Settings, "private_key_passphrase", ""),
		HostKey:              getStringSetting(cfg.Settings, "host_key", ""),
		InsecureSkipHostKey:  getBoolSetting(cfg.Settings, "insecure_skip_host_key", false),
		KeepaliveInterval:    getIntSetting(cfg.Settings, "keepalive_interval", 30),
	}
	return ssh.New(cfg.Name, sshCfg)
```

- [ ] **Step 3: Add imports**

Add to imports in `tunnel_controller.go`:

```go
"awg-split-tunnel/internal/provider/hysteria2"
"awg-split-tunnel/internal/provider/ssh"
```

- [ ] **Step 4: Verify build**

```bash
go build ./internal/service/...
```
Expected: SUCCESS

- [ ] **Step 5: Commit**

```bash
git add internal/service/tunnel_controller.go
git commit -m "feat: register Hysteria2 and SSH providers in CreateProvider"
```

---

## Task 5: Config Example

**Files:**
- Modify: `config.example.yaml`

- [ ] **Step 1: Add Hysteria2 example**

Add to `tunnels:` section in `config.example.yaml`:

```yaml
  # Hysteria2 — QUIC-based protocol with Brutal congestion control
  - id: hy2
    protocol: hysteria2
    name: "Hysteria2 Server"
    settings:
      server: "example.com:443"
      password: "my-password"
      # obfs_type: salamander         # optional: obfuscation type
      # obfs_password: "obfs-key"     # required if obfs_type is set
      # sni: "cover.example.com"      # optional: TLS SNI override
      # insecure: false               # optional: skip TLS verification
      # up_mbps: 100                  # optional: upload bandwidth hint for Brutal CC
      # down_mbps: 200                # optional: download bandwidth hint
```

- [ ] **Step 2: Add SSH example**

```yaml
  # SSH Tunnel — TCP forwarding over SSH (any VPS with OpenSSH)
  - id: ssh1
    protocol: ssh
    name: "SSH Server"
    settings:
      server: "example.com"
      port: 22
      username: "user"
      password: "pass"                          # auth option 1: password
      # private_key_path: "C:/Users/user/.ssh/id_ed25519"  # auth option 2: key file
      # private_key_passphrase: ""              # passphrase for encrypted key
      host_key: "ssh-ed25519 AAAA..."           # server host key (required by default)
      # insecure_skip_host_key: false           # DANGEROUS: skip host key verification
      # keepalive_interval: 30                  # keepalive interval in seconds
```

- [ ] **Step 3: Commit**

```bash
git add config.example.yaml
git commit -m "docs: add Hysteria2 and SSH tunnel examples to config"
```

---

## Task 6: Flow Table Snapshot Methods

**Files:**
- Modify: `internal/gateway/flow_table.go`

- [ ] **Step 1: Add snapshot structs**

Add after the existing entry structs (after `RawFlowEntry`, around line 96):

```go
// NATSnapshotEntry is a lightweight copy of a TCP NAT entry for monitoring.
type NATSnapshotEntry struct {
	SrcPort         uint16
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	ResolvedDstIP   netip.Addr
	TunnelID        string
	ExeLower        string
	BaseLower       string
	LastActivity    int64
	FinSeen         int32
}

// UDPSnapshotEntry is a lightweight copy of a UDP NAT entry for monitoring.
type UDPSnapshotEntry struct {
	SrcPort         uint16
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	ResolvedDstIP   netip.Addr
	TunnelID        string
	ExeLower        string
	BaseLower       string
	LastActivity    int64
}

// RawSnapshotEntry is a lightweight copy of a raw flow entry for monitoring.
type RawSnapshotEntry struct {
	Protocol     uint8
	DstIP        netip.Addr
	SrcPort      uint16
	TunnelID     string
	LastActivity int64
	FakeIP       netip.Addr
	RealDstIP    netip.Addr
}
```

- [ ] **Step 2: Add SnapshotNAT method**

Add to `FlowTable`:

```go
// SnapshotNAT returns copies of all active TCP NAT entries.
// Read-only operation under RLock — no hot-path impact.
func (ft *FlowTable) SnapshotNAT() []NATSnapshotEntry {
	var result []NATSnapshotEntry
	for i := range ft.tcp {
		s := &ft.tcp[i]
		s.mu.RLock()
		for _, idx := range s.index {
			if idx < 0 || int(idx) >= len(s.store) {
				continue
			}
			e := &s.store[idx]
			if e.TunnelID == "" {
				continue
			}
			result = append(result, NATSnapshotEntry{
				SrcPort:         e.ProxyPort,
				OriginalDstIP:   e.OriginalDstIP,
				OriginalDstPort: e.OriginalDstPort,
				ResolvedDstIP:   e.ResolvedDstIP,
				TunnelID:        e.TunnelID,
				ExeLower:        e.ExeLower,
				BaseLower:       e.BaseLower,
				LastActivity:    atomic.LoadInt64(&e.LastActivity),
				FinSeen:         atomic.LoadInt32(&e.FinSeen),
			})
		}
		s.mu.RUnlock()
	}
	return result
}
```

- [ ] **Step 3: Add SnapshotUDP method**

```go
// SnapshotUDP returns copies of all active UDP NAT entries.
func (ft *FlowTable) SnapshotUDP() []UDPSnapshotEntry {
	var result []UDPSnapshotEntry
	for i := range ft.udp {
		s := &ft.udp[i]
		s.mu.RLock()
		for _, idx := range s.index {
			if idx < 0 || int(idx) >= len(s.store) {
				continue
			}
			e := &s.store[idx]
			if e.TunnelID == "" {
				continue
			}
			result = append(result, UDPSnapshotEntry{
				SrcPort:         e.UDPProxyPort,
				OriginalDstIP:   e.OriginalDstIP,
				OriginalDstPort: e.OriginalDstPort,
				ResolvedDstIP:   e.ResolvedDstIP,
				TunnelID:        e.TunnelID,
				ExeLower:        e.ExeLower,
				BaseLower:       e.BaseLower,
				LastActivity:    atomic.LoadInt64(&e.LastActivity),
			})
		}
		s.mu.RUnlock()
	}
	return result
}
```

- [ ] **Step 4: Add SnapshotRaw method**

```go
// SnapshotRaw returns copies of all active raw flow entries.
// rawFlowKey is [7]byte: proto(1) + dstIP(4) + srcPort(2 big-endian).
// Protocol/DstIP/SrcPort are in the KEY, not in RawFlowEntry fields.
func (ft *FlowTable) SnapshotRaw() []RawSnapshotEntry {
	var result []RawSnapshotEntry
	for i := range ft.raw {
		s := &ft.raw[i]
		s.mu.RLock()
		for k, idx := range s.index {
			if idx < 0 || int(idx) >= len(s.store) {
				continue
			}
			e := &s.store[idx]
			if e.TunnelID == "" {
				continue
			}
			// Decompose rawFlowKey [7]byte: proto(1) + dstIP(4) + srcPort(2).
			proto := k[0]
			var dstIP4 [4]byte
			copy(dstIP4[:], k[1:5])
			srcPort := uint16(k[5])<<8 | uint16(k[6])

			var fakeIP, realDstIP netip.Addr
			if e.FakeIP != [4]byte{} {
				fakeIP = netip.AddrFrom4(e.FakeIP)
			}
			if e.RealDstIP != [4]byte{} {
				realDstIP = netip.AddrFrom4(e.RealDstIP)
			}
			result = append(result, RawSnapshotEntry{
				Protocol:     proto,
				DstIP:        netip.AddrFrom4(dstIP4),
				SrcPort:      srcPort,
				TunnelID:     e.TunnelID,
				LastActivity: atomic.LoadInt64(&e.LastActivity),
				FakeIP:       fakeIP,
				RealDstIP:    realDstIP,
			})
		}
		s.mu.RUnlock()
	}
	return result
}
```

- [ ] **Step 5: Verify build**

```bash
go build ./internal/gateway/...
```
Expected: SUCCESS

- [ ] **Step 6: Commit**

```bash
git add internal/gateway/flow_table.go
git commit -m "feat(flow_table): add SnapshotNAT/SnapshotUDP/SnapshotRaw for connection monitor"
```

---

## Task 7: Domain Table ReverseLookup

**Files:**
- Modify: `internal/gateway/domain_table.go`

- [ ] **Step 1: Add ReverseLookup method**

```go
// ReverseLookup returns the domain name associated with the given IP address.
// Returns empty string if not found or if the IP is IPv6 (domain table is IPv4-only).
func (dt *DomainTable) ReverseLookup(ip netip.Addr) string {
	if !ip.Is4() {
		return ""
	}
	ip4 := ip.As4()
	dt.mu.RLock()
	entry, ok := dt.entries[ip4]
	dt.mu.RUnlock()
	if ok {
		return entry.Domain
	}
	return ""
}
```

**Note:** Verify that `dt.entries` is keyed by `[4]byte` and `DomainEntry` has a `Domain string` field. Adjust field names if needed.

- [ ] **Step 2: Verify build**

```bash
go build ./internal/gateway/...
```

- [ ] **Step 3: Commit**

```bash
git add internal/gateway/domain_table.go
git commit -m "feat(domain_table): add ReverseLookup for connection monitor"
```

---

## Task 8: Proto Definition + Code Generation

**Files:**
- Modify: `api/proto/vpn_service.proto`
- Regenerate: `api/gen/vpn_service.pb.go`, `api/gen/vpn_service_grpc.pb.go`

- [ ] **Step 1: Add message definitions**

Add before the `service VPNService` block (before line 500):

```protobuf
// Connection Monitor
message ConnectionEntry {
  string process_name = 1;
  string process_path = 2;
  string protocol = 3;
  string dst_ip = 4;
  uint32 dst_port = 5;
  string domain = 6;
  string tunnel_id = 7;
  string state = 8;
  string country = 9;
  int64 last_activity = 10;
}

message ConnectionMonitorRequest {
  string tunnel_filter = 1;
  string process_filter = 2;
}

message ConnectionSnapshot {
  repeated ConnectionEntry connections = 1;
}
```

- [ ] **Step 2: Add StreamConnections RPC**

Add inside `service VPNService` block (after StreamStats, around line 538):

```protobuf
rpc StreamConnections(ConnectionMonitorRequest) returns (stream ConnectionSnapshot);
```

- [ ] **Step 3: Regenerate Go code**

```bash
protoc --proto_path=api/proto --go_out=api/gen --go_opt=paths=source_relative --go-grpc_out=api/gen --go-grpc_opt=paths=source_relative api/proto/vpn_service.proto
```

- [ ] **Step 4: Verify build**

```bash
go build ./api/gen/...
```

- [ ] **Step 5: Commit**

```bash
git add api/proto/vpn_service.proto api/gen/
git commit -m "feat(proto): add ConnectionEntry and StreamConnections RPC for connection monitor"
```

---

## Task 9: Connection Monitor Backend

**Files:**
- Create: `internal/service/connection_monitor.go`

- [ ] **Step 1: Create connection monitor**

Create `internal/service/connection_monitor.go`:

```go
package service

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/gateway"
)

const (
	connectionSnapshotInterval = 2 * time.Second
	maxSnapshotEntries         = 2000
)

// ConnectionMonitor periodically snapshots active flows and publishes them.
type ConnectionMonitor struct {
	flows       *gateway.FlowTable
	domainTable *gateway.DomainTable
	geoIP       *gateway.GeoIPResolver

	mu          sync.Mutex
	subscribers map[chan *vpnapi.ConnectionSnapshot]struct{}
}

// NewConnectionMonitor creates a connection monitor.
func NewConnectionMonitor(flows *gateway.FlowTable, domainTable *gateway.DomainTable, geoIP *gateway.GeoIPResolver) *ConnectionMonitor {
	return &ConnectionMonitor{
		flows:       flows,
		domainTable: domainTable,
		geoIP:       geoIP,
		subscribers: make(map[chan *vpnapi.ConnectionSnapshot]struct{}),
	}
}

// Subscribe returns a channel that receives connection snapshots.
func (cm *ConnectionMonitor) Subscribe() chan *vpnapi.ConnectionSnapshot {
	ch := make(chan *vpnapi.ConnectionSnapshot, 4)
	cm.mu.Lock()
	cm.subscribers[ch] = struct{}{}
	cm.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel.
func (cm *ConnectionMonitor) Unsubscribe(ch chan *vpnapi.ConnectionSnapshot) {
	cm.mu.Lock()
	delete(cm.subscribers, ch)
	cm.mu.Unlock()
	close(ch)
}

// Start begins periodic snapshot collection. Only ticks when subscribers exist.
func (cm *ConnectionMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(connectionSnapshotInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cm.mu.Lock()
			n := len(cm.subscribers)
			cm.mu.Unlock()
			if n == 0 {
				continue
			}
			snap := cm.buildSnapshot()
			cm.publish(snap)
		}
	}
}

func (cm *ConnectionMonitor) buildSnapshot() *vpnapi.ConnectionSnapshot {
	var entries []*vpnapi.ConnectionEntry

	// TCP NAT entries.
	for _, e := range cm.flows.SnapshotNAT() {
		dstIP := e.OriginalDstIP
		if e.ResolvedDstIP.IsValid() {
			dstIP = e.ResolvedDstIP
		}
		state := "active"
		if e.FinSeen != 0 {
			state = "fin"
		}
		entry := &vpnapi.ConnectionEntry{
			ProcessName:  e.BaseLower,
			ProcessPath:  e.ExeLower,
			Protocol:     "TCP",
			DstIp:        dstIP.String(),
			DstPort:      uint32(e.OriginalDstPort),
			TunnelId:     e.TunnelID,
			State:        state,
			LastActivity: e.LastActivity,
		}
		cm.enrichEntry(entry, e.OriginalDstIP, dstIP)
		entries = append(entries, entry)
	}

	// UDP NAT entries.
	for _, e := range cm.flows.SnapshotUDP() {
		dstIP := e.OriginalDstIP
		if e.ResolvedDstIP.IsValid() {
			dstIP = e.ResolvedDstIP
		}
		entry := &vpnapi.ConnectionEntry{
			ProcessName:  e.BaseLower,
			ProcessPath:  e.ExeLower,
			Protocol:     "UDP",
			DstIp:        dstIP.String(),
			DstPort:      uint32(e.OriginalDstPort),
			TunnelId:     e.TunnelID,
			State:        "active",
			LastActivity: e.LastActivity,
		}
		cm.enrichEntry(entry, e.OriginalDstIP, dstIP)
		entries = append(entries, entry)
	}

	// Raw flow entries (no process info — protocol/dstIP/srcPort from key).
	for _, e := range cm.flows.SnapshotRaw() {
		dstIP := e.DstIP
		if e.RealDstIP.IsValid() {
			dstIP = e.RealDstIP
		}
		protoStr := "IP"
		switch e.Protocol {
		case 6:
			protoStr = "TCP"
		case 17:
			protoStr = "UDP"
		}
		entry := &vpnapi.ConnectionEntry{
			Protocol:     protoStr,
			DstIp:        dstIP.String(),
			DstPort:      0, // raw flows don't track destination port
			TunnelId:     e.TunnelID,
			State:        "active",
			LastActivity: e.LastActivity,
		}
		cm.enrichEntry(entry, e.DstIP, dstIP)
		entries = append(entries, entry)
	}

	// Sort by LastActivity descending, limit to maxSnapshotEntries.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LastActivity > entries[j].LastActivity
	})
	if len(entries) > maxSnapshotEntries {
		entries = entries[:maxSnapshotEntries]
	}

	return &vpnapi.ConnectionSnapshot{Connections: entries}
}

// enrichEntry adds domain and country info to a connection entry.
func (cm *ConnectionMonitor) enrichEntry(entry *vpnapi.ConnectionEntry, originalIP, resolvedIP netip.Addr) {
	// Domain reverse lookup — try original IP first (may be FakeIP with domain mapping).
	if cm.domainTable != nil {
		if domain := cm.domainTable.ReverseLookup(originalIP); domain != "" {
			entry.Domain = domain
		}
	}
	// GeoIP country lookup on resolved IP.
	if cm.geoIP != nil && resolvedIP.IsValid() {
		entry.Country = cm.geoIP.Lookup(resolvedIP)
	}
}

func (cm *ConnectionMonitor) publish(snap *vpnapi.ConnectionSnapshot) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for ch := range cm.subscribers {
		select {
		case ch <- snap:
		default:
			// Drop if subscriber is slow.
		}
	}
}
```

**Note:** The `enrichEntry` method has placeholder logic for domain/GeoIP lookups. The implementer must:
1. Verify `DomainTable.ReverseLookup` accepts `netip.Addr` (from Task 7)
2. Verify `GeoIPMatcher` method name for country lookup (check `gateway/geoip.go`)
3. Fill in proper type handling for both lookups

- [ ] **Step 2: Verify build**

```bash
go build ./internal/service/...
```

- [ ] **Step 3: Commit**

```bash
git add internal/service/connection_monitor.go
git commit -m "feat(service): add ConnectionMonitor with snapshot collection + pub/sub"
```

---

## Task 10: gRPC Handler for StreamConnections

**Files:**
- Create: `internal/service/grpc_handler_connections.go`

- [ ] **Step 1: Create handler file**

Create `internal/service/grpc_handler_connections.go`:

```go
package service

import (
	"fmt"
	"strings"

	vpnapi "awg-split-tunnel/api/gen"
)

// StreamConnections streams active connection snapshots to the client.
func (s *Service) StreamConnections(req *vpnapi.ConnectionMonitorRequest, stream vpnapi.VPNService_StreamConnectionsServer) error {
	if s.connMonitor == nil {
		return fmt.Errorf("connection monitor not initialized")
	}

	ch := s.connMonitor.Subscribe()
	defer s.connMonitor.Unsubscribe(ch)

	tunnelFilter := strings.ToLower(req.GetTunnelFilter())
	processFilter := strings.ToLower(req.GetProcessFilter())

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case snap, ok := <-ch:
			if !ok {
				return nil
			}
			// Apply server-side filtering.
			if tunnelFilter != "" || processFilter != "" {
				filtered := make([]*vpnapi.ConnectionEntry, 0, len(snap.Connections))
				for _, e := range snap.Connections {
					if tunnelFilter != "" && !strings.Contains(strings.ToLower(e.TunnelId), tunnelFilter) {
						continue
					}
					if processFilter != "" && !strings.Contains(strings.ToLower(e.ProcessName), processFilter) {
						continue
					}
					filtered = append(filtered, e)
				}
				snap = &vpnapi.ConnectionSnapshot{Connections: filtered}
			}
			if err := stream.Send(snap); err != nil {
				return err
			}
		}
	}
}
```

- [ ] **Step 2: Add connMonitor field to Service**

In `internal/service/service.go`, add field to `Service` struct:

```go
connMonitor *ConnectionMonitor
```

- [ ] **Step 3: Verify build**

```bash
go build ./internal/service/...
```

- [ ] **Step 4: Commit**

```bash
git add internal/service/grpc_handler_connections.go internal/service/service.go
git commit -m "feat(grpc): add StreamConnections handler with server-side filtering"
```

---

## Task 11: Wire Connection Monitor in Main

**Files:**
- Modify: `cmd/awg-split-tunnel/main.go` (or wherever Service is constructed)

- [ ] **Step 1: Add ConnMonitor to Service.Config**

In `internal/service/service.go`, add to the `Config` struct:

```go
ConnMonitor *ConnectionMonitor
```

And in the `New()` function, store it:

```go
s.connMonitor = cfg.ConnMonitor
```

- [ ] **Step 2: Create and wire ConnectionMonitor in main.go**

In `cmd/awg-split-tunnel/main.go`, in the `runVPN` function, after `domainTable` is created (around line 735) and `geoIPResolver` is available, add:

```go
connMon := service.NewConnectionMonitor(flows, domainTable, geoIPResolver)
go connMon.Start(ctx)
```

Then pass it to `service.New()` in the `service.Config{}` struct (around line 838):

```go
ConnMonitor: connMon,
```

The `flows` variable is the `FlowTable` created at line 301, `domainTable` at line 735, and `geoIPResolver` should be the existing GeoIPResolver instance (verify the variable name in main.go).

- [ ] **Step 3: Verify build**

```bash
go build ./cmd/awg-split-tunnel/...
```

- [ ] **Step 4: Commit**

```bash
git add cmd/awg-split-tunnel/main.go internal/service/service.go
git commit -m "feat: wire ConnectionMonitor into main application lifecycle"
```

---

## Task 12: Wails Binding for Connection Monitor Stream

**Files:**
- Modify: `ui/binding_streaming.go`

- [ ] **Step 1: Add StartConnectionMonitorStream method**

Add to `binding_streaming.go`, following the pattern of `StartStatsStream`/`runStatsStream`:

```go
// StartConnectionMonitorStream starts streaming connection snapshots to the frontend.
func (b *BindingService) StartConnectionMonitorStream() {
	b.connMonOnce.Do(func() {
		go b.runConnectionMonitorStream()
	})
}

func (b *BindingService) runConnectionMonitorStream() {
	for {
		if b.client == nil {
			time.Sleep(time.Second)
			continue
		}
		stream, err := b.client.Service.StreamConnections(context.Background(), &vpnapi.ConnectionMonitorRequest{})
		if err != nil {
			core.Logger.Warn("[Binding] connection monitor stream error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		for {
			snap, err := stream.Recv()
			if err != nil {
				core.Logger.Warn("[Binding] connection monitor stream recv error: %v", err)
				break
			}
			// Skip if window is hidden.
			if !b.windowVisible.Load() {
				continue
			}
			// Convert to JSON-friendly format.
			connections := make([]map[string]interface{}, 0, len(snap.Connections))
			for _, c := range snap.Connections {
				connections = append(connections, map[string]interface{}{
					"processName":  c.ProcessName,
					"processPath":  c.ProcessPath,
					"protocol":     c.Protocol,
					"dstIp":        c.DstIp,
					"dstPort":      c.DstPort,
					"domain":       c.Domain,
					"tunnelId":     c.TunnelId,
					"state":        c.State,
					"country":      c.Country,
					"lastActivity": c.LastActivity,
				})
			}
			app := application.Get()
			app.Event.Emit("connection-snapshot", connections)
		}
	}
}
```

- [ ] **Step 2: Add sync.Once field**

Add to `BindingService` struct:

```go
connMonOnce sync.Once
```

- [ ] **Step 3: Verify build**

```bash
go build ./ui/...
```

- [ ] **Step 4: Commit**

```bash
git add ui/binding_streaming.go
git commit -m "feat(ui): add connection monitor Wails binding with window visibility check"
```

---

## Task 13: Frontend — Connection Store

**Files:**
- Create: `ui/frontend/src/lib/stores/connections.js`

- [ ] **Step 1: Create connections store**

```javascript
import { writable } from 'svelte/store';

/** @type {import('svelte/store').Writable<Array>} */
export const connections = writable([]);

/** @type {import('svelte/store').Writable<boolean>} */
export const paused = writable(false);

let isPaused = false;
paused.subscribe(v => isPaused = v);

/**
 * Initialize connection monitor stream.
 * Call once from ConnectionMonitorTab on mount.
 */
export function initConnectionStream() {
    // Start backend stream.
    if (window.wails?.Call) {
        window.wails.Call.ByName("main.BindingService.StartConnectionMonitorStream");
    }

    // Listen for snapshot events.
    if (window.wails?.Events) {
        window.wails.Events.On("connection-snapshot", (data) => {
            if (!isPaused) {
                connections.set(data);
            }
        });
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add ui/frontend/src/lib/stores/connections.js
git commit -m "feat(ui): add connections Svelte store with pause support"
```

---

## Task 14: Frontend — Connection Monitor Tab

**Files:**
- Create: `ui/frontend/src/lib/tabs/ConnectionMonitorTab.svelte`

- [ ] **Step 1: Create tab component**

Create `ui/frontend/src/lib/tabs/ConnectionMonitorTab.svelte`:

```svelte
<script>
    import { onMount } from 'svelte';
    import { connections, paused, initConnectionStream } from '../stores/connections.js';
    import { t } from '../i18n/index.js';

    let processFilter = '';
    let tunnelFilter = '';
    let sortKey = 'lastActivity';
    let sortAsc = false;

    onMount(() => {
        initConnectionStream();
    });

    $: filteredConnections = ($connections || [])
        .filter(c => {
            if (processFilter && !c.processName?.toLowerCase().includes(processFilter.toLowerCase())) return false;
            if (tunnelFilter && c.tunnelId !== tunnelFilter) return false;
            return true;
        })
        .sort((a, b) => {
            let va = a[sortKey], vb = b[sortKey];
            if (typeof va === 'string') va = va.toLowerCase();
            if (typeof vb === 'string') vb = vb.toLowerCase();
            if (va < vb) return sortAsc ? -1 : 1;
            if (va > vb) return sortAsc ? 1 : -1;
            return 0;
        });

    $: tunnelIds = [...new Set(($connections || []).map(c => c.tunnelId).filter(Boolean))].sort();

    function toggleSort(key) {
        if (sortKey === key) {
            sortAsc = !sortAsc;
        } else {
            sortKey = key;
            sortAsc = true;
        }
    }

    function formatTime(unix) {
        if (!unix) return '';
        const d = new Date(unix * 1000);
        return d.toLocaleTimeString();
    }

    function sortIndicator(key) {
        if (sortKey !== key) return '';
        return sortAsc ? ' ▲' : ' ▼';
    }
</script>

<div class="flex flex-col h-full">
    <!-- Filters -->
    <div class="flex items-center gap-3 p-3 border-b border-white/10">
        <input
            type="text"
            bind:value={processFilter}
            placeholder={$t('monitor.filterProcess')}
            class="bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white placeholder-white/30 w-48 focus:outline-none focus:border-white/30"
        />
        <select
            bind:value={tunnelFilter}
            class="bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white w-40 focus:outline-none focus:border-white/30"
        >
            <option value="">{$t('monitor.allTunnels')}</option>
            {#each tunnelIds as tid}
                <option value={tid}>{tid}</option>
            {/each}
        </select>
        <button
            on:click={() => $paused = !$paused}
            class="ml-auto px-3 py-1.5 rounded text-sm {$paused ? 'bg-yellow-600/30 text-yellow-300' : 'bg-white/5 text-white/60'} hover:bg-white/10 transition-colors"
        >
            {$paused ? '▶ ' + $t('monitor.resume') : '⏸ ' + $t('monitor.pause')}
        </button>
        <span class="text-xs text-white/40">{filteredConnections.length} {$t('monitor.connections')}</span>
    </div>

    <!-- Table -->
    <div class="flex-1 overflow-auto">
        <table class="w-full text-sm">
            <thead class="sticky top-0 bg-[#1a1a2e] z-10">
                <tr class="text-white/50 text-xs uppercase tracking-wider">
                    <th class="px-3 py-2 text-left cursor-pointer hover:text-white/80" on:click={() => toggleSort('processName')}>
                        {$t('monitor.process')}{sortIndicator('processName')}
                    </th>
                    <th class="px-3 py-2 text-left cursor-pointer hover:text-white/80" on:click={() => toggleSort('protocol')}>
                        {$t('monitor.proto')}{sortIndicator('protocol')}
                    </th>
                    <th class="px-3 py-2 text-left cursor-pointer hover:text-white/80" on:click={() => toggleSort('dstIp')}>
                        {$t('monitor.destination')}{sortIndicator('dstIp')}
                    </th>
                    <th class="px-3 py-2 text-left cursor-pointer hover:text-white/80" on:click={() => toggleSort('domain')}>
                        {$t('monitor.domain')}{sortIndicator('domain')}
                    </th>
                    <th class="px-3 py-2 text-left cursor-pointer hover:text-white/80" on:click={() => toggleSort('tunnelId')}>
                        {$t('monitor.tunnel')}{sortIndicator('tunnelId')}
                    </th>
                    <th class="px-3 py-2 text-center cursor-pointer hover:text-white/80" on:click={() => toggleSort('country')}>
                        {$t('monitor.country')}{sortIndicator('country')}
                    </th>
                    <th class="px-3 py-2 text-center cursor-pointer hover:text-white/80" on:click={() => toggleSort('state')}>
                        {$t('monitor.state')}{sortIndicator('state')}
                    </th>
                    <th class="px-3 py-2 text-right cursor-pointer hover:text-white/80" on:click={() => toggleSort('lastActivity')}>
                        {$t('monitor.lastSeen')}{sortIndicator('lastActivity')}
                    </th>
                </tr>
            </thead>
            <tbody>
                {#each filteredConnections as conn (conn.dstIp + ':' + conn.dstPort + ':' + conn.protocol + ':' + conn.processName)}
                    <tr class="border-b border-white/5 hover:bg-white/5 transition-colors">
                        <td class="px-3 py-1.5 text-white/80 truncate max-w-[200px]" title={conn.processPath || conn.processName}>
                            {conn.processName || '—'}
                        </td>
                        <td class="px-3 py-1.5">
                            <span class="px-1.5 py-0.5 rounded text-xs {conn.protocol === 'TCP' ? 'bg-blue-500/20 text-blue-300' : conn.protocol === 'UDP' ? 'bg-green-500/20 text-green-300' : 'bg-gray-500/20 text-gray-300'}">
                                {conn.protocol}
                            </span>
                        </td>
                        <td class="px-3 py-1.5 text-white/60 font-mono text-xs">
                            {conn.dstIp}:{conn.dstPort}
                        </td>
                        <td class="px-3 py-1.5 text-white/70 truncate max-w-[180px]" title={conn.domain}>
                            {conn.domain || '—'}
                        </td>
                        <td class="px-3 py-1.5">
                            <span class="px-1.5 py-0.5 rounded text-xs bg-purple-500/20 text-purple-300">
                                {conn.tunnelId}
                            </span>
                        </td>
                        <td class="px-3 py-1.5 text-center text-xs text-white/60">
                            {conn.country || '—'}
                        </td>
                        <td class="px-3 py-1.5 text-center">
                            <span class="inline-block w-2 h-2 rounded-full {conn.state === 'active' ? 'bg-green-400' : 'bg-gray-500'}"></span>
                        </td>
                        <td class="px-3 py-1.5 text-right text-xs text-white/40">
                            {formatTime(conn.lastActivity)}
                        </td>
                    </tr>
                {/each}
                {#if filteredConnections.length === 0}
                    <tr>
                        <td colspan="8" class="px-3 py-8 text-center text-white/30">
                            {$t('monitor.noConnections')}
                        </td>
                    </tr>
                {/if}
            </tbody>
        </table>
    </div>
</div>
```

- [ ] **Step 2: Commit**

```bash
git add ui/frontend/src/lib/tabs/ConnectionMonitorTab.svelte
git commit -m "feat(ui): add ConnectionMonitorTab with filtering, sorting, and live updates"
```

---

## Task 15: Register Tab in App.svelte + i18n

**Files:**
- Modify: `ui/frontend/src/App.svelte:20-28,133-147`
- Modify: `ui/frontend/src/lib/i18n/en.json`
- Modify: `ui/frontend/src/lib/i18n/ru.json`

- [ ] **Step 1: Add tab definition**

In `App.svelte`, add to `tabDefs` array (after `logs` entry, before `about`):

```javascript
{ id: 'monitor', key: 'tabs.monitor', icon: 'M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z' },
```

- [ ] **Step 2: Add conditional render**

In the tab content section (around line 145), add before the `about` block:

```svelte
{:else if activeTab === 'monitor'}
    <ConnectionMonitorTab />
```

- [ ] **Step 3: Add import**

At the top of `App.svelte`:

```javascript
import ConnectionMonitorTab from './lib/tabs/ConnectionMonitorTab.svelte';
```

- [ ] **Step 4: Add i18n keys to en.json**

```json
"monitor": {
    "filterProcess": "Filter by process...",
    "allTunnels": "All tunnels",
    "pause": "Pause",
    "resume": "Resume",
    "connections": "connections",
    "process": "Process",
    "proto": "Proto",
    "destination": "Destination",
    "domain": "Domain",
    "tunnel": "Tunnel",
    "country": "Country",
    "state": "State",
    "lastSeen": "Last Seen",
    "noConnections": "No active connections"
}
```

And add to `tabs` section:

```json
"monitor": "Monitor"
```

- [ ] **Step 5: Add i18n keys to ru.json**

```json
"monitor": {
    "filterProcess": "Фильтр по процессу...",
    "allTunnels": "Все туннели",
    "pause": "Пауза",
    "resume": "Продолжить",
    "connections": "соединений",
    "process": "Процесс",
    "proto": "Прото",
    "destination": "Назначение",
    "domain": "Домен",
    "tunnel": "Туннель",
    "country": "Страна",
    "state": "Статус",
    "lastSeen": "Посл. активность",
    "noConnections": "Нет активных соединений"
}
```

And add to `tabs` section:

```json
"monitor": "Монитор"
```

- [ ] **Step 6: Verify frontend build**

```bash
cd ui/frontend && npm run build
```

- [ ] **Step 7: Commit**

```bash
git add ui/frontend/src/App.svelte ui/frontend/src/lib/i18n/en.json ui/frontend/src/lib/i18n/ru.json
git commit -m "feat(ui): register ConnectionMonitor tab with i18n support"
```

---

## Task 16: Integration Verification

- [ ] **Step 1: Full Go build**

```bash
go build ./...
```
Expected: SUCCESS

- [ ] **Step 2: Frontend build**

```bash
cd ui/frontend && npm run build
```
Expected: SUCCESS

- [ ] **Step 3: Verify no regressions**

Run any existing tests:

```bash
go test ./internal/core/... ./internal/gateway/... ./internal/service/...
```

- [ ] **Step 4: Manual smoke test**

1. Start the application
2. Verify new `Monitor` tab appears in GUI
3. Add an SSH or SOCKS5 tunnel, connect
4. Open Monitor tab — verify connections appear
5. Test process filter, tunnel filter, pause button
6. Test column sorting

- [ ] **Step 5: Final commit if any fixes needed**

```bash
git add -A
git commit -m "fix: integration fixes for Hysteria2/SSH/ConnectionMonitor"
```

---

## Implementation Notes

### Hysteria2 API Verification
The Hysteria2 provider (Task 2) has TODO placeholders. Before filling them in:
1. Check `go doc github.com/apernet/hysteria/core/v2` after `go get`
2. Look at example code in the hysteria repo
3. If the library API doesn't support embedded use, implement a subprocess wrapper instead

### Verified Field Names
The following field names have been verified against the actual codebase:
- FlowTable shard fields: `ft.tcp`, `ft.udp`, `ft.raw`
- Shard internals: `mu` (sync.RWMutex), `index` (map), `store` (slice), `free` (slice)
- rawFlowKey: `[7]byte` — proto(1) + dstIP(4) + srcPort(2 big-endian)
- RawFlowEntry: `TunnelID`, `VpnIP`, `FakeIP`, `RealDstIP`, `LastActivity`, `Priority`, `IsAuto`
- DomainEntry: `TunnelID`, `Action`, `Domain`, `ExpiresAt`
- GeoIP: use `GeoIPResolver.Lookup(netip.Addr) string` for country codes (NOT GeoIPMatcher)
- Wails events: `app := application.Get(); app.Event.Emit("name", data)`
- Window visibility: `b.windowVisible.Load()` (atomic.Bool)
