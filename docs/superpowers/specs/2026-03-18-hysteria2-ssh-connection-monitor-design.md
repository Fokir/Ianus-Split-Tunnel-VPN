# Design: Hysteria2, SSH Tunnel, Connection Monitor

**Date:** 2026-03-18
**Status:** Approved

## Overview

Three features for AWG Split Tunnel:
1. **Hysteria2** — QUIC-based VPN protocol with Brutal congestion control
2. **SSH Tunnel** — TCP forwarding over SSH (any VPS with OpenSSH = ready server)
3. **Connection Monitor** — real-time active connections tab in GUI

All three follow existing architectural patterns: proxy-based TunnelProvider for protocols, streaming gRPC + Wails binding + Svelte tab for the monitor.

---

## 1. Hysteria2 Provider

### Architecture
- **Type:** Proxy-based provider (like SOCKS5/VLESS). No RawForwarder.
- **Interfaces:** `TunnelProvider` + `EndpointProvider`
- **Library:** `github.com/apernet/hysteria/core/v2` — Go Hysteria2 client. QUIC transport (quic-go) with Brutal congestion control.

### Config
```yaml
tunnels:
  - id: hy2
    protocol: hysteria2
    name: "Hysteria2 Server"
    settings:
      server: "example.com:443"
      password: "my-password"
      obfs_type: salamander       # none / salamander
      obfs_password: "obfs-pw"
      sni: "cover.example.com"    # TLS SNI
      insecure: false             # skip TLS verify
      up_mbps: 100                # upload bandwidth hint (Brutal CC)
      down_mbps: 200              # download bandwidth hint
```

### Files
```
internal/provider/hysteria2/
  provider.go    # Provider struct, Connect/Disconnect/DialTCP/DialUDP
```

### Implementation Details
- **Protocol constant:** `ProtocolHysteria2 = "hysteria2"` in `core/config.go`
- **Connect():** Creates QUIC connection via `hysteria2.NewClient(clientConfig)`. Client config includes server address, TLS config (SNI, insecure), auth (password), bandwidth hints, and optional obfuscation.
- **DialTCP():** `client.TCP(addr)` returns `net.Conn` — proxied TCP connection through QUIC tunnel.
- **DialUDP():** `client.UDP()` returns `HyUDPConn`. Needs `net.Conn`-compatible adapter wrapping `HyUDPConn.ReadFrom`/`WriteTo` into `Read`/`Write` with connected-UDP semantics.
- **Disconnect():** `client.Close()` — graceful QUIC teardown.
- **GetServerEndpoints():** Returns parsed server address for bypass route creation.
- **Bandwidth hints:** Passed to server for Brutal CC — this is what gives speed advantage on lossy networks. If not set, server uses default (may throttle).
- **Obfuscation:** Salamander mode XORs QUIC packets with a key, making them undetectable as QUIC by DPI.

### Registration
In `tunnel_controller.go` `CreateProvider()`:
```go
case core.ProtocolHysteria2:
    cfg := hysteria2.Config{
        Server:       getStringSetting(s, "server", ""),
        Password:     getStringSetting(s, "password", ""),
        ObfsType:     getStringSetting(s, "obfs_type", ""),
        ObfsPassword: getStringSetting(s, "obfs_password", ""),
        SNI:          getStringSetting(s, "sni", ""),
        Insecure:     getBoolSetting(s, "insecure", false),
        UpMbps:       getIntSetting(s, "up_mbps", 0),
        DownMbps:     getIntSetting(s, "down_mbps", 0),
    }
    return hysteria2.New(name, cfg)
```

---

## 2. SSH Tunnel Provider

### Architecture
- **Type:** Proxy-based provider. TCP only — SSH does not support native UDP forwarding.
- **Interfaces:** `TunnelProvider` + `EndpointProvider`
- **Library:** `golang.org/x/crypto/ssh` — standard Go SSH library.

### Config
```yaml
tunnels:
  - id: ssh1
    protocol: ssh
    name: "SSH Server"
    settings:
      server: "example.com"
      port: 22
      username: "user"
      password: "pass"                    # auth option 1
      private_key_path: "~/.ssh/id_ed25519"  # auth option 2
      private_key_passphrase: ""          # if key is encrypted
      host_key: "ssh-ed25519 AAAA..."     # known host (empty = accept any)
      keepalive_interval: 30              # seconds, default 30
```

### Files
```
internal/provider/ssh/
  provider.go    # Provider struct, Connect/Disconnect/DialTCP/DialUDP
```

### Implementation Details
- **Protocol constant:** `ProtocolSSH = "ssh"` in `core/config.go`
- **Connect():** `ssh.Dial("tcp", addr, clientConfig)`. Auth methods: password (`ssh.Password`) and/or publickey (`ssh.PublicKeys` from parsed private key file). Host key callback uses `host_key` setting if provided, otherwise `ssh.InsecureIgnoreHostKey()` with a log warning.
- **DialTCP():** `client.Dial("tcp", addr)` — SSH channel-based TCP forwarding (equivalent to `ssh -L`).
- **DialUDP():** Returns `ErrUDPNotSupported` (same pattern as HTTP Proxy provider).
- **Keepalive:** Background goroutine sends `client.SendRequest("keepalive@openssh.com", true, nil)` every N seconds. If keepalive fails, marks state as Error and triggers reconnect.
- **State management:** `sync.RWMutex`-protected state. Transitions: Down → Connecting → Up → Error/Down.
- **GetServerEndpoints():** Returns server:port for bypass route.

### UDP Limitation
DNS queries for processes bound to SSH tunnel will use DNS-over-TCP fallback, which is already implemented in `dns_resolver.go`. This is acceptable — SSH tunnels are typically used for web browsing where TCP DNS has negligible impact.

### Registration
In `tunnel_controller.go` `CreateProvider()`:
```go
case core.ProtocolSSH:
    cfg := ssh.Config{
        Server:               getStringSetting(s, "server", ""),
        Port:                 getIntSetting(s, "port", 22),
        Username:             getStringSetting(s, "username", ""),
        Password:             getStringSetting(s, "password", ""),
        PrivateKeyPath:       getStringSetting(s, "private_key_path", ""),
        PrivateKeyPassphrase: getStringSetting(s, "private_key_passphrase", ""),
        HostKey:              getStringSetting(s, "host_key", ""),
        KeepaliveInterval:    getIntSetting(s, "keepalive_interval", 30),
    }
    return ssh.New(name, cfg)
```

---

## 3. Connection Monitor

### Architecture
New streaming gRPC RPC + Wails binding + Svelte tab. Data sourced from flow table (NAT + raw entries) + process lookup + GeoIP + domain table.

### Proto Definition
```protobuf
message ConnectionEntry {
  uint32 pid = 1;
  string process_name = 2;       // "chrome.exe"
  string process_path = 3;       // full path
  string protocol = 4;           // "TCP" / "UDP"
  string dst_ip = 5;
  uint32 dst_port = 6;
  string domain = 7;             // from domain table reverse lookup
  string tunnel_id = 8;
  string state = 9;              // "active" / "fin"
  string country = 10;           // GeoIP: "RU", "US", etc.
  int64 created_at = 11;         // unix seconds
}

message ConnectionMonitorRequest {
  string tunnel_filter = 1;      // optional: filter by tunnel ID
  string process_filter = 2;     // optional: filter by process name
}

message ConnectionSnapshot {
  repeated ConnectionEntry connections = 1;
}

// In VPNService:
rpc StreamConnections(ConnectionMonitorRequest) returns (stream ConnectionSnapshot);
```

### Backend Files

**`internal/service/connection_monitor.go`** — New file:
- `ConnectionMonitor` struct: holds references to FlowTable, ProcessIdentifier, DomainTable, GeoIPMatcher
- `Start(ctx)` — launches snapshot goroutine (2s interval)
- `Subscribe() <-chan *ConnectionSnapshot` / `Unsubscribe(ch)`
- Each tick: calls `FlowTable.SnapshotNAT()` + `FlowTable.SnapshotRaw()`, enriches with process name, domain, GeoIP country, sends to subscribers

### Flow Table Changes (`flow_table.go`)

New methods (read-only, no hot-path impact):
- `SnapshotNAT() []NATSnapshotEntry` — iterates all shards under RLock, copies active NAT entries (TCP proxy path)
- `SnapshotRaw() []RawSnapshotEntry` — iterates all shards under RLock, copies active raw flow entries (IP-level tunnels)

Snapshot structs (lightweight copies):
```go
type NATSnapshotEntry struct {
    SrcPort       uint16
    OriginalDstIP netip.Addr
    OriginalDstPort uint16
    TunnelID      string
    LastActivity  int64
    FinSeen       int32
}

type RawSnapshotEntry struct {
    Protocol    uint8
    DstIP       netip.Addr
    SrcPort     uint16
    TunnelID    string
    LastActivity int64
    FakeIP      netip.Addr
    RealDstIP   netip.Addr
}
```

### Domain Table Changes (`domain_table.go`)

New method:
- `ReverseLookup(ip netip.Addr) string` — reverse lookup IP → domain name. The domain table already stores `ip → DomainEntry` mapping; this just exposes the domain name field.

### gRPC Handler (`grpc_handler.go`)

New method `StreamConnections()`:
- Subscribes to ConnectionMonitor
- Forwards snapshots to gRPC stream
- Filters by tunnel_filter / process_filter if set
- Unsubscribes on context cancellation

### Wails Binding (`binding_streaming.go`)

- `StartConnectionMonitorStream()` — starts goroutine, emits `"connection-snapshot"` Wails events
- Respects window visibility (pauses when hidden, same pattern as stats/logs streams)
- Debounce: skips emit if previous snapshot hasn't been consumed

### GUI (`ConnectionMonitorTab.svelte`)

**Tab definition** in `App.svelte`:
- ID: `monitor`
- i18n key: `tabs.monitor`
- Icon: network/connections icon (eye or signal icon)
- Position: after Logs tab, before About

**Component layout:**
```
┌─────────────────────────────────────────────────────┐
│ [Process filter ___] [Tunnel dropdown ▼] [Pause ⏸] │
├────┬──────┬────┬──────────┬────────┬──────┬───┬─────┤
│PID │Process│Proto│Destination│Domain │Tunnel│ 🌍 │State│
├────┼──────┼────┼──────────┼────────┼──────┼───┼─────┤
│1234│chrome │TCP │1.2.3.4:443│google. │awg1  │US │  ●  │
│5678│discord│UDP │5.6.7.8:50│discord.│hy2   │NL │  ●  │
│... │       │    │          │        │      │   │     │
└────┴──────┴────┴──────────┴────────┴──────┴───┴─────┘
```

**Features:**
- Virtual scroll (pattern from LogsTab) for potentially thousands of connections
- Column sorting (click header)
- Process filter: text input, client-side filtering
- Tunnel filter: dropdown populated from active tunnels
- Pause button: stops snapshot updates (for inspection)
- State indicator: green dot = active, gray = fin
- Country: 2-letter code or flag emoji
- Auto-refresh every 2s (full snapshot replacement)

### i18n
Add keys to `en.json` and `ru.json`:
- `tabs.monitor`: "Connections" / "Соединения"
- Column headers, filter placeholders, state labels

---

## Integration Checklist

### Protocol Constants (`core/config.go`)
- [ ] Add `ProtocolHysteria2 = "hysteria2"`
- [ ] Add `ProtocolSSH = "ssh"`
- [ ] Add both to `validProtocols` map

### Provider Registration (`tunnel_controller.go`)
- [ ] Add `case core.ProtocolHysteria2:` block
- [ ] Add `case core.ProtocolSSH:` block

### Dependencies (`go.mod`)
- [ ] `github.com/apernet/hysteria/core/v2` (Hysteria2 client)
- [ ] `golang.org/x/crypto/ssh` (SSH client — may already be transitive)

### Config Example (`config.example.yaml`)
- [ ] Add Hysteria2 tunnel example
- [ ] Add SSH tunnel example

### Proto (`vpn_service.proto`)
- [ ] Add `ConnectionEntry`, `ConnectionMonitorRequest`, `ConnectionSnapshot` messages
- [ ] Add `StreamConnections` RPC
- [ ] Regenerate Go code

### GUI
- [ ] Add `monitor` tab to `App.svelte`
- [ ] Create `ConnectionMonitorTab.svelte`
- [ ] Create `connections.js` store
- [ ] Add i18n keys

---

## Out of Scope
- Hysteria2 port hopping (future enhancement)
- SSH SOCKS5 dynamic forwarding (`-D` mode) — direct TCP forwarding is simpler and sufficient
- Per-connection byte counters (would require hot-path changes to flow table)
- Connection history / persistence (only live connections shown)
