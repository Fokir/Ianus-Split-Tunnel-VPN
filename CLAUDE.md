# CLAUDE.md — AWG Split Tunnel

## Что это

Многотуннельный VPN-клиент для Windows с per-process split tunneling.
Маршрутизирует трафик процессов в VPN-туннели по правилам (exe name, path pattern).
Поддерживает несколько протоколов одновременно (AmneziaWG, WireGuard планируется).

> Детальная архитектура, data flow, reference repos, performance requirements — в памяти Serena.

## Архитектура

WinTUN Gateway + WFP per-process interface blocking.
Raw IP forwarding для VPN-туннелей (bypass gVisor/proxy), proxy path для direct-трафика.

## Структура

```
cmd/awg-split-tunnel/main.go          # Точка входа
internal/
  core/
    config.go                          # ConfigManager + DNS config
    events.go                          # EventBus (pub/sub)
    tunnel_registry.go                 # Реестр туннелей + состояния
    rule_engine.go                     # Process→Tunnel matching + fallback
  gateway/
    adapter.go                         # WinTUN адаптер, IP/MTU via iphlpapi, DNS via netsh
    router.go                          # TUN Router (packet loop, raw forwarding, MSS clamping)
    flow_table.go                      # 64-shard NAT tables + raw flow tracking
    wfp.go                             # WFP: per-process blocking, DNS leak protection, bypass permits
    route.go                           # Route manager (default 0/1+128/1, bypass routes)
    dns.go                             # Per-process DNS routing
    dns_resolver.go                    # Локальный DNS forwarder (10.255.0.1:53 → VPN)
    process.go                         # PID lookup (GetExtendedTcpTable/UdpTable)
    helpers.go                         # Packet manipulation (raw IP, checksums, MSS clamping)
    ip_filter.go                       # IPFilter + PrefixTrie (AllowedIPs/DisallowedIPs/DisallowedApps)
  provider/
    interface.go                       # TunnelProvider + RawForwarder контракты
    amneziawg/provider.go              # AWG provider (netstack + raw forwarding)
    direct/provider.go                 # DirectProvider (IP_UNICAST_IF → real NIC)
  proxy/
    tunnel_proxy.go                    # TCP transparent proxy
    udp_proxy.go                       # UDP transparent proxy
  process/matcher.go                   # exe name / partial / dir matching
refs/                                  # Git submodule референсы (см. Serena: reference_repos)
ui/                                    # GUI (будущее)
```

## Соглашения

- Build tag: `//go:build windows`
- Логи: `[Core]`, `[Gateway]`, `[Route]`, `[AWG]`, `[Direct]`, `[Proxy]`, `[Rule]`, `[WFP]`, `[DNS]`
- Конфиг: YAML (см. `config.example.yaml`)
- TUN IP: `10.255.0.1/24`, MTU: 1400
- Special tunnel ID: `__direct__` для unmatched трафика
