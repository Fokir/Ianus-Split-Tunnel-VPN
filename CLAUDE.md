# CLAUDE.md — AWG Split Tunnel

## Что это

Многотуннельный VPN-клиент для Windows с per-process split tunneling.
Маршрутизирует трафик процессов в VPN-туннели по правилам (exe name, path pattern).
Поддерживает несколько протоколов одновременно (AmneziaWG, WireGuard, HTTP Proxy, SOCKS5).

## Структура (Индекс Serena)

awg-split-tunnel/
├── CLAUDE.md
├── go.mod / go.sum
├── README.md
├── cmd/
│   └── awg-split-tunnel/
│       └── main.go                       # Точка входа
├── internal/
│   ├── core/
│   │   ├── config.go                     # ConfigManager
│   │   ├── events.go                     # EventBus (pub/sub)
│   │   ├── tunnel_registry.go            # Реестр туннелей + состояния
│   │   ├── rule_engine.go                # Process→Tunnel matching + fallback
│   │   └── packet_router.go              # NDISAPI фильтр + NAT
│   ├── provider/
│   │   ├── interface.go                  # TunnelProvider контракт
│   │   ├── amneziawg/provider.go         # AWG: bind to wintun IP
│   │   ├── wireguard/provider.go         # (будущее)
│   │   ├── httpproxy/provider.go         # (будущее)
│   │   └── socks5/provider.go            # (будущее)
│   ├── proxy/
│   │   └── tunnel_proxy.go              # Per-tunnel transparent proxy
│   └── process/
│       └── matcher.go                    # exe name / partial / dir matching
├── ui/                                   # GUI (будущее)
└── refs/                                 # Git submodule референсы
    ├── ndisapi-go/
    ├── ndisapi/
    ├── proxifyre/
    ├── gopacket/
    ├── amneziawg-go/
    ├── amneziawg-windows-client/
    ├── tailscale-wf/
    └── mullvad-split-tunnel/

## Референсные репозитории (refs/)

### refs/ndisapi-go/ — ГЛАВНЫЙ РЕФЕРЕНС
- **examples/socksify/** — базовый шаблон: transparent proxy → SOCKS5
  - main.go: SimplePacketFilter, ProcessLookup, NAT-таблица, hairpin redirect
  - transparent_proxy.go: SOCKS5 dialer, bidirectional forwarding
- **examples/httpproxy/** — аналог через HTTP CONNECT
- **examples/capture/** — FastIOPacketFilter + pcap
- Типы: NdisApi, IntermediateBuffer, Handle, FilterAction (Pass/Drop/Redirect)
- driver/: SimplePacketFilter, FastIOPacketFilter, QueuedMultiInterfacePacketFilter
- netlib/: ProcessLookup.FindProcessInfo(ctx, isUDP, src, dst, isIPv6)

### refs/ndisapi/
- examples/cpp/socksify/, snat/, dns_proxy/ — C++ референсы

### refs/proxifyre/
- Multi-SOCKS5, per-app, UDP, Windows Service, JSON конфиг

### refs/gopacket/
- layers/, DecodingLayerParser (zero-alloc), SerializePacket

### refs/amneziawg-go/
- device/, tun/, ipc/uapi_windows.go, обфускация (Jc, Jmin, Jmax, H1-H4)

### refs/amneziawg-windows-client/
- tunnel/, manager/ (Windows service)

### refs/tailscale-wf/
- WFP из Go: сессии, фильтры, ALE_APP_ID — для kill switch

### refs/mullvad-split-tunnel/
- Kernel WFP callout, ALE_BIND_REDIRECT, process tracking

## Соглашения

- Build tag: //go:build windows
- Импорты NDISAPI: A = ndisapi, D = driver, N = netlib
- Логи: [Core], [Router], [AWG], [Proxy], [Rule]
- Конфиг: YAML

## Архитектура: три уровня

### Уровень 1: Core (Ядро)
- ConfigManager — CRUD конфигурации, персистентность, уведомления
- TunnelRegistry — реестр туннелей, состояния, health monitoring
- RuleEngine — matching процессов, определение туннеля и fallback policy
- PacketRouter — NDISAPI фильтр + NAT-таблица, вызывает RuleEngine
- EventBus — pub/sub между уровнями

### Уровень 2: VPN Providers
- TunnelProvider интерфейс: Connect / Disconnect / Status / GetAdapterIP / DialTCP
- AmneziaWG (текущий фокус), WireGuard, HTTP Proxy, SOCKS5 (будущее)

### Уровень 3: GUI (будущее)

## Fallback политики

| Политика      | Туннель UP      | Туннель DOWN        |
|---------------|-----------------|---------------------|
| Allow Direct  | → через туннель | → напрямую (Pass)   |
| Block         | → через туннель | → блокировать (Drop)|
| Drop          | → блокировать   | → блокировать       |

## Поток данных

```
Процесс → TCP SYN → PacketRouter (NDISAPI)
  → Parse (gopacket DecodingLayerParser)
  → SYN: ProcessLookup → PID → exe path
  → RuleEngine.Match(exePath) → {tunnel, fallback}
  → TunnelRegistry.Get(tunnel) → status, proxy port
    UP     → NAT + hairpin redirect
    DOWN+block → Drop
    DOWN+allow → Pass
    drop → Drop (всегда)
  → TunnelProxy → NAT lookup → provider.DialTCP → io.Copy
  → VPN → Интернет
```

## Требования к производительности

- Packet filter callback: НИКАКИХ аллокаций, сетевых вызовов, блокировок
- FastIOPacketFilter (shared memory) вместо SimplePacketFilter
- NAT-таблица: sync.RWMutex, минимальное время под lock
- Process path: кеш PID→exe path
- gopacket: DecodingLayerParser вместо NewPacket на hot path
- Proxy forwarding: буферизированный io.Copy
