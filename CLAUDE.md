# CLAUDE.md — AWG Split Tunnel

## Что это

Многотуннельный VPN-клиент для Windows с per-process split tunneling.
Маршрутизирует трафик процессов в VPN-туннели по правилам (exe name, path pattern).
Поддерживает несколько протоколов одновременно (AmneziaWG, WireGuard, HTTP Proxy, SOCKS5).

> Детальная архитектура, data flow, reference repos, performance requirements — в памяти Serena.

## Структура

```
cmd/awg-split-tunnel/main.go          # Точка входа
internal/
  core/
    config.go                          # ConfigManager
    events.go                          # EventBus (pub/sub)
    tunnel_registry.go                 # Реестр туннелей + состояния
    rule_engine.go                     # Process→Tunnel matching + fallback
    packet_router.go                   # NDISAPI фильтр + NAT
  provider/
    interface.go                       # TunnelProvider контракт
    amneziawg/provider.go              # AWG provider (текущий фокус)
  proxy/tunnel_proxy.go               # Per-tunnel transparent proxy
  process/matcher.go                   # exe name / partial / dir matching
refs/                                  # Git submodule референсы (см. Serena: reference_repos)
ui/                                    # GUI (будущее)
```

## Соглашения

- Build tag: `//go:build windows`
- Импорты NDISAPI: `A` = ndisapi, `D` = driver, `N` = netlib
- Логи: `[Core]`, `[Router]`, `[AWG]`, `[Proxy]`, `[Rule]`
- Конфиг: YAML (см. `config.example.yaml`)
