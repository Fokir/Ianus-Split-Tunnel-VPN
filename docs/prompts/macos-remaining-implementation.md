# Промт: Реализация оставшегося функционала macOS

## Контекст

Проект AWG Split Tunnel — многотуннельный VPN-клиент с per-process split tunneling.
Проведён большой рефакторинг: код разделён на кросс-платформенные интерфейсы
(`internal/platform/interfaces.go`) и платформенные реализации
(`internal/platform/windows/`, `internal/platform/darwin/`).

### Что уже сделано (шаги 1-7)

1. Платформенные интерфейсы: `TUNAdapter`, `ProcessFilter`, `RouteManager`,
   `ProcessIdentifier`, `IPCTransport`, `InterfaceBinder`, `Notifier`
2. Windows-реализации вынесены в `internal/platform/windows/`
3. Кросс-платформенный `main.go` + `main_darwin.go` / `main_windows.go`
4. Кросс-платформенные пакеты: `gateway/router.go`, `gateway/flow_table.go`,
   `proxy/`, `provider/` и т.д.
5. **Реальные macOS-реализации** в `internal/platform/darwin/`:
   - `tun.go` — utun через kernel control socket (AF_SYSTEM), 4-byte AF header,
     networksetup DNS, sync.Pool write buffers
   - `route_manager.go` — `route` command, split routes (0/1 + 128/1), bypass routes
   - `process_filter.go` — PF anchors (com.awg/dns, com.awg/ipv6),
     DNS leak protection, IPv6 blocking, per-process tracking advisory
   - `process_identifier.go` — raw proc_info syscall (336), cached port→PID map (300ms TTL)
   - `interface_binder.go` — IP_BOUND_IF=25, IPV6_BOUND_IF=125
   - `ipc.go` — Unix domain socket `/var/run/awg-split-tunnel.sock`
   - `notifier.go` — osascript `display notification`
   - `dns.go` — `dscacheutil -flushcache` + `killall -HUP mDNSResponder`
   - `factory.go` — NewPlatform() wiring all components

6. **gRPC stubs** в `internal/service/grpc_handler_darwin.go`:
   - `ListProcesses` — TODO (returns empty)
   - `GetAutostart` / `SetAutostart` — TODO (returns "not supported")
   - `ApplyUpdate` — TODO (returns "not supported")
   - `CheckConflictingServices` / `StopConflictingServices` — no-op (not needed on macOS)

7. **Process matcher stub** в `internal/process/matcher_stub.go`:
   - `queryProcessPath()` — TODO (returns error "not implemented")

### Билд проходит
```
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build ./...  ✅
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build ./...  ✅
GOOS=windows go build ./...  ✅
```

---

## Задачи для реализации

Реализуй всё по порядку. Каждый блок — атомарный коммит.
Читай память Serena (`read_memory`) перед началом для полного контекста.

---

### Блок 1: PID→exe path (критично для per-process routing)

**Файл**: `internal/process/matcher_darwin.go` (новый, `//go:build darwin`)

Замени stub `matcher_stub.go` (сделай его `//go:build !windows && !darwin`).

Реализуй `queryProcessPath(pid uint32) (string, error)` через raw syscall
`proc_pidpath` — **без CGO**:

```go
// proc_pidpath equivalent via raw syscall.
// SYS_PROC_INFO = 336, callnum = PROC_INFO_CALL_PIDINFO (2),
// flavor = PROC_PIDPATHINFO (11), arg = 0, buf = path buffer, bufsize = MAXPATHLEN (1024).
func queryProcessPath(pid uint32) (string, error) {
    const (
        procInfoCallPIDInfo  = 2
        procPIDPathInfo      = 11  // PROC_PIDPATHINFO
        maxPathLen           = 1024
    )
    buf := make([]byte, maxPathLen)
    n, _, errno := unix.Syscall6(
        336, // SYS_PROC_INFO
        uintptr(procInfoCallPIDInfo),
        uintptr(pid),
        uintptr(procPIDPathInfo),
        0,    // arg
        uintptr(unsafe.Pointer(&buf[0])),
        uintptr(maxPathLen),
    )
    if errno != 0 {
        return "", errno
    }
    // n = bytes written (null-terminated C string)
    return unix.ByteSliceToString(buf[:n]), nil
}
```

**Верификация**: пусть это будет через `Syscall6(336, 2, pid, 11, 0, buf, 1024)`.
Offset значения из XNU: `PROC_PIDPATHINFO = 11`, `PROC_PIDPATHINFO_MAXSIZE = 4*MAXPATHLEN = 4096`.
Используй `bufsize = 4096` на всякий случай.

**Тест**: можно проверить вызовом `queryProcessPath(uint32(os.Getpid()))` — должен
вернуть путь к текущему бинарнику.

---

### Блок 2: ListProcesses для gRPC (GUI)

**Файл**: `internal/service/grpc_handler_darwin.go`

Замени stub `ListProcesses` реальной реализацией:

1. Используй `proc_listallpids` (уже есть в `process_identifier.go` → `listAllPIDs()`)
   — но она в пакете `darwin`, а нужна в `service`. Вариант: вызвать `process.Matcher.GetExePath(pid)`
   для каждого PID, или перенести `listAllPIDs` в общий пакет.

2. **Рекомендуемый подход**: создай helper `listRunningProcesses()` в файле
   `internal/service/process_lister_darwin.go` (//go:build darwin), который:
   - Через raw syscall #336 получает список PID (как в `process_identifier.go`)
   - Для каждого PID получает exe path через `proc_pidpath` (SYS_PROC_INFO, flavor=11)
   - Возвращает `[]*vpnapi.ProcessInfo` с полями `Pid`, `Name`, `Path`

3. В `grpc_handler_darwin.go` вызови `listRunningProcesses()`.

**Важно**: не дублируй syscall обёртки. Если нужны общие функции — вынеси в
`internal/platform/darwin/proc_info.go` и экспортируй.

Однако, проще сделать отдельный файл `process_lister_darwin.go` с собственными вызовами,
чтобы не нарушать границы пакетов.

---

### Блок 3: Network Monitor (детекция смены сети)

**Файл**: `internal/platform/darwin/network_monitor.go` (новый)

Мониторинг смены сети через PF_ROUTE socket (чистый Go, без CGO):

```go
type NetworkMonitor struct {
    routeFD  int
    onChange func()  // callback при смене default route
    done     chan struct{}
}

func NewNetworkMonitor(onChange func()) (*NetworkMonitor, error)
func (nm *NetworkMonitor) Start() error  // горутина читает route socket
func (nm *NetworkMonitor) Stop() error
```

Реализация:
1. Открой `unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)`
2. В горутине читай сообщения (RTM_NEWADDR, RTM_DELADDR, RTM_IFINFO)
3. При получении — вызывай `onChange()` (с debounce 2 секунды)

**Интеграция**: Добавь `NewNetworkMonitor` в `platform.Platform` struct:
```go
type Platform struct {
    // ... existing fields ...
    NewNetworkMonitor func(onChange func()) (NetworkMonitor, error)
}
```

Добавь интерфейс `NetworkMonitor` в `interfaces.go`:
```go
type NetworkMonitor interface {
    Start() error
    Stop() error
}
```

В `main.go` / `service.go` используй для:
- Пересоздания bypass routes при смене gateway
- Обновления DNS при смене сети
- Пересоединения VPN туннелей

**NE-ready**: интерфейс тот же, NE-реализация будет через
`NWPathMonitor` (но для daemon mode route socket достаточно).

---

### Блок 4: Kill Switch (PF anchor)

**Файл**: `internal/platform/darwin/process_filter.go` (расширение)

Добавь Kill Switch через PF anchor `com.awg/killswitch`.
Добавь метод в интерфейс `ProcessFilter`:

```go
// В interfaces.go:
type ProcessFilter interface {
    // ... existing methods ...
    EnableKillSwitch(tunIfName string, vpnEndpoints []netip.Addr) error
    DisableKillSwitch() error
}
```

Реализация в `process_filter.go`:
```go
func (f *ProcessFilter) EnableKillSwitch(tunIfName string, vpnEndpoints []netip.Addr) error {
    // PF rules:
    // pass out quick on lo0 all
    // pass out quick on <tunIfName> all
    // pass out quick proto udp to <vpnEndpoint> port <vpnPort>  (для каждого endpoint)
    // block drop out quick all
    // block drop in quick all
}
```

**Windows**: добавь stub `EnableKillSwitch` / `DisableKillSwitch` в Windows ProcessFilter
(WFP already has similar functionality via existing rules, можно сделать no-op или
вызвать существующий WFP killswitch).

**NE-ready**: PF kill switch работает ЛУЧШЕ чем NE (фильтрует Apple apps).
При переходе на NE — PF останется как fallback, NE добавит
`includeAllNetworks = true` на `NEPacketTunnelNetworkSettings`.

---

### Блок 5: Service Manager (launchd)

**Файлы**:
- `internal/service/service_darwin.go` (новый, //go:build darwin)
- `internal/service/autostart_darwin.go` (новый, //go:build darwin)

#### 5a. LaunchDaemon management

Создай `service_darwin.go`:
```go
const (
    daemonLabel    = "com.awg.split-tunnel"
    daemonPlistDir = "/Library/LaunchDaemons"
    daemonPlist    = daemonPlistDir + "/" + daemonLabel + ".plist"
    daemonBinary   = "/usr/local/bin/awg-split-tunnel"
    configDir      = "/etc/awg-split-tunnel"
)

func InstallDaemon() error    // копирует бинарник + plist, launchctl bootstrap
func UninstallDaemon() error  // launchctl bootout, удаляет файлы
func IsDaemonInstalled() bool // проверяет наличие plist
func RestartDaemon() error    // launchctl kickstart -k
```

Plist-шаблон:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" ...>
<plist version="1.0">
<dict>
    <key>Label</key><string>com.awg.split-tunnel</string>
    <key>ProgramArguments</key><array>
        <string>/usr/local/bin/awg-split-tunnel</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/var/log/awg-split-tunnel.log</string>
    <key>StandardErrorPath</key><string>/var/log/awg-split-tunnel.log</string>
</dict>
</plist>
```

**Важно**: используй `launchctl bootstrap system <plist>` (macOS 10.10+)
вместо deprecated `launchctl load`. Для выгрузки — `launchctl bootout system/<label>`.

#### 5b. Autostart (LaunchAgent для GUI)

Создай `autostart_darwin.go`:
```go
func isAutostartEnabled() bool       // проверяет ~/Library/LaunchAgents/com.awg.split-tunnel.gui.plist
func setAutostartEnabled(enable bool) error  // создаёт/удаляет LaunchAgent plist
```

LaunchAgent plist (для GUI, запускается при логине пользователя):
```xml
<dict>
    <key>Label</key><string>com.awg.split-tunnel.gui</string>
    <key>ProgramArguments</key><array>
        <string>/Applications/AWG Split Tunnel.app/Contents/MacOS/awg-split-tunnel-gui</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>LimitLoadToSessionType</key><string>Aqua</string>
</dict>
```

Обнови `grpc_handler_darwin.go`:
- `GetAutostart` → вызывай `isAutostartEnabled()`
- `SetAutostart` → вызывай `setAutostartEnabled(req.Enabled)`

Также переименуй `autostart.go` build tag с `windows` на `windows` (он уже только windows,
просто убедись что `autostart_darwin.go` не конфликтует).

---

### Блок 6: Update mechanism для macOS

**Файлы**:
- `internal/update/asset_darwin.go` — уже есть (AssetPattern + AssetSuffix)
- `internal/update/updater_darwin.go` (новый, //go:build darwin)

Реализуй `ApplyUpdate` в `grpc_handler_darwin.go`:

Стратегия обновления для daemon mode:
1. Скачай tarball (уже работает через `update.Download()`)
2. Распакуй во временную директорию
3. Замени бинарник: `cp new-binary /usr/local/bin/awg-split-tunnel`
4. Перезапусти daemon: `launchctl kickstart -k system/com.awg.split-tunnel`

```go
func applyDarwinUpdate(downloadedPath string) error {
    // 1. Извлечь tar.gz
    // 2. Заменить бинарник (atomic: write to tmp, rename)
    // 3. launchctl kickstart -k system/com.awg.split-tunnel
}
```

Также обнови `asset_darwin.go` если нужна поддержка universal binary:
```go
const AssetSuffix = "-darwin-universal.tar.gz"
// или определяй runtime.GOARCH для выбора arm64/amd64
```

---

### Блок 7: DNS watcher (восстановление DNS при смене сети)

Интегрируй в Network Monitor (блок 3):
- При событии смены сети проверяй, совпадает ли текущий primary network service
  с тем, что был при `SetDNS()`
- Если primary service сменился (WiFi→Ethernet), переприменяй DNS конфигурацию
- Добавь метод в `TUNAdapter`:
  ```go
  func (a *TUNAdapter) ReapplyDNS() error  // повторно ставит DNS на текущий primary service
  ```

**NE-ready**: В NE-режиме DNS задаётся через `NEDNSSettings` и
пересоздание `setTunnelNetworkSettings()`. Интерфейс `TUNAdapter.SetDNS()`
уже поддерживает оба варианта.

---

### Блок 8: main_darwin.go — CLI подкоманды

**Файл**: `cmd/awg-split-tunnel/main_darwin.go`

Добавь поддержку CLI подкоманд (аналог Windows service subcommands):
```go
func main() {
    if len(os.Args) > 1 {
        switch os.Args[1] {
        case "install":
            // Вызвать service.InstallDaemon()
        case "uninstall":
            // Вызвать service.UninstallDaemon()
        case "version":
            // Вывести версию
        default:
            // Unknown subcommand
        }
        return
    }
    // Normal daemon run
    plat := platformDarwin.NewPlatform()
    runVPN(plat)
}
```

---

### Блок 9: Build & packaging (macOS)

**Файлы**:
- `Makefile` или `scripts/build-darwin.sh` (новый)

```bash
#!/bin/bash
set -e

VERSION=${1:-"dev"}
BINARY="awg-split-tunnel"

# Build arm64
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
    go build -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${BINARY}-arm64" ./cmd/awg-split-tunnel/

# Build amd64
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 \
    go build -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${BINARY}-amd64" ./cmd/awg-split-tunnel/

# Universal binary
lipo -create -output "${BINARY}" "${BINARY}-arm64" "${BINARY}-amd64"

# Package
tar -czf "${BINARY}-v${VERSION}-darwin-universal.tar.gz" \
    "${BINARY}" \
    scripts/install-daemon.sh \
    scripts/uninstall-daemon.sh
```

Создай install/uninstall скрипты:
- `scripts/install-daemon.sh` — копирует бинарник, создаёт plist, bootstrap
- `scripts/uninstall-daemon.sh` — bootout, удаляет файлы

---

## NE-Ready минимум (не реализовывать NE, только подготовить)

### Что сделать сейчас для совместимости:

1. **Build tags**: все darwin-файлы должны использовать `//go:build darwin`
   (без `&& !ne`). Когда появится NE — добавим `//go:build darwin && !ne`
   к daemon-файлам и `//go:build darwin && ne` к NE-файлам.

2. **Экспортируй ключевые функции** из `internal/platform/darwin/` для будущего
   c-archive bridge:
   - `process_identifier.go`: `scanPortPIDs()` → keep unexported, NE не нужен port scan
   - `tun.go`: `ReadPacket/WritePacket` → NE будет через packetFlow, не через utun
   - **Вывод**: ничего экспортировать не нужно. NE будет реализовывать
     те же интерфейсы через другие механизмы.

3. **NetworkMonitor интерфейс** (блок 3) — уже NE-ready, NE реализация
   будет через NWPathMonitor.

4. **Kill Switch** (блок 4) — PF kill switch останется даже при NE,
   т.к. `includeAllNetworks` не фильтрует Apple apps.

5. **Не** создавай Xcode project, Swift bridge, c-archive, System Extension —
   всё это будет в отдельной задаче.

### Чего НЕ делать:

- Не создавать `tun_ne.go`, `routes_ne.go` и т.д. — пустые файлы бесполезны
- Не добавлять build tag `ne` — пока нет кода под него
- Не создавать c-archive bridge API — преждевременно
- Не проектировать IPC между Container App и Extension — дизайн зависит от
  конкретных ограничений NE sandbox

---

## Порядок выполнения

1. Блок 1 (PID→exe path) — без этого не работает per-process routing на macOS
2. Блок 2 (ListProcesses) — GUI не показывает процессы без этого
3. Блок 4 (Kill Switch) — безопасность
4. Блок 3 (Network Monitor) — reconnect при смене сети
5. Блок 7 (DNS watcher) — зависит от Network Monitor
6. Блок 5 (Service Manager) — launchd + autostart
7. Блок 8 (CLI подкоманды) — install/uninstall
8. Блок 6 (Update mechanism) — self-update
9. Блок 9 (Build & packaging) — финальная сборка

---

## Важные технические детали

### proc_pidpath без CGO
```
SYS_PROC_INFO = 336
PROC_INFO_CALL_PIDINFO = 2
PROC_PIDPATHINFO = 11
PROC_PIDPATHINFO_MAXSIZE = 4 * MAXPATHLEN = 4096
```
Вызов: `Syscall6(336, 2, pid, 11, 0, &buf, 4096)` → возвращает C-строку с путём.

### PF_ROUTE socket
```go
fd, _ := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
// Читай RTM_* сообщения: RTM_NEWADDR=0xC, RTM_DELADDR=0xD, RTM_IFINFO=0xE
// Структура: rt_msghdr (версия 5 на macOS)
```

### launchctl commands (macOS 10.10+)
```bash
# Install
sudo launchctl bootstrap system /Library/LaunchDaemons/com.awg.split-tunnel.plist
# Uninstall
sudo launchctl bootout system/com.awg.split-tunnel
# Restart
sudo launchctl kickstart -k system/com.awg.split-tunnel
# Status
sudo launchctl print system/com.awg.split-tunnel
```

### Пути на macOS
- Daemon binary: `/usr/local/bin/awg-split-tunnel`
- Daemon config: `/etc/awg-split-tunnel/config.yaml`
- Daemon plist: `/Library/LaunchDaemons/com.awg.split-tunnel.plist`
- Daemon log: `/var/log/awg-split-tunnel.log`
- GUI LaunchAgent: `~/Library/LaunchAgents/com.awg.split-tunnel.gui.plist`
- IPC socket: `/var/run/awg-split-tunnel.sock`

---

## Память Serena

Прочитай перед началом:
- `cross_platform/macos_implementation_status` — что уже сделано
- `cross_platform/macos_plan` — общий план
- `cross_platform/macos_practical_guide` — NE details, pitfalls
- `project_structure` — структура проекта
- `code_conventions` — стиль кода

После завершения обнови:
- `cross_platform/macos_implementation_status` — добавь выполненные блоки
