# Wails3 Bindings Generation Report

Generated: 2026-02-20

## Command Executed
```bash
wails3 generate bindings -ts './...'
```

## Results
- **Status**: Success ✓
- **Packages Processed**: 582
- **Services**: 1 (BindingService)
- **Methods**: 16
- **Models**: 13
- **Enums**: 1
- **Events**: 0
- **Generation Time**: 16.32 seconds
- **Output Directory**: `C:\Users\sokol\Documents\awg-split-tunnel\frontend\bindings`

## Generated TypeScript Bindings

### Available Methods (16 total)
1. `AddTunnel(params: AddTunnelParams): Promise<void>`
2. `ConnectAll(): Promise<void>`
3. `ConnectTunnel(tunnelID: string): Promise<void>`
4. `DisconnectAll(): Promise<void>`
5. `DisconnectTunnel(tunnelID: string): Promise<void>`
6. `GetAutostart(): Promise<AutostartInfo | null>`
7. `GetConfig(): Promise<AppConfig | null>`
8. `GetStatus(): Promise<ServiceStatusResult | null>`
9. `ListProcesses(nameFilter: string): Promise<ProcessInfo[]>`
10. `ListRules(): Promise<RuleInfo[]>`
11. `ListTunnels(): Promise<TunnelInfo[]>`
12. `RemoveTunnel(tunnelID: string): Promise<void>`
13. `RestartTunnel(tunnelID: string): Promise<void>`
14. `SaveConfig(config: AppConfig | null, restartIfConnected: boolean): Promise<boolean>`
15. `SaveRules(rules: RuleInfo[]): Promise<void>`
16. `SetAutostart(enabled: boolean): Promise<void>`

### Model Classes (13 total)
1. **AddTunnelParams** - Parameters for adding a tunnel
   - id: string
   - protocol: string
   - name: string
   - settings: { [key: string]: string }
   - configFileData: string

2. **AutostartInfo** - Autostart configuration
   - enabled: boolean
   - restoreConnections: boolean

3. **ProcessInfo** - Process information
   - pid: number
   - name: string
   - path: string

4. **RuleInfo** - Split tunnel rule
   - pattern: string
   - tunnelId: string
   - fallback: string ("allow_direct", "block", "drop")

5. **ServiceStatusResult** - Service status
   - running: boolean
   - activeTunnels: number
   - totalTunnels: number
   - version: string
   - uptimeSeconds: number

6. **TunnelInfo** - Tunnel status and metadata
   - id: string
   - protocol: string
   - name: string
   - state: string ("down", "connecting", "up", "error")
   - error: string
   - adapterIp: string

7-13. **API Models** from `api/gen/models.ts` (e.g., AppConfig from core package)

## File Structure
```
frontend/bindings/
├── awg-split-tunnel/
│   └── ui/
│       ├── bindingservice.ts    (16 exported functions)
│       ├── models.ts             (6 TypeScript classes)
│       └── index.ts
├── github.com/
│   └── wailsapp/wails/v3/...
```

## Import Examples
```typescript
import {
  AddTunnel,
  ConnectTunnel,
  ListTunnels,
  GetStatus,
  SaveRules,
  ListRules
} from "../bindings/awg-split-tunnel/ui";

import {
  TunnelInfo,
  RuleInfo,
  ProcessInfo,
  ServiceStatusResult
} from "../bindings/awg-split-tunnel/ui/models";

// Usage example:
const tunnels = await ListTunnels();
const rules = await ListRules();
```

## Notes
- All bindings are CancellablePromise types (Wails3 native)
- Models include `createFrom()` static method for deserialization
- Type-safe Go-to-JavaScript bridge established
- Ready for frontend integration with Svelte
