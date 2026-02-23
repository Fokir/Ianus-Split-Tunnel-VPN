# 12_per_tunnel.ps1 -- Per-tunnel connectivity tests.
# Iterates all configured tunnels, connects each one exclusively,
# routes awg-diag.exe through it, and runs basic network checks.

. "$PSScriptRoot\_common.ps1"
Reset-TestCounters
Write-TestHeader "12: Per-Tunnel Connectivity"

$ConfigPath = $Script:ConfigPath

# -- Prerequisite: service must be running ----------------------------------
Write-Info "Checking service status..."
$svcResult = Invoke-Diag -Arguments @("service", "status")

if (-not ($svcResult.Json -and $svcResult.Json.running)) {
    Write-Skip "per-tunnel:precondition" "Service not running -- cannot switch tunnels"
    Write-TestSummary
    return
}

Write-Pass "per-tunnel:service-running" "Service is running"

# -- Get list of unique tunnels ---------------------------------------------
Write-Info "Getting tunnel list..."
$tunnelResult = Invoke-Diag -Arguments @("tunnel", "list")

if (-not $tunnelResult.Json) {
    Write-Fail "per-tunnel:list" "Failed to get tunnel list: $($tunnelResult.Stderr)"
    Write-TestSummary
    return
}

# Deduplicate by ID.
$tunnels = @{}
foreach ($t in $tunnelResult.Json) {
    if (-not $tunnels.ContainsKey($t.id)) {
        $tunnels[$t.id] = $t
    }
}

$uniqueTunnels = $tunnels.Values | Sort-Object { $_.id }
Write-Pass "per-tunnel:list" "$($uniqueTunnels.Count) unique tunnel(s) found"

foreach ($t in $uniqueTunnels) {
    Write-Info "  $($t.id) ($($t.protocol)) -- $($t.status)"
}

# -- Save original config for restore --------------------------------------
$configBackup = "$ConfigPath.tunnel-test-backup"
Write-Info "Backing up config..."
Copy-Item $ConfigPath $configBackup -Force

# -- Save originally active tunnels ----------------------------------------
$originallyActive = @($tunnelResult.Json | Where-Object {
    $_.status -eq "TUNNEL_UP" -or $_.status -eq "up"
} | ForEach-Object { $_.id } | Select-Object -Unique)

Write-Info "Originally active tunnels: $($originallyActive -join ', ')"

# -- Test each tunnel -------------------------------------------------------
$tunnelResults = @()

foreach ($tunnel in $uniqueTunnels) {
    $tid = $tunnel.id
    $proto = $tunnel.protocol
    Write-Host ""
    Write-Host "  ---- Testing tunnel: $tid ($proto) ----" -ForegroundColor Cyan

    $tunnelTestPassed = 0
    $tunnelTestFailed = 0

    try {
        # 1. Disconnect all tunnels.
        Write-Info "Disconnecting all tunnels..."
        $disconnResult = Invoke-Diag -Arguments @("tunnel", "disconnect") -TimeoutSec 15
        Start-Sleep -Seconds 2

        # 2. Connect this tunnel only.
        Write-Info "Connecting $tid..."
        $connResult = Invoke-Diag -Arguments @("tunnel", "connect", $tid) -TimeoutSec 30

        if ($connResult.Json -and $connResult.Json.success) {
            Write-Pass "tunnel[$tid]:connect" "Connected"
            $tunnelTestPassed++
        } else {
            $errMsg = if ($connResult.Json) { $connResult.Json.error } else { $connResult.Stderr }
            Write-Fail "tunnel[$tid]:connect" "Failed: $errMsg"
            $tunnelTestFailed++
            $tunnelResults += @{ ID=$tid; Protocol=$proto; Passed=$tunnelTestPassed; Failed=$tunnelTestFailed }
            continue
        }

        # 3. Wait for tunnel to stabilize.
        Write-Info "Waiting for tunnel to stabilize..."
        Start-Sleep -Seconds 5

        # 4. Verify tunnel is UP.
        $statusResult = Invoke-Diag -Arguments @("tunnel", "status", $tid)
        $isUp = $false
        if ($statusResult.Json) {
            $state = $statusResult.Json.status
            if ($state -eq "TUNNEL_UP" -or $state -eq "up") {
                $isUp = $true
            }
        }

        if ($isUp) {
            Write-Pass "tunnel[$tid]:status" "Status: UP"
            $tunnelTestPassed++
        } else {
            $state = if ($statusResult.Json) { $statusResult.Json.status } else { "unknown" }
            Write-Fail "tunnel[$tid]:status" "Status: $state (expected UP)"
            $tunnelTestFailed++
            $tunnelResults += @{ ID=$tid; Protocol=$proto; Passed=$tunnelTestPassed; Failed=$tunnelTestFailed }
            continue
        }

        # 5. Add temp rule: route awg-diag.exe through this tunnel.
        Write-Info "Adding temp rule: awg-diag.exe -> $tid..."
        # First remove if exists (in case previous run left it).
        Invoke-DiagRaw -Arguments @("config", "remove-rule", "--pattern", "awg-diag.exe") -TimeoutSec 5 2>$null
        Start-Sleep -Seconds 1
        $addResult = Invoke-DiagRaw -Arguments @("config", "add-rule", "--pattern", "awg-diag.exe", "--tunnel", $tid, "--fallback", "block")
        if ($addResult.ExitCode -ne 0) {
            Write-Fail "tunnel[$tid]:add-rule" "Failed: $($addResult.Stderr)"
            $tunnelTestFailed++
            $tunnelResults += @{ ID=$tid; Protocol=$proto; Passed=$tunnelTestPassed; Failed=$tunnelTestFailed }
            continue
        }

        # Wait for config reload.
        Start-Sleep -Seconds 3

        # 6. Check IP.
        Write-Info "Checking external IP..."
        $ipResult = Invoke-Diag -Arguments @("check-ip") -TimeoutSec 15
        if ($ipResult.Json -and $ipResult.Json.success) {
            Write-Pass "tunnel[$tid]:check-ip" "IP: $($ipResult.Json.details) ($($ipResult.Json.latency_ms)ms)"
            $tunnelTestPassed++
        } else {
            $errMsg = if ($ipResult.Json) { $ipResult.Json.error } else { $ipResult.Stderr }
            Write-Fail "tunnel[$tid]:check-ip" "$errMsg"
            $tunnelTestFailed++
        }

        # 7. DNS test.
        Write-Info "Testing DNS..."
        $dnsResult = Invoke-Diag -Arguments @("dns", "google.com")
        if ($dnsResult.Json -and $dnsResult.Json.success) {
            Write-Pass "tunnel[$tid]:dns" "$($dnsResult.Json.details)"
            $tunnelTestPassed++
        } else {
            $errMsg = if ($dnsResult.Json) { $dnsResult.Json.error } else { $dnsResult.Stderr }
            Write-Fail "tunnel[$tid]:dns" "$errMsg"
            $tunnelTestFailed++
        }

        # 8. TCP test.
        Write-Info "Testing TCP..."
        $tcpResult = Invoke-Diag -Arguments @("tcp", "1.1.1.1:443") -TimeoutSec 10
        if ($tcpResult.Json -and $tcpResult.Json.success) {
            Write-Pass "tunnel[$tid]:tcp" "$($tcpResult.Json.details)"
            $tunnelTestPassed++
        } else {
            $errMsg = if ($tcpResult.Json) { $tcpResult.Json.error } else { $tcpResult.Stderr }
            Write-Fail "tunnel[$tid]:tcp" "$errMsg"
            $tunnelTestFailed++
        }

        # 9. UDP test.
        Write-Info "Testing UDP..."
        $udpResult = Invoke-Diag -Arguments @("udp", "8.8.8.8:53") -TimeoutSec 10
        if ($udpResult.Json -and $udpResult.Json.success) {
            Write-Pass "tunnel[$tid]:udp" "$($udpResult.Json.details)"
            $tunnelTestPassed++
        } else {
            $errMsg = if ($udpResult.Json) { $udpResult.Json.error } else { $udpResult.Stderr }
            Write-Fail "tunnel[$tid]:udp" "$errMsg"
            $tunnelTestFailed++
        }

        # 10. HTTP test.
        Write-Info "Testing HTTP..."
        $httpResult = Invoke-Diag -Arguments @("http", "https://httpbin.org/ip") -TimeoutSec 15
        if ($httpResult.Json -and $httpResult.Json.success) {
            Write-Pass "tunnel[$tid]:http" "$($httpResult.Json.details)"
            $tunnelTestPassed++
        } else {
            $errMsg = if ($httpResult.Json) { $httpResult.Json.error } else { $httpResult.Stderr }
            Write-Fail "tunnel[$tid]:http" "$errMsg"
            $tunnelTestFailed++
        }

        # 11. HTTPS test.
        Write-Info "Testing HTTPS..."
        $httpsResult = Invoke-Diag -Arguments @("http", "https://api.ipify.org") -TimeoutSec 15
        if ($httpsResult.Json -and $httpsResult.Json.success) {
            Write-Pass "tunnel[$tid]:https" "$($httpsResult.Json.details)"
            $tunnelTestPassed++
        } else {
            $errMsg = if ($httpsResult.Json) { $httpsResult.Json.error } else { $httpsResult.Stderr }
            Write-Fail "tunnel[$tid]:https" "$errMsg"
            $tunnelTestFailed++
        }

        # 12. Remove temp rule.
        Invoke-DiagRaw -Arguments @("config", "remove-rule", "--pattern", "awg-diag.exe") -TimeoutSec 5 | Out-Null

    } catch {
        Write-Fail "tunnel[$tid]:exception" "$_"
        $tunnelTestFailed++
        # Cleanup rule.
        Invoke-DiagRaw -Arguments @("config", "remove-rule", "--pattern", "awg-diag.exe") -TimeoutSec 5 2>$null | Out-Null
    }

    $tunnelResults += @{ ID=$tid; Protocol=$proto; Passed=$tunnelTestPassed; Failed=$tunnelTestFailed }
}

# -- Restore original state -------------------------------------------------
Write-Host ""
Write-Host "  ---- Restoring original state ----" -ForegroundColor Cyan

# Restore config.
Write-Info "Restoring config..."
Copy-Item $configBackup $ConfigPath -Force
Remove-Item $configBackup -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Reconnect originally active tunnels.
if ($originallyActive.Count -gt 0) {
    Write-Info "Reconnecting originally active tunnels..."
    foreach ($tid in $originallyActive) {
        Write-Info "  Connecting $tid..."
        Invoke-Diag -Arguments @("tunnel", "connect", $tid) -TimeoutSec 30 | Out-Null
    }
    Start-Sleep -Seconds 3
}

Write-Pass "per-tunnel:restore" "Original state restored"

# -- Per-tunnel summary -----------------------------------------------------
Write-Host ""
Write-Host "  ---- Per-Tunnel Summary ----" -ForegroundColor Cyan
Write-Host ""
Write-Host ("  {0,-30} {1,-12} {2,6} {3,6}" -f "TUNNEL", "PROTOCOL", "PASS", "FAIL") -ForegroundColor White
Write-Host ("  " + ("-" * 56)) -ForegroundColor DarkGray
foreach ($tr in $tunnelResults) {
    $color = if ($tr.Failed -gt 0) { "Red" } else { "Green" }
    Write-Host ("  {0,-30} {1,-12} {2,6} {3,6}" -f $tr.ID, $tr.Protocol, $tr.Passed, $tr.Failed) -ForegroundColor $color
}
Write-Host ""

Write-TestSummary
