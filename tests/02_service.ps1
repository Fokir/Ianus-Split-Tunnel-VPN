# 02_service.ps1 -- Service management tests.
# Verifies service start/stop/status via awg-diag.

. "$PSScriptRoot\_common.ps1"
Reset-TestCounters
Write-TestHeader "02: Service Management"

# ── Service Status ─────────────────────────────────────────────────────────
Write-Info "Checking service status..."
$result = Invoke-Diag -Arguments @("service", "status")

if ($result.ExitCode -eq 0 -and $result.Json) {
    Write-Pass "service:status" "installed=$($result.Json.installed), running=$($result.Json.running)"

    if (-not $result.Json.installed) {
        Write-Skip "service:start" "Service not installed -- install first"
        Write-Skip "service:tunnel-connect" "Service not installed"
        Write-TestSummary
        return
    }

    # ── Start Service (if not running) ─────────────────────────────────────
    if (-not $result.Json.running) {
        Write-Info "Starting service..."
        $startResult = Invoke-DiagRaw -Arguments @("service", "start") -TimeoutSec 30

        if ($startResult.ExitCode -eq 0) {
            Write-Pass "service:start" "Service started"
        } else {
            Write-Fail "service:start" "Failed: $($startResult.Stderr)"
            Write-TestSummary
            return
        }

        # Wait for service to become ready.
        Start-Sleep -Seconds 3
    } else {
        Write-Pass "service:start" "Already running"
    }

    # ── Verify Running ─────────────────────────────────────────────────────
    $statusCheck = Invoke-Diag -Arguments @("service", "status")
    if ($statusCheck.Json -and $statusCheck.Json.running) {
        Write-Pass "service:running" "Confirmed running"

        if ($statusCheck.Json.uptime_seconds) {
            Write-Info "Uptime: $($statusCheck.Json.uptime_seconds)s"
        }
        if ($statusCheck.Json.active_tunnels -ne $null) {
            Write-Info "Active tunnels: $($statusCheck.Json.active_tunnels)/$($statusCheck.Json.total_tunnels)"
        }
    } else {
        Write-Fail "service:running" "Service not running after start"
    }

} else {
    Write-Fail "service:status" "Failed to get status: $($result.Stderr)"
}

# ── List Tunnels ───────────────────────────────────────────────────────────
Write-Info "Listing configured tunnels..."
$tunnels = Invoke-Diag -Arguments @("config", "list-tunnels")

if ($tunnels.Json) {
    $count = if ($tunnels.Json -is [array]) { $tunnels.Json.Count } else { 1 }
    Write-Pass "config:list-tunnels" "$count tunnel(s) configured"

    foreach ($t in $tunnels.Json) {
        Write-Info "  $($t.id) ($($t.protocol)) -- $($t.status)"
    }

    # Check if any tunnel is UP.
    $upTunnels = @($tunnels.Json | Where-Object { $_.status -eq "TUNNEL_UP" -or $_.status -eq "up" })
    if ($upTunnels.Count -gt 0) {
        Write-Pass "tunnel:connected" "$($upTunnels.Count) tunnel(s) connected"
        # Export first active tunnel ID for use by other tests.
        $env:AWG_TEST_TUNNEL_ID = $upTunnels[0].id
        Write-Info "Active tunnel for tests: $($env:AWG_TEST_TUNNEL_ID)"
    } else {
        Write-Fail "tunnel:connected" "No tunnels in UP state"
    }
} else {
    Write-Fail "config:list-tunnels" "Failed: $($tunnels.Stderr)"
}

Write-TestSummary
