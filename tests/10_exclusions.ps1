# 10_exclusions.ps1 -- Exclusion/routing rules tests.
# Verifies that:
#   1. awg-diag.exe routed through VPN gets VPN IP
#   2. Adding awg-diag.exe to disallowed_apps excludes it from VPN
#   3. Config rule add/remove works correctly

. "$PSScriptRoot\_common.ps1"
Reset-TestCounters
Write-TestHeader "10: Exclusion Rules"

$ConfigPath = $Script:ConfigPath

# ── Prerequisite: get VPN IP first ─────────────────────────────────────────
Write-Info "Step 1: Getting current IP through VPN..."
$vpnResult = Invoke-Diag -Arguments @("check-ip") -TimeoutSec 15

if (-not ($vpnResult.Json -and $vpnResult.Json.success)) {
    $errMsg = if ($vpnResult.Json) { $vpnResult.Json.error } else { $vpnResult.Stderr }
    Write-Fail "exclusion:precondition" "Cannot get VPN IP: $errMsg"
    Write-Skip "exclusion:add-rule" "Skipped -- no VPN IP"
    Write-Skip "exclusion:verify-excluded" "Skipped"
    Write-Skip "exclusion:remove-rule" "Skipped"
    Write-Skip "exclusion:verify-restored" "Skipped"
    Write-TestSummary
    return
}

$vpnIP = $vpnResult.Json.details
Write-Pass "exclusion:vpn-ip" "VPN IP: $vpnIP"

# ── Backup config ──────────────────────────────────────────────────────────
$configBackup = "$ConfigPath.test-backup"
Write-Info "Backing up config..."
Copy-Item $ConfigPath $configBackup -Force

try {
    # ── Add awg-diag.exe to disallowed_apps ────────────────────────────────
    Write-Info "Step 2: Adding awg-diag.exe to global disallowed_apps..."

    # Read current config, add exclusion, write back.
    $configContent = Get-Content $ConfigPath -Raw

    # Parse YAML manually -- add disallowed_apps entry.
    # We need to add "awg-diag.exe" to global.disallowed_apps.
    if ($configContent -match 'disallowed_apps:') {
        # Section exists -- append entry.
        $configContent = $configContent -replace '(disallowed_apps:\s*\n)', "`$1    - `"awg-diag.exe`"`n"
    } else {
        # Add global section with disallowed_apps.
        if ($configContent -match 'global:') {
            $configContent = $configContent -replace '(global:\s*\n)', "`$1  disallowed_apps:`n    - `"awg-diag.exe`"`n"
        } else {
            $configContent = "global:`n  disallowed_apps:`n    - `"awg-diag.exe`"`n" + $configContent
        }
    }

    Set-Content -Path $ConfigPath -Value $configContent -NoNewline
    Write-Pass "exclusion:add-rule" "Added awg-diag.exe to disallowed_apps"

    # Wait for config reload (service watches config file).
    Write-Info "Waiting for config reload..."
    Start-Sleep -Seconds 5

    # ── Verify exclusion works ─────────────────────────────────────────────
    Write-Info "Step 3: Checking IP with exclusion active..."
    $excludedResult = Invoke-Diag -Arguments @("check-ip") -TimeoutSec 15

    if ($excludedResult.Json -and $excludedResult.Json.success) {
        $excludedIP = $excludedResult.Json.details
        Write-Info "IP with exclusion: $excludedIP"

        if ($excludedIP -ne $vpnIP) {
            Write-Pass "exclusion:verify-excluded" "IP changed from $vpnIP to $excludedIP (exclusion working)"
        } else {
            Write-Fail "exclusion:verify-excluded" "IP still $vpnIP -- exclusion may not have taken effect yet"
        }
    } else {
        $errMsg = if ($excludedResult.Json) { $excludedResult.Json.error } else { $excludedResult.Stderr }
        Write-Fail "exclusion:verify-excluded" "Failed to get IP: $errMsg"
    }

} finally {
    # ── Restore config ─────────────────────────────────────────────────────
    Write-Info "Step 4: Restoring original config..."
    Copy-Item $configBackup $ConfigPath -Force
    Remove-Item $configBackup -Force -ErrorAction SilentlyContinue
    Write-Pass "exclusion:restore-config" "Config restored"

    # Wait for reload.
    Start-Sleep -Seconds 5

    # ── Verify VPN routing restored ────────────────────────────────────────
    Write-Info "Step 5: Verifying VPN routing restored..."
    $restoredResult = Invoke-Diag -Arguments @("check-ip") -TimeoutSec 15

    if ($restoredResult.Json -and $restoredResult.Json.success) {
        $restoredIP = $restoredResult.Json.details
        if ($restoredIP -eq $vpnIP) {
            Write-Pass "exclusion:verify-restored" "IP back to VPN: $restoredIP"
        } else {
            Write-Fail "exclusion:verify-restored" "IP is $restoredIP, expected $vpnIP"
        }
    } else {
        $errMsg = if ($restoredResult.Json) { $restoredResult.Json.error } else { $restoredResult.Stderr }
        Write-Fail "exclusion:verify-restored" "Failed: $errMsg"
    }
}

# ── Test config rule management ────────────────────────────────────────────
Write-TestHeader "10b: Config Rule Management"

Write-Info "Testing config add-rule / remove-rule..."

# Show current rules.
$rules = Invoke-Diag -Arguments @("config", "show-rules")
$initialCount = 0
if ($rules.Json -and $rules.Json -is [array]) {
    $initialCount = $rules.Json.Count
}
Write-Info "Current rules: $initialCount"

# Add a test rule.
$testPattern = "__test_exclusion_pattern__"
$tunnelId = if ($env:AWG_TEST_TUNNEL_ID) { $env:AWG_TEST_TUNNEL_ID } else { "__direct__" }

$addResult = Invoke-DiagRaw -Arguments @("config", "add-rule", "--pattern", $testPattern, "--tunnel", $tunnelId, "--fallback", "block")
if ($addResult.ExitCode -eq 0) {
    Write-Pass "rule:add" "Added test rule: $testPattern -> $tunnelId"
} else {
    Write-Fail "rule:add" "Failed: $($addResult.Stderr)"
}

# Verify rule was added.
$rules = Invoke-Diag -Arguments @("config", "show-rules")
$found = $false
if ($rules.Json -and $rules.Json -is [array]) {
    foreach ($r in $rules.Json) {
        if ($r.pattern -eq $testPattern) {
            $found = $true
            break
        }
    }
}
if ($found) {
    Write-Pass "rule:verify-added" "Rule found in config"
} else {
    Write-Fail "rule:verify-added" "Rule not found after add"
}

# Remove the test rule.
$removeResult = Invoke-DiagRaw -Arguments @("config", "remove-rule", "--pattern", $testPattern)
if ($removeResult.ExitCode -eq 0) {
    Write-Pass "rule:remove" "Removed test rule"
} else {
    Write-Fail "rule:remove" "Failed: $($removeResult.Stderr)"
}

# Verify rule was removed.
$rules = Invoke-Diag -Arguments @("config", "show-rules")
$found = $false
if ($rules.Json -and $rules.Json -is [array]) {
    foreach ($r in $rules.Json) {
        if ($r.pattern -eq $testPattern) {
            $found = $true
            break
        }
    }
}
if (-not $found) {
    Write-Pass "rule:verify-removed" "Rule correctly removed"
} else {
    Write-Fail "rule:verify-removed" "Rule still present after remove"
}

Write-TestSummary
