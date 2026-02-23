# 03_ip_change.ps1 -- Verify that VPN changes the external IP address.
# Compares IP before VPN (direct) with IP through VPN tunnel.

. "$PSScriptRoot\_common.ps1"
Reset-TestCounters
Write-TestHeader "03: IP Change Verification"

# ── Check External IP Through VPN ──────────────────────────────────────────
Write-Info "Getting external IP through VPN (via awg-diag check-ip)..."
$vpnResult = Invoke-Diag -Arguments @("check-ip") -TimeoutSec 15

if ($vpnResult.Json -and $vpnResult.Json.success) {
    $vpnIP = $vpnResult.Json.details
    Write-Pass "check-ip:vpn" "VPN IP: $vpnIP (latency: $($vpnResult.Json.latency_ms)ms)"

    # ── Get Direct IP (bypassing VPN) ──────────────────────────────────────
    # Use PowerShell's own HTTP client which may bypass the TUN adapter
    # depending on whether PowerShell is routed through VPN.
    Write-Info "Getting external IP directly (PowerShell web request)..."
    $directIP = $null
    try {
        $response = Invoke-WebRequest -Uri "https://api.ipify.org" -TimeoutSec 10 -UseBasicParsing
        $directIP = $response.Content.Trim()
        Write-Info "Direct IP: $directIP"
    } catch {
        Write-Info "Could not get direct IP: $_"
    }

    # ── Compare ────────────────────────────────────────────────────────────
    if ($directIP) {
        if ($vpnIP -ne $directIP) {
            Write-Pass "ip:changed" "VPN=$vpnIP differs from Direct=$directIP"
        } else {
            Write-Fail "ip:changed" "IPs are the same ($vpnIP) -- VPN may not be routing awg-diag traffic"
        }
    } else {
        Write-Skip "ip:changed" "Could not get direct IP for comparison"
        Write-Info "VPN IP obtained: $vpnIP -- manual verification needed"
    }

    # ── Validate IP Format ─────────────────────────────────────────────────
    if ($vpnIP -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        Write-Pass "ip:format" "Valid IPv4 format"
    } else {
        Write-Fail "ip:format" "Unexpected format: $vpnIP"
    }

} else {
    $errMsg = if ($vpnResult.Json) { $vpnResult.Json.error } else { $vpnResult.Stderr }
    Write-Fail "check-ip:vpn" "Failed: $errMsg"
    Write-Skip "ip:changed" "Cannot compare without VPN IP"
}

# ── HTTP-based IP Check (alternative endpoint) ────────────────────────────
Write-Info "Cross-checking with httpbin.org..."
$httpResult = Invoke-Diag -Arguments @("http", "https://httpbin.org/ip") -TimeoutSec 15

if ($httpResult.Json -and $httpResult.Json.success) {
    Write-Pass "check-ip:httpbin" "HTTP IP check: $($httpResult.Json.details)"
} else {
    $errMsg = if ($httpResult.Json) { $httpResult.Json.error } else { $httpResult.Stderr }
    Write-Fail "check-ip:httpbin" "Failed: $errMsg"
}

Write-TestSummary
