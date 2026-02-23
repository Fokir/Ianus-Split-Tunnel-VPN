# 06_udp.ps1 -- UDP connectivity tests through VPN tunnel.

. "$PSScriptRoot\_common.ps1"
Reset-TestCounters
Write-TestHeader "06: UDP Connectivity"

# ── UDP DNS query to well-known servers ────────────────────────────────────
$dnsServers = @(
    @{ Addr="8.8.8.8:53";   Name="Google DNS" },
    @{ Addr="1.1.1.1:53";   Name="Cloudflare DNS" },
    @{ Addr="9.9.9.9:53";   Name="Quad9 DNS" }
)

foreach ($server in $dnsServers) {
    Write-Info "UDP DNS query to $($server.Name) ($($server.Addr))..."
    # Default payload is a DNS root query -- perfect for testing UDP.
    $result = Invoke-Diag -Arguments @("udp", $server.Addr) -TimeoutSec 10

    if ($result.Json -and $result.Json.success) {
        Write-Pass "udp:$($server.Addr)" "$($server.Name) -- $($result.Json.details) ($($result.Json.latency_ms)ms)"
    } else {
        $errMsg = if ($result.Json) { $result.Json.error } else { $result.Stderr }
        Write-Fail "udp:$($server.Addr)" "$($server.Name) -- $errMsg"
    }
}

# ── UDP to non-responding endpoint (should timeout) ────────────────────────
Write-Info "UDP to non-responding endpoint (should timeout)..."
$result = Invoke-Diag -Arguments @("udp", "192.0.2.1:9999") -TimeoutSec 5

if ($result.Json -and -not $result.Json.success) {
    Write-Pass "udp:timeout" "Correctly timed out: $($result.Json.error)"
} elseif ($result.Json -and $result.Json.success) {
    Write-Fail "udp:timeout" "Unexpectedly received response from TEST-NET"
} else {
    Write-Pass "udp:timeout" "Correctly returned error"
}

Write-TestSummary
