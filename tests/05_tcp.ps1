# 05_tcp.ps1 -- TCP connectivity tests through VPN tunnel.

. "$PSScriptRoot\_common.ps1"
Reset-TestCounters
Write-TestHeader "05: TCP Connectivity"

# ── TCP to well-known services ────────────────────────────────────────────
$targets = @(
    @{ Addr="1.1.1.1:443";      Name="Cloudflare HTTPS" },
    @{ Addr="8.8.8.8:53";       Name="Google DNS" },
    @{ Addr="8.8.8.8:443";      Name="Google HTTPS" },
    @{ Addr="93.184.216.34:80"; Name="example.com HTTP" },
    @{ Addr="140.82.121.4:443"; Name="GitHub HTTPS" }
)

foreach ($target in $targets) {
    Write-Info "TCP connect to $($target.Name) ($($target.Addr))..."
    $result = Invoke-Diag -Arguments @("tcp", $target.Addr) -TimeoutSec 15

    if ($result.Json -and $result.Json.success) {
        Write-Pass "tcp:$($target.Addr)" "$($target.Name) -- $($result.Json.details)"
    } else {
        $errMsg = if ($result.Json) { $result.Json.error } else { $result.Stderr }
        Write-Fail "tcp:$($target.Addr)" "$($target.Name) -- $errMsg"
    }
}

# ── TCP to unreachable port (should fail) ──────────────────────────────────
Write-Info "TCP to unreachable port (should timeout/fail)..."
$result = Invoke-Diag -Arguments @("tcp", "192.0.2.1:12345") -TimeoutSec 5

if ($result.Json -and -not $result.Json.success) {
    Write-Pass "tcp:unreachable" "Correctly failed: $($result.Json.error)"
} elseif ($result.Json -and $result.Json.success) {
    Write-Fail "tcp:unreachable" "Unexpectedly connected to TEST-NET address"
} else {
    Write-Pass "tcp:unreachable" "Correctly returned error"
}

Write-TestSummary
