# 09_https.ps1 -- HTTPS connectivity tests through VPN tunnel.

. "$PSScriptRoot\_common.ps1"
Reset-TestCounters
Write-TestHeader "09: HTTPS Connectivity"

# ── HTTPS GET tests ────────────────────────────────────────────────────────
$urls = @(
    @{ Url="https://httpbin.org/ip";          Name="httpbin HTTPS" },
    @{ Url="https://api.ipify.org";           Name="ipify HTTPS" },
    @{ Url="https://www.google.com";          Name="Google" },
    @{ Url="https://github.com";              Name="GitHub" },
    @{ Url="https://cloudflare.com";          Name="Cloudflare" }
)

foreach ($target in $urls) {
    Write-Info "HTTPS GET $($target.Name) ($($target.Url))..."
    $result = Invoke-Diag -Arguments @("http", $target.Url) -TimeoutSec 15

    if ($result.Json -and $result.Json.success) {
        Write-Pass "https:$($target.Name)" "$($result.Json.details) ($($result.Json.latency_ms)ms)"
    } else {
        $errMsg = if ($result.Json) { $result.Json.error } else { $result.Stderr }
        Write-Fail "https:$($target.Name)" "$errMsg"
    }
}

# ── TLS to known port (TCP level) ─────────────────────────────────────────
Write-Info "TCP handshake to HTTPS endpoints..."
$tlsTargets = @(
    @{ Addr="1.1.1.1:443";   Name="Cloudflare" },
    @{ Addr="8.8.8.8:443";   Name="Google" }
)

foreach ($target in $tlsTargets) {
    $result = Invoke-Diag -Arguments @("tcp", $target.Addr) -TimeoutSec 10
    if ($result.Json -and $result.Json.success) {
        Write-Pass "tls-tcp:$($target.Name)" "$($result.Json.details)"
    } else {
        $errMsg = if ($result.Json) { $result.Json.error } else { $result.Stderr }
        Write-Fail "tls-tcp:$($target.Name)" "$errMsg"
    }
}

Write-TestSummary
