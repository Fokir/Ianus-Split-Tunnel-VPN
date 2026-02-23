# 08_http.ps1 -- HTTP connectivity tests through VPN tunnel.

. "$PSScriptRoot\_common.ps1"
Reset-TestCounters
Write-TestHeader "08: HTTP Connectivity"

# ── HTTP GET tests ─────────────────────────────────────────────────────────
$urls = @(
    @{ Url="http://httpbin.org/get";       Name="httpbin HTTP" },
    @{ Url="http://example.com";           Name="example.com" },
    @{ Url="http://ifconfig.me/ip";        Name="ifconfig.me (IP)" }
)

foreach ($target in $urls) {
    Write-Info "HTTP GET $($target.Name) ($($target.Url))..."
    $result = Invoke-Diag -Arguments @("http", $target.Url) -TimeoutSec 15

    if ($result.Json -and $result.Json.success) {
        Write-Pass "http:$($target.Name)" "$($result.Json.details) ($($result.Json.latency_ms)ms)"
    } else {
        $errMsg = if ($result.Json) { $result.Json.error } else { $result.Stderr }
        Write-Fail "http:$($target.Name)" "$errMsg"
    }
}

Write-TestSummary
