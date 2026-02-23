# 04_dns.ps1 -- DNS resolution tests.
# Tests DNS through system resolver and custom servers.

. "$PSScriptRoot\_common.ps1"
Reset-TestCounters
Write-TestHeader "04: DNS Resolution"

# ── System DNS ─────────────────────────────────────────────────────────────
Write-Info "Testing DNS resolution via system resolver..."
$result = Invoke-Diag -Arguments @("dns", "google.com")

if ($result.Json -and $result.Json.success) {
    Write-Pass "dns:system:google.com" "Resolved: $($result.Json.details) ($($result.Json.latency_ms)ms)"
} else {
    $errMsg = if ($result.Json) { $result.Json.error } else { $result.Stderr }
    Write-Fail "dns:system:google.com" "Failed: $errMsg"
}

# ── Custom DNS Server (8.8.8.8) ───────────────────────────────────────────
Write-Info "Testing DNS via Google DNS (8.8.8.8)..."
$result = Invoke-Diag -Arguments @("dns", "google.com", "--server", "8.8.8.8")

if ($result.Json -and $result.Json.success) {
    Write-Pass "dns:google:google.com" "Resolved: $($result.Json.details) ($($result.Json.latency_ms)ms)"
} else {
    $errMsg = if ($result.Json) { $result.Json.error } else { $result.Stderr }
    Write-Fail "dns:google:google.com" "Failed: $errMsg"
}

# ── Custom DNS Server (1.1.1.1) ───────────────────────────────────────────
Write-Info "Testing DNS via Cloudflare (1.1.1.1)..."
$result = Invoke-Diag -Arguments @("dns", "cloudflare.com", "--server", "1.1.1.1")

if ($result.Json -and $result.Json.success) {
    Write-Pass "dns:cloudflare:cloudflare.com" "Resolved: $($result.Json.details) ($($result.Json.latency_ms)ms)"
} else {
    $errMsg = if ($result.Json) { $result.Json.error } else { $result.Stderr }
    Write-Fail "dns:cloudflare:cloudflare.com" "Failed: $errMsg"
}

# ── Resolve multiple domains ──────────────────────────────────────────────
$domains = @("github.com", "stackoverflow.com", "example.com")

foreach ($domain in $domains) {
    Write-Info "Resolving $domain..."
    $result = Invoke-Diag -Arguments @("dns", $domain)

    if ($result.Json -and $result.Json.success) {
        Write-Pass "dns:resolve:$domain" "$($result.Json.details) ($($result.Json.latency_ms)ms)"
    } else {
        $errMsg = if ($result.Json) { $result.Json.error } else { $result.Stderr }
        Write-Fail "dns:resolve:$domain" "Failed: $errMsg"
    }
}

# ── NXDOMAIN test (non-existent domain) ───────────────────────────────────
Write-Info "Testing NXDOMAIN (non-existent domain)..."
$result = Invoke-Diag -Arguments @("dns", "this-domain-should-not-exist-12345.test")

if ($result.Json -and -not $result.Json.success) {
    Write-Pass "dns:nxdomain" "Correctly failed: $($result.Json.error)"
} elseif ($result.Json -and $result.Json.success) {
    Write-Fail "dns:nxdomain" "Resolved unexpectedly: $($result.Json.details)"
} else {
    Write-Pass "dns:nxdomain" "Correctly returned error"
}

Write-TestSummary
