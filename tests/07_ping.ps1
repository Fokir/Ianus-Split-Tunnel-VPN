# 07_ping.ps1 -- ICMP ping tests through VPN tunnel.
# Uses system ping since awg-diag doesn't have a built-in ping command.

. "$PSScriptRoot\_common.ps1"
Reset-TestCounters
Write-TestHeader "07: ICMP Ping"

# ── Ping targets ───────────────────────────────────────────────────────────
$targets = @(
    @{ Host="1.1.1.1";         Name="Cloudflare" },
    @{ Host="8.8.8.8";         Name="Google DNS" },
    @{ Host="google.com";      Name="google.com" },
    @{ Host="github.com";      Name="github.com" }
)

foreach ($target in $targets) {
    Write-Info "Pinging $($target.Name) ($($target.Host))..."

    try {
        # Use Test-Connection (PowerShell cmdlet) with count=3, timeout=5s.
        $pingResults = Test-Connection -ComputerName $target.Host -Count 3 -BufferSize 32 -ErrorAction Stop

        if ($pingResults) {
            # PowerShell 5.x returns Win32_PingStatus, 7.x returns different object.
            $avgMs = ($pingResults | ForEach-Object {
                if ($_.ResponseTime) { $_.ResponseTime }
                elseif ($_.Latency) { $_.Latency }
                else { 0 }
            } | Measure-Object -Average).Average

            $successCount = ($pingResults | Where-Object {
                ($_.StatusCode -eq 0) -or ($_.Status -eq "Success") -or ($_.ResponseTime -ge 0)
            }).Count

            if ($successCount -gt 0) {
                Write-Pass "ping:$($target.Host)" "$($target.Name) -- $successCount/3 replies, avg ${avgMs}ms"
            } else {
                Write-Fail "ping:$($target.Host)" "$($target.Name) -- 0/3 replies"
            }
        } else {
            Write-Fail "ping:$($target.Host)" "$($target.Name) -- no response"
        }
    } catch {
        Write-Fail "ping:$($target.Host)" "$($target.Name) -- $_"
    }
}

# ── Ping unreachable (TEST-NET, should fail) ───────────────────────────────
Write-Info "Pinging unreachable host (192.0.2.1)..."
try {
    $pingResult = Test-Connection -ComputerName "192.0.2.1" -Count 1 -BufferSize 32 -ErrorAction SilentlyContinue

    $success = $false
    if ($pingResult) {
        $success = ($pingResult.StatusCode -eq 0) -or ($pingResult.Status -eq "Success")
    }

    if (-not $success) {
        Write-Pass "ping:unreachable" "Correctly failed (no response from TEST-NET)"
    } else {
        Write-Fail "ping:unreachable" "Unexpectedly reachable"
    }
} catch {
    Write-Pass "ping:unreachable" "Correctly failed: $_"
}

Write-TestSummary
