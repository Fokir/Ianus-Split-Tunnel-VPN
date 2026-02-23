# 11_full_diag.ps1 -- Full diagnostic suite (awg-diag full).
# Runs the built-in combined test and validates all results.

. "$PSScriptRoot\_common.ps1"
Reset-TestCounters
Write-TestHeader "11: Full Diagnostic Suite"

Write-Info "Running awg-diag full (combined network tests)..."
$result = Invoke-Diag -Arguments @("full") -TimeoutSec 60

if ($result.Json -and $result.Json -is [array]) {
    $totalTests = $result.Json.Count
    $passedTests = ($result.Json | Where-Object { $_.success }).Count
    $failedTests = $totalTests - $passedTests

    Write-Info "Full suite: $passedTests/$totalTests passed"

    foreach ($test in $result.Json) {
        $detail = if ($test.details) { $test.details } else { $test.error }
        $latency = if ($test.latency_ms) { " ($($test.latency_ms)ms)" } else { "" }

        if ($test.success) {
            Write-Pass "full:$($test.name)" "${detail}${latency}"
        } else {
            Write-Fail "full:$($test.name)" "${detail}${latency}"
        }
    }
} else {
    # Fallback: raw text output.
    $raw = if ($result.Stdout) { $result.Stdout } else { $result.Stderr }
    if ($result.ExitCode -eq 0) {
        Write-Pass "full:suite" "Completed (raw output, JSON parse failed)"
        Write-Info $raw
    } else {
        Write-Fail "full:suite" "Failed: $raw"
    }
}

Write-TestSummary
