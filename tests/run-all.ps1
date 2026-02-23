# run-all.ps1 -- Main test runner for AWG Split Tunnel.
# Builds the project, then runs all integration tests in sequence.
#
# Usage:
#   .\tests\run-all.ps1                  # Build + run all tests
#   .\tests\run-all.ps1 -SkipBuild       # Skip build, run tests only
#   .\tests\run-all.ps1 -Only 03,05      # Run only specific test files
#   .\tests\run-all.ps1 -From 05         # Run from test 05 onwards
#   .\tests\run-all.ps1 -SkipService     # Skip service-dependent tests (03-11)

[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$SkipService,
    [string]$Only,          # Comma-separated test numbers: "03,05,08"
    [string]$From           # Start from test number: "05"
)

$ErrorActionPreference = "Stop"
$startTime = Get-Date

# ── Resolve script directory (works from bash and PowerShell) ──────────────
$testDir = $PSScriptRoot
if (-not $testDir) {
    $testDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
if (-not $testDir) {
    $testDir = (Get-Location).Path
}

# ── Banner ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  AWG Split Tunnel - Integration Test Suite" -ForegroundColor Magenta
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "  Test dir: $testDir" -ForegroundColor DarkGray
Write-Host ""

# ── Discover test files ────────────────────────────────────────────────────
$allTests = Get-ChildItem -Path $testDir -Filter "*.ps1" |
    Where-Object { $_.Name -match '^\d{2}_' } |
    Sort-Object Name

# Filter tests by --Only or --From.
if ($Only) {
    $numbers = $Only -split ',' | ForEach-Object { $_.Trim().PadLeft(2, '0') }
    $allTests = $allTests | Where-Object { $_.Name.Substring(0,2) -in $numbers }
}
if ($From) {
    $fromNum = $From.PadLeft(2, '0')
    $allTests = $allTests | Where-Object { $_.Name.Substring(0,2) -ge $fromNum }
}

Write-Host "  Tests to run: $($allTests.Count)" -ForegroundColor White
foreach ($t in $allTests) {
    Write-Host "    - $($t.Name)" -ForegroundColor DarkGray
}
Write-Host ""

# ── Tracking ───────────────────────────────────────────────────────────────
$globalPassed = 0
$globalFailed = 0
$globalSkipped = 0
$fileResults = @()

# ── Run tests ──────────────────────────────────────────────────────────────
foreach ($testFile in $allTests) {
    $testNum = $testFile.Name.Substring(0, 2)

    # Skip service-dependent tests if requested.
    if ($SkipService -and [int]$testNum -ge 2 -and $testFile.Name -ne "01_build.ps1") {
        Write-Host "  [SKIP] $($testFile.Name) (--SkipService)" -ForegroundColor DarkYellow
        $globalSkipped++
        $fileResults += @{ File=$testFile.Name; Status="SKIPPED"; Passed=0; Failed=0; Skipped=0 }
        continue
    }

    # Pass -SkipBuild to build test if requested.
    $extraArgs = @{}
    if ($testFile.Name -eq "01_build.ps1" -and $SkipBuild) {
        $extraArgs["SkipBuild"] = $true
    }

    try {
        # Run test file in a child scope to isolate variables.
        # Capture the test counters from the common module.
        $result = & {
            . $testFile.FullName @extraArgs

            # Return counters from _common.ps1.
            return @{
                Passed  = $Script:TestsPassed
                Failed  = $Script:TestsFailed
                Skipped = $Script:TestsSkipped
            }
        }

        $p = if ($result.Passed) { $result.Passed } else { 0 }
        $f = if ($result.Failed) { $result.Failed } else { 0 }
        $s = if ($result.Skipped) { $result.Skipped } else { 0 }

        $globalPassed += $p
        $globalFailed += $f
        $globalSkipped += $s

        $status = if ($f -gt 0) { "FAILED" } elseif ($p -gt 0) { "PASSED" } else { "SKIPPED" }
        $fileResults += @{ File=$testFile.Name; Status=$status; Passed=$p; Failed=$f; Skipped=$s }

    } catch {
        Write-Host ""
        Write-Host "  [ERROR] $($testFile.Name) threw an exception:" -ForegroundColor Red
        Write-Host "          $_" -ForegroundColor Red
        Write-Host ""
        $globalFailed++
        $fileResults += @{ File=$testFile.Name; Status="ERROR"; Passed=0; Failed=1; Skipped=0 }
    }
}

# ── Global Summary ─────────────────────────────────────────────────────────
$elapsed = (Get-Date) - $startTime
$totalTests = $globalPassed + $globalFailed + $globalSkipped

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Magenta
Write-Host "  GLOBAL TEST SUMMARY" -ForegroundColor Magenta
Write-Host ("=" * 60) -ForegroundColor Magenta
Write-Host ""

# Per-file summary table.
Write-Host ("  {0,-25} {1,-10} {2,6} {3,6} {4,6}" -f "FILE", "STATUS", "PASS", "FAIL", "SKIP") -ForegroundColor White
Write-Host ("  " + ("-" * 55)) -ForegroundColor DarkGray
foreach ($fr in $fileResults) {
    $color = switch ($fr.Status) {
        "PASSED"  { "Green" }
        "FAILED"  { "Red" }
        "ERROR"   { "Red" }
        "SKIPPED" { "DarkYellow" }
        default   { "White" }
    }
    Write-Host ("  {0,-25} {1,-10} {2,6} {3,6} {4,6}" -f $fr.File, $fr.Status, $fr.Passed, $fr.Failed, $fr.Skipped) -ForegroundColor $color
}

Write-Host ""
Write-Host "  Total assertions:  $totalTests" -ForegroundColor White
Write-Host "  Passed:            $globalPassed" -ForegroundColor Green
Write-Host "  Failed:            $globalFailed" -ForegroundColor $(if ($globalFailed -gt 0) { "Red" } else { "Green" })
Write-Host "  Skipped:           $globalSkipped" -ForegroundColor DarkYellow
Write-Host "  Duration:          $($elapsed.ToString('mm\:ss\.fff'))" -ForegroundColor DarkGray
Write-Host ""

if ($globalFailed -gt 0) {
    Write-Host "  RESULT: FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "  RESULT: PASSED" -ForegroundColor Green
    exit 0
}
