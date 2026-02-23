# _common.ps1 -- Shared test utilities for AWG Split Tunnel integration tests.
# Sourced by each test file and the main runner.

$ErrorActionPreference = "Stop"

# ── Resolve script directory (works from bash and PowerShell) ──────────────
$Script:TestsDir = $PSScriptRoot
if (-not $Script:TestsDir) {
    $Script:TestsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
if (-not $Script:TestsDir) {
    $Script:TestsDir = (Get-Location).Path
}

# ── Paths ──────────────────────────────────────────────────────────────────
$Script:ProjectRoot = Split-Path -Parent $Script:TestsDir
if (-not $Script:ProjectRoot) {
    $Script:ProjectRoot = Split-Path -Parent (Get-Location).Path
}
$Script:BuildDir    = Join-Path $Script:ProjectRoot "build"
$Script:DiagExe     = Join-Path $Script:BuildDir "awg-diag.exe"
$Script:ServiceExe  = Join-Path $Script:BuildDir "awg-split-tunnel.exe"
$Script:ConfigPath  = Join-Path $Script:BuildDir "config.yaml"

# ── Counters ───────────────────────────────────────────────────────────────
$Script:TestsPassed = 0
$Script:TestsFailed = 0
$Script:TestsSkipped = 0
$Script:TestResults = @()

# ── Colors ─────────────────────────────────────────────────────────────────
function Write-TestHeader($title) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Pass($name, $detail) {
    $Script:TestsPassed++
    $Script:TestResults += @{ Name=$name; Status="PASS"; Detail=$detail }
    Write-Host "  [PASS] $name" -ForegroundColor Green
    if ($detail) { Write-Host "         $detail" -ForegroundColor DarkGray }
}

function Write-Fail($name, $detail) {
    $Script:TestsFailed++
    $Script:TestResults += @{ Name=$name; Status="FAIL"; Detail=$detail }
    Write-Host "  [FAIL] $name" -ForegroundColor Red
    if ($detail) { Write-Host "         $detail" -ForegroundColor Yellow }
}

function Write-Skip($name, $reason) {
    $Script:TestsSkipped++
    $Script:TestResults += @{ Name=$name; Status="SKIP"; Detail=$reason }
    Write-Host "  [SKIP] $name" -ForegroundColor DarkYellow
    if ($reason) { Write-Host "         $reason" -ForegroundColor DarkGray }
}

function Write-Info($msg) {
    Write-Host "  [INFO] $msg" -ForegroundColor DarkGray
}

# ── Diag Runner ────────────────────────────────────────────────────────────

# Invoke awg-diag.exe with --json and parse the output.
# Returns a PSObject from the JSON response.
function Invoke-Diag {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [int]$TimeoutSec = 30
    )

    if (-not (Test-Path $Script:DiagExe)) {
        throw "awg-diag.exe not found at $($Script:DiagExe). Run build first."
    }

    $allArgs = @("--json", "--config", $Script:ConfigPath, "--timeout", "${TimeoutSec}s") + $Arguments

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Script:DiagExe
    $psi.Arguments = $allArgs -join " "
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit([Math]::Max($TimeoutSec * 1000 + 5000, 35000))

    $exitCode = $proc.ExitCode

    $result = @{
        ExitCode = $exitCode
        Stdout   = $stdout.Trim()
        Stderr   = $stderr.Trim()
        Json     = $null
    }

    # Try to parse JSON from stdout.
    if ($stdout.Trim()) {
        try {
            $result.Json = $stdout.Trim() | ConvertFrom-Json
        } catch {
            # Not JSON -- leave as raw text.
        }
    }

    return $result
}

# Invoke awg-diag.exe without --json (raw text output).
function Invoke-DiagRaw {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [int]$TimeoutSec = 30
    )

    if (-not (Test-Path $Script:DiagExe)) {
        throw "awg-diag.exe not found at $($Script:DiagExe). Run build first."
    }

    $allArgs = @("--config", $Script:ConfigPath, "--timeout", "${TimeoutSec}s") + $Arguments

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Script:DiagExe
    $psi.Arguments = $allArgs -join " "
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit([Math]::Max($TimeoutSec * 1000 + 5000, 35000))

    return @{
        ExitCode = $proc.ExitCode
        Stdout   = $stdout.Trim()
        Stderr   = $stderr.Trim()
    }
}

# ── Service Helpers ────────────────────────────────────────────────────────

function Test-ServiceRunning {
    $result = Invoke-Diag -Arguments @("service", "status") -TimeoutSec 10
    if ($result.Json -and $result.Json.running) {
        return $true
    }
    return $false
}

function Get-RealIP {
    # Get external IP without VPN (direct request).
    try {
        $response = Invoke-WebRequest -Uri "https://api.ipify.org" -TimeoutSec 10 -UseBasicParsing
        return $response.Content.Trim()
    } catch {
        return $null
    }
}

# ── Summary ────────────────────────────────────────────────────────────────

function Write-TestSummary {
    $total = $Script:TestsPassed + $Script:TestsFailed + $Script:TestsSkipped
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  TEST SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Total:   $total" -ForegroundColor White
    Write-Host "  Passed:  $($Script:TestsPassed)" -ForegroundColor Green
    Write-Host "  Failed:  $($Script:TestsFailed)" -ForegroundColor $(if ($Script:TestsFailed -gt 0) { "Red" } else { "Green" })
    Write-Host "  Skipped: $($Script:TestsSkipped)" -ForegroundColor DarkYellow
    Write-Host ""

    if ($Script:TestsFailed -gt 0) {
        Write-Host "  FAILED TESTS:" -ForegroundColor Red
        foreach ($r in $Script:TestResults) {
            if ($r.Status -eq "FAIL") {
                Write-Host "    - $($r.Name): $($r.Detail)" -ForegroundColor Red
            }
        }
        Write-Host ""
    }

    return $Script:TestsFailed -eq 0
}

# Reset counters (called at start of each test file).
function Reset-TestCounters {
    $Script:TestsPassed = 0
    $Script:TestsFailed = 0
    $Script:TestsSkipped = 0
    $Script:TestResults = @()
}
