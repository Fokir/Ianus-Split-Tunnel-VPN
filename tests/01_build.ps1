# 01_build.ps1 -- Build verification tests.
# Builds the project and verifies output binaries exist.

param(
    [switch]$SkipBuild
)

. "$PSScriptRoot\_common.ps1"
Reset-TestCounters
Write-TestHeader "01: Build Verification"

$BuildDir = $Script:BuildDir
$ProjectRoot = $Script:ProjectRoot

# ── Build ──────────────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    Write-Info "Building awg-diag.exe..."

    # Build only awg-diag and main service (skip UI/updater for test runs).
    $version = & git -C $ProjectRoot describe --tags --always --dirty 2>$null
    if (-not $version) { $version = "dev" }
    $commitHash = & git -C $ProjectRoot rev-parse --short HEAD 2>$null
    if (-not $commitHash) { $commitHash = "unknown" }
    $buildDate = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")

    $ldflags = "-s -w -X `"main.version=$version`" -X `"main.commit=$commitHash`" -X `"main.buildDate=$buildDate`""

    if (-not (Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
    }

    # Build main VPN service.
    Write-Info "go build awg-split-tunnel.exe..."
    $env:CGO_ENABLED = "0"
    $proc = Start-Process -FilePath "go" `
        -ArgumentList "build -ldflags `"$ldflags`" -o `"$BuildDir\awg-split-tunnel.exe`" ./cmd/awg-split-tunnel" `
        -WorkingDirectory $ProjectRoot `
        -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -eq 0) {
        Write-Pass "build:service" "awg-split-tunnel.exe built"
    } else {
        Write-Fail "build:service" "go build failed (exit code $($proc.ExitCode))"
    }

    # Build diag tool.
    Write-Info "go build awg-diag.exe..."
    $proc = Start-Process -FilePath "go" `
        -ArgumentList "build -ldflags `"$ldflags`" -o `"$BuildDir\awg-diag.exe`" ./cmd/awg-diag" `
        -WorkingDirectory $ProjectRoot `
        -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -eq 0) {
        Write-Pass "build:diag" "awg-diag.exe built"
    } else {
        Write-Fail "build:diag" "go build failed (exit code $($proc.ExitCode))"
    }

    # Copy wintun.dll if needed.
    $wintunDst = Join-Path $BuildDir "wintun.dll"
    $wintunSrc = Join-Path $ProjectRoot "dll\wintun.dll"
    if (-not (Test-Path $wintunDst) -and (Test-Path $wintunSrc)) {
        Copy-Item $wintunSrc $wintunDst
        Write-Info "Copied wintun.dll"
    }
} else {
    Write-Info "Skipping build (--SkipBuild)"
}

# ── Verify Binaries ───────────────────────────────────────────────────────
$binaries = @(
    @{ Name="awg-split-tunnel.exe"; Required=$true },
    @{ Name="awg-diag.exe";         Required=$true },
    @{ Name="wintun.dll";           Required=$true }
)

foreach ($bin in $binaries) {
    $path = Join-Path $BuildDir $bin.Name
    if (Test-Path $path) {
        $size = (Get-Item $path).Length
        Write-Pass "exists:$($bin.Name)" ("{0:N0} bytes" -f $size)
    } elseif ($bin.Required) {
        Write-Fail "exists:$($bin.Name)" "File not found in $BuildDir"
    } else {
        Write-Skip "exists:$($bin.Name)" "Optional, not found"
    }
}

# ── Version Check ──────────────────────────────────────────────────────────
$result = Invoke-DiagRaw -Arguments @("version")
if ($result.ExitCode -eq 0 -and $result.Stdout -match "awg-diag") {
    Write-Pass "diag:version" $result.Stdout
} else {
    Write-Fail "diag:version" "Failed to get version: $($result.Stderr)"
}

Write-TestSummary
