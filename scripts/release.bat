@echo off
setlocal EnableDelayedExpansion

:: AWG Split Tunnel — Release build script
:: Builds all binaries, runs NSIS installer, creates release zip

:: Change to project root (parent of scripts/).
cd /d "%~dp0.."

set APP_NAME=awg-split-tunnel
set OUT_DIR=.\build
set NSIS_DIR=.\ui\build\windows\nsis

:: Get version from git tag.
for /f "delims=" %%i in ('git describe --tags --always --dirty 2^>nul') do set VERSION=%%i
if not defined VERSION set VERSION=dev

echo ============================================
echo  AWG Split Tunnel — Release Build
echo  Version: %VERSION%
echo ============================================
echo.

:: ── Step 1: Build all binaries ──────────────────────────────────────
echo [1/3] Building all binaries...
call "%~dp0..\build.bat"
if %ERRORLEVEL% NEQ 0 (
    echo Build FAILED
    exit /b 1
)

:: Verify all binaries exist.
if not exist "%OUT_DIR%\%APP_NAME%.exe" (
    echo ERROR: %APP_NAME%.exe not found
    exit /b 1
)
if not exist "%OUT_DIR%\%APP_NAME%-ui.exe" (
    echo ERROR: %APP_NAME%-ui.exe not found
    exit /b 1
)
if not exist "%OUT_DIR%\%APP_NAME%-updater.exe" (
    echo ERROR: %APP_NAME%-updater.exe not found
    exit /b 1
)

:: ── Step 2: Create NSIS installer ───────────────────────────────────
echo.
echo [2/3] Building NSIS installer...

:: Check if makensis is available.
where makensis >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo WARNING: makensis not found in PATH — skipping installer build
    echo   Install NSIS from https://nsis.sourceforge.io/
    goto skipInstaller
)

:: Resolve absolute paths for NSIS.
set ABS_SERVICE=%CD%\%OUT_DIR%\%APP_NAME%.exe
set ABS_UPDATER=%CD%\%OUT_DIR%\%APP_NAME%-updater.exe
set ABS_GUI=%CD%\%OUT_DIR%\%APP_NAME%-ui.exe

:: WinTUN DLL.
set ABS_WINTUN=%CD%\%OUT_DIR%\wintun.dll
if not exist "%ABS_WINTUN%" (
    set ABS_WINTUN=%CD%\dll\wintun.dll
)

:: Config example.
set ABS_CONFIG=%CD%\config.example.yaml
if not exist "%ABS_CONFIG%" (
    echo WARNING: config.example.yaml not found — installer will skip config
    set ABS_CONFIG=
)

set NSIS_ARGS=-DARG_WAILS_AMD64_BINARY="%ABS_GUI%"
set NSIS_ARGS=%NSIS_ARGS% -DARG_SERVICE_BINARY="%ABS_SERVICE%"
set NSIS_ARGS=%NSIS_ARGS% -DARG_UPDATER_BINARY="%ABS_UPDATER%"
:: Strip 'v' prefix and any suffix after dash for NSIS (needs X.X.X format).
set NSIS_VERSION=%VERSION%
if "%NSIS_VERSION:~0,1%"=="v" set NSIS_VERSION=%NSIS_VERSION:~1%
for /f "tokens=1 delims=-" %%a in ("%NSIS_VERSION%") do set NSIS_VERSION=%%a
set NSIS_ARGS=%NSIS_ARGS% -DINFO_PRODUCTVERSION="%NSIS_VERSION%"

if exist "%ABS_WINTUN%" (
    set NSIS_ARGS=%NSIS_ARGS% -DARG_WINTUN_DLL="%ABS_WINTUN%"
)
if defined ABS_CONFIG (
    if exist "%ABS_CONFIG%" (
        set NSIS_ARGS=%NSIS_ARGS% -DARG_CONFIG_EXAMPLE="%ABS_CONFIG%"
    )
)

makensis %NSIS_ARGS% "%NSIS_DIR%\project.nsi"
if %ERRORLEVEL% NEQ 0 (
    echo NSIS installer build FAILED
    exit /b 1
)

echo Installer built successfully.
:skipInstaller

:: ── Step 3: Create release zip ──────────────────────────────────────
echo.
echo [3/3] Creating release zip...

set ZIP_NAME=%APP_NAME%-%VERSION%-windows-amd64.zip
set ZIP_PATH=%OUT_DIR%\%ZIP_NAME%

:: Remove old zip if exists.
if exist "%ZIP_PATH%" del "%ZIP_PATH%"

:: Use PowerShell to create zip (available on all modern Windows).
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "$files = @('%OUT_DIR%\%APP_NAME%.exe', '%OUT_DIR%\%APP_NAME%-ui.exe', '%OUT_DIR%\%APP_NAME%-updater.exe'); if (Test-Path '%OUT_DIR%\wintun.dll') { $files += '%OUT_DIR%\wintun.dll' }; if (Test-Path 'config.example.yaml') { $files += 'config.example.yaml' }; Compress-Archive -Path $files -DestinationPath '%ZIP_PATH%' -Force"

if %ERRORLEVEL% NEQ 0 (
    echo WARNING: Failed to create release zip
) else (
    echo Release zip: %ZIP_PATH%
)

:: ── Summary ─────────────────────────────────────────────────────────
echo.
echo ============================================
echo  Release artifacts (%VERSION%):
echo ============================================
echo.
echo  Binaries:
echo    %OUT_DIR%\%APP_NAME%.exe            (VPN service)
echo    %OUT_DIR%\%APP_NAME%-ui.exe         (GUI)
echo    %OUT_DIR%\%APP_NAME%-updater.exe    (Updater)
echo.
if exist "%OUT_DIR%\%APP_NAME%-gui-amd64-installer.exe" (
    echo  Installer:
    echo    %OUT_DIR%\%APP_NAME%-gui-amd64-installer.exe
    echo.
)
if exist "%ZIP_PATH%" (
    echo  Release zip:
    echo    %ZIP_PATH%
    echo.
)
echo Done.
