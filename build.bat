@echo off
setlocal EnableDelayedExpansion

:: AWG Split Tunnel — Windows build script

set APP_NAME=awg-split-tunnel
set CMD_DIR=.\cmd\awg-split-tunnel
set UPDATER_CMD_DIR=.\cmd\awg-split-tunnel-updater
set OUT_DIR=.\build
set BINARY=%OUT_DIR%\%APP_NAME%.exe

:: Get version info from git (unless VERSION is already set externally, e.g. by release.sh).
if not defined VERSION (
    for /f "delims=" %%i in ('git describe --tags --always --dirty 2^>nul') do set VERSION=%%i
    if not defined VERSION set VERSION=dev
)

for /f "delims=" %%i in ('git rev-parse --short HEAD 2^>nul') do set COMMIT=%%i
if not defined COMMIT set COMMIT=unknown

:: Date in ISO format via wmic (no powershell dependency).
for /f "skip=1 delims=" %%i in ('wmic os get localdatetime 2^>nul') do (
    if not defined DATE (
        set RAW=%%i
        set DATE=!RAW:~0,4!-!RAW:~4,2!-!RAW:~6,2!T!RAW:~8,2!:!RAW:~10,2!:!RAW:~12,2!Z
    )
)
if not defined DATE set DATE=unknown

set LDFLAGS=-s -w -X "main.version=%VERSION%" -X "main.commit=%COMMIT%" -X "main.buildDate=%DATE%"

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

:: ── Frontend build ──────────────────────────────────────────────────
echo.
echo [1/8] Installing frontend dependencies...
pushd ui\frontend
call npm install --silent
if %ERRORLEVEL% NEQ 0 (
    popd
    echo Frontend npm install FAILED
    exit /b 1
)

echo [2/8] Building frontend...
call npm run build
if %ERRORLEVEL% NEQ 0 (
    popd
    echo Frontend build FAILED
    exit /b 1
)
popd

:: ── Wails bindings ──────────────────────────────────────────────────
echo [3/8] Generating Wails bindings...
pushd ui
wails3 generate bindings
if %ERRORLEVEL% NEQ 0 (
    popd
    echo Wails binding generation FAILED
    exit /b 1
)
popd

:: Move bindings to frontend directory (wails3 generates at project root).
if exist frontend\bindings (
    if exist ui\frontend\bindings rmdir /s /q ui\frontend\bindings
    move /Y frontend\bindings ui\frontend\bindings >nul
    rmdir frontend 2>nul
)

:: ── Windows resources (manifest + icon → .syso) ──────────────────────
echo [4/8] Generating Windows resources (manifest + icon)...

set ICON=.\ui\build\windows\icon.ico

where rsrc >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo   WARNING: rsrc not found — EXE files will not have icons or manifests
    echo   Install with: go install github.com/akavel/rsrc@latest
    goto skip_resources
)

:: Service
if exist ".\cmd\awg-split-tunnel\app.manifest" (
    rsrc -manifest ".\cmd\awg-split-tunnel\app.manifest" -ico "%ICON%" -o ".\cmd\awg-split-tunnel\rsrc_windows_amd64.syso"
    echo   - awg-split-tunnel.syso
)

:: GUI
if exist ".\ui\build\windows\wails.exe.manifest" (
    rsrc -manifest ".\ui\build\windows\wails.exe.manifest" -ico "%ICON%" -o ".\ui\rsrc_windows_amd64.syso"
    echo   - awg-split-tunnel-ui.syso
)

:: Updater
if exist "%UPDATER_CMD_DIR%\app.manifest" (
    rsrc -manifest "%UPDATER_CMD_DIR%\app.manifest" -ico "%ICON%" -o "%UPDATER_CMD_DIR%\rsrc_windows_amd64.syso"
    echo   - awg-split-tunnel-updater.syso
)

:: Test runner
if exist ".\cmd\awg-test\app.manifest" (
    rsrc -manifest ".\cmd\awg-test\app.manifest" -ico "%ICON%" -o ".\cmd\awg-test\rsrc_windows_amd64.syso"
    echo   - awg-test.syso
)

:: Diagnostic tool
if exist ".\cmd\awg-diag\app.manifest" (
    rsrc -manifest ".\cmd\awg-diag\app.manifest" -ico "%ICON%" -o ".\cmd\awg-diag\rsrc_windows_amd64.syso"
    echo   - awg-diag.syso
)

:skip_resources

:: ── Go builds ───────────────────────────────────────────────────────
echo [5/8] Building Go binaries (%VERSION%)...

echo   - %APP_NAME%.exe (VPN service)
go build -ldflags "%LDFLAGS%" -o "%BINARY%" %CMD_DIR%

if %ERRORLEVEL% NEQ 0 (
    echo VPN service build FAILED
    exit /b 1
)

echo   - %APP_NAME%-ui.exe (GUI)
go build -ldflags "%LDFLAGS% -H windowsgui" -o "%OUT_DIR%\%APP_NAME%-ui.exe" .\ui\

if %ERRORLEVEL% NEQ 0 (
    echo GUI build FAILED
    exit /b 1
)

:: ── Diagnostic tool build ──────────────────────────────────────────
echo [6/8] Building diagnostic tool...

echo   - %APP_NAME%-diag.exe
go build -ldflags "%LDFLAGS%" -o "%OUT_DIR%\%APP_NAME%-diag.exe" .\cmd\awg-diag\

if %ERRORLEVEL% NEQ 0 (
    echo Diagnostic tool build FAILED
    exit /b 1
)

:: ── Test runner build ─────────────────────────────────────────────
echo [7/8] Building test runner...

echo   - awg-test.exe
go build -ldflags "%LDFLAGS%" -o "%OUT_DIR%\awg-test.exe" .\cmd\awg-test\

if %ERRORLEVEL% NEQ 0 (
    echo Test runner build FAILED
    exit /b 1
)

:: ── Updater build ───────────────────────────────────────────────────
echo [8/8] Building updater...

echo   - %APP_NAME%-updater.exe
go build -ldflags "%LDFLAGS%" -o "%OUT_DIR%\%APP_NAME%-updater.exe" %UPDATER_CMD_DIR%

if %ERRORLEVEL% NEQ 0 (
    echo Updater build FAILED
    exit /b 1
)

:: Copy wintun.dll to build output (skip if already present — may be locked by running VPN).
if exist "%OUT_DIR%\wintun.dll" (
    echo wintun.dll already in %OUT_DIR%, skipping copy
) else if exist ".\dll\wintun.dll" (
    copy /Y ".\dll\wintun.dll" "%OUT_DIR%\wintun.dll" >nul
    echo Copied wintun.dll to %OUT_DIR%
) else (
    echo WARNING: dll\wintun.dll not found — adapter will fail at runtime
)

echo.
echo Built successfully (%VERSION%):
echo   %OUT_DIR%\%APP_NAME%.exe            (VPN service)
echo   %OUT_DIR%\%APP_NAME%-ui.exe         (GUI)
echo   %OUT_DIR%\%APP_NAME%-diag.exe       (Diagnostic tool)
echo   %OUT_DIR%\awg-test.exe              (Test runner)
echo   %OUT_DIR%\%APP_NAME%-updater.exe    (Updater)
