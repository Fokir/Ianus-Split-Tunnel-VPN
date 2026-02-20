@echo off
setlocal EnableDelayedExpansion

:: AWG Split Tunnel — Windows build script

set APP_NAME=awg-split-tunnel
set CMD_DIR=.\cmd\awg-split-tunnel
set OUT_DIR=.\build
set BINARY=%OUT_DIR%\%APP_NAME%.exe

:: Get version info from git.
for /f "delims=" %%i in ('git describe --tags --always --dirty 2^>nul') do set VERSION=%%i
if not defined VERSION set VERSION=dev

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

echo Building %APP_NAME% %VERSION% ...
go build -ldflags "%LDFLAGS%" -o "%BINARY%" %CMD_DIR%

if %ERRORLEVEL% NEQ 0 (
    echo Build FAILED
    exit /b 1
)

:: Copy wintun.dll to build output.
if exist ".\dll\wintun.dll" (
    copy /Y ".\dll\wintun.dll" "%OUT_DIR%\wintun.dll" >nul
    echo Copied wintun.dll to %OUT_DIR%
) else (
    echo WARNING: dll\wintun.dll not found — adapter will fail at runtime
)

echo Built %BINARY% (%VERSION%)
