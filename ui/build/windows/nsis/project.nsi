Unicode true

####
## AWG Split Tunnel — NSIS Installer
## Installs: GUI, VPN service, updater, wintun.dll, config
## Registers Windows Service, creates shortcuts, GUI autostart
####

## Project defines (override wails_tools.nsh defaults)
!define INFO_PROJECTNAME    "awg-split-tunnel-gui"
!define INFO_COMPANYNAME    "AWG"
!define INFO_PRODUCTNAME    "AWG Split Tunnel"
!define INFO_COPYRIGHT      "© 2026, AWG"

## Custom defines
!define SERVICE_BINARY      "awg-split-tunnel.exe"
!define UPDATER_BINARY      "awg-split-tunnel-updater.exe"
!define SERVICE_NAME        "AWGSplitTunnel"
!define GUI_REG_KEY         "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
!define GUI_REG_NAME        "AWGSplitTunnelGUI"

## Include wails tools
!include "wails_tools.nsh"

# Version info (4-part)
VIProductVersion "${INFO_PRODUCTVERSION}.0"
VIFileVersion    "${INFO_PRODUCTVERSION}.0"

VIAddVersionKey "CompanyName"     "${INFO_COMPANYNAME}"
VIAddVersionKey "FileDescription" "${INFO_PRODUCTNAME} Installer"
VIAddVersionKey "ProductVersion"  "${INFO_PRODUCTVERSION}"
VIAddVersionKey "FileVersion"     "${INFO_PRODUCTVERSION}"
VIAddVersionKey "LegalCopyright"  "${INFO_COPYRIGHT}"
VIAddVersionKey "ProductName"     "${INFO_PRODUCTNAME}"

# HiDPI support
ManifestDPIAware true

!include "MUI.nsh"

!define MUI_ICON "..\icon.ico"
!define MUI_UNICON "..\icon.ico"
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_ABORTWARNING

# Finish page: offer to launch the app
!define MUI_FINISHPAGE_RUN "$INSTDIR\${PRODUCT_EXECUTABLE}"
!define MUI_FINISHPAGE_RUN_TEXT "Запустить ${INFO_PRODUCTNAME}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "English"

Name "${INFO_PRODUCTNAME}"
OutFile "..\..\..\bin\${INFO_PROJECTNAME}-${ARCH}-installer.exe"
InstallDir "$PROGRAMFILES64\${INFO_COMPANYNAME}\${INFO_PRODUCTNAME}"
ShowInstDetails show

# ─── Upgrade detection ─────────────────────────────────────────────

Function .onInit
    !insertmacro wails.checkArchitecture

    # Check for existing installation
    SetRegView 64
    ReadRegStr $0 HKLM "${UNINST_KEY}" "UninstallString"
    ${If} $0 != ""
        MessageBox MB_OKCANCEL|MB_ICONINFORMATION \
            "$(^Name) уже установлен.$\n$\nНажмите ОК чтобы обновить, или Отмена для выхода." \
            IDOK upgradeOk
        Abort
        upgradeOk:

        # Stop running service
        nsExec::ExecToLog '"$INSTDIR\${SERVICE_BINARY}" stop'

        # Kill GUI process
        nsExec::ExecToLog 'taskkill /F /IM ${PRODUCT_EXECUTABLE}'

        # Small delay for processes to exit
        Sleep 2000
    ${EndIf}
FunctionEnd

# ─── Install section ───────────────────────────────────────────────

Section "install"
    !insertmacro wails.setShellContext
    !insertmacro wails.webview2runtime

    SetOutPath $INSTDIR

    # GUI binary (via wails macro)
    !insertmacro wails.files

    # Service binary
    !ifdef ARG_SERVICE_BINARY
        File "/oname=${SERVICE_BINARY}" "${ARG_SERVICE_BINARY}"
    !endif

    # Updater binary
    !ifdef ARG_UPDATER_BINARY
        File "/oname=${UPDATER_BINARY}" "${ARG_UPDATER_BINARY}"
    !endif

    # WinTUN DLL
    !ifdef ARG_WINTUN_DLL
        File "/oname=wintun.dll" "${ARG_WINTUN_DLL}"
    !endif

    # Config: only copy if not exists (preserve user config on upgrade)
    !ifdef ARG_CONFIG_EXAMPLE
        IfFileExists "$INSTDIR\config.yaml" configExists
            File "/oname=config.yaml" "${ARG_CONFIG_EXAMPLE}"
        configExists:
        # Always install the example config as reference
        File "/oname=config.example.yaml" "${ARG_CONFIG_EXAMPLE}"
    !endif

    # Register Windows Service
    DetailPrint "Registering Windows Service..."
    nsExec::ExecToLog '"$INSTDIR\${SERVICE_BINARY}" install'

    # Start the service
    DetailPrint "Starting Windows Service..."
    nsExec::ExecToLog '"$INSTDIR\${SERVICE_BINARY}" start'

    # GUI autostart via Task Scheduler (HIGHEST run level for elevated GUI)
    nsExec::ExecToLog 'schtasks /Create /TN "AWGSplitTunnelGUI" /TR "\"$INSTDIR\${PRODUCT_EXECUTABLE}\" --minimized" /SC ONLOGON /RL HIGHEST /F'

    # Remove legacy entries (old registry + old schtasks)
    DeleteRegValue HKCU "${GUI_REG_KEY}" "${GUI_REG_NAME}"
    nsExec::ExecToLog 'schtasks /Delete /TN "AWGSplitTunnel" /F'

    # Shortcuts
    CreateDirectory "$SMPROGRAMS\${INFO_PRODUCTNAME}"
    CreateShortcut "$SMPROGRAMS\${INFO_PRODUCTNAME}\${INFO_PRODUCTNAME}.lnk" "$INSTDIR\${PRODUCT_EXECUTABLE}"
    CreateShortcut "$SMPROGRAMS\${INFO_PRODUCTNAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"
    CreateShortcut "$DESKTOP\${INFO_PRODUCTNAME}.lnk" "$INSTDIR\${PRODUCT_EXECUTABLE}"

    !insertmacro wails.associateFiles
    !insertmacro wails.associateCustomProtocols

    !insertmacro wails.writeUninstaller
SectionEnd

# ─── Uninstall section ─────────────────────────────────────────────

Section "uninstall"
    !insertmacro wails.setShellContext

    # Stop and unregister service
    DetailPrint "Stopping Windows Service..."
    nsExec::ExecToLog '"$INSTDIR\${SERVICE_BINARY}" stop'
    DetailPrint "Unregistering Windows Service..."
    nsExec::ExecToLog '"$INSTDIR\${SERVICE_BINARY}" uninstall'

    # Kill GUI process
    nsExec::ExecToLog 'taskkill /F /IM ${PRODUCT_EXECUTABLE}'
    Sleep 1000

    # Remove GUI autostart (schtasks + legacy registry)
    nsExec::ExecToLog 'schtasks /Delete /TN "AWGSplitTunnelGUI" /F'
    DeleteRegValue HKCU "${GUI_REG_KEY}" "${GUI_REG_NAME}"

    # Remove legacy schtasks
    nsExec::ExecToLog 'schtasks /Delete /TN "AWGSplitTunnel" /F'

    # Remove WebView2 data
    RMDir /r "$AppData\${PRODUCT_EXECUTABLE}"

    # Delete files EXCEPT config.yaml (user data)
    Delete "$INSTDIR\${PRODUCT_EXECUTABLE}"
    Delete "$INSTDIR\${SERVICE_BINARY}"
    Delete "$INSTDIR\${UPDATER_BINARY}"
    Delete "$INSTDIR\wintun.dll"
    Delete "$INSTDIR\config.example.yaml"
    Delete "$INSTDIR\update.log"
    Delete "$INSTDIR\uninstall.exe"

    # Remove *.old backup files (from updater)
    Delete "$INSTDIR\*.old"

    # Remove geosite data
    Delete "$INSTDIR\geosite.dat"

    # Shortcuts
    Delete "$SMPROGRAMS\${INFO_PRODUCTNAME}\${INFO_PRODUCTNAME}.lnk"
    Delete "$SMPROGRAMS\${INFO_PRODUCTNAME}\Uninstall.lnk"
    RMDir  "$SMPROGRAMS\${INFO_PRODUCTNAME}"
    Delete "$DESKTOP\${INFO_PRODUCTNAME}.lnk"

    !insertmacro wails.unassociateFiles
    !insertmacro wails.unassociateCustomProtocols

    # Remove install dir only if empty (config.yaml may remain)
    RMDir "$INSTDIR"

    !insertmacro wails.deleteUninstaller
SectionEnd
