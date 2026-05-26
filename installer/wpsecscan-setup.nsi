; WPSecScan Windows installer (NSIS)
; Build:  makensis installer/wpsecscan-setup.nsi
; Output: dist/wpsecscan-setup-VERSION.exe
;
; Requires NSIS 3+ with the EnVar plugin (for PATH manipulation).
; If EnVar isn't installed, the "Add to PATH" checkbox is a no-op.

!define APP_NAME       "WPSecScan"
!define APP_PUBLISHER  "Bryan"
!define APP_VERSION    "2.4.0"
!define APP_EXE_CLI    "wpsecscan.exe"
!define APP_EXE_GUI    "wpsecscan-gui.exe"
!define APP_URL        "https://github.com/bryanflowers/wpsecscan"
!define UNINST_KEY     "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"
!define AUTOSTART_KEY  "Software\Microsoft\Windows\CurrentVersion\Run"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "..\dist\wpsecscan-setup-${APP_VERSION}.exe"
InstallDir "$PROGRAMFILES64\${APP_NAME}"
InstallDirRegKey HKLM "Software\${APP_NAME}" "InstallPath"
RequestExecutionLevel admin
ShowInstDetails show
ShowUninstDetails show

; ---- Modern UI ----
!include "MUI2.nsh"
!include "LogicLib.nsh"

!define MUI_ABORTWARNING
!define MUI_ICON   "..\wpsecscan\data\icon.ico"
!define MUI_UNICON "..\wpsecscan\data\icon.ico"

; ---- Pages ----
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE_GUI}"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.md"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Open README"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ---- Sections ----

Section "${APP_NAME} core (required)" SecCore
    SectionIn RO
    SetOutPath "$INSTDIR"
    File "..\dist\${APP_EXE_CLI}"
    File "..\dist\${APP_EXE_GUI}"
    File "..\README.md"
    File "..\LICENSE"
    File "..\NOTICE"
    File "..\CHANGELOG.md"
    File "..\FEATURES.md"
    File "..\scripts\add-defender-exclusion.ps1"

    ; Companion WP plugin (optional, but ships in the installer)
    SetOutPath "$INSTDIR\wp-plugin"
    File /nonfatal "..\dist\wpsecscan-companion.zip"

    ; Start Menu shortcuts
    SetOutPath "$INSTDIR"
    CreateDirectory "$SMPROGRAMS\${APP_NAME}"
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME} (GUI).lnk" "$INSTDIR\${APP_EXE_GUI}" "" "$INSTDIR\${APP_EXE_GUI}"
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME} (CLI).lnk" "$INSTDIR\${APP_EXE_CLI}" "" "$INSTDIR\${APP_EXE_CLI}"
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk" "$INSTDIR\uninstall.exe"

    ; Registry — install path + Add/Remove Programs entry
    WriteRegStr HKLM "Software\${APP_NAME}" "InstallPath" "$INSTDIR"
    WriteRegStr HKLM "Software\${APP_NAME}" "Version"     "${APP_VERSION}"

    WriteRegStr HKLM "${UNINST_KEY}" "DisplayName"     "${APP_NAME}"
    WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion"  "${APP_VERSION}"
    WriteRegStr HKLM "${UNINST_KEY}" "Publisher"       "${APP_PUBLISHER}"
    WriteRegStr HKLM "${UNINST_KEY}" "URLInfoAbout"    "${APP_URL}"
    WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon"     "$INSTDIR\${APP_EXE_GUI}"
    WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
    WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1

    WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section /o "Add to PATH" SecPath
    EnVar::SetHKLM
    EnVar::AddValue "Path" "$INSTDIR"
    Pop $0
SectionEnd

Section /o "Run ${APP_NAME} GUI at Windows startup" SecAutoStart
    WriteRegStr HKCU "${AUTOSTART_KEY}" "${APP_NAME}" '"$INSTDIR\${APP_EXE_GUI}" --minimized'
SectionEnd

Section /o "Register weekly auto-scan task" SecSchedule
    ; Calls our own subcommand to add the schtasks entry as the installing user.
    ExecWait '"$INSTDIR\${APP_EXE_CLI}" schedule install --weekly --time 03:00'
SectionEnd

Section /o "Allow ${APP_NAME} in Windows Defender" SecDefender
    ExecWait 'powershell -ExecutionPolicy Bypass -File "$INSTDIR\add-defender-exclusion.ps1" -Silent'
SectionEnd

; ---- Component descriptions ----
LangString DESC_SecCore     ${LANG_ENGLISH} "Required core files."
LangString DESC_SecPath     ${LANG_ENGLISH} "Add the install dir to your PATH so 'wpsecscan' works in any terminal."
LangString DESC_SecAutoStart ${LANG_ENGLISH} "Start the GUI minimised to the system tray when you log in."
LangString DESC_SecSchedule ${LANG_ENGLISH} "Register a Windows Task Scheduler entry to scan your saved sites weekly at 03:00."
LangString DESC_SecDefender ${LANG_ENGLISH} "Add an exclusion to Microsoft Defender (avoids false-positive flagging of pattern-detection strings)."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore}     $(DESC_SecCore)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecPath}     $(DESC_SecPath)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecAutoStart} $(DESC_SecAutoStart)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecSchedule} $(DESC_SecSchedule)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecDefender} $(DESC_SecDefender)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ---- Uninstaller ----
Section "Uninstall"
    ; Remove schedule (best effort)
    ExecWait '"$INSTDIR\${APP_EXE_CLI}" schedule uninstall'

    ; Remove autostart
    DeleteRegValue HKCU "${AUTOSTART_KEY}" "${APP_NAME}"

    ; Remove from PATH
    EnVar::SetHKLM
    EnVar::DeleteValue "Path" "$INSTDIR"
    Pop $0

    ; Ask about user config wipe
    MessageBox MB_YESNO "Remove personal config + scan history in %USERPROFILE%\.wpsecscan?$\n$\nDefault: NO (keeps your data)." IDNO skipConfig
        RMDir /r "$PROFILE\.wpsecscan"
    skipConfig:

    ; Delete files
    Delete "$INSTDIR\${APP_EXE_CLI}"
    Delete "$INSTDIR\${APP_EXE_GUI}"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\NOTICE"
    Delete "$INSTDIR\CHANGELOG.md"
    Delete "$INSTDIR\FEATURES.md"
    Delete "$INSTDIR\add-defender-exclusion.ps1"
    RMDir /r "$INSTDIR\wp-plugin"
    Delete "$INSTDIR\uninstall.exe"
    RMDir "$INSTDIR"

    Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME} (GUI).lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME} (CLI).lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\Uninstall ${APP_NAME}.lnk"
    RMDir "$SMPROGRAMS\${APP_NAME}"

    DeleteRegKey HKLM "${UNINST_KEY}"
    DeleteRegKey HKLM "Software\${APP_NAME}"
SectionEnd
