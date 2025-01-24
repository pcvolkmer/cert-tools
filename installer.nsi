!include "MUI.nsh"

!define APP_NAME "Cert Tools"
!define APP_EXE "cert-tools-ui.exe"
!define MUI_ICON "resources\icon.ico"
!define UNINSTALLER_EXE "uninstaller.exe"
!define INSTALL_DIR "$LocalAppData\Programs\${APP_NAME}"

Name "${APP_NAME} Installer"
RequestExecutionLevel user
OutFile "target/cert-tools-installer.exe"
InstallDir "${INSTALL_DIR}"
LicenseData "LICENSE"

!include LogicLib.nsh

!insertmacro MUI_PAGE_WELCOME
page license
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Section "MainSection" SEC01
    SetOutPath "$INSTDIR"
    File "target\x86_64-pc-windows-gnu\release\${APP_EXE}"
    File "LICENSE"
    CreateShortcut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}"
    CreateDirectory "$SMPROGRAMS\${APP_NAME}"
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" ""
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\Uninstaller.lnk" "$INSTDIR\${UNINSTALLER_EXE}" "" ""
    WriteUninstaller $INSTDIR\${UNINSTALLER_EXE}
SectionEnd

Section "Uninstall"
    Delete "$INSTDIR\${APP_EXE}"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\${UNINSTALLER_EXE}"
    Delete "$DESKTOP\${APP_NAME}.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\Uninstaller.lnk"
    RMDir /r "$INSTDIR"
SectionEnd