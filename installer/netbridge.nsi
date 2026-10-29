; NetBridge 자료전송 클라이언트 설치 파일
Unicode true
!include "MUI2.nsh"

!ifndef VERSION
  !define VERSION "0.2.0"
!endif
!define APP "NetBridge"
!define APPNAME "NetBridge 자료전송"
!define UNINST "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetBridge"

Name "${APPNAME} ${VERSION}"
OutFile "..\dist\NetBridge-Setup-${VERSION}.exe"
InstallDir "$PROGRAMFILES64\NetBridge"
InstallDirRegKey HKLM "Software\NetBridge" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText "${APPNAME}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=1042 "ProductName" "${APPNAME}"
VIAddVersionKey /LANG=1042 "FileDescription" "${APPNAME} 설치"
VIAddVersionKey /LANG=1042 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1042 "LegalCopyright" "NetBridge contributors"

!define MUI_ICON "..\dist\netbridge.ico"
!define MUI_UNICON "..\dist\netbridge.ico"
!define MUI_FINISHPAGE_RUN "$INSTDIR\netbridge.exe"
!define MUI_FINISHPAGE_RUN_TEXT "NetBridge 실행"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Korean"

Section "NetBridge (필수)" SecMain
  SectionIn RO
  SetShellVarContext all
  ; a running copy would lock netbridge.exe
  nsExec::Exec 'taskkill /IM netbridge.exe /F'
  SetOutPath "$INSTDIR"
  File "..\dist\win\netbridge.exe"
  File "..\assets\fonts\OFL.txt"
  File /oname=LICENSE.txt "..\LICENSE"
  ; ca.pem placed next to the setup file is installed with the app
  IfFileExists "$EXEDIR\ca.pem" 0 +2
    CopyFiles /SILENT "$EXEDIR\ca.pem" "$INSTDIR\ca.pem"
  CreateDirectory "$SMPROGRAMS\NetBridge"
  CreateShortcut "$SMPROGRAMS\NetBridge\NetBridge 자료전송.lnk" "$INSTDIR\netbridge.exe"
  CreateShortcut "$SMPROGRAMS\NetBridge\NetBridge 제거.lnk" "$INSTDIR\uninstall.exe"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\NetBridge" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${UNINST}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "${UNINST}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST}" "Publisher" "NetBridge"
  WriteRegStr HKLM "${UNINST}" "DisplayIcon" "$INSTDIR\netbridge.exe"
  WriteRegStr HKLM "${UNINST}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINST}" "URLInfoAbout" "https://github.com/spsp4755/netbridge"
  WriteRegDWORD HKLM "${UNINST}" "EstimatedSize" 20000
  WriteRegDWORD HKLM "${UNINST}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST}" "NoRepair" 1
SectionEnd

Section "바탕화면 바로가기" SecDesktop
  SetShellVarContext all
  CreateShortcut "$DESKTOP\NetBridge 자료전송.lnk" "$INSTDIR\netbridge.exe"
SectionEnd

Section "Windows 시작 시 자동 실행" SecStartup
  SetShellVarContext all
  CreateShortcut "$SMSTARTUP\NetBridge 자료전송.lnk" "$INSTDIR\netbridge.exe" "--minimized"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "NetBridge 앱을 설치합니다."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "바탕화면에 바로가기를 만듭니다."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartup} "로그인하면 트레이에서 자동으로 실행합니다. 클립보드 단축키를 바로 쓸 수 있습니다."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  SetShellVarContext all
  nsExec::Exec 'taskkill /IM netbridge.exe /F'
  Delete "$INSTDIR\netbridge.exe"
  Delete "$INSTDIR\OFL.txt"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\ca.pem"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\NetBridge\*.lnk"
  RMDir "$SMPROGRAMS\NetBridge"
  Delete "$DESKTOP\NetBridge 자료전송.lnk"
  Delete "$SMSTARTUP\NetBridge 자료전송.lnk"
  DeleteRegKey HKLM "${UNINST}"
  DeleteRegKey HKLM "Software\NetBridge"
  ; user settings in %APPDATA%\NetBridge are kept
SectionEnd
