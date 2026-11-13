Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "StrFunc.nsh"
${StrStr}
Var WasRunning
Name "Proxy"
OutFile "..\..\dist\installer\Proxy-Setup-x64.exe"
InstallDir "$PROGRAMFILES64\Proxy"
InstallDirRegKey HKLM "Software\ProxyTransparent" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

Function .onInit
 ${IfNot} ${RunningX64}
  MessageBox MB_ICONSTOP "This package requires Windows x64."
  Abort
 ${EndIf}
 SetRegView 64
FunctionEnd

!macro RemoveProxyService
 nsExec::ExecToLog '"$SYSDIR\sc.exe" query ProxyD'
 Pop $2
 ${If} $2 == 0
  nsExec::ExecToLog '"$INSTDIR\proxy.exe" service stop'
  Pop $1
  ${If} $1 != 0
   MessageBox MB_ICONSTOP "Unable to stop ProxyD."
   Abort
  ${EndIf}
  nsExec::ExecToLog '"$INSTDIR\proxy.exe" service uninstall'
  Pop $1
  ${If} $1 != 0
   MessageBox MB_ICONSTOP "Unable to unregister ProxyD."
   Abort
  ${EndIf}
 ${ElseIf} $2 != 1060
  MessageBox MB_ICONSTOP "Unable to query ProxyD."
  Abort
 ${EndIf}
!macroend

!macro RemoveWinDivertDriver
 nsExec::ExecToLog '"$SYSDIR\sc.exe" query WinDivert'
 Pop $2
 ${If} $2 == 0
  nsExec::ExecToLog '"$SYSDIR\net.exe" stop WinDivert'
  Pop $1
  nsExec::ExecToLog '"$SYSDIR\sc.exe" delete WinDivert'
  Pop $1
  Sleep 500
 ${ElseIf} $2 != 1060
  MessageBox MB_ICONSTOP "Unable to query WinDivert."
  Abort
 ${EndIf}
!macroend

Section "Proxy"
 SetShellVarContext all
 StrCpy $WasRunning 0
 ReadRegStr $0 HKLM "Software\ProxyTransparent" "InstallDir"
 ${If} $0 != ""
  ${If} $0 != $INSTDIR
   MessageBox MB_ICONSTOP "Upgrade using the existing directory."
   Abort
  ${EndIf}
  nsExec::ExecToStack '"$SYSDIR\sc.exe" query ProxyD'
  Pop $2
  Pop $3
  ${If} $2 == 0
   ${StrStr} $4 "$3" "RUNNING"
   ${If} $4 != ""
    StrCpy $WasRunning 1
   ${EndIf}
  ${EndIf}
  !insertmacro RemoveProxyService
 ${EndIf}
 !insertmacro RemoveWinDivertDriver
 SetOutPath "$INSTDIR"
 ; Remove files shipped only by earlier installer revisions.
 Delete "$INSTDIR\installer-environment.ps1"
 Delete "$INSTDIR\安装与后台运行说明.md"
 Delete "$INSTDIR\WinDivert-README.md"
 File "..\..\dist\windows-amd64\proxy.exe"
 Delete "$INSTDIR\proxyd.exe"
 File "..\..\dist\windows-amd64\WinDivert.dll"
 File "..\..\dist\windows-amd64\WinDivert64.sys"
 File /oname=WinDivert-LICENSE "..\..\dist\windows-amd64\WinDivert-LICENSE"
 Delete "$PROFILE\.proxy\runtime\proxyd.log"
 CreateDirectory "$PROFILE\.proxy"
 ; Keep user access while granting SYSTEM access to the service configuration.
 nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$PROFILE\.proxy" /grant *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F'
 Pop $1
 ${If} $1 != 0
  MessageBox MB_ICONSTOP "Unable to secure configuration directory."
  Abort
 ${EndIf}
 SetOutPath "$PROFILE\.proxy"
 SetOutPath "$PROFILE\.proxy\data"
 File "..\..\dist\windows-amd64\data\geoip.dat"
 File "..\..\dist\windows-amd64\data\geosite.dat"

 nsExec::ExecToLog '"$INSTDIR\proxy.exe" installer-path --action add --directory "$INSTDIR"'
 Pop $1
 ${If} $1 != 0
  MessageBox MB_ICONSTOP "Unable to update system PATH."
  Abort
 ${EndIf}
 WriteUninstaller "$INSTDIR\Uninstall.exe"
 WriteRegStr HKLM "Software\ProxyTransparent" "InstallDir" "$INSTDIR"
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ProxyTransparent" "DisplayName" "Proxy"
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ProxyTransparent" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
 WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ProxyTransparent" "DisplayVersion" "0.1.0"
 WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ProxyTransparent" "NoModify" 1
 WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ProxyTransparent" "NoRepair" 1
 ${If} $WasRunning == 1
  nsExec::ExecToLog '"$INSTDIR\proxy.exe" start'
  Pop $1
  ${If} $1 != 0
   MessageBox MB_ICONEXCLAMATION "Installation completed, but ProxyD could not be started automatically."
  ${EndIf}
 ${EndIf}
SectionEnd

Section "Uninstall"
 SetRegView 64
 SetShellVarContext all
 !insertmacro RemoveProxyService
 !insertmacro RemoveWinDivertDriver
 nsExec::ExecToLog '"$INSTDIR\proxy.exe" installer-path --action remove --directory "$INSTDIR"'
 Pop $1
 ${If} $1 != 0
  MessageBox MB_ICONSTOP "Unable to remove system PATH entry."
  Abort
 ${EndIf}
 Delete "$INSTDIR\installer-environment.ps1"
 Delete "$INSTDIR\proxy.exe"
 Delete "$INSTDIR\proxyd.exe"
 Delete /REBOOTOK "$INSTDIR\WinDivert.dll"
 Delete /REBOOTOK "$INSTDIR\WinDivert64.sys"
 Delete "$INSTDIR\WinDivert-LICENSE"
 Delete "$INSTDIR\WinDivert-README.md"
 Delete "$INSTDIR\proxyd.exe"
 Delete "$INSTDIR\安装与后台运行说明.md"
 Delete "$INSTDIR\Uninstall.exe"
 RMDir "$INSTDIR"
 ; Preserve configuration, data and runtime for future installations.
 DeleteRegKey HKLM "Software\ProxyTransparent"
 DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ProxyTransparent"
SectionEnd











