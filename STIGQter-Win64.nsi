!include x64.nsh
OutFile "STIGQter-Win64.exe"
InstallDir $PROGRAMFILES64\STIGQter
InstallDirRegKey HKLM 'Software\STIGQter' InstallDir
!define LANG_ENGLISH 1033-English
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "STIGQter"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "Open Source STIGViewer Reimplementation"
VIAddVersionKey /LANG=${LANG_ENGLISH} "LegalCopyright" "2018-2020 Jon Hood"
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName" "Jon Hood"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "1.0.2-1"
VIProductVersion "1.0.2.0"
RequestExecutionLevel admin
Section
	${IfNot} ${RunningX64}
		MessageBox MB_OK|MB_ICONSTOP '64-bit Windows required.'
	        Quit
	${EndIf}
	SetOutPath $INSTDIR
	WriteUninstaller "$INSTDIR\uninstall.exe"
	CreateShortCut "$SMPROGRAMS\uninstall.lnk" "$INSTDIR\uninstall.exe"
	file STIGQter.exe
	file CHANGES.md
	file LICENSE
	file README.md
	file doc/UsersGuide.pdf
	CreateShortCut "$SMPROGRAMS\STIGQter.lnk" "$INSTDIR\STIGQter.exe"
SectionEnd
Section "uninstall"
	Delete "$INSTDIR\uninstall.exe"
	Delete "$SMPROGRAMS\uninstall.lnk"
	Delete "$INSTDIR\STIGQter.exe"
	Delete "$INSTDIR\CHANGES.md"
	Delete "$INSTDIR\LICENSE"
	Delete "$INSTDIR\README.md"
	Delete "$INSTDIR\UsersGuide.pdf"
SectionEnd
