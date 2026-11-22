#define AppName "TorProxy"
#ifndef AppVersion
  #define AppVersion "1.6.0"
#endif

[Setup]
AppId={{E3A4C7C1-5FAE-4B07-90F2-62CFA6A4D24D}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Nima Salamat
AppPublisherURL=https://github.com/nima-salamat/tor-proxy
AppSupportURL=https://github.com/nima-salamat/tor-proxy/issues
AppUpdatesURL=https://github.com/nima-salamat/tor-proxy/releases
DefaultDirName={localappdata}\Programs\TorProxy
DefaultGroupName=TorProxy
DisableProgramGroupPage=yes
AllowNoIcons=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
OutputDir=..\dist
OutputBaseFilename=TorProxy-Setup-windows-x64
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\assets\icon.ico
WizardStyle=modern
Compression=lzma2/ultra64
SolidCompression=yes
CloseApplications=yes
RestartApplications=no
UninstallDisplayName=TorProxy
VersionInfoVersion={#AppVersion}.0
VersionInfoProductVersion={#AppVersion}.0
VersionInfoProductName=TorProxy
VersionInfoCompany=Nima Salamat
VersionInfoDescription=TorProxy desktop installer
VersionInfoCopyright=Copyright (C) 2026 Nima Salamat

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
; Package only the lightweight PyInstaller output. The Tor and sing-box bundles
; are assembled later for the separate With-Tor portable archive.
Source: "..\dist\TorProxy\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\TorProxy"; Filename: "{app}\TorProxyLauncher.exe"; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"
Name: "{autodesktop}\TorProxy"; Filename: "{app}\TorProxyLauncher.exe"; WorkingDir: "{app}"; IconFilename: "{app}\assets\icon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\TorProxyLauncher.exe"; Description: "Launch TorProxy"; WorkingDir: "{app}"; Flags: postinstall nowait skipifsilent
