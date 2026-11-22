#define AppName "TorProxy"
#ifndef AppVersion
  #define AppVersion "1.6.0"
#endif

[Setup]
; Share the product identity with the lightweight installer so this edition
; upgrades the same TorProxy installation instead of registering a second app.
AppId={{E3A4C7C1-5FAE-4B07-90F2-62CFA6A4D24D}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion} (Full)
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
OutputBaseFilename=TorProxy-Full-Setup-windows-x64
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\_internal\assets\icon.ico
WizardStyle=modern
Compression=lzma2/ultra64
SolidCompression=yes
CloseApplications=yes
RestartApplications=no
UninstallDisplayName=TorProxy (Full)
VersionInfoVersion={#AppVersion}.0
VersionInfoProductVersion={#AppVersion}.0
VersionInfoProductName=TorProxy Full
VersionInfoCompany=Nima Salamat
VersionInfoDescription=TorProxy full installer with Tor and sing-box bundles
VersionInfoCopyright=Copyright (C) 2026 Nima Salamat

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
; This staged tree contains the frozen app plus the verified Tor Expert Bundle
; and the pinned sing-box archive under bundles/.
Source: "..\dist\TorProxy-Full\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\TorProxy"; Filename: "{app}\TorProxyLauncher.exe"; WorkingDir: "{app}"; IconFilename: "{app}\_internal\assets\icon.ico"
Name: "{autodesktop}\TorProxy"; Filename: "{app}\TorProxyLauncher.exe"; WorkingDir: "{app}"; IconFilename: "{app}\_internal\assets\icon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\TorProxyLauncher.exe"; Description: "Launch TorProxy"; WorkingDir: "{app}"; Flags: postinstall nowait skipifsilent
