param(
    [switch]$Desktop
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$launcher = Join-Path $root "TorProxyLauncher.exe"

if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
    throw "TorProxyLauncher.exe was not found. Run this script from the extracted TorProxy folder."
}

$destinationFolder = if ($Desktop) {
    [Environment]::GetFolderPath("DesktopDirectory")
} else {
    [Environment]::GetFolderPath("Programs")
}
if (-not (Test-Path -LiteralPath $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder -Force | Out-Null
}

$shortcutPath = Join-Path $destinationFolder "TorProxy.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $launcher
$shortcut.WorkingDirectory = $root
$shortcut.IconLocation = "$launcher,0"
$shortcut.Description = "TorProxy"
$shortcut.Save()

Write-Host "Created: $shortcutPath"
Write-Host "You can now pin TorProxy from the Start menu or desktop."
