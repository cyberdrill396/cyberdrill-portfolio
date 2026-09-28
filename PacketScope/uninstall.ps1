$ErrorActionPreference = "Stop"

$installPath = Join-Path $env:LOCALAPPDATA "Programs\PacketScope"
$startMenuPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\PacketScope"
$desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "PacketScope.lnk"

Remove-Item -LiteralPath (Join-Path $startMenuPath "PacketScope.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $desktopShortcut -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $startMenuPath -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $installPath -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "PacketScope was removed. Wireshark and Npcap were left unchanged."