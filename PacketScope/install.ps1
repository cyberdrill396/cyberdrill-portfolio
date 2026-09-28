$ErrorActionPreference = "Stop"

$node = Get-Command node.exe -ErrorAction SilentlyContinue
if (-not $node) {
  throw "Node.js is required. Install Node.js 26.10.0, then run install.cmd again."
}

$sourceWs = Join-Path $PSScriptRoot "node_modules\ws"
if (-not (Test-Path $sourceWs)) {
  throw "The ws runtime dependency is missing. Run npm install in the project folder, then run install.cmd again."
}

$installPath = Join-Path $env:LOCALAPPDATA "Programs\PacketScope"
$startMenuPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\PacketScope"
$desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "PacketScope.lnk"

New-Item -ItemType Directory -Path $installPath -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $installPath "public") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $installPath "node_modules") -Force | Out-Null
New-Item -ItemType Directory -Path $startMenuPath -Force | Out-Null

foreach ($file in @("server.js", "launch.js", "package.json", "package-lock.json", "README.md", "uninstall.ps1")) {
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $installPath -Force
}
Copy-Item -Path (Join-Path $PSScriptRoot "public\*") -Destination (Join-Path $installPath "public") -Recurse -Force
$installedWs = Join-Path $installPath "node_modules\ws"
if (Test-Path $installedWs) { Remove-Item -LiteralPath $installedWs -Recurse -Force }
Copy-Item -LiteralPath $sourceWs -Destination $installedWs -Recurse -Force

$shell = New-Object -ComObject WScript.Shell
foreach ($shortcutPath in @(
  (Join-Path $startMenuPath "PacketScope.lnk"),
  $desktopShortcut
)) {
  $shortcut = $shell.CreateShortcut($shortcutPath)
  $shortcut.TargetPath = $node.Source
  $shortcut.Arguments = '"' + (Join-Path $installPath "launch.js") + '"'
  $shortcut.WorkingDirectory = $installPath
  $shortcut.Description = "Start PacketScope local network monitor"
  $shortcut.Save()
}

$tsharkCandidates = @(
  (Join-Path $env:ProgramFiles "Wireshark\tshark.exe"),
  (Join-Path ${env:ProgramFiles(x86)} "Wireshark\tshark.exe")
)
$hasTshark = (Get-Command tshark.exe -ErrorAction SilentlyContinue) -or
  ($tsharkCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1)

Write-Host "PacketScope installed to $installPath"
Write-Host "Start it from the Start Menu or Desktop shortcut."
if (-not $hasTshark) {
  Write-Warning "Wireshark with Npcap was not found. The dashboard will open, but packet capture requires tshark.exe and Npcap."
}