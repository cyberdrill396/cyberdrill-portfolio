$ErrorActionPreference = "Stop"

$projectPath = $PSScriptRoot
$package = Get-Content -LiteralPath (Join-Path $projectPath "package.json") -Raw | ConvertFrom-Json
$wsPath = Join-Path $projectPath "node_modules\ws"
if (-not (Test-Path $wsPath)) {
  throw "The ws runtime dependency is missing. Run npm install before packaging."
}

$releasePath = Join-Path $projectPath "release"
$buildTag = Get-Date -Format "yyyyMMdd-HHmmss"
$stagePath = Join-Path $releasePath "PacketScope-$($package.version)-$buildTag"
$archivePath = Join-Path $releasePath "PacketScope-Windows-$($package.version)-$buildTag.zip"
New-Item -ItemType Directory -Path $stagePath -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stagePath "public") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stagePath "node_modules") -Force | Out-Null

foreach ($file in @("server.js", "launch.js", "install.ps1", "uninstall.ps1", "install.cmd", "package.json", "package-lock.json", "README.md")) {
  Copy-Item -LiteralPath (Join-Path $projectPath $file) -Destination $stagePath -Force
}
Copy-Item -Path (Join-Path $projectPath "public\*") -Destination (Join-Path $stagePath "public") -Recurse -Force
Copy-Item -LiteralPath $wsPath -Destination (Join-Path $stagePath "node_modules\ws") -Recurse -Force
Compress-Archive -Path (Join-Path $stagePath "*") -DestinationPath $archivePath -CompressionLevel Optimal

Write-Host "Windows install bundle created: $archivePath"