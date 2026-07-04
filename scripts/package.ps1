<#
.SYNOPSIS
  Build GuderRay in release mode and produce a portable, self-contained zip
  (exe + sing-box core + wintun.dll + rule-sets), mirroring nekoray's
  "extract and run" portable distribution.

.USAGE
  pwsh ./scripts/package.ps1                # build + package, download fresh assets
  pwsh ./scripts/package.ps1 -SkipAssets     # package using assets already cached
                                              # under $env:GUDERRAY_HOME (fast, offline)
  pwsh ./scripts/package.ps1 -SingBoxVersion 1.13.14
#>
param(
    [string]$SingBoxVersion = "",
    [switch]$SkipAssets,
    [switch]$SkipBuild,
    # Optional Authenticode signing. Requires Windows SDK signtool and a code-signing certificate.
    [string]$SignTool = "",
    [string]$CertThumbprint = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# crate Cargo.tomls use `version.workspace = true`, so the version lives in the root Cargo.toml
$version = (Select-String -Path (Join-Path $root "Cargo.toml") `
    -Pattern '^\s*version\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value

$distName = "GuderRay-$version-windows-x86_64"
$distDir  = Join-Path $root "dist\$distName"
$dataDir  = Join-Path $distDir "data"

Write-Host "==> GuderRay v$version -> $distDir" -ForegroundColor Cyan

if (-not $SkipBuild) {
    Write-Host "==> cargo build --release" -ForegroundColor Cyan
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}

if (Test-Path $distDir) { Remove-Item -Recurse -Force $distDir }
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

# --- binaries ---
Copy-Item "target\release\guderray.exe"     $distDir
Copy-Item "target\release\guderray-gui.exe" $distDir

# --- optional signing ---
if ($SignTool -ne "" -and $CertThumbprint -ne "") {
    Write-Host "==> signing binaries with signtool" -ForegroundColor Cyan
    & $SignTool sign /sha1 $CertThumbprint /tr $TimestampUrl /td sha256 /fd sha256 (Join-Path $distDir "guderray.exe")
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for guderray.exe" }
    & $SignTool sign /sha1 $CertThumbprint /tr $TimestampUrl /td sha256 /fd sha256 (Join-Path $distDir "guderray-gui.exe")
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for guderray-gui.exe" }
} elseif ($SignTool -ne "" -or $CertThumbprint -ne "") {
    throw "Signing requires both -SignTool and -CertThumbprint"
}

# --- portable marker (belt-and-suspenders; presence of data\ already triggers portable mode) ---
New-Item -ItemType File -Force -Path (Join-Path $distDir "portable") | Out-Null

# --- assets: sing-box core + wintun.dll + rule-sets, fetched straight into the portable data dir ---
if (-not $SkipAssets) {
    Write-Host "==> guderray assets sync (into portable data dir)" -ForegroundColor Cyan
    $env:GUDERRAY_HOME = $dataDir
    if ($SingBoxVersion -ne "") {
        & "$distDir\guderray.exe" assets sync --version $SingBoxVersion
    } else {
        & "$distDir\guderray.exe" assets sync
    }
    if ($LASTEXITCODE -ne 0) { throw "assets sync failed" }
    Remove-Item Env:\GUDERRAY_HOME
} else {
    Write-Host "==> -SkipAssets: copying from existing `$env:GUDERRAY_HOME cache" -ForegroundColor Yellow
    if (-not $env:GUDERRAY_HOME) { throw "-SkipAssets requires `$env:GUDERRAY_HOME to point at a populated cache" }
    New-Item -ItemType Directory -Force -Path (Join-Path $dataDir "assets") | Out-Null
    Copy-Item (Join-Path $env:GUDERRAY_HOME "assets\*") (Join-Path $dataDir "assets") -Recurse -Force
}

# --- docs ---
Copy-Item "README.md" $distDir -ErrorAction SilentlyContinue

$distReadme = @"
GuderRay v$version (portable)
==============================

解压后直接运行，无需安装。配置/日志保存在本目录下的 data\ 文件夹（不写注册表、不碰 %APPDATA%）。

快速开始:
  1. guderray.exe profile add --link "vless://..."      导入节点
  2. guderray.exe routing set cn-direct                  国内直连，国外走代理
  3. guderray.exe up 1                                   启动 (或 guderray-gui.exe 用图形界面)
  4. guderray.exe up 1 --tun --sysproxy --elevate         TUN 模式 (会弹 UAC 提权)
  5. guderray.exe down                                   停止

所有命令输出 JSON，可供脚本/AI agent 直接调用。详见 README.md。
"@
Set-Content -Path (Join-Path $distDir "PORTABLE_README.txt") -Value $distReadme -Encoding utf8

# --- zip ---
$zipPath = Join-Path $root "dist\$distName.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath }
Compress-Archive -Path $distDir -DestinationPath $zipPath -CompressionLevel Optimal

$sizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
Write-Host "==> Done: $zipPath ($sizeMB MB)" -ForegroundColor Green
Write-Host "==> Unpacked folder: $distDir" -ForegroundColor Green
