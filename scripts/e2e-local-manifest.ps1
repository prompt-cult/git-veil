# Local end-to-end manifest install test for the winget bootstrap (ticket #86).
# Enable local manifests in an elevated shell before running this script. The
# package itself is installed in the current user's scope so uninstall uses the
# same scope as install.
[CmdletBinding()]
param([string]$Version = "0.18.4")

$ErrorActionPreference = "Stop"
$log = "$env:TEMP\git-veil-winget-e2e.log"
Remove-Item -Force $log -ErrorAction SilentlyContinue
$manifestDir = "C:\dev\git-veil\dist\winget\manifests\p\PromptCult\GitVeil\$Version"
$alias = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links\git-veil.exe"
$releaseBase = "https://github.com/prompt-cult/git-veil/releases/download/v$Version"
$publishedExeHash = ((Invoke-WebRequest "$releaseBase/git-veil-windows-x86_64.exe.sha256" -UseBasicParsing).Content.Trim() -split '\s+')[0].ToLower()

Write-Host "== installing from local manifest =="
$install = winget install -m $manifestDir --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Tee-Object -FilePath $log -Append
if ($LASTEXITCODE -ne 0) { throw "winget install failed: $LASTEXITCODE" }
Write-Host "== installed check =="
& $alias --version 2>&1 | Tee-Object -FilePath $log -Append
if ($LASTEXITCODE -ne 0) { throw "portable command alias failed: $LASTEXITCODE" }
$hash = (Get-FileHash -Algorithm SHA256 $alias).Hash.ToLower()
Write-Host "installed sha256: $hash" | Tee-Object -FilePath $log -Append
if ($hash -ne $publishedExeHash) { throw "installed binary differs from the published executable" }
Write-Host "== uninstalling from local manifest =="
winget uninstall -m $manifestDir --accept-source-agreements --disable-interactivity 2>&1 | Tee-Object -FilePath $log -Append
if ($LASTEXITCODE -ne 0) { throw "winget uninstall failed: $LASTEXITCODE" }
if (Test-Path $alias) { throw "portable command alias remains after uninstall" }
Write-Host "WINGET_PORTABLE_E2E=PASS"
