# Local end-to-end manifest install test for the winget bootstrap (ticket #86).
# Enable local manifests in an elevated shell before running this script. The
# package itself is installed in the current user's scope so uninstall uses the
# same scope as install.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Version)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')
$log = "$env:TEMP\git-veil-winget-e2e.log"
Remove-Item -Force $log -ErrorAction SilentlyContinue
$manifestDir = Join-Path $PSScriptRoot "..\packaging\winget\p\PromptCult\GitVeil\$Version"
$alias = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links\git-veil.exe"
$packageDir = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages\PromptCult.GitVeil__DefaultSource'
$releaseBase = "https://github.com/prompt-cult/git-veil/releases/download/v$Version"
$checksum = (Invoke-WebRequest "$releaseBase/git-veil-windows-x86_64.exe.sha256" -UseBasicParsing).Content
if ($checksum -is [byte[]]) { $checksum = [Text.Encoding]::UTF8.GetString($checksum) }
$publishedExeHash = (([string]$checksum).Trim() -split '\s+')[0].ToLower()
if ((Test-Path $alias) -or (Test-Path $packageDir)) { throw 'An existing git-veil installation must not be replaced by the test.' }

Write-Host "== installing from local manifest =="
$install = winget install -m $manifestDir --scope user --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Tee-Object -FilePath $log -Append
if ($LASTEXITCODE -ne 0) { throw "winget install failed: $LASTEXITCODE" }
try {
    $command = if (Test-Path $alias) { $alias } else { Join-Path $packageDir 'git-veil.exe' }
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User') -split ';'
    if (-not (Test-Path $command) -or ($userPath -notcontains (Split-Path $command))) { throw 'git-veil command is not on the user PATH.' }
    if ((& $command --version).Trim() -ne "git-veil $Version") { throw 'Installed executable reports the wrong version.' }
    if ((Get-FileHash -Algorithm SHA256 $command).Hash.ToLower() -ne $publishedExeHash) { throw 'Installed executable differs from the release EXE.' }
} finally {
    winget uninstall -m $manifestDir --accept-source-agreements --disable-interactivity 2>&1 | Tee-Object -FilePath $log -Append
    if ($LASTEXITCODE -ne 0) { throw "winget uninstall failed: $LASTEXITCODE" }
}
if ((Test-Path $alias) -or (Test-Path $packageDir)) { throw 'Portable package remains after uninstall.' }
Write-Host "WINGET_PORTABLE_E2E=PASS"
