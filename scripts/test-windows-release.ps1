# Run on Windows 11 against the published release before WinGet submission.
# Verifies downloaded checksums, EXE and ZIP contents, then installs the MSI,
# checks its executable, and uninstalls it. MSI installation can prompt for UAC.
# Do not run over an existing git-veil MSI installation.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Version)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')
$base = "https://github.com/prompt-cult/git-veil/releases/download/v$Version"
$dir = Join-Path $env:TEMP "git-veil-release-test-$Version"
New-Item -ItemType Directory -Force $dir | Out-Null
foreach ($name in @('git-veil-windows-x86_64.exe', 'git-veil-windows-x86_64-portable.zip', 'git-veil-windows-x86_64.msi')) {
    $path = Join-Path $dir $name
    Invoke-WebRequest "$base/$name" -OutFile $path -UseBasicParsing
    $checksum = (Invoke-WebRequest "$base/$name.sha256" -UseBasicParsing).Content
    if ($checksum -is [byte[]]) { $checksum = [Text.Encoding]::UTF8.GetString($checksum) }
    $expected = (([string]$checksum).Trim() -split '\s+')[0]
    if ((Get-FileHash $path -Algorithm SHA256).Hash -ne $expected) { throw "Checksum mismatch: $name" }
    Write-Host "Verified $name"
}
$exe = Join-Path $dir 'git-veil-windows-x86_64.exe'
if ((& $exe --version).Trim() -ne "git-veil $Version") { throw 'EXE version mismatch.' }
& $exe --help | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'EXE help failed.' }
$zipDir = Join-Path $dir 'portable'
Expand-Archive -Path (Join-Path $dir 'git-veil-windows-x86_64-portable.zip') -DestinationPath $zipDir -Force
$portable = Join-Path $zipDir 'git-veil.exe'
if ((Get-FileHash $portable).Hash -ne (Get-FileHash $exe).Hash) { throw 'ZIP executable does not match the release EXE.' }
if ((& $portable --version).Trim() -ne "git-veil $Version") { throw 'ZIP executable version mismatch.' }
$installed = Join-Path $env:ProgramFiles 'git-veil\git-veil.exe'
if (Test-Path $installed) { throw 'An existing git-veil installation must not be replaced by the test.' }
$msi = Join-Path $dir 'git-veil-windows-x86_64.msi'
$install = Start-Process msiexec.exe -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart') -Wait -PassThru
if ($install.ExitCode -ne 0) { throw "MSI install returned $($install.ExitCode)." }
try {
    if ((Get-FileHash $installed).Hash -ne (Get-FileHash $exe).Hash) { throw 'MSI executable differs from the release EXE.' }
    if ((& $installed --version).Trim() -ne "git-veil $Version") { throw 'MSI executable version mismatch.' }
} finally {
    $uninstall = Start-Process msiexec.exe -ArgumentList @('/x', "`"$msi`"", '/qn', '/norestart') -Wait -PassThru
    if ($uninstall.ExitCode -ne 0) { throw "MSI uninstall returned $($uninstall.ExitCode)." }
}
if (Test-Path $installed) { throw 'MSI executable remains after uninstall.' }
Write-Host 'WINDOWS_RELEASE_TEST=PASS'
