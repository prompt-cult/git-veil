[CmdletBinding()]
param(
    [string]$Configuration = "release",
    [string]$OutputDirectory = "dist"
)

$ErrorActionPreference = "Stop"

# Resolve the normal per-user tool locations even when this script is started
# from a fresh PowerShell session that has not inherited the user's PATH.
$cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargoCommand) {
    $userCargo = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
    if (Test-Path $userCargo) {
        $cargoCommand = Get-Command $userCargo
    }
}
if (-not $cargoCommand) {
    throw "Cargo was not found. Install Rust with rustup, or add $env:USERPROFILE\.cargo\bin to PATH."
}

$wixCommand = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wixCommand) {
    foreach ($globalToolWix in @(
        (Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"),
        (Join-Path $env:USERPROFILE ".dotnet\tools\wix.cmd")
    )) {
        if (Test-Path $globalToolWix) {
            $wixCommand = Get-Command $globalToolWix
            break
        }
    }
}
if (-not $wixCommand) {
    throw "WiX Toolset v4 is required. Install it with: dotnet tool install --global wix"
}

$cargoToml = Join-Path $PSScriptRoot "..\Cargo.toml"
$manifest = Get-Content -Raw $cargoToml
$versionMatch = [regex]::Match($manifest, '(?m)^version\s*=\s*"([^"]+)"')
if (-not $versionMatch.Success) {
    throw "Could not read the package version from Cargo.toml"
}
$version = $versionMatch.Groups[1].Value

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$icon = Join-Path $root "installer\git-veil.ico"
if (-not (Test-Path $icon)) {
    throw "Missing $icon. Run scripts\generate-brand-assets.ps1 first."
}
$targetRoot = $env:CARGO_TARGET_DIR
if ([string]::IsNullOrWhiteSpace($targetRoot)) {
    $targetRoot = Join-Path $root "target"
} elseif (-not [IO.Path]::IsPathRooted($targetRoot)) {
    $targetRoot = Join-Path $root $targetRoot
}
$binary = Join-Path $targetRoot "x86_64-pc-windows-msvc\$Configuration\git-veil.exe"
if (-not (Test-Path $binary)) {
    throw "Missing $binary. Build it first with: cargo build --locked --$Configuration --target x86_64-pc-windows-msvc"
}

$output = Join-Path $root $OutputDirectory
New-Item -ItemType Directory -Force -Path $output | Out-Null
$msi = Join-Path $output "git-veil-$version-windows-x86_64.msi"

& $wixCommand.Source build (Join-Path $root "installer\git-veil.wxs") `
    -arch x64 `
    -d "ProductVersion=$version" `
    -d "BinaryPath=$binary" `
    -d "IconPath=$icon" `
    -o $msi `
    -acceptEula wix7
if ($LASTEXITCODE -ne 0) {
    throw "WiX failed with exit code $LASTEXITCODE"
}

Get-FileHash -Algorithm SHA256 $msi | Format-List
Write-Host "Created $msi"
