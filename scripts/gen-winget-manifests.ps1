# Generates winget manifests for a git-veil release.
# The winget mirror of `deploy-tap` (see the brew-justfile on origin/brew-justfile):
# hashes the published Windows release assets,
# and writes the three manifests for the winget-pkgs bootstrap PR.
# The generated manifests are the only output; nothing is submitted here.
[CmdletBinding()]
param(
    [string]$Tag,
    [string]$PackageIdentifier = "PromptCult.GitVeil",
    [string]$OutputDirectory = "dist\winget\manifests"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (-not $Tag) {
    $cargoToml = Get-Content -Raw (Join-Path $PSScriptRoot "..\Cargo.toml")
    $manifest = [regex]::Match($cargoToml, '(?m)^version\s*=\s*"([^"]+)"')
    if (-not $manifest.Success) { throw "Could not read the package version from Cargo.toml; pass -Tag explicitly." }
    $Tag = "v" + $manifest.Groups[1].Value
}
if (-not $Tag.StartsWith("v")) { $Tag = "v$Tag" }
$version = $Tag.TrimStart("v")

$releaseBase = "https://github.com/prompt-cult/git-veil/releases/download/$Tag"
$kinds = @{
    portable = @{ asset = "git-veil-windows-x86_64-portable.zip"; checksum = "git-veil-windows-x86_64-portable.zip.sha256" }
}

# Hash each asset and cross-check against the .sha256 the release workflow published.
# Mirrors deploy-tap's `curl -sL ... | sha256sum` on the published release.
$hashes = @{}
$tempFiles = @{}
foreach ($kind in $kinds.Keys) {
    $url = "$releaseBase/$($kinds[$kind].asset)"
    $tempFile = Join-Path $env:TEMP $kinds[$kind].asset
    Invoke-WebRequest -Uri $url -OutFile $tempFile -UseBasicParsing
    $tempFiles[$kind] = $tempFile

    # Windows PowerShell 5.1 hands byte[] back for small text/plain responses;
    # decode explicitly instead of letting `-split` stringify decimal byte codes.
    $content = (Invoke-WebRequest -Uri "$releaseBase/$($kinds[$kind].checksum)" -UseBasicParsing).Content
    if ($content -is [byte[]]) { $content = [Text.Encoding]::UTF8.GetString($content) }
    $published = (([string]$content).Trim() -split '\s+')[0]
    $computed = (Get-FileHash -Algorithm SHA256 $tempFile).Hash.ToLower()
    # winget expects uppercase hex in InstallerSha256; the published checksum is lowercase.
    $hashes[$kind] = $computed.ToUpper()
    if ($computed -ne $published.ToLower()) {
        throw "$($kinds[$kind].asset): computed $computed does not match the published $published"
    }
}

$release = Invoke-RestMethod -Uri "https://api.github.com/repos/prompt-cult/git-veil/releases/tags/$Tag"
$releaseDate = ([datetime]$release.published_at).ToString("yyyy-MM-dd")

$letters = $PackageIdentifier.Split(".")
$outDir = Join-Path $OutputDirectory ($letters[0].Substring(0,1).ToLower())
foreach ($part in ($letters + $version)) { $outDir = Join-Path $outDir $part }
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$idPath = Join-Path $outDir $PackageIdentifier
$description = "Secret management for git repositories using age X25519 encryption"

# 1. Version manifest.
@"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.version.1.12.0.schema.json
PackageIdentifier: $PackageIdentifier
PackageVersion: $version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.12.0
"@ | Set-Content -NoNewline "$idPath.yaml" -Encoding ascii

# 2. Default locale manifest.
@"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.defaultLocale.1.12.0.schema.json
PackageIdentifier: $PackageIdentifier
PackageVersion: $version
PackageLocale: en-US
Publisher: prompt-cult
PublisherUrl: https://github.com/prompt-cult
PackageName: git-veil
PackageUrl: https://github.com/prompt-cult/git-veil
License: MIT OR Apache-2.0
LicenseUrl: https://github.com/prompt-cult/git-veil/blob/main/LICENSE
Copyright: Copyright (c) git-veil contributors
ShortDescription: $description
Moniker: git-veil
Tags:
- git
- secrets
- encryption
- age
ManifestType: defaultLocale
ManifestVersion: 1.12.0
"@ | Set-Content -NoNewline "$idPath.locale.en-US.yaml" -Encoding ascii

# 3. Portable package manifest: WinGet stages the ZIP and adds the CLI alias to PATH.
@"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.installer.1.12.0.schema.json
PackageIdentifier: $PackageIdentifier
PackageVersion: $version
Platform:
- Windows.Desktop
MinimumOSVersion: 10.0.0.0
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
- RelativeFilePath: git-veil-windows-x86_64.exe
  PortableCommandAlias: git-veil
ReleaseDate: $releaseDate
Installers:
- Architecture: x64
  InstallerUrl: $releaseBase/$($kinds["portable"].asset)
  InstallerSha256: $($hashes["portable"])
ManifestType: installer
ManifestVersion: 1.12.0
"@ | Set-Content -NoNewline "$idPath.installer.yaml" -Encoding ascii

# winget's own schema check is the local gate on this host.
$wingetCommand = Get-Command winget -ErrorAction SilentlyContinue
if ($wingetCommand) {
    & winget validate --manifest $outDir
    if ($LASTEXITCODE -ne 0) { throw "winget validate failed with exit code $LASTEXITCODE" }
} else {
    Write-Host "winget is not on PATH; skipped winget validate."
}

$tempFiles.Values | ForEach-Object { Remove-Item -Force $_ -ErrorAction SilentlyContinue }

Write-Host "manifests: $outDir"
Write-Host "portable zip sha256: $($hashes["portable"])"
