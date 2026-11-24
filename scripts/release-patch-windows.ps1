# The Windows mirror of `release-patch` (see the brew-justfile on origin/brew-justfile):
# bump -> tag -> push -> wait for the release and MSI workflows -> winget manifest prep -> fork branch.
# The final compare URL is printed and opened in the browser; that page's
# "Create pull request" click - the winget submission itself - stays with the owner.
# No agent submits anything to winget on the owner's behalf (ticket #86).
[CmdletBinding()]
param(
    [string]$Slug = "prompt-cult/git-veil",
    [string]$WingetUpstream = "microsoft/winget-pkgs",
    [string]$ForkOwner = "simbo1905",
    [string]$PackageIdentifier = "PromptCult.GitVeil"
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
# PS 5.1 only ships a BOM'd UTF8 encoder; cargo needs BOM-less manifests,
# so everything rewritten here goes through WriteAllText(utf8NoBom).
$noBom = New-Object System.Text.UTF8Encoding $false
function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, $script:noBom)
}
# 1. Bump the version in Cargo.toml (first `^version = ` line) and Cargo.lock
#    (first occurrence of the old version value), mirroring the sed-edits on the mac side.
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$cargoTomlPath = Join-Path $root "Cargo.toml"
$cargoToml = Get-Content -Raw $cargoTomlPath
$old = [regex]::Match($cargoToml, '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
if (-not $old) { throw "Could not read the package version from Cargo.toml" }
$parts = $old.Split(".")
$new = "{0}.{1}.{2}" -f $parts[0], $parts[1], ([int]$parts[2] + 1)
Write-Host "bumping $old -> $new"
Write-Utf8NoBom $cargoTomlPath ([regex]::new("(?m)^version\s*=\s*`"$old`"").Replace($cargoToml, "version = `"$new`"", 1))
$cargoLockPath = Join-Path $root "Cargo.lock"
Write-Utf8NoBom $cargoLockPath ([regex]::new("version\s*=\s*`"$old`"").Replace((Get-Content -Raw $cargoLockPath), "version = `"$new`"", 1))
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to $new"
git tag "v$new"
git push origin HEAD:main
git push origin "v$new"
# 2. Wait for the release build and the Windows MSI build (the winget manifest
#    hashes come from the assets those two workflows attach to the release).
#    Filter on the exact tag: -L 1 alone can match the previous tag's run.
function Wait-Workflow([string]$Workflow) {
    Write-Host "waiting for $Workflow on v$new"
    for ($i = 1; $i -le 90; $i++) {
        $run = gh run list --repo $Slug --workflow $Workflow -L 1 --branch "v$new" --json status,conclusion | ConvertFrom-Json
        $state = "{0}:{1}" -f $run[0].status, $run[0].conclusion
        Write-Host "  ${Workflow}: $state"
        if ($state -eq "completed:success") { return }
        Start-Sleep -Seconds 20
    }
    throw "$Workflow never completed on v$new"
}
Wait-Workflow release.yml  # release.yml calls windows-msi.yml and (after the fix) gates on it
# 3. Winget prep: generate + validate manifests, push the fork branch (prep only;
#    the Create pull request click stays with the owner, ticket #86).
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "push-winget-fork.ps1") -Version $new -PackageIdentifier $PackageIdentifier -Slug $Slug -WingetUpstream $WingetUpstream -ForkOwner $ForkOwner
if ($LASTEXITCODE -ne 0) { throw "push-winget-fork.ps1 failed with exit code $LASTEXITCODE" }