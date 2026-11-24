# Pushes the winget manifests for a released version to the owner's winget-pkgs fork.
# Flow (mirrors deploy-tap on the brew side): generate manifests from the published
# release assets, winget-validate them, then build the fork branch through the GitHub
# API (a winget-pkgs clone is 785k files / ~250MB - never clone it).
#
# Default mode PREP-ONLY: the branch waits on the fork and the compare URL is printed.
# -Submit creates the pull request against microsoft/winget-pkgs - that click belongs
# to the owner (ticket #86); the switch exists so the owner can run it deliberately.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$PackageIdentifier = "PromptCult.GitVeil",
    [string]$Slug = "prompt-cult/git-veil",
    [string]$WingetUpstream = "microsoft/winget-pkgs",
    [string]$ForkOwner = "simbo1905",
    [switch]$Submit
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (-not $Version.StartsWith("v")) { $Version = "v$Version" }
$v = $Version.TrimStart("v")

# 1. Generate + winget-validate the manifests from the published release assets.
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "gen-winget-manifests.ps1") -Tag $Version -PackageIdentifier $PackageIdentifier
if ($LASTEXITCODE -ne 0) { throw "gen-winget-manifests.ps1 failed with exit code $LASTEXITCODE" }

$outDir = Join-Path $PSScriptRoot "..\dist\winget\manifests\p\PromptCult\GitVeil\$v"
$files = @(
    @{ path = "manifests/p/PromptCult/GitVeil/$v/$PackageIdentifier.yaml"; local = Join-Path $outDir "$PackageIdentifier.yaml" },
    @{ path = "manifests/p/PromptCult/GitVeil/$v/$PackageIdentifier.locale.en-US.yaml"; local = Join-Path $outDir "$PackageIdentifier.locale.en-US.yaml" },
    @{ path = "manifests/p/PromptCult/GitVeil/$v/$PackageIdentifier.installer.yaml"; local = Join-Path $outDir "$PackageIdentifier.installer.yaml" }
)

# 2. Fork (idempotent) and resolve the owner identity for the commit.
& gh repo fork $WingetUpstream --clone=false --default-branch-only | Out-Null
$login = gh api user -q ".login"
$email = gh api user -q ".email"
if (-not $email -or $email -eq "null") { $email = "$login@users.noreply.github.com" }
$now = [datetime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")

# 3. Blobs on the fork, then a tree on top of upstream master, then commit + ref.
#    Payloads go through --input files: gh api -f "tree=[...]" mis-encodes the array.
$entries = foreach ($f in $files) {
    $content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($f.local))
    $sha = gh api "repos/$ForkOwner/winget-pkgs/git/blobs" -f content=$content -f encoding="base64" -q ".sha"
    @{ path = $f.path; mode = "100644"; type = "blob"; sha = $sha }
}

$masterSha = gh api "repos/$WingetUpstream/git/ref/heads/master" -q ".object.sha"
$masterTree = gh api "repos/$WingetUpstream/git/commits/$masterSha" -q ".tree.sha"

$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "git-veil-winget-$(New-Guid)") -Force
$treePayload = Join-Path $tmp "tree.json"
@{ base_tree = $masterTree; tree = $entries } | ConvertTo-Json -Depth 6 | Set-Content -NoNewline $treePayload -Encoding ascii
$tree = gh api "repos/$ForkOwner/winget-pkgs/git/trees" --input $treePayload -q ".sha"

$commitPayload = Join-Path $tmp "commit.json"
@{
    message  = "Add $PackageIdentifier $v"
    tree     = $tree
    parents  = @($masterSha)
    author   = @{ name = $login; email = $email; date = $now }
    committer = @{ name = $login; email = $email; date = $now }
} | ConvertTo-Json -Depth 6 | Set-Content -NoNewline $commitPayload -Encoding ascii
$commit = gh api "repos/$ForkOwner/winget-pkgs/git/commits" --input $commitPayload -q ".sha"

$refPayload = Join-Path $tmp "ref.json"
@{ ref = "refs/heads/git-veil-$v"; sha = $commit } | ConvertTo-Json -Depth 6 | Set-Content -NoNewline $refPayload -Encoding ascii
try {
    $null = gh api "repos/$ForkOwner/winget-pkgs/git/refs" --input $refPayload
} catch {
    # Branch already exists from a previous prep: force-update it to the fresh commit.
    $null = gh api "repos/$ForkOwner/winget-pkgs/git/refs/heads/git-veil-$v" -X PATCH --input $refPayload
}
Remove-Item -Recurse -Force $tmp

$branch = "git-veil-$v"
$compare = "https://github.com/$WingetUpstream/compare/master...${ForkOwner}:winget-pkgs:${branch}?quick_pull=1"
Write-Host ""
Write-Host "fork branch primed: $ForkOwner/winget-pkgs@$branch (commit $commit)"
Write-Host "compare: $compare"

if ($Submit) {
    gh pr create --repo $WingetUpstream --head "${ForkOwner}:$branch" --base master `
        --title "$PackageIdentifier version $v" `
        --body "New package submission for git-veil $v (Windows x86_64 MSI). Installer: $Slug releases/download/$Version/git-veil-windows-x86_64.msi"
    Write-Host "PR created - review + CLA signing happen on the winget-pkgs side."
} else {
    Write-Host "prep only - the Create pull request click stays with the owner (ticket #86)."
    Write-Host "to submit deliberately later: just push-winget-windows $v -Submit  (owner-run)"
}
