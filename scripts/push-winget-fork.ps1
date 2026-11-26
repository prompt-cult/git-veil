# Windows 11 release submission, run from a clean local main at origin/main:
# 1. Publish the release. In an elevated Windows 11 shell, run
#    `just test-windows-release VERSION` to check EXE, MSI and ZIP.
# 2. Generate the manifest from the release:
#    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/gen-winget-manifests.ps1 -Tag vVERSION -OutputDirectory packaging/winget
#    Enable local manifests in an elevated shell with
#    `winget settings --enable LocalManifestFiles`, then run
#    `just test-winget-windows VERSION` from a normal shell. Disable that
#    setting afterward if it was disabled before the test.
#    PR the verified manifest files and any tooling updates to main.
# 3. Fetch and fast-forward local main. Run `just submit-winget-windows VERSION`.
#    This submits the committed files. Record the main commit in the PR.
# 4. Follow the WinGet PR checks and reviewer requests. A CLA may be required.
# The WinGet PR contains only this version's three manifest files. The MSI is a
# separate release download; the submitted package is the portable ZIP.
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

# Submit exactly the files committed on main; regenerating here would break the
# correspondence between the submission and its main commit.
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$branchName = git -C $root branch --show-current
if ($branchName -ne 'main') { throw 'Run from local main.' }
if (git -C $root status --porcelain) { throw 'Working tree must be clean.' }
git -C $root fetch origin main
if ($LASTEXITCODE -ne 0) { throw 'Could not fetch origin/main.' }
$head = git -C $root rev-parse HEAD
$remote = git -C $root rev-parse origin/main
if ($head -ne $remote) { throw 'Fast-forward local main to origin/main before submission.' }
$outDir = Join-Path $root "packaging\winget\p\PromptCult\GitVeil\$v"
& winget validate --manifest $outDir
if ($LASTEXITCODE -ne 0) { throw 'Manifest validation failed.' }
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
$null = gh api "repos/$ForkOwner/winget-pkgs/git/refs" --input $refPayload
if ($LASTEXITCODE -ne 0) { throw "Could not create fork branch; inspect any existing branch before retrying." }
Remove-Item -Recurse -Force $tmp

$branch = "git-veil-$v"
$compare = "https://github.com/$WingetUpstream/compare/master...${ForkOwner}:winget-pkgs:${branch}?quick_pull=1"
Write-Host ""
Write-Host "fork branch primed: $ForkOwner/winget-pkgs@$branch (commit $commit)"
Write-Host "compare: $compare"

if ($Submit) {
    gh pr create --repo $WingetUpstream --head "${ForkOwner}:$branch" --base master `
        --title "New package: $PackageIdentifier version $v" `
        --body "Add git-veil $v as a portable x64 package."
    if ($LASTEXITCODE -ne 0) { throw 'Pull request creation failed.' }
    Write-Host "PR created from main commit $head."
} else {
    Write-Host "Prepared branch only; inspect it before submitting."
}
