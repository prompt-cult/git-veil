# Local end-to-end manifest install test for the winget bootstrap (ticket #86).
# Mirrors the windows-msi.yml CI lane: enable local manifests, install the
# release MSI from the generated manifest, verify, uninstall. One elevated pass.
$ErrorActionPreference = "Continue"
$log = "$env:TEMP\git-veil-winget-e2e.log"
Remove-Item -Force $log -ErrorAction SilentlyContinue
$manifestDir = "C:\dev\git-veil\dist\winget\manifests\p\PromptCult\GitVeil\0.17.1"

Write-Host "== winget settings --enable LocalManifestFiles =="
winget settings --enable LocalManifestFiles 2>&1 | Tee-Object -FilePath $log -Append
Write-Host "== installing from local manifest =="
winget install -m $manifestDir --accept-package-agreements --accept-source-agreements 2>&1 | Tee-Object -FilePath $log -Append
$installExit = $LASTEXITCODE
Write-Host "== installed check =="
$installed = Join-Path $env:ProgramFiles "git-veil\git-veil.exe"
& $installed --version 2>&1 | Tee-Object -FilePath $log -Append
$hash = (Get-FileHash -Algorithm SHA256 $installed).Hash.ToLower()
Write-Host "installed sha256: $hash" | Tee-Object -FilePath $log -Append
if ($hash -ne "15543eaeee2bf34d58803f7ac34462eb779d2b32c85ac352bb01c55cba5c9db5") {
    Write-Host "UNINSTALLING BACK: installed binary differs from the release executable." | Tee-Object -FilePath $log -Append
    winget uninstall -m $manifestDir --accept-source-agreements --disable-interactivity 2>&1 | Tee-Object -FilePath $log -Append
    exit 3
}
Write-Host "== uninstalling from local manifest =="
winget uninstall -m $manifestDir --accept-source-agreements 2>&1 | Tee-Object -FilePath $log -Append
Write-Host "post-uninstall check (expecting a missing-binary error):" | Tee-Object -FilePath $log -Append
$gone = Test-Path $installed
Write-Host "binary still present: $gone" | Tee-Object -FilePath $log -Append
exit $installExit
