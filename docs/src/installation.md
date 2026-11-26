# Installation

git-veil is a single static binary. You also need the standard `age` tooling
to create keys and `openssl` for the signing key; both are one-time needs,
see step 1 of the [Solo guide](solo.md).

## Homebrew

```sh
brew tap prompt-cult/tap
brew install prompt-cult/tap/git-veil
```

## Release binary

Grab a binary from the
[releases page](https://github.com/prompt-cult/git-veil/releases), verify
its `.sha256`, put it on your `PATH`:

```sh
# Linux x86_64 example. macOS binaries sit beside it in the same release.
curl -sLO https://github.com/prompt-cult/git-veil/releases/latest/download/git-veil-linux-x86_64
echo "$(curl -sL https://github.com/prompt-cult/git-veil/releases/latest/download/git-veil-linux-x86_64.sha256)  git-veil-linux-x86_64" | sha256sum -c -
chmod +x git-veil-linux-x86_64 && sudo mv git-veil-linux-x86_64 /usr/local/bin/git-veil
```

`cargo binstall git-veil` resolves the same release assets (the manifest is
wired into Cargo.toml).

## Windows

Download the Windows x86-64 MSI from the [latest release](https://github.com/prompt-cult/git-veil/releases/latest), or run the following in PowerShell. It downloads the MSI and its published checksum, verifies the download, and opens the installer:

```powershell
$base = 'https://github.com/prompt-cult/git-veil/releases/latest/download'
$msi = Join-Path $env:TEMP 'git-veil-windows-x86_64.msi'
Invoke-WebRequest "$base/git-veil-windows-x86_64.msi" -OutFile $msi
$checksum = (Invoke-WebRequest "$base/git-veil-windows-x86_64.msi.sha256" -UseBasicParsing).Content
if ($checksum -is [byte[]]) { $checksum = [Text.Encoding]::UTF8.GetString($checksum) }
if ((Get-FileHash $msi -Algorithm SHA256).Hash -ne (($checksum.Trim() -split '\s+')[0])) { throw 'MSI checksum mismatch' }
Start-Process msiexec.exe -ArgumentList @('/i', "`"$msi`"") -Wait
```

The MSI installs for all users and may request administrator approval. Open a new PowerShell window after installation, then run `git-veil --version`. The release also provides a standalone `.exe` and a portable ZIP; place the executable on your `PATH` to run it directly.

## Build from source

```sh
cargo build --release
```

The binary lands at `target/release/git-veil`.

On Windows, install the Rust MSVC toolchain and WiX Toolset v4, then build
the release binary and MSI:

```powershell
cargo build --release --locked --target x86_64-pc-windows-msvc
dotnet tool install --global wix
.\scripts\build-msi.ps1
```

If Windows Application Control blocks generated build DLLs under the
checkout, keep Cargo's target directory under the user profile and the MSI
script will follow it automatically:

```powershell
$env:CARGO_TARGET_DIR = "$env:USERPROFILE\.cargo-target\git-veil"
cargo build --release --locked --target x86_64-pc-windows-msvc
.\scripts\build-msi.ps1
```

The MSI is written to `dist/git-veil-<version>-windows-x86_64.msi`. It installs
the executable under `Program Files\git-veil` and adds that directory to the
system `PATH`.

The Windows release also publishes a portable ZIP containing the CLI
executable. WinGet submission uses that ZIP and exposes the `git-veil` command.
The MSI is available separately. Maintainer submission steps are documented in
`scripts/push-winget-fork.ps1`; see also Microsoft's [manifest creation] and
[submission] guidance.

[manifest creation]: https://learn.microsoft.com/en-us/windows/package-manager/package/manifest
[submission]: https://learn.microsoft.com/en-us/windows/package-manager/package/repository

## Man pages and completions

```sh
git-veil manpages docs/man             # write roff pages into docs/man
git-veil completions zsh > "${fpath[1]}/_git-veil"   # bash, zsh or fish, to stdout
```

Every release also ships the pages as `git-veil-man-pages.tar.gz`.
