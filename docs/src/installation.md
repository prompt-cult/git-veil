# Installation

git-veil ships as a single static binary. You need one of: a prebuilt
release binary, `cargo binstall`, or a build from source. You also need the
standard `age` tooling to create keys, and `openssl` for the signing key.
Both are one-time needs; see step 1 of the [Solo guide](solo.md).

## Prebuilt binary

Grab a release binary from the
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

After publishing a tagged release, create the WinGet manifest from that MSI
with `wingetcreate new`, use the release URL and SHA-256, validate it with
`winget validate`, and submit it to the `microsoft/winget-pkgs` repository.
WinGet accepts MSI installers and requires the installer URL and SHA-256 in
the manifest. See Microsoft's [manifest creation] and [submission] guidance.

[manifest creation]: https://learn.microsoft.com/en-us/windows/package-manager/package/manifest
[submission]: https://learn.microsoft.com/en-us/windows/package-manager/package/repository

## Man pages and completions

Man pages and shell completions are generated from the CLI definition
itself, so they always match the installed binary:

```sh
git-veil manpages docs/man             # write roff pages into docs/man
git-veil completions zsh > "${fpath[1]}/_git-veil"   # bash, zsh or fish, to stdout
```

`scripts/gen-docs.sh` regenerates the committed pages under `docs/man` and
`docs/completions` in one go. To install the man pages system-wide:

```sh
cp docs/man/*.1 /usr/local/share/man/man1/
```

Every release also ships the pages as `git-veil-man-pages.tar.gz`.
