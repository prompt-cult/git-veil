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
