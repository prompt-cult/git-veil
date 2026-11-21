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

## Man pages and completions

```sh
git-veil manpages docs/man             # write roff pages into docs/man
git-veil completions zsh > "${fpath[1]}/_git-veil"   # bash, zsh or fish, to stdout
```

Every release also ships the pages as `git-veil-man-pages.tar.gz`.
