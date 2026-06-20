# Git GPG

**Git GPG** is a pure Rust replacement for `git-secret` that manages encrypted files in Git repositories using OpenPGP (RFC 4880 / RFC 9580) cryptography.

## Overview

### What It Is
- A **pure Rust** CLI tool for managing secrets in Git repositories
- Uses **zero C dependencies** - only pure Rust crates (`pgp`, `clap`, `anyhow`, `serde_json`)
- **No bash** - eliminates the problems of `git-secret` (forking, version issues, shell injection)
- **Cross-platform** - works on macOS, Linux, Windows
- **RFC 4880 / RFC 9580 compatible** - roundtrips with `gpg`

### What It Does
- Encrypts/decrypts files using **OpenPGP** (Ed25519, RSA-4096, etc.)
- Tracks which files should be encrypted in `.git-gpg/config.json`
- Stores encrypted files in `.git-gpg/secrets/` (which is gitignored)
- Provides a clean CLI interface: `git gpg <command>`

### Why It Exists
`git-secret` is a bash script that:
- Forks the `gpg` CLI for every operation (slow, fragile)
- Has issues with GPG versions across systems
- Requires bash and proper shell environment
- Has potential shell injection vulnerabilities

**Git GPG solves these problems** by:
- Using the pure Rust [`pgp`](https://crates.io/crates/pgp) crate
- Implementing OpenPGP directly (RFC 4880 / RFC 9580)
- Using RustCrypto primitives (NIST-approved, audited)
- Being a single statically-linked binary

---

## Specification - Supported Commands

Based on the original `git-secret` commands, Git GPG supports:

### Core Commands

| Command | Description | Original git-secret equivalent |
|---------|-------------|-------------------------------|
| `git gpg init` | Initialize git-gpg in the current repository | `git secret init` |
| `git gpg add <files...>` | Add files to be encrypted | `git secret add <files>` |
| `git gpg remove <files...>` | Remove files from encryption tracking | `git secret remove <files>` |
| `git gpg list` | List all encrypted files | `git secret list` |
| `git gpg hide` | Encrypt all tracked files | `git secret hide` |
| `git gpg reveal` | Decrypt all tracked files | `git secret reveal` |
| `git gpg clean` | Remove all git-gpg metadata | `git secret clean` |

### Key Management Commands

| Command | Description | Notes |
|---------|-------------|-------|
| `git gpg keygen` | Generate a new OpenPGP key pair | Generates Ed25519 or RSA-4096 keys |
| `git gpg export-pubkey` | Export public key (armored ASCII) | For sharing with collaborators |
| `git gpg export-privkey` | Export private key (armored ASCII) | BACKUP ONLY - keep safe! |
| `git gpg change-passphrase` | Change passphrase on private key | Future feature |

### Additional Commands

| Command | Description |
|---------|-------------|
| `git gpg --help` | Show help |
| `git gpg --version` | Show version |

---

## Command Details

### `git gpg init`

Initialize git-gpg in the current Git repository.

**Creates:**
- `.git-gpg/config.json` - Configuration file tracking encrypted files
- `.git-gpg/secrets/` - Directory for encrypted files
- `.gitignore` entry for `.git-gpg/secrets/`

**Usage:**
```bash
cd my-project
git gpg init
```

---

### `git gpg add <files...>`

Add one or more files to be encrypted/decrypted.

**Arguments:**
- `<files...>` - One or more file paths to track

**Behavior:**
- Adds absolute paths to `.git-gpg/config.json`
- Does not encrypt the files (use `hide` for that)

**Usage:**
```bash
git gpg add secrets.env .env.local config/credentials.yml
git gpg add directory/*.key
```

---

### `git gpg remove <files...>`

Remove files from encryption tracking.

**Arguments:**
- `<files...>` - One or more file paths to stop tracking

**Behavior:**
- Removes paths from `.git-gpg/config.json`
- Does not delete the files or their encrypted versions

**Usage:**
```bash
git gpg remove old-secret.txt
git gpg remove temp/*.key
```

---

### `git gpg list`

List all files currently being tracked for encryption.

**Output:**
- Lists all files in `.git-gpg/config.json`
- Shows absolute paths

**Usage:**
```bash
git gpg list

# Example output:
# Tracked files:
#   - /home/user/project/secrets.env
#   - /home/user/project/.env.local
```

---

### `git gpg hide`

Encrypt all tracked files and remove the originals.

**Behavior:**
1. For each tracked file in `.git-gpg/config.json`:
   - Reads the plaintext file
   - Encrypts it using OpenPGP (to the default public key)
   - Saves encrypted version to `.git-gpg/secrets/<relative-path>.asc`
   - Deletes the original file
2. Encrypted files use ASCII-armored OpenPGP format (`.asc` extension)

**After running:**
- Tracked files are **encrypted at rest** in `.git-gpg/secrets/`
- Original files are **removed** from the working directory
- Safe to commit and push to Git

**Usage:**
```bash
git gpg add secrets.env
git gpg hide

# Now secrets.env is encrypted and safe to commit
git add .git-gpg/secrets/secrets.env.asc
git commit -m "Add encrypted secrets"
```

---

### `git gpg reveal`

Decrypt all tracked files and restore the originals.

**Behavior:**
1. For each tracked file in `.git-gpg/config.json`:
   - Finds the encrypted file in `.git-gpg/secrets/<relative-path>.asc`
   - Decrypts it using the default private key
   - Restores the original file to its location
   - Deletes the encrypted `.asc` file

**After running:**
- Original files are **restored** to their locations
- Encrypted files are **removed** from `.git-gpg/secrets/`
- Files are in plaintext (be careful!)

**Usage:**
```bash
# After cloning a repo with encrypted files
git gpg reveal

# Now secrets.env is available in plaintext
cat secrets.env
```

---

### `git gpg clean`

Remove all git-gpg metadata and encrypted files.

**Behavior:**
- Deletes `.git-gpg/` directory entirely
- Removes `.gitignore` entry for `.git-gpg/secrets/`
- **Warning:** This also deletes any encrypted files that haven't been revealed!

**Usage:**
```bash
# Start fresh
git gpg clean
git gpg init
```

---

### `git gpg keygen`

Generate a new OpenPGP key pair.

**Options:**
- `--name <name>` - Name for the key (default: "git-gpg user")
- `--email <email>` - Email for the key (default: "git-gpg@example.com")
- `--key-type <type>` - Key type: `ed25519` (default) or `rsa4096`

**Creates:**
- `.git-gpg/public.key` - Your public key (share with collaborators)
- `.git-gpg/private.key` - Your private key (KEEP THIS SAFE!)

**Usage:**
```bash
# Generate Ed25519 key (recommended)
git gpg keygen --name "Alice" --email "alice@example.com"

# Generate RSA-4096 key
git gpg keygen --name "Bob" --email "bob@example.com" --key-type rsa4096
```

---

### `git gpg export-pubkey`

Export your public key in ASCII-armored format.

**Output:**
- Prints public key to stdout (OpenPGP ASCII-armored format)

**Usage:**
```bash
# Export to file
git gpg export-pubkey > my-public-key.asc

# Share with collaborators
# (send them my-public-key.asc)
```

---

### `git gpg export-privkey`

Export your private key in ASCII-armored format.

**Warning:** Your private key can decrypt ALL files encrypted to your public key. Keep it safe!

**Output:**
- Prints private key to stdout (OpenPGP ASCII-armored format)

**Usage:**
```bash
# Export to file (BACKUP ONLY!)
git gpg export-privkey > my-private-key.asc

# Store in a secure location
# (encrypted USB drive, password manager, etc.)
```

---

## Installation

### Using mise (Recommended)

This project uses [mise](https://mise.jdx.dev/) for toolchain management.

```bash
# Install mise
curl https://mise.jdx.dev/install.sh | sh

# In the project directory
mise use rust@stable
mise exec -- cargo build --release

# Binary is at ./target/release/git-gpg
```

### Direct cargo install

```bash
cargo install --git https://codeforge.io/git-gpg/git-gpg.git
```

---

## Project Structure

```
.
├── .git-gpg/                          # Git GPG metadata
│   ├── config.json                    # Tracked files list
│   ├── public.key                     # Public key
│   ├── private.key                    # Private key (KEEP SAFE!)
│   └── secrets/                       # Encrypted files
│       ├── file1.txt.asc             # Encrypted files
│       └── dir/file2.yml.asc         # (preserve directory structure)
├── Cargo.toml                         # Rust dependencies
├── .mise.toml                        # mise configuration
├── README.md                          # This file
└── src/
    └── main.rs                        # Implementation
```

---

## Technical Details

### OpenPGP Implementation

Git GPG uses the [`pgp`](https://crates.io/crates/pgp) crate which provides:
- **Pure Rust** OpenPGP implementation
- **RFC 4880** compliance (baseline for RFC 9580)
- **Zero C dependencies**
- Uses **RustCrypto** primitives:
  - `aes` - AES-256 symmetric encryption
  - `sha2` - SHA-256/512 hashing
  - `rsa` - RSA public-key crypto
  - `ed25519-dalek` - Ed25519 signatures
  - `curve25519-dalek` - Curve25519 key exchange

### Key Types Supported

| Type | Algorithm | Security | Speed |
|------|-----------|----------|-------|
| `ed25519` | EdDSA over Curve25519 | ✅ Modern | ⚡ Fast |
| `rsa4096` | RSA 4096-bit | ✅ NIST-approved | 🐢 Slower |

### File Format

- **Plaintext:** Original files (stored in working directory when revealed)
- **Encrypted:** ASCII-armored OpenPGP messages (`.asc` extension)
- **Config:** JSON file tracking which files are encrypted
- **Keys:** ASCII-armored OpenPGP keys

### Interoperability

Git GPG files are **fully compatible** with:
- `gpg --encrypt` / `gpg --decrypt`
- Other OpenPGP implementations
- Existing GPG keyrings

---

## License

**GPL-3.0-or-later**

---

## Repository

- **Host:** CodeForge
- **URL:** https://codeforge.io/git-gpg/git-gpg
