# Git GPG

**Git GPG** is a pure Rust tool for managing encrypted files in Git repositories using OpenPGP, with a trust model based on digitally-signed keyrings.

## Overview

### What It Is
- A **pure Rust** CLI tool for managing secrets in Git repositories
- Uses **zero C dependencies** - only pure Rust crates (`pgp`, `clap`, `anyhow`, `serde_json`)
- **No external `gpg` process forking** - all crypto is pure Rust
- **Cross-platform** - works on macOS, Linux, Windows
- **RFC 4880 / RFC 9580 compatible** - interoperates with standard GPG

### What It Does
- Encrypts/decrypts files using **OpenPGP** with a signed keyring trust model
- Repository owner signs a keyring file containing collaborator public keys
- Each command verifies the keyring signature before encrypting/decrypting
- Derives repository identity from `git remote` push URL
- Integrates with your existing GPG keyring (defaults to `~/.gnupg`)

### Trust Model

1. **Repository Identity**: Derived from git remote push URL
   - Format: `{repo}+{user}@{service}`
   - Example: `fara+simbo1905@github.com` from `git@github.com:simbo1905/fara.git`
   - Example: `nextcloud-hello-world+simbo1905@codeberg.org` from `ssh://git@codeberg.org/simbo1905/nextcloud-hello-world.git`

2. **Signed Keyring**: `.git-gpg/keyring` contains:
   ```
   -----BEGIN GIT-GPG KEYRING-----
   alice@example.com:LS0tLS1CRUdJTi...=:ABCD1234EF567890
   bob@work.com:bXkgcHVibGljIGtleQ==:1234ABCD5678EF90
   -----END GIT-GPG KEYRING-----
   -----BEGIN PGP SIGNATURE-----
   ... digital signature of everything above ...
   -----END PGP SIGNATURE-----
   ```

3. **Trust Flow**:
   - Repository owner uses `git gpg trust {repo-id} {signing-key.pub}` to establish trust in the signing key
   - Owner uses `git gpg tell {email} {collaborator.pub}` to add collaborators (signs keyring after each addition)
   - All `hide`/`reveal` operations verify the keyring signature against the trusted signing key
   - If signature verification fails, operations abort

---

## Repository Identity

Git GPG derives a unique repository identity from the git remote push URL.

### Examples

| Push URL | Repository Identity |
|----------|---------------------|
| `git@github.com:microsoft/fara.git` | `fara+microsoft@github.com` |
| `ssh://git@codeberg.org/simbo1905/nextcloud-hello-world.git` | `nextcloud-hello-world+simbo1905@codeberg.org` |
| `https://gitlab.com/myorg/project.git` | `project+myorg@gitlab.com` |

### Remote Selection

All commands accept `--remote <name>` to specify which git remote to use (defaults to `origin`).

```bash
# Use default 'origin' remote
git gpg hide

# Use 'simbo1905' remote
git gpg hide --remote simbo1905
```

---

## Command Reference

### Core Workflow Commands

| Command | Description |
|---------|-------------|
| `git gpg init` | Initialize git-gpg in the current repository |
| `git gpg trust <repo-id> <signing-key.pub>` | Trust a signing key for this repository |
| `git gpg tell <email> <collaborator.pub>` | Add a collaborator's public key to the signed keyring |
| `git gpg add <files...>` | Track files for encryption |
| `git gpg remove <files...>` | Stop tracking files |
| `git gpg list` | List tracked files |
| `git gpg hide` | Encrypt all tracked files (verifies keyring signature first) |
| `git gpg reveal` | Decrypt all tracked files (verifies keyring signature first) |
| `git gpg clean` | Remove all git-gpg metadata |

### Query Commands

| Command | Description |
|---------|-------------|
| `git gpg whoami` | Show your identity (from git config or `--email` override) |
| `git gpg show-repo-id` | Show derived repository identity |
| `git gpg verify-keyring` | Verify keyring signature |
| `git gpg list-keys` | List all keys in the keyring |

---

## Setup Workflow

### 1. Repository Owner Setup

```bash
cd my-repo

# Initialize git-gpg
git gpg init

# Generate or export your signing key (using standard gpg)
gpg --gen-key  # or use existing key
gpg --armor --export alice@example.com > alice.pub

# Trust your signing key for this repo
# (computes repo-id from 'origin' remote push URL)
git gpg trust fara+simbo1905@github.com alice.pub

# Add yourself to the keyring
git gpg tell alice@example.com alice.pub

# Track secret files
git gpg add .env secrets.yml

# Commit the signed keyring
git add .git-gpg/keyring
git commit -m "Add signed keyring"
```

### 2. Add Collaborators

```bash
# Bob sends you bob.pub
# Verify it's really Bob's key, then:
git gpg tell bob@work.com bob.pub

# This:
# 1. Checks bob@work.com is an identity in bob.pub
# 2. Extracts fingerprint and base64-encodes the key
# 3. Appends to keyring
# 4. Signs the entire keyring with alice@example.com's private key
# 5. Test-encrypts a temp file to verify the key works

git add .git-gpg/keyring
git commit -m "Add Bob to keyring"
```

### 3. Collaborator Setup

```bash
# Clone the repo
git clone git@github.com:simbo1905/fara.git
cd fara

# Trust the repo signing key (Alice's key)
# This installs alice.pub into Bob's GPG keyring
git gpg trust fara+simbo1905@github.com alice.pub

# Verify the keyring
git gpg verify-keyring
# ✓ Keyring signature valid (signed by alice@example.com)

# Reveal secrets
git gpg reveal
# This:
# 1. Verifies keyring signature
# 2. Finds bob@work.com in keyring (uses git config user.email)
# 3. Decrypts tracked files using bob@work.com's private key from ~/.gnupg
```

---

## Command Details

### `git gpg init`

Initialize git-gpg in the current repository.

**Creates:**
- `.git-gpg/keyring` - Empty signed keyring file
- `.git-gpg/tracked.json` - Tracked files list
- `.gitignore` entry for `.git-gpg/secrets/`

**Usage:**
```bash
cd my-project
git gpg init
```

---

### `git gpg trust <repo-id> <signing-key.pub>`

Trust a signing key for this repository. The signing key is used to verify the keyring.

**Arguments:**
- `<repo-id>` - Repository identity (e.g., `fara+simbo1905@github.com`)
- `<signing-key.pub>` - Path to ASCII-armored public key

**Options:**
- `--remote <name>` - Git remote to verify against (default: `origin`)
- `--gpg-home <path>` - GPG home directory (default: `~/.gnupg`)

**Behavior:**
1. Computes expected repo-id from `git remote show <remote>` push URL
2. Verifies provided repo-id matches computed value
3. Verifies signing-key.pub contains an identity matching repo-id
4. Imports signing-key.pub into GPG keyring at `--gpg-home`
5. Stores trust mapping in `.git-gpg/trust.json`

**Usage:**
```bash
# Trust alice.pub for this repo (using 'origin' remote)
git gpg trust fara+simbo1905@github.com alice.pub

# Use custom remote
git gpg trust fara+simbo1905@codeberg.org alice.pub --remote simbo1905

# Use custom GPG home
git gpg trust fara+simbo1905@github.com alice.pub --gpg-home /opt/gpg
```

---

### `git gpg tell <email> <collaborator.pub>`

Add a collaborator's public key to the signed keyring.

**Arguments:**
- `<email>` - Email address (must be an identity in the public key)
- `<collaborator.pub>` - Path to ASCII-armored public key

**Options:**
- `--remote <name>` - Git remote (default: `origin`)
- `--gpg-home <path>` - GPG home directory (default: `~/.gnupg`)

**Behavior:**
1. Verifies `<email>` is an identity in `<collaborator.pub>`
2. Extracts key fingerprint
3. Base64-encodes the public key
4. Appends `{email}:{base64_key}:{fingerprint}` to `.git-gpg/keyring`
5. Signs the entire keyring (including end marker) using the trusted signing key
6. Test-encrypts `.git-gpg/keyring` with the new key to verify it works

**Keyring Format:**
```
-----BEGIN GIT-GPG KEYRING-----
alice@example.com:LS0tLS1CRUdJTi...=:ABCD1234EF567890
bob@work.com:bXkgcHVibGljIGtleQ==:1234ABCD5678EF90
-----END GIT-GPG KEYRING-----
-----BEGIN PGP SIGNATURE-----
iQIzBAABCAAdFiEE...
-----END PGP SIGNATURE-----
```

**Usage:**
```bash
# Add Bob's key
git gpg tell bob@work.com bob.pub

# Verify it was added
git gpg list-keys
# alice@example.com (ABCD1234EF567890)
# bob@work.com (1234ABCD5678EF90)
```

**Failure Cases:**
- `<email>` not found in `<collaborator.pub>` identities → error
- Test encryption fails → error (key is invalid or corrupted)
- Signing key not trusted → error (run `git gpg trust` first)

---

### `git gpg add <files...>`

Track files for encryption.

**Arguments:**
- `<files...>` - One or more file paths

**Behavior:**
- Adds absolute paths to `.git-gpg/tracked.json`
- Does not encrypt files (use `hide` for that)

**Usage:**
```bash
git gpg add .env secrets.yml config/credentials.json
```

---

### `git gpg remove <files...>`

Stop tracking files.

**Arguments:**
- `<files...>` - One or more file paths

**Behavior:**
- Removes paths from `.git-gpg/tracked.json`
- Does not delete encrypted or plaintext versions

**Usage:**
```bash
git gpg remove old-secret.txt
```

---

### `git gpg list`

List all tracked files.

**Output:**
```bash
Tracked files:
  - /home/user/project/.env
  - /home/user/project/secrets.yml
```

---

### `git gpg hide`

Encrypt all tracked files.

**Options:**
- `--remote <name>` - Git remote (default: `origin`)
- `--gpg-home <path>` - GPG home directory (default: `~/.gnupg`)

**Behavior:**
1. Verifies `.git-gpg/keyring` signature against trusted signing key
2. If signature invalid or signing key not trusted → **abort**
3. Reads all public keys from keyring
4. For each tracked file:
   - Encrypts to **all** public keys in keyring
   - Saves encrypted version to `.git-gpg/secrets/<relative-path>.asc`
   - Deletes plaintext original
5. Updates `.git-gpg/tracked.json` with encryption metadata

**Usage:**
```bash
# Encrypt using 'origin' remote
git gpg hide

# Encrypt using custom remote
git gpg hide --remote simbo1905

# After hiding, commit encrypted files
git add .git-gpg/secrets/
git commit -m "Hide secrets"
```

**Failure Cases:**
- Keyring signature verification fails → abort
- Signing key not trusted → abort (run `git gpg trust` first)
- No public keys in keyring → abort

---

### `git gpg reveal`

Decrypt all tracked files.

**Options:**
- `--email <addr>` - Email to use for decryption (default: `git config user.email`)
- `--remote <name>` - Git remote (default: `origin`)
- `--gpg-home <path>` - GPG home directory (default: `~/.gnupg`)

**Behavior:**
1. Verifies `.git-gpg/keyring` signature against trusted signing key
2. If signature invalid → **abort**
3. Finds `--email` in keyring to get key fingerprint
4. For each tracked file:
   - Finds encrypted file at `.git-gpg/secrets/<relative-path>.asc`
   - Decrypts using private key from `--gpg-home` matching `--email`
   - Restores plaintext to original location
   - Deletes encrypted `.asc` file

**Usage:**
```bash
# Decrypt using git config user.email
git gpg reveal

# Decrypt using specific email
git gpg reveal --email bob@work.com

# Decrypt using custom GPG home
git gpg reveal --gpg-home /opt/gpg
```

**Failure Cases:**
- Keyring signature verification fails → abort
- `--email` not found in keyring → abort
- Private key not found in GPG keyring → abort
- Decryption fails (wrong key) → abort

---

### `git gpg whoami`

Show your identity.

**Options:**
- `--email <addr>` - Override email (default: `git config user.email`)

**Output:**
```bash
Your identity: alice@example.com
GPG home: /home/alice/.gnupg
```

---

### `git gpg show-repo-id`

Show derived repository identity.

**Options:**
- `--remote <name>` - Git remote (default: `origin`)

**Output:**
```bash
Repository ID: fara+simbo1905@github.com
Remote: origin
Push URL: git@github.com:simbo1905/fara.git
```

---

### `git gpg verify-keyring`

Verify keyring signature.

**Options:**
- `--remote <name>` - Git remote (default: `origin`)
- `--gpg-home <path>` - GPG home directory (default: `~/.gnupg`)

**Output:**
```bash
✓ Keyring signature valid
  Signed by: alice@example.com (ABCD1234EF567890)
  Repository ID: fara+simbo1905@github.com
  Keys in keyring: 2
```

**Failure:**
```bash
✗ Keyring signature verification failed
  Expected signer: alice@example.com
  Trusted key fingerprint: ABCD1234EF567890
```

---

### `git gpg list-keys`

List all keys in the keyring.

**Output:**
```bash
Keys in keyring:
  alice@example.com (ABCD1234EF567890)
  bob@work.com (1234ABCD5678EF90)
  charlie@company.com (EF901234ABCD5678)
```

---

### `git gpg clean`

Remove all git-gpg metadata.

**Warning:** This deletes:
- `.git-gpg/` directory
- `.gitignore` entry for `.git-gpg/secrets/`

**Usage:**
```bash
git gpg clean
```

---

## File Structure

```
.git-gpg/
├── keyring              # Signed keyring: email:base64_key:fingerprint
├── trust.json           # Trusted signing keys: { "repo-id": "fingerprint" }
├── tracked.json         # Tracked files list
└── secrets/             # Encrypted files (gitignored)
    ├── .env.asc
    └── secrets.yml.asc
```

### `.git-gpg/keyring` Format

```
-----BEGIN GIT-GPG KEYRING-----
alice@example.com:LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWS...=:ABCD1234EF567890
bob@work.com:bXkgcHVibGljIGtleSBkYXRh...=:1234ABCD5678EF90
-----END GIT-GPG KEYRING-----
-----BEGIN PGP SIGNATURE-----
iQIzBAABCAAdFiEEABCD1234EF567890ABCD1234EF567890AAoJEABCD1234EF56
789012345678901234567890123456789012345678901234567890123456789012
...
-----END PGP SIGNATURE-----
```

**Format Details:**
- Each line: `{email}:{base64_public_key}:{fingerprint}`
- `:` is the separator (not in email addresses or base64)
- Entire content (including markers and key lines) is signed
- Signature follows the `-----END GIT-GPG KEYRING-----` marker

### `.git-gpg/trust.json` Format

```json
{
  "fara+simbo1905@github.com": "ABCD1234EF567890"
}
```

Maps repository identity to trusted signing key fingerprint.

### `.git-gpg/tracked.json` Format

```json
{
  "files": [
    "/home/user/project/.env",
    "/home/user/project/secrets.yml"
  ]
}
```

---

## Integration with Existing GPG

Git GPG uses your existing GPG keyring (defaults to `~/.gnupg`).

**No key generation** - use `gpg --gen-key` to create keys.

**Import keys:**
```bash
# Import into default GPG home
gpg --import alice.pub

# Import into custom location
gpg --homedir /opt/gpg --import alice.pub
```

**Export keys:**
```bash
# Export public key
gpg --armor --export alice@example.com > alice.pub

# Export private key (backup only!)
gpg --armor --export-secret-keys alice@example.com > alice.priv
```

---

## Security Model

### Trust Chain

1. **Repository owner** creates and signs the keyring
2. **Collaborators** verify the signature before every `hide`/`reveal`
3. **Signing key** is trusted via `git gpg trust` (one-time setup)
4. **Keyring tampering** is detected (signature verification fails)

### Threat Model

**Protects against:**
- ✅ Accidental secret commits (secrets are encrypted)
- ✅ Unauthorized keyring modifications (signature verification)
- ✅ Man-in-the-middle attacks (keyring is signed)

**Does NOT protect against:**
- ❌ Compromised signing key (re-sign malicious keyring)
- ❌ Compromised collaborator private key (decrypt secrets)
- ❌ Malicious repository owner (sign malicious keyring)

### Best Practices

1. **Verify signing key out-of-band** (phone call, video chat, key signing party)
2. **Use strong passphrases** on private keys
3. **Regularly audit keyring** with `git gpg list-keys`
4. **Rotate signing keys** if compromised
5. **Backup private keys** securely

---

## Installation

### Using the install script

```bash
# Install to ~/.local/bin (default)
./scripts/install.sh

# Install to custom location
./scripts/install.sh /usr/local/bin

# Or set INSTALL_DIR environment variable
INSTALL_DIR=/opt/bin ./scripts/install.sh
```

### Using cargo

```bash
# Install from source
cargo install --path . --locked --root ~/.local

# Or use the cargo alias
cargo install-local --root ~/.local
```

---

## Example Workflow

### Alice (Repository Owner)

```bash
# Setup
cd my-project
git gpg init
gpg --armor --export alice@example.com > alice.pub
git gpg trust fara+simbo1905@github.com alice.pub
git gpg tell alice@example.com alice.pub

# Track secrets
git gpg add .env secrets.yml
git gpg hide

# Commit
git add .git-gpg/keyring .git-gpg/tracked.json .git-gpg/secrets/
git commit -m "Add encrypted secrets"
git push

# Add Bob
git gpg tell bob@work.com bob.pub
git add .git-gpg/keyring
git commit -m "Add Bob to keyring"
git push
```

### Bob (Collaborator)

```bash
# Clone
git clone git@github.com:simbo1905/fara.git
cd fara

# Trust Alice's signing key
git gpg trust fara+simbo1905@github.com alice.pub

# Verify keyring
git gpg verify-keyring
# ✓ Keyring signature valid (signed by alice@example.com)

# Reveal secrets
git gpg reveal
# Decrypts .env and secrets.yml

# Work with secrets
vim .env

# Hide before committing
git gpg hide
git add .git-gpg/secrets/
git commit -m "Update secrets"
git push
```

---

## License

**GPL-3.0-or-later**

---

## Repository

- **Host:** CodeForge
- **URL:** https://codeforge.io/git-gpg/git-gpg
