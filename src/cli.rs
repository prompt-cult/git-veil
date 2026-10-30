//! CLI definition shared by the binary and the docs-generation subcommands.
//!
//! Keeping `Cli`/`Commands` in the library lets the `completions` and
//! `manpages` subcommands regenerate their output from the real clap
//! definition (`Cli::command()`) with zero duplication. No build.rs copy
//! of the parser is needed.

use anyhow::{Context as _, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

fn verifying_key_selection(s: &str) -> Result<String, String> {
    let trimmed = s.trim().to_lowercase();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(trimmed)
    } else {
        Err(
            "--signing-key takes the full 64 hex character Ed25519 verifying key. The index form and the fingerprint form are removed.".to_string(),
        )
    }
}

#[derive(Debug, Parser)]
#[command(name = "git-veil")]
#[command(about = "Git secret management using \"age\" encryption")]
#[command(version)]
pub struct Cli {
    /// Bypass the key store permission checks (also: GIT_VEIL_SKIP_PERMISSIONS=1)
    #[arg(long, global = true)]
    pub dangerously_skip_permissions_check: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize git-veil state (.git-veil/) in the current repository
    #[command(after_long_help = "\
Run init first: add-key, add-file and hide all require the .git-veil/
state directory it creates (keyring, trust.json, tracked.json). init
also copies the owner verifying key from VERIFYING_KEY into
.git-veil/owner.verifying and pins the owner key on this machine, in the
same possession-proof ceremony the owner's key always required: the
verifying key passed in must exactly match the key derived from a seed
in <key store>/signing-keys.txt, so only the repo owner can run init. A
remote (default origin) must be configured; the repository id derived
from it labels the pin.

VERIFYING_KEY must point OUTSIDE the repository worktree: the trust
anchor travels in from outside, never through the repository itself.

init never touches .gitignore - the <name>.secret ciphertext files are
meant to be committed, so gitignoring them would defeat the fresh-clone
decryptability contract.

init refuses to reset a repository that already has established trust;
remove .git-veil/ explicitly if you really want a fresh start.

EXAMPLES
  $ git-veil init \"$HOME/.git-veil/owner.verifying\"
")]
    Init {
        /// Path to the repo owner's Ed25519 verifying key file, from outside the repository
        verifying_key: PathBuf,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Suppress the CODEOWNERS suggestion and other non-error output
        #[arg(long, short = 'q')]
        quiet: bool,
        /// Suppress the CODEOWNERS warning for this pinned repository; the suppression is
        /// recorded in the key store next to the pin
        #[arg(long)]
        suppress_codeowners: bool,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil). The store and its
        /// pins are the trust boundary for every repository that uses it.
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Import your X25519 private key into the git-veil key store
    #[command(after_long_help = "\
Imports X25519 private keys (\"age\" identities - the AGE-SECRET-KEY-1...
lines produced by age-keygen) into your per-machine key store
($GIT_VEIL_HOME or $HOME/.git-veil). This is where reveal/cat/changes
find the private key matching your keyring entry. The key store
is local to this machine and is never committed; each collaborator
imports their own private key. The store is written mode 0600 regardless
of umask. git-veil never generates keys - create yours with age-keygen
(or rage-keygen) and back the AGE-SECRET-KEY-1... line up; without it,
ciphertexts encrypted to you are unrecoverable.

Here \"age\" refers to the open source age encryption tooling, which may
be installed separately to securely create and maintain cryptographic
keys outside of the git repo; the git-veil software uses the Rust \"rage\"
library to work with the keys.

A private key whose X25519 public key is already present in the key store
is not duplicated.

EXAMPLES
  $ age-keygen -o my-age-identity.txt      # create + print the recipe
  $ git-veil import my-age-identity.txt
  $ git-veil import a.txt b.txt --key-store /path/to/store
")]
    Import {
        /// File(s) containing AGE-SECRET-KEY-1... lines (age-keygen output works as-is)
        #[arg(required = true)]
        files: Vec<String>,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Export an X25519 public key from the local key store
    #[command(after_long_help = "\
Prints - or with --output writes - the X25519 public key (\"age\"
recipient), bech32-encoded (age1xxxx), for the given key, read from the
local key store on this machine ($GIT_VEIL_HOME or $HOME/.git-veil). This
is the key handoff between collaborators without any external tool: the
local store only holds keys THIS machine knows about (your imported
private key and any public key trust has pinned), so each collaborator
runs export on their OWN machine and sends the public key encoding to the
owner, who adds it to the keyring with add-key. It cannot export a
collaborator's key for them. Here \"age\" refers to the open source age
encryption tooling, installed separately; git-veil uses the Rust \"rage\"
library to work with the keys.

The output never contains private key material - even when the match is
your imported private key, export always emits the public half.

Matching is exact: the identifier is the key's public key encoding. Keys
are selected by public key string only.
export does not touch the repository and needs no init or trust state.

EXAMPLES
  $ git-veil export age1xxxx                     # to stdout
  $ git-veil export age1xxxx --output alice.pub  # hand-off file
")]
    Export {
        /// X25519 public key encoding (age1xxxx) of the key to export
        identifier: String,
        /// Write the public key encoding to this file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Remove a key from the local key store (destructive, local-only)
    #[command(after_long_help = "\
Drops key material from the LOCAL key store: every X25519 private key in
$GIT_VEIL_HOME (or $HOME/.git-veil) identities.txt and every X25519
public key in recipients.txt whose public key encoding exactly matches
the identifier is removed. Keys are selected by public key string only.

This is destructive and LOCAL-ONLY: it does not touch any repository,
keyring or trust state, and it does NOT revoke anything. Removing a
private key from the store does not stop old ciphertext that was
encrypted to it from being decryptable by whoever holds it. Revoking a
departing collaborator is remove-key + re-hide (docs/departing.md);
forget is the departing user's housekeeping step for their own
machine's store.

Danger guard: if the target private key is the only one in
identities.txt, forget refuses without --yes - this is your only
private key, and without it you cannot decrypt anything.

The store rewrite is atomic and lossless for the retained lines. A
corrupt (e.g. truncated) store is refused untouched - the error names the
file, the line number, and the corrupt line so you can delete exactly it;
forget never rewrites a store it could not fully parse. On success a
per-store summary prints the public key encodings removed.

EXAMPLES
  $ git-veil forget age1xxxx                 # exact public key encoding
  $ git-veil forget age1xxxx --yes           # confirm only-private-key removal
  $ git-veil forget age1xxxx --key-store /path/to/store
")]
    Forget {
        /// Exact X25519 public key encoding (age1xxxx) of the key to remove
        identifier: String,
        /// Confirm destructive removal: required when the target is the only
        /// private key in the store.
        #[arg(long)]
        yes: bool,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Pin this repository's owner key on this machine from an exported pin-file
    #[command(after_long_help = "\
Pin this repository's owner key on this machine by importing a pin-file
produced by git-veil export-pin on a machine that proved possession.
Three mandatory consistency checks: the pin-file's repo-id must match
this repository; its verifying key must exactly match the committed
.git-veil/owner.verifying; and its owner key fingerprint must match the
owner fingerprint recorded in .git-veil/trust.json. Any mismatch ->
refusal: one of the two channels is compromised.

There is no possession-proof form: the repo owner pins at init, and every
other machine imports.

A pin or trust record in the 16 hex character fingerprint format is
refused as hostile: every gated command fails until trust is re-established.
See the fingerprint documentation for the derivation.

The pin-file must point OUTSIDE the repository worktree, so a pin-file
always travels out of band (e.g. ssh) - the same model as known_hosts
provisioning. The pin lives in the key store, never committed.

Trust domain: the key store named by --key-store holds this machine's pins
for EVERY repository that uses that store, so the store and its pins are
one trust boundary. Sharing a single store across mutually distrusting
repositories is not advised; use a separate --key-store per trust domain.

Requires init first. Typical next step: add-key.

EXAMPLES
  $ git-veil trust --import /tmp/fara.pin        # pin-file from export-pin
")]
    Trust {
        /// Import a pin-file produced by git-veil export-pin on a machine holding the signing key
        #[arg(long, value_name = "PIN_FILE")]
        import: PathBuf,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Suppress the CODEOWNERS warning for this pinned repository; the suppression is
        /// recorded in the key store next to the pin
        #[arg(long)]
        suppress_codeowners: bool,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil). The store and its
        /// pins are the trust boundary for every repository that uses it.
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Export this repository's pin-file for import on another machine
    #[command(name = "export-pin")]
    #[command(after_long_help = "\
Writes this repository's pin-file for import on a machine WITHOUT the
signing key (which runs git-veil trust --import <pin-file>). Export
requires the same possession proof as trust: an exact match between the
repository's committed .git-veil/owner.verifying and the verifying key
derived from a seed in <key store>/signing-keys.txt. A machine without the
matching seed cannot export at all - pins originate only from machines
holding the signing key; store-less machines are consumers, never producers.

--output must point OUTSIDE the repository worktree: a committed pin-file
would be exactly the self-supplied anchor the pin model exists to
prevent. Transfer the file out of band (e.g. ssh); its integrity rides
the transport, the same model as known_hosts provisioning.

The printed owner key fingerprint is the human out-of-band verification
token: read it to the importing machine's operator and have them compare
it against the repository's committed .git-veil/trust.json. It is the
single documented derivation with the repository id as the label, so it
is reproducible with stock OS tools; see the fingerprint documentation.

EXAMPLES
  $ git-veil export-pin fara+simbo1905@github.com --output /tmp/fara.pin
  $ scp /tmp/fara.pin box:fara.pin               # out of band
  $ git-veil trust --import fara.pin            # on the target machine
")]
    ExportPin {
        /// Repository ID (e.g., fara+simbo1905@github.com)
        repo_id: String,
        /// Pin-file destination - must be OUTSIDE the repository worktree
        #[arg(long)]
        output: PathBuf,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Print the git-veil fingerprint of a labelled public key
    #[command(after_long_help = "\
Computes and prints the single fingerprint derivation every git-veil
fingerprint uses:

  FP = SHA-256( UTF8(label) + \":\" + UTF8(public-key-encoding) )

printed as 64 lowercase hex characters.

label is the principal label for a keyring principal, or the repository
id for the owner key. public-key-encoding is the bech32 X25519 public
key (age1xxxx) or the 64 hex character Ed25519 verifying key. Both
arguments are used verbatim - no trimming, no case folding.

This is a pure function: no repository, no key store, no pin, no
network. A clean host reproduces the exact value with stock OS tools:

  printf '%s:%s' 'alice@example.com' \"$(age-keygen -y identity.txt)\" | sha256sum
  printf '%s:%s' 'demo+example@github.com' \"$(head -n 1 .git-veil/owner.verifying)\" | sha256sum

Use printf, never echo (echo appends a newline and hashes different
bytes). Exactly one colon separates label and key. The digest is
lowercase hex.

EXAMPLES
  $ git-veil fingerprint alice@example.com age1xxxx
  $ git-veil fingerprint demo+example@github.com 3f1a9c...64hex
")]
    Fingerprint {
        /// Principal label (keyring principal) or repository id (owner key)
        label: String,
        /// Public key encoding: bech32 X25519 public key (age1xxxx) or 64-hex Ed25519 verifying key
        public_key: String,
    },

    /// Add a collaborator's X25519 public key to the keyring and re-sign it
    #[command(after_long_help = "\
Adds a collaborator's X25519 public key to the repository keyring and
re-signs the keyring with the owner's Ed25519 signing key. The second
argument is the collaborator's bech32 X25519 public key encoding
(age1xxxx), pasted literally: the encoding git-veil export prints on the
collaborator's machine, or age-keygen -y prints from their key file. A
file name is not a valid key encoding and is refused. The existing
keyring signature is verified against the pinned trusted key before any
modification, and a canary is test-encrypted to the new key so a key that
cannot encrypt is never signed into the ring.

The keyring is signed with the TRUSTED key - the one whose owner key
fingerprint is pinned for this repository. signing-keys.txt must contain
that seed; git-veil never generates it (docs/solo.md step 1 has the
recipe). With several signing keys present, --signing-key names one by
its full 64 hex character Ed25519 verifying key (the public half, never
the seed). A missing signing key exits with code 20 and the
create-and-back-up recipe.

Requires init, an established trust pin (trust) for this repository on
this machine, and the signing key in the local key store. Next steps:
add files, then hide.

EXAMPLES
  $ git-veil add-key alice@example.com age1xxxx
")]
    AddKey {
        /// Collaborator's email
        email: String,
        /// The collaborator's bech32 X25519 public key encoding (age1xxxx), pasted literally
        public_key: String,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Signing key to use: its full 64-hex Ed25519 verifying key (default: the key matching the pinned fingerprint)
        #[arg(long, value_name = "VERIFYING_KEY", value_parser = verifying_key_selection)]
        signing_key: Option<String>,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Remove a collaborator from the keyring and re-sign it
    #[command(after_long_help = "\
Removes a collaborator's entry from the keyring and re-signs it with the
owner's Ed25519 signing key. The existing keyring signature is verified
against the pinned trusted key before any modification. After removal the
ex-collaborator can no longer decrypt newly hidden files - but files
hidden while they were a member were encrypted to their key, so rotate
the underlying secrets if that matters.

The keyring is signed with the TRUSTED key - the one whose owner key
fingerprint is pinned for this repository. With several signing keys
present, --signing-key names one by its full 64 hex character Ed25519
verifying key (the public half, never the seed). A missing signing key
exits with code 20 and the create-and-back-up recipe.

Requires init, an established trust pin (trust), and the signing key in
the local key store.

EXAMPLES
  $ git-veil remove-key alice@example.com
")]
    RemoveKey {
        /// Email of the collaborator to remove
        email: String,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Signing key to use: its full 64-hex Ed25519 verifying key (default: the key matching the pinned fingerprint)
        #[arg(long, value_name = "VERIFYING_KEY", value_parser = verifying_key_selection)]
        signing_key: Option<String>,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Track files for encryption
    #[command(alias = "add")]
    #[command(after_long_help = "\
Tracks files for encryption in .git-veil/tracked.json (stored
repo-relative). Nothing is encrypted yet - hide does that. Files must
exist, and a symlink must resolve inside the repository, so hide can
never be tricked into reading or deleting a file outside the repo.

The manifest nomination is also your standing instruction, so each added
path is recorded in the machine-local allowance store in your key store:
hide refuses to first-encrypt a tracked path that was never allowed on
this machine (exit code 72), so a tracked.json modified by someone else
cannot silently nominate your files for encryption.

Typical flow: init -> trust -> add-key (once per collaborator) -> add-file
-> hide.

EXAMPLES
  $ git-veil add-file .env
  $ git-veil add-file config/credentials.yml notes.md
")]
    AddFile {
        /// File(s) to add
        #[arg(required = true)]
        files: Vec<String>,
        /// Git remote name (derives the repository id for the allowance store)
        #[arg(long, default_value = "origin")]
        remote: String,
    },

    /// Allow files for encryption on this machine
    #[command(after_long_help = "\
Records paths in the machine-local allowance store in your key store:
this repository, anchored by the trust pin, and this git user, have
allowed these paths for encryption. tracked.json is committed and
unsigned, so any repo writer can nominate a path in it; hide refuses to
first-encrypt a tracked path that was never allowed on this machine
(exit code 72). Once recorded, an allowance survives manifest changes
and never needs re-recording. remove-key purges the allowance record
of a removed principal.

allow resolves paths exactly like add-file: the file must exist and resolve
inside the repository. add-file records the allowance too, so allow is only
needed for a path someone else nominated, or to allow a path under a
principal the manifest nomination did not run for.

allow reads your principal from git config user.email and requires an
established trust pin (git-veil trust) on this machine.

EXAMPLES
  $ git-veil allow .env
  $ git-veil allow config/credentials.yml notes.md
")]
    Allow {
        /// File(s) to allow
        #[arg(required = true)]
        files: Vec<String>,
        /// Git remote name (derives the repository id for the allowance store)
        #[arg(long, default_value = "origin")]
        remote: String,
    },

    /// Untrack files (deletes the sibling .secret unless --keep-ciphertext)
    #[command(alias = "rm")]
    #[command(after_long_help = "\
Untracks files (removes them from .git-veil/tracked.json). The plaintext
may already be gone - hide deletes plaintexts by default - so the file
does not need to exist.

By default the sibling <name>.secret ciphertext is deleted too: a
de-tracked but committed ciphertext would otherwise be silently skipped
by the next hide and stay decryptable by collaborators removed in a
later rotation (hide refuses such orphans with exit code 42). Deletion
is recoverable from git history. Pass --keep-ciphertext to leave the
ciphertext in place; hide will refuse it as an orphan until it is
removed or the path is re-tracked.

EXAMPLES
  $ git-veil remove-file .env
  $ git-veil remove-file --keep-ciphertext config/credentials.yml
")]
    RemoveFile {
        /// File(s) to remove
        #[arg(required = true)]
        files: Vec<String>,
        /// Leave the <name>.secret ciphertext in place (hide will refuse it as an orphan)
        #[arg(long)]
        keep_ciphertext: bool,
    },

    /// List all tracked files
    #[command(after_long_help = "\
Prints every file tracked in .git-veil/tracked.json. Whether the
plaintext or its .secret ciphertext currently exists on disk is not
checked.

EXAMPLES
  $ git-veil list
")]
    List,

    /// Encrypt named tracked files to the keyring
    #[command(after_long_help = "\
Encrypts each named tracked file to every key in the keyring and leaves
<name>.secret beside where the plaintext was (notes -> notes.secret).
You gitignore the PLAINTEXT filenames and commit the .secret files:
a fresh clone carrying only ciphertext stays decryptable by every
keyring member via reveal.

hide is TWO-PHASE and ALL-OR-NOTHING: phase 1 reads and validates every
named plaintext and encrypts EVERY named file to the full public key set
in memory - if any plaintext is missing, unreadable or cannot be
encrypted, hide aborts having changed NOTHING on disk. Phase 2 (only
after every encryption succeeded) writes each .secret atomically.

hide only works after the repository is initialized (git-veil init), the
owner's key is trusted on this machine (git-veil trust), collaborators are
in the keyring (git-veil add-key), and files are tracked (git-veil
add-file). Before encrypting anything, the keyring signature is verified
against the pinned trusted key. reveal and cat invert hide.

hide REFUSES (exit code 40) when a <name>.secret ciphertext path is
itself git-ignored - e.g. swallowed by a parent-directory rule like
.tmp/ - because that ciphertext would silently never reach the
repository. It WARNS (error code 41) when a tracked plaintext exists on
disk but is not git-ignored, since a blind `git add -A` would then commit
it. It also REFUSES (exit code 72) a tracked path that has a plaintext on
disk, no committed ciphertext in the git index, and no allowance on this
machine: tracked.json is committed and unsigned, so a path added by
someone else is refused until you allow it here. The allowance is
recorded by add-file on this machine, or deliberately with git-veil allow.
The plaintext is DELETED by default once every ciphertext is durably
written - the normal loop is reveal (restore plaintexts) -> edit -> hide.
--keep-plaintext leaves the plaintexts beside their ciphertexts. Each
named file must exist when you name it (hide resolves paths the way
add-file does); once a plaintext is hidden, reveal restores it before
hide can re-encrypt it.

hide covers exactly the named files: each is resolved the way add-file
resolves paths, and must already be tracked - an unknown or untracked
name refuses (error code 71). The allowance check (error code 72) then
applies to the named files only, and names only the offenders among
them. You name the file, the gate checks that file.

The whole-manifest re-encrypt is the ring-change pass, and it is a
separate command: git-veil rotate.

EXAMPLES
  $ git-veil hide .env    # encrypt .env and delete the plaintext (the default)
  $ git-veil hide .env --keep-plaintext
  $ git-veil hide .env --remote upstream
  $ git-veil hide .env config.yml    # encrypt exactly the named files
  $ echo .env >> .gitignore    # ignore plaintext names; commit the .secret files
")]
    Hide {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
        /// Leave plaintext files beside their ciphertexts instead of deleting them
        #[arg(long)]
        keep_plaintext: bool,
        /// Tracked files to hide
        #[arg(value_name = "FILE", required = true)]
        files: Vec<String>,
    },

    /// Re-encrypt every tracked ciphertext to the current keyring
    #[command(after_long_help = "\
Re-encrypts every tracked ciphertext to the current keyring: each
<name>.secret on disk is decrypted in memory and re-encrypted to the
full current keyring, then written back atomically. This is the
ring-change pass: run it after add-key or remove-key so the committed
ciphertext reflects the updated keyring.

rotate is TWO-PHASE and ALL-OR-NOTHING: phase 1 decrypts and re-encrypts
every working-set ciphertext in memory - if any ciphertext is missing or
cannot be rotated, rotate aborts having changed NOTHING on disk. Phase 2
(only after every re-encryption succeeded) writes each .secret atomically.

rotate NEVER TOUCHES PLAINTEXTS. The ciphertext is the input: no
plaintext is read, written, deleted or compared, and none is left on
disk by the pass. An edited-not-yet-hidden plaintext is orthogonal to
the pass; hide encrypts it later.

The pass is gated. add-key and remove-key stamp the keyring change on
this machine when they re-sign the keyring, and one rotate consumes
that stamp. Without a stamp for this repository on this machine, or
when the committed keyring does not match the stamped version and
digest, rotate refuses (exit code 70) and names the repository id. It
also refuses (error code 42) a committed ciphertext whose path is no
longer tracked: the pass covers the whole manifest, and an untracked
ciphertext would silently stay decryptable by removed collaborators.
A tracked path with no .secret ciphertext on disk is skipped with a
note.

EXAMPLES
  $ git-veil rotate    # the ring-change pass, after add-key or remove-key
")]
    Rotate {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Decrypt named tracked files back to plaintext
    #[command(after_long_help = "\
Decrypts each named tracked file back to its plaintext path, using your
X25519 private key from the local key store. The keyring signature is
verified against the pinned trusted key before any decryption. Your
principal comes from git config user.email or --email; a missing private
key exits with code 21 and the create-and-back-up recipe.

reveal covers exactly the named files: each must already be tracked -
an unknown or untracked name refuses (error code 71). Reveal is never
gated by the encryption allowance: decryption needs only keyring
membership, so a named path is revealed without any allow step.

reveal is the inverse of hide; cat prints one
file without touching disk state.

reveal is TWO-PHASE and ALL-OR-NOTHING: EVERY file in the working set
must have its .secret ciphertext present and decrypt successfully.
Phase 1 verifies and decrypts all files in memory - if any ciphertext
is missing or cannot be decrypted, reveal refuses WITHOUT changing
anything on disk. Phase 2 (only after every decryption succeeded)
writes each plaintext atomically.

EXAMPLES
  $ git-veil reveal .env    # restore only .env, leave every other file hidden
  $ git-veil reveal .env --email alice@example.com
  $ git-veil reveal .env config.yml    # restore exactly the named files
")]
    Reveal {
        /// Your email address
        #[arg(long)]
        email: Option<String>,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
        /// Tracked files to reveal
        #[arg(value_name = "FILE", required = true)]
        files: Vec<String>,
    },

    /// Decrypt a single tracked file to stdout
    #[command(after_long_help = "\
Decrypts a single tracked file to stdout without touching disk state:
neither the plaintext nor its .secret ciphertext is modified. The keyring
signature is verified against the pinned trusted key first, and the file
must be tracked with its ciphertext present beside it.

EXAMPLES
  $ git-veil cat .env
  $ git-veil cat .env --email alice@example.com
")]
    Cat {
        /// File to decrypt
        file: String,
        /// Your email address
        #[arg(long)]
        email: Option<String>,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Report where plaintext differs from the last hidden version
    #[command(after_long_help = "\
Reports where the on-disk plaintext differs from the last hidden version:
each tracked file's .secret ciphertext is decrypted and compared with the
plaintext beside it. Differences are data, not errors. Files with no
ciphertext, or no plaintext on disk, are skipped with a note and are not
counted as changed.

EXAMPLES
  $ git-veil changes                # check every tracked file
  $ git-veil changes .env           # check one file
")]
    Changes {
        /// File(s) to check (default: all tracked files)
        files: Vec<String>,
        /// Your email address
        #[arg(long)]
        email: Option<String>,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Show the repository ID derived from the git remote push URL
    #[command(after_long_help = "\
Prints the repository ID derived from the git remote push URL - the
exact string trust expects as its repo_id argument (trust re-derives it
from the remote and refuses a mismatch). Pass --remote if your remote is
not 'origin'.

EXAMPLES
  $ git-veil repo-id
  $ git-veil repo-id --remote upstream
")]
    RepoId {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
    },

    /// Show the principal git-veil will use for you
    #[command(after_long_help = "\
Prints the principal git-veil will use for you: git config user.email, or
the --email override. The principal label is committed in the public
keyring, so naming it leaks nothing. Use it to check which keyring entry
reveal/cat will look up before they fail on a missing private key.

EXAMPLES
  $ git-veil whoami
  $ git-veil whoami --email alice@example.com
")]
    Whoami {
        /// Email override
        #[arg(long)]
        email: Option<String>,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Verify the keyring signature against the pinned trusted key
    #[command(after_long_help = "\
Verifies the keyring's signature against the pinned trusted key for this
repository. Fail-closed: without an established trust pin (git-veil
trust) on this machine, or when the signature does not verify, the
command exits with an error. Every gated command (hide, reveal, cat,
changes, add-key, remove-key, list-keys) runs this same check
before touching secrets.

EXAMPLES
  $ git-veil verify-keys
  $ git-veil verify-keys --remote upstream
")]
    VerifyKeys {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// List keyring keys after verifying the keyring signature
    #[command(name = "list-keys")]
    #[command(after_long_help = "\
Lists all keys in the keyring after verifying its signature against the
pinned trusted key. On failure the unverified content is still printed
under a loud invalid-signature banner (an auditor must SEE the tampered
content), but the command exits nonzero so scripts never mistake an audit
of a tampered ring for a clean one. A repo with no trust established or
no local pin fails closed like every other gated command.

EXAMPLES
  $ git-veil list-keys
  $ git-veil list-keys --remote upstream
")]
    ListKeys {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Acknowledge the key store's current permissions as trusted
    #[command(name = "trust-permissions")]
    #[command(after_long_help = "\
Records the key store's current permission state - for the store
directory itself and for identities.txt / signing-keys.txt when they
carry group or world bits - as explicitly trusted, exactly the way git's
dubious-ownership acknowledgment works. The acknowledgment pins the exact
(path, mode) pairs in <key store>/permissions-ack.json (mode 0600); the
permission check passes only while the observed modes still match those
pairs, so any later change fails again until you re-acknowledge.

git-veil NEVER changes permissions on key material it did not create  - 
either chmod the paths right (the error message lists the exact commands)
or acknowledge the current state deliberately here. The check can also be
bypassed per invocation with --dangerously-skip-permissions-check or
GIT_VEIL_SKIP_PERMISSIONS=1.

EXAMPLES
  $ git-veil trust-permissions
  $ git-veil trust-permissions --key-store /path/to/store
")]
    TrustPermissions {
        /// Key store directory (default: $GIT_VEIL_HOME or $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// List every documented exit code with its name and meaning
    #[command(after_long_help = "\
Prints the table of documented exit codes - number, enum name, and
meaning - that every deliberate failure exits with. Failures without a
more specific code exit 1, and command-line usage errors exit 2. The
codes are public API: they are never renumbered, only appended, and the
specification lives in docs/design.md.

EXAMPLES
  $ git-veil error-codes
  $ git-veil hide; echo $?    # a refusal exits with its documented code
")]
    ErrorCodes,

    /// Remove the .git-veil state directory (--yes required when data would be lost)
    #[command(after_long_help = "\
Removes the .git-veil state directory (keyring, trust.json,
tracked.json, and the committed owner.verifying). .gitignore is never
rewritten, and the in-place .secret ciphertext files are ordinary
committable files that clean does not disown.

The .secret ciphertexts can be the ONLY remaining copy of a secret. A
clean that would destroy tracked state or ciphertext therefore refuses
unless --yes confirms it.

EXAMPLES
  $ git-veil clean          # refuses while tracked files or ciphertext exist
  $ git-veil clean --yes    # confirmed destruction of .git-veil/
")]
    Clean {
        /// Confirm destruction of tracked state and any ciphertext. Required
        /// when the clean would destroy tracked files or their in-place
        /// `<name>.secret` ciphertext (which may be the only remaining copy).
        #[arg(long)]
        yes: bool,
    },

    /// Emit a shell completion script for the given shell to stdout
    #[command(after_long_help = "\
Writes a shell completion script for the git-veil CLI to stdout. The
script is generated from the live clap definition, so it always matches
the installed binary.

EXAMPLES
  $ git-veil completions bash > /etc/bash_completion.d/git-veil
  $ git-veil completions zsh > \"${fpath[1]}/_git-veil\"
  $ git-veil completions fish > ~/.config/fish/completions/git-veil.fish
")]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Write roff man pages (git-veil.1 plus one per subcommand) to a directory
    #[command(after_long_help = "\
Writes roff man pages - git-veil.1 plus one page per subcommand - to a
directory, all generated from the live clap definition. Defaults to
./man relative to the current directory.

EXAMPLES
  $ git-veil manpages                            # write into ./man
  $ git-veil manpages /usr/local/share/man/man1
")]
    Manpages {
        /// Directory to write the .1 files into (default: ./man)
        output_dir: Option<PathBuf>,
    },
}

/// Handler for `git-veil completions <shell>`: writes the completion script
/// for the real clap definition to stdout.
pub fn run_completions(shell: clap_complete::Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "git-veil", &mut std::io::stdout());
}

/// Handler for `git-veil manpages [OUTPUT_DIR]`: writes `git-veil.1` plus one
/// `git-veil-<sub>.1` per subcommand, all generated from the real clap
/// definition. Defaults to `./man` relative to the current directory.
pub fn run_manpages(output_dir: &std::path::Path) -> Result<()> {
    let root = Cli::command();
    let bin_name = root.get_name().to_string();

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create output directory {}", output_dir.display()))?;

    let root_page = output_dir.join(format!("{}.1", bin_name));
    let man = clap_mangen::Man::new(root.clone());
    man.render(
        &mut std::fs::File::create(&root_page)
            .with_context(|| format!("failed to create {}", root_page.display()))?,
    )
    .with_context(|| format!("failed to render {}", root_page.display()))?;

    for sub in root.get_subcommands() {
        let full_name = format!("{}-{}", bin_name, sub.get_name());
        let page = output_dir.join(format!("{}.1", full_name));
        let usage_bin_name = format!("{} {}", bin_name, sub.get_name());
        let man = clap_mangen::Man::new(sub.clone().name(full_name).bin_name(usage_bin_name));
        man.render(
            &mut std::fs::File::create(&page)
                .with_context(|| format!("failed to create {}", page.display()))?,
        )
        .with_context(|| format!("failed to render {}", page.display()))?;
    }

    Ok(())
}
