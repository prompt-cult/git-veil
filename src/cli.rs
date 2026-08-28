//! CLI definition shared by the binary and the docs-generation subcommands.
//!
//! Keeping `Cli`/`Commands` in the library lets the `completions` and
//! `manpages` subcommands regenerate their output from the real clap
//! definition (`Cli::command()`) with zero duplication — no build.rs
//! copy of the parser is needed.

use anyhow::{Context as _, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "git-veil")]
#[command(about = "Git secret management using pure Rust OpenPGP")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize git-veil state (.git-veil/) in the current repository
    #[command(after_long_help = "\
Run init first: trust, tell, add and hide all require the .git-veil/ state
directory it creates (keyring, trust.json, tracked.json). init never
touches .gitignore — the <name>.secret ciphertext files are meant to be
committed, so gitignoring them would defeat the fresh-clone decryptability
contract.

init refuses to reset a repository that already has established trust;
remove .git-veil/ explicitly if you really want a fresh start.

EXAMPLES
  $ git-veil init    # create .git-veil/ in the current git repository
")]
    Init,

    /// Import your private key(s) into the git-veil key store
    #[command(after_long_help = "\
Imports armoured PRIVATE key blocks into your per-machine key store
($HOME/.git-veil/secret-keys.pgp). This is where reveal/cat/unhide/changes
find the private key matching your email, and where tell/removeperson find
the owner's signing key. The key store is local to this machine and is
never committed; each collaborator imports their own key.

Keys whose fingerprint is already present in the key store are not
duplicated.

EXAMPLES
  $ git-veil import my-key.asc
  $ git-veil import key1.asc key2.asc --key-store /path/to/store
")]
    Import {
        /// File(s) containing armoured private key blocks
        #[arg(required = true)]
        files: Vec<String>,
        /// Key store directory (default: $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Export an armoured public key from the local key store
    #[command(after_long_help = "\
Prints — or with --output writes — the armoured PUBLIC key for the given
email or fingerprint, read from the local key store on this machine
($HOME/.git-veil). This is the key handoff between collaborators without
any external OpenPGP tool: the local store only holds keys THIS machine
knows about
(your imported private key and any key trust has pinned), so each
collaborator runs export on their OWN machine and sends the .pub file to
the owner, who adds it to the keyring with tell. It cannot export a
collaborator's key for them.

The output never contains private key material — even when the match is
your imported private key, export always re-armours the public half.

Matching is exact: the identifier equals the key's fingerprint, or the
address in one of its user-IDs. If several keys share the requested
email, the fingerprints are listed so you can retry with one of them.
export does not touch the repository and needs no init or trust state.

EXAMPLES
  $ git-veil export alice@example.com                     # armour to stdout
  $ git-veil export alice@example.com --output alice.pub  # hand-off file
  $ git-veil export 9A1F... --output alice.pub            # by fingerprint
")]
    Export {
        /// Email or fingerprint of the key to export
        identifier: String,
        /// Write the armoured public key to this file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
        /// Key store directory (default: $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Remove a key from the local key store (destructive, local-only)
    #[command(name = "removekey")]
    #[command(after_long_help = "\
Drops key material from the LOCAL key store: every armoured block in
$HOME/.git-veil/secret-keys.pgp and public-keys.pgp whose key's
fingerprint matches the identifier, or whose exact case-insensitive email
matches, is removed from both stores. Prefer the FINGERPRINT when it is
not unambiguous which key you mean — a shared email that matches several
keys is refused unless --yes confirms removing ALL of them.

This is destructive and LOCAL-ONLY: it does not touch any repository,
keyring or trust state, and it does NOT revoke anything. Removing a key
from the store does not stop old ciphertext that was encrypted to it from
being decryptable by whoever holds the key. Revoking a departing
collaborator is removeperson + re-hide (docs/departing.md); removekey is
the departing user's housekeeping step for their own machine's store.

Danger guard: if the target key is the only private key in
secret-keys.pgp, removekey refuses without --yes — this is your only
private key, and without it you cannot decrypt anything.

The store rewrite is atomic and lossless for the retained blocks. A
corrupt (e.g. truncated) store is refused untouched — repair it by hand;
removekey never deletes a corrupt store. On success a per-store summary
prints the fingerprints removed.

EXAMPLES
  $ git-veil removekey 9A1F...                     # by fingerprint (preferred)
  $ git-veil removekey bob@example.com             # exact case-insensitive email
  $ git-veil removekey bob@example.com --yes       # confirm only-private-key removal
  $ git-veil removekey bob@example.com --key-store /path/to/store
")]
    RemoveKey {
        /// Fingerprint or exact case-insensitive email of the key(s) to remove
        identifier: String,
        /// Confirm destructive removals: required when the target is the only
        /// private key in the store, and to remove ALL keys when the email
        /// matches several.
        #[arg(long)]
        yes: bool,
        /// Key store directory (default: $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Verify and pin the repository owner's signing key (per machine)
    #[command(after_long_help = "\
Verifies the repository owner's public signing key and pins it in your
local key store, keyed by the repository ID derived from the git remote
push URL. The pin is per machine: it lives in $HOME/.git-veil, is never
committed, and every collaborator must run trust themselves after a fresh
clone. The pinned key is the anchor against which every subsequent keyring
signature is verified — tell, hide, reveal, cat, unhide, changes,
removeperson, verify-keyring and list-keys all fail closed without it.

The provided repo_id must match the one computed from the remote push URL
(see show-repo-id), the key file must carry the repository's email
identity, and the key must not be expired, revoked or unsigned.

Trust domain: the key store named by --key-store holds this machine's pins
for EVERY repository that uses that store, so the store and its pins are
one trust boundary. Sharing a single store across mutually distrusting
repositories is not advised; use a separate --key-store per trust domain.

Requires init first. Typical next step: tell.

EXAMPLES
  $ git-veil show-repo-id                          # get the repo id to pass here
  $ git-veil trust fara+simbo1905@github.com owner.pub
  $ git-veil trust fara+simbo1905@github.com owner.pub --remote upstream
")]
    Trust {
        /// Repository ID (e.g., fara+simbo1905@github.com)
        repo_id: String,
        /// Path to owner's public key file
        signing_key: String,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-veil). The store and its
        /// pins are the trust boundary for every repository that uses it.
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Add a collaborator's public key to the keyring and re-sign it
    #[command(after_long_help = "\
Adds a collaborator's public key to the repository keyring and re-signs
the keyring with the owner's private key. The existing keyring signature
is verified against the pinned trusted key before any modification, and a
canary is test-encrypted to the new key so a key that cannot encrypt is
never signed into the ring.

Requires init, an established trust pin (trust) for this repository on
this machine, and the owner's private key in the local key store
(import). Next steps: add files, then hide.

EXAMPLES
  $ git-veil tell alice@example.com alice.pub
  $ git-veil tell alice@example.com alice.pub --passphrase-stdin < pass.txt
")]
    Tell {
        /// Collaborator's email
        email: String,
        /// Path to collaborator's public key file
        public_key: String,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITVEIL_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Remove a collaborator from the keyring and re-sign it
    #[command(name = "removeperson")]
    #[command(after_long_help = "\
Removes a collaborator's entry from the keyring and re-signs it with the
owner's private key. The existing keyring signature is verified against
the pinned trusted key before any modification. After removal the
ex-collaborator can no longer decrypt newly hidden files — but files
hidden while they were a member were encrypted to their key, so rotate
the underlying secrets if that matters.

Requires init, an established trust pin (trust), and the owner's private
key in the local key store (import).

EXAMPLES
  $ git-veil removeperson alice@example.com
  $ git-veil removeperson alice@example.com --passphrase-stdin < pass.txt
")]
    RemovePerson {
        /// Email of the collaborator to remove
        email: String,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITVEIL_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Track files for encryption
    #[command(after_long_help = "\
Tracks files for encryption in .git-veil/tracked.json (stored
repo-relative). Nothing is encrypted yet — hide does that. Files must
exist, and a symlink must resolve inside the repository, so hide can
never be tricked into reading or deleting a file outside the repo.

Typical flow: init -> trust -> tell (once per collaborator) -> add -> hide.

EXAMPLES
  $ git-veil add .env
  $ git-veil add config/credentials.yml notes.md
")]
    Add {
        /// File(s) to add
        #[arg(required = true)]
        files: Vec<String>,
    },

    /// Untrack files (leaves any ciphertext in place)
    #[command(after_long_help = "\
Untracks files (removes them from .git-veil/tracked.json). The plaintext
may already be gone — hide deletes it — so the file does not need to
exist. Untracking is not decrypting: any <name>.secret ciphertext is left
in place; restore the plaintext with unhide or reveal first if you want
it gone too.

EXAMPLES
  $ git-veil remove .env
  $ git-veil remove config/credentials.yml
")]
    Remove {
        /// File(s) to remove
        #[arg(required = true)]
        files: Vec<String>,
    },

    /// List all tracked files
    #[command(after_long_help = "\
Prints every file tracked in .git-veil/tracked.json. Tracking records
intent only: whether the plaintext or its .secret ciphertext currently
exists on disk is not checked.

EXAMPLES
  $ git-veil list
")]
    List,

    /// Encrypt all tracked files to the keyring and delete the plaintexts
    #[command(after_long_help = "\
Encrypts every tracked file to every key in the keyring, deletes the
plaintext, and leaves <name>.secret beside where the plaintext was
(notes -> notes.secret). You gitignore the PLAINTEXT filenames and commit
the .secret files: a fresh clone carrying only ciphertext stays
decryptable by every keyring member via reveal.

hide is TWO-PHASE and ALL-OR-NOTHING: phase 1 reads and validates every
tracked plaintext and encrypts EVERY file to the full recipient set in
memory — if any plaintext is missing, unreadable or cannot be encrypted,
hide aborts having changed NOTHING on disk. Phase 2 (only after every
encryption succeeded) writes each .secret atomically and then deletes each
plaintext; a plaintext is deleted only after its own ciphertext is durably
on disk, so a crash can never leave a secret neither plaintext nor
encrypted. If a phase-2 write fails part-way, the remaining ciphertexts
are still written, only plaintexts whose ciphertext landed are deleted,
and hide reports exactly what was done and what was left before exiting
with an error.

hide only works after the repository is initialized (git-veil init), the
owner's key is trusted on this machine (git-veil trust), collaborators are
in the keyring (git-veil tell), and files are tracked (git-veil add).
Before encrypting anything, the keyring signature is verified against the
pinned trusted key. unhide, reveal and cat invert hide.

EXAMPLES
  $ git-veil hide    # encrypt all tracked files, delete the plaintexts
  $ git-veil hide --remote upstream
  $ echo .env >> .gitignore    # ignore plaintext names; commit the .secret files
")]
    Hide {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Decrypt all tracked files back to plaintext
    #[command(after_long_help = "\
Decrypts every tracked file back to its plaintext path, using your private
key from the local key store. The keyring signature is verified against
the pinned trusted key before any decryption. Your identity comes from
git config user.email or --email; passphrase-protected keys take the
passphrase from GITVEIL_PASSPHRASE or --passphrase-stdin.

reveal is the inverse of hide for all files; unhide does one file and
deletes its ciphertext; cat prints one file without touching disk state.

reveal is TWO-PHASE and ALL-OR-NOTHING: EVERY tracked file must have its
.secret ciphertext present and decrypt successfully. Phase 1 verifies and
decrypts all files in memory — if any ciphertext is missing or cannot be
decrypted, reveal refuses WITHOUT changing anything on disk. Phase 2
(only after every decryption succeeded) writes each plaintext atomically
and then deletes each ciphertext; a ciphertext is deleted only after its
own plaintext is durably on disk. If a phase-2 write fails part-way, the
remaining plaintexts are still written, only ciphertexts whose plaintext
landed are deleted, and reveal reports exactly what was done and what was
left before exiting with an error.

EXAMPLES
  $ git-veil reveal
  $ git-veil reveal --email alice@example.com
  $ git-veil reveal --passphrase-stdin < pass.txt
")]
    Reveal {
        /// Your email address
        #[arg(long)]
        email: Option<String>,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITVEIL_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
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
  $ git-veil cat .env --passphrase-stdin < pass.txt
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
        /// Key store directory (default: $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITVEIL_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Decrypt one tracked file back to plaintext and delete its ciphertext
    #[command(after_long_help = "\
Decrypts one tracked file's in-place <name>.secret ciphertext back to
the plaintext path and deletes the ciphertext — the inverse of hide for a
single file. The keyring signature is verified against the pinned trusted
key first; the file must be tracked and its ciphertext present. Typical
round trip: unhide to edit, then hide to re-encrypt.

EXAMPLES
  $ git-veil unhide .env
  $ git-veil unhide .env --email alice@example.com
  $ git-veil unhide .env --passphrase-stdin < pass.txt
")]
    Unhide {
        /// File to unhide
        file: String,
        /// Your email address
        #[arg(long)]
        email: Option<String>,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITVEIL_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
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
  $ git-veil changes --passphrase-stdin < pass.txt
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
        /// Key store directory (default: $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITVEIL_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Show the repository ID derived from the git remote push URL
    #[command(name = "show-repo-id")]
    #[command(after_long_help = "\
Prints the repository ID derived from the git remote push URL — the
exact string trust expects as its repo_id argument (trust re-derives it
from the remote and refuses a mismatch). Pass --remote if your remote is
not 'origin'.

EXAMPLES
  $ git-veil show-repo-id
  $ git-veil show-repo-id --remote upstream
")]
    ShowRepoId {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
    },

    /// Show the identity and key store git-veil will use
    #[command(after_long_help = "\
Prints the identity git-veil will use for you — git config user.email, or
the --email override — plus the local key store path where your private
key must be imported (git-veil import). Use it to check which key
reveal/cat/unhide will look up before they fail on a missing identity.

EXAMPLES
  $ git-veil whoami
  $ git-veil whoami --email alice@example.com
")]
    Whoami {
        /// Email override
        #[arg(long)]
        email: Option<String>,
        /// Key store directory (default: $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Verify the keyring signature against the pinned trusted key
    #[command(name = "verify-keyring")]
    #[command(after_long_help = "\
Verifies the keyring's signature against the pinned trusted key for this
repository. Fail-closed: without an established trust pin (git-veil
trust) on this machine, or when the signature does not verify, the
command exits with an error. Every gated command (hide, reveal, cat,
unhide, changes, tell, removeperson, list-keys) runs this same check
before touching secrets.

EXAMPLES
  $ git-veil verify-keyring
  $ git-veil verify-keyring --remote upstream
")]
    VerifyKeyring {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-veil)
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
        /// Key store directory (default: $HOME/.git-veil)
        #[arg(long)]
        key_store: Option<PathBuf>,
    },

    /// Remove the .git-veil state directory (--yes required when data would be lost)
    #[command(after_long_help = "\
Removes the .git-veil state directory (keyring, trust.json,
tracked.json). .gitignore is never rewritten, and the in-place .secret
ciphertext files are ordinary committable files that clean does not
disown.

Because hide deletes the plaintexts, the .secret ciphertexts beside them
can be the ONLY remaining copy of a secret. A clean that would destroy
tracked state or ciphertext therefore refuses unless --yes confirms it.

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
Writes roff man pages — git-veil.1 plus one page per subcommand — to a
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
