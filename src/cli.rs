//! CLI definition shared by the binary and the docs-generation subcommands.
//!
//! Keeping `Cli`/`Commands` in the library lets the `completions` and
//! `manpages` subcommands regenerate their output from the real clap
//! definition (`Cli::command()`) with zero duplication — no build.rs
//! copy of the parser is needed.

use clap::{Parser, Subcommand, CommandFactory};
use std::path::PathBuf;
use anyhow::{Context as _, Result};

#[derive(Debug, Parser)]
#[command(name = "git-gpg")]
#[command(about = "Git secret management using pure Rust OpenPGP")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize git-gpg state (.git-gpg/) in the current repository
    #[command(after_long_help = "\
Run init first: trust, tell, add and hide all require the .git-gpg/ state
directory it creates (keyring, trust.json, tracked.json). init never
touches .gitignore — the <name>.secret ciphertext files are meant to be
committed, so gitignoring them would defeat the fresh-clone decryptability
contract.

init refuses to reset a repository that already has established trust;
remove .git-gpg/ explicitly if you really want a fresh start.

EXAMPLES
  $ git-gpg init    # create .git-gpg/ in the current git repository
")]
    Init,

    /// Import your private key(s) into the git-gpg key store
    #[command(after_long_help = "\
Imports armoured PRIVATE key blocks into your per-machine key store
($HOME/.git-gpg/secret-keys.pgp). This is where reveal/cat/unhide/changes
find the private key matching your email, and where tell/removeperson find
the owner's signing key. The key store is local to this machine and is
never committed; each collaborator imports their own key.

Keys whose fingerprint is already present in the key store are not
duplicated.

EXAMPLES
  $ git-gpg import my-key.asc
  $ git-gpg import key1.asc key2.asc --gpg-home /path/to/store
")]
    Import {
        /// File(s) containing armoured private key blocks
        #[arg(required = true)]
        files: Vec<String>,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Verify and pin the repository owner's signing key (per machine)
    #[command(after_long_help = "\
Verifies the repository owner's public signing key and pins it in your
local key store, keyed by the repository ID derived from the git remote
push URL. The pin is per machine: it lives in $HOME/.git-gpg, is never
committed, and every collaborator must run trust themselves after a fresh
clone. The pinned key is the anchor against which every subsequent keyring
signature is verified — tell, hide, reveal, cat, unhide, changes,
removeperson, verify-keyring and list-keys all fail closed without it.

The provided repo_id must match the one computed from the remote push URL
(see show-repo-id), the key file must carry the repository's email
identity, and the key must not be expired, revoked or unsigned.

Requires init first. Typical next step: tell.

EXAMPLES
  $ git-gpg show-repo-id                          # get the repo id to pass here
  $ git-gpg trust fara+simbo1905@github.com owner.pub
  $ git-gpg trust fara+simbo1905@github.com owner.pub --remote upstream
")]
    Trust {
        /// Repository ID (e.g., fara+simbo1905@github.com)
        repo_id: String,
        /// Path to owner's public key file
        signing_key: String,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
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
  $ git-gpg tell alice@example.com alice.pub
  $ git-gpg tell alice@example.com alice.pub --passphrase-stdin < pass.txt
")]
    Tell {
        /// Collaborator's email
        email: String,
        /// Path to collaborator's public key file
        public_key: String,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITGPG_PASSPHRASE
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
  $ git-gpg removeperson alice@example.com
  $ git-gpg removeperson alice@example.com --passphrase-stdin < pass.txt
")]
    RemovePerson {
        /// Email of the collaborator to remove
        email: String,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITGPG_PASSPHRASE
        /// environment variable; never pass a passphrase as a CLI argument.
        #[arg(long)]
        passphrase_stdin: bool,
    },

    /// Track files for encryption
    #[command(after_long_help = "\
Tracks files for encryption in .git-gpg/tracked.json (stored
repo-relative). Nothing is encrypted yet — hide does that. Files must
exist, and a symlink must resolve inside the repository, so hide can
never be tricked into reading or deleting a file outside the repo.

Typical flow: init -> trust -> tell (once per collaborator) -> add -> hide.

EXAMPLES
  $ git-gpg add .env
  $ git-gpg add config/credentials.yml notes.md
")]
    Add {
        /// File(s) to add
        #[arg(required = true)]
        files: Vec<String>,
    },

    /// Untrack files (leaves any ciphertext in place)
    #[command(after_long_help = "\
Untracks files (removes them from .git-gpg/tracked.json). The plaintext
may already be gone — hide deletes it — so the file does not need to
exist. Untracking is not decrypting: any <name>.secret ciphertext is left
in place; restore the plaintext with unhide or reveal first if you want
it gone too.

EXAMPLES
  $ git-gpg remove .env
  $ git-gpg remove config/credentials.yml
")]
    Remove {
        /// File(s) to remove
        #[arg(required = true)]
        files: Vec<String>,
    },

    /// List all tracked files
    #[command(after_long_help = "\
Prints every file tracked in .git-gpg/tracked.json. Tracking records
intent only: whether the plaintext or its .secret ciphertext currently
exists on disk is not checked.

EXAMPLES
  $ git-gpg list
")]
    List,

    /// Encrypt all tracked files to the keyring and delete the plaintexts
    #[command(after_long_help = "\
Encrypts every tracked file to every key in the keyring, deletes the
plaintext, and leaves <name>.secret beside where the plaintext was
(notes -> notes.secret). You gitignore the PLAINTEXT filenames and commit
the .secret files: a fresh clone carrying only ciphertext stays
decryptable by every keyring member via reveal.

hide only works after the repository is initialized (git-gpg init), the
owner's key is trusted on this machine (git-gpg trust), collaborators are
in the keyring (git-gpg tell), and files are tracked (git-gpg add).
Before encrypting anything, the keyring signature is verified against the
pinned trusted key. unhide, reveal and cat invert hide.

EXAMPLES
  $ git-gpg hide    # encrypt all tracked files, delete the plaintexts
  $ git-gpg hide --remote upstream
  $ echo .env >> .gitignore    # ignore plaintext names; commit the .secret files
")]
    Hide {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Decrypt all tracked files back to plaintext
    #[command(after_long_help = "\
Decrypts every tracked file whose .secret ciphertext exists back to its
plaintext path, using your private key from the local key store. The
keyring signature is verified against the pinned trusted key before any
decryption. Your identity comes from git config user.email or --email;
passphrase-protected keys take the passphrase from GITGPG_PASSPHRASE or
--passphrase-stdin.

reveal is the inverse of hide for all files; unhide does one file and
deletes its ciphertext; cat prints one file without touching disk state.

EXAMPLES
  $ git-gpg reveal
  $ git-gpg reveal --email alice@example.com
  $ git-gpg reveal --passphrase-stdin < pass.txt
")]
    Reveal {
        /// Your email address
        #[arg(long)]
        email: Option<String>,
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITGPG_PASSPHRASE
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
  $ git-gpg cat .env
  $ git-gpg cat .env --email alice@example.com
  $ git-gpg cat .env --passphrase-stdin < pass.txt
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
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITGPG_PASSPHRASE
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
  $ git-gpg unhide .env
  $ git-gpg unhide .env --email alice@example.com
  $ git-gpg unhide .env --passphrase-stdin < pass.txt
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
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITGPG_PASSPHRASE
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
  $ git-gpg changes                # check every tracked file
  $ git-gpg changes .env           # check one file
  $ git-gpg changes --passphrase-stdin < pass.txt
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
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
        /// Read the passphrase for a passphrase-protected private key from
        /// stdin (exactly one line). Wins over the GITGPG_PASSPHRASE
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
  $ git-gpg show-repo-id
  $ git-gpg show-repo-id --remote upstream
")]
    ShowRepoId {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
    },

    /// Show the identity and key store git-gpg will use
    #[command(after_long_help = "\
Prints the identity git-gpg will use for you — git config user.email, or
the --email override — plus the local key store path where your private
key must be imported (git-gpg import). Use it to check which key
reveal/cat/unhide will look up before they fail on a missing identity.

EXAMPLES
  $ git-gpg whoami
  $ git-gpg whoami --email alice@example.com
")]
    Whoami {
        /// Email override
        #[arg(long)]
        email: Option<String>,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Verify the keyring signature against the pinned trusted key
    #[command(name = "verify-keyring")]
    #[command(after_long_help = "\
Verifies the keyring's signature against the pinned trusted key for this
repository. Fail-closed: without an established trust pin (git-gpg
trust) on this machine, or when the signature does not verify, the
command exits with an error. Every gated command (hide, reveal, cat,
unhide, changes, tell, removeperson, list-keys) runs this same check
before touching secrets.

EXAMPLES
  $ git-gpg verify-keyring
  $ git-gpg verify-keyring --remote upstream
")]
    VerifyKeyring {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
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
  $ git-gpg list-keys
  $ git-gpg list-keys --remote upstream
")]
    ListKeys {
        /// Git remote name
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Key store directory (default: $HOME/.git-gpg)
        #[arg(long)]
        gpg_home: Option<PathBuf>,
    },

    /// Remove the .git-gpg state directory (--yes required when data would be lost)
    #[command(after_long_help = "\
Removes the .git-gpg state directory (keyring, trust.json,
tracked.json). .gitignore is never rewritten, and the in-place .secret
ciphertext files are ordinary committable files that clean does not
disown.

Because hide deletes the plaintexts, the .secret ciphertexts beside them
can be the ONLY remaining copy of a secret. A clean that would destroy
tracked state or ciphertext therefore refuses unless --yes confirms it.

EXAMPLES
  $ git-gpg clean          # refuses while tracked files or ciphertext exist
  $ git-gpg clean --yes    # confirmed destruction of .git-gpg/
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
Writes a shell completion script for the git-gpg CLI to stdout. The
script is generated from the live clap definition, so it always matches
the installed binary.

EXAMPLES
  $ git-gpg completions bash > /etc/bash_completion.d/git-gpg
  $ git-gpg completions zsh > \"${fpath[1]}/_git-gpg\"
  $ git-gpg completions fish > ~/.config/fish/completions/git-gpg.fish
")]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Write roff man pages (git-gpg.1 plus one per subcommand) to a directory
    #[command(after_long_help = "\
Writes roff man pages — git-gpg.1 plus one page per subcommand — to a
directory, all generated from the live clap definition. Defaults to
./man relative to the current directory.

EXAMPLES
  $ git-gpg manpages                            # write into ./man
  $ git-gpg manpages /usr/local/share/man/man1
")]
    Manpages {
        /// Directory to write the .1 files into (default: ./man)
        output_dir: Option<PathBuf>,
    },
}

/// Handler for `git-gpg completions <shell>`: writes the completion script
/// for the real clap definition to stdout.
pub fn run_completions(shell: clap_complete::Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "git-gpg", &mut std::io::stdout());
}

/// Handler for `git-gpg manpages [OUTPUT_DIR]`: writes `git-gpg.1` plus one
/// `git-gpg-<sub>.1` per subcommand, all generated from the real clap
/// definition. Defaults to `./man` relative to the current directory.
pub fn run_manpages(output_dir: &std::path::Path) -> Result<()> {
    let root = Cli::command();
    let bin_name = root.get_name().to_string();

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create output directory {}", output_dir.display()))?;

    let root_page = output_dir.join(format!("{}.1", bin_name));
    let man = clap_mangen::Man::new(root.clone());
    man.render(&mut std::fs::File::create(&root_page).with_context(|| {
        format!("failed to create {}", root_page.display())
    })?)
    .with_context(|| format!("failed to render {}", root_page.display()))?;

    for sub in root.get_subcommands() {
        let full_name = format!("{}-{}", bin_name, sub.get_name());
        let page = output_dir.join(format!("{}.1", full_name));
        let usage_bin_name = format!("{} {}", bin_name, sub.get_name());
        let man = clap_mangen::Man::new(
            sub.clone()
                .name(full_name)
                .bin_name(usage_bin_name),
        );
        man.render(&mut std::fs::File::create(&page)
            .with_context(|| format!("failed to create {}", page.display()))?)
        .with_context(|| format!("failed to render {}", page.display()))?;
    }

    Ok(())
}
