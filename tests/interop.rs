//! GnuPG interoperability contract tests.
//!
//! These tests run only when a `gpg` binary is available on the machine.
//! They verify the two-way contract between git-gpg and real GnuPG:
//!
//! 1. a GnuPG-generated key can be imported into our key store and then
//!    decrypt data we encrypted to it, and
//! 2. ciphertext produced by git-gpg can be decrypted by GnuPG itself.
//!
//! Every gpg invocation runs against an isolated GNUPGHOME temp directory,
//! so the user's real GnuPG state is never touched.

use git_gpg::{
    cmd_import, decrypt_with_gpg_key, encrypt_to_gpg_key, find_private_key_by_email,
    parse_armored_public_key,
};
use std::path::Path;
use std::process::Command;

/// Detects a usable `gpg` binary. Returns false (and the caller skips)
/// when gpg is absent or fails to run.
fn gpg_available() -> bool {
    Command::new("gpg")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Runs gpg with an isolated GNUPGHOME, failing the test on a non-zero exit.
fn gpg(home: &Path, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("gpg")
        .env("GNUPGHOME", home)
        .args(args)
        .output()
        .map_err(|err| anyhow::anyhow!("failed to spawn gpg: {}", err))?;
    if !output.status.success() {
        anyhow::bail!(
            "gpg {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Generates a primary key of the given algorithm with a matching encryption
/// subkey for interop@example.com in the given (isolated) GnuPG home.
fn generate_gpg_key_of_type(home: &Path, primary: &str, subkey: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(home).map_err(|err| anyhow::anyhow!("create GNUPGHOME: {}", err))?;
    gpg(
        home,
        &[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "Test User <interop@example.com>",
            primary,
        ],
    )?;

    let listing = gpg(home, &["--with-colons", "--list-keys", "interop@example.com"])?;
    let fingerprint = listing
        .lines()
        .find(|line| line.starts_with("fpr:"))
        .and_then(|line| line.split(':').nth(9))
        .ok_or_else(|| anyhow::anyhow!("no fingerprint in gpg listing"))?;

    gpg(
        home,
        &[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-add-key",
            fingerprint,
            subkey,
            "encr",
            "never",
        ],
    )?;
    Ok(())
}

fn generate_gpg_key(home: &Path) -> anyhow::Result<()> {
    generate_gpg_key_of_type(home, "ed25519", "cv25519")
}

/// Full acquisition + round-trip: gpg generates a key, we import its secret
/// key through cmd_import, encrypt to it and decrypt with it. Shared by the
/// ed25519 and RSA variants (RSA pins the F1 assessment).
fn roundtrips_gpg_generated_key(primary: &str, subkey: &str) -> anyhow::Result<()> {
    let temp = tempfile::tempdir().expect("create temp dir");
    let gpg_home = temp.path().join("gnupg");
    let tool_home = temp.path().join("tool-gnupg");
    generate_gpg_key_of_type(&gpg_home, primary, subkey).expect("generate gpg key");

    // Export the secret key exactly as a real user would hand it to us.
    let secret_armored = gpg(
        &gpg_home,
        &[
            "--armor",
            "--export-secret-keys",
            "interop@example.com",
        ],
    )
    .expect("export secret key from gpg");
    let key_file = temp.path().join("secret-key.asc");
    std::fs::write(&key_file, &secret_armored).expect("write secret key file");

    // Import through the new acquisition command.
    let files = vec![key_file.to_string_lossy().to_string()];
    cmd_import(temp.path(), &files, &tool_home).expect("import gpg-generated secret key");

    // cmd_reveal-style: look the key up by email and decrypt with it.
    let secret_key = find_private_key_by_email(&tool_home, "interop@example.com")
        .expect("find imported secret key");
    let public_key = secret_key.to_public_key();

    let plaintext = b"hello from git-gpg interop";
    let ciphertext = encrypt_to_gpg_key(plaintext, &public_key).expect("encrypt to imported key");
    let decrypted = decrypt_with_gpg_key(&ciphertext, &secret_key, None).expect("decrypt with imported key");
    assert_eq!(decrypted, plaintext, "round-trip through imported gpg key must preserve bytes");
    Ok(())
}

#[test]
fn gpg_generated_key_roundtrips_through_our_tool() {
    if !gpg_available() {
        println!("skipping interop test: gpg not available");
        return;
    }
    roundtrips_gpg_generated_key("ed25519", "cv25519").expect("ed25519 round-trip");
}

/// Regression probe for audit finding F1: a GnuPG-generated RSA key with
/// S2K-protected secret material must import and decrypt via the pgp crate.
#[test]
fn gpg_generated_rsa_key_roundtrips_through_our_tool() {
    if !gpg_available() {
        println!("skipping interop test: gpg not available");
        return;
    }
    roundtrips_gpg_generated_key("rsa2048", "rsa2048").expect("rsa round-trip");
}

#[test]
fn our_ciphertext_is_readable_by_gpg() {
    if !gpg_available() {
        println!("skipping interop test: gpg not available");
        return;
    }

    let temp = tempfile::tempdir().expect("create temp dir");
    let gpg_home = temp.path().join("gnupg");
    generate_gpg_key(&gpg_home).expect("generate gpg key");

    let public_armored = gpg(&gpg_home, &["--armor", "--export", "interop@example.com"])
        .expect("export public key from gpg");
    let public_key = parse_armored_public_key(&public_armored).expect("parse gpg public key");

    let plaintext = b"readable by gpg";
    let ciphertext = encrypt_to_gpg_key(plaintext, &public_key).expect("encrypt with git-gpg");
    let ciphertext_file = temp.path().join("message.asc");
    std::fs::write(&ciphertext_file, &ciphertext).expect("write ciphertext file");

    let decrypted = gpg(
        &gpg_home,
        &[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--decrypt",
            ciphertext_file.to_str().expect("utf-8 path"),
        ],
    )
    .expect("gpg must decrypt our ciphertext");
    assert_eq!(decrypted.as_bytes(), plaintext, "gpg decryption must match our plaintext");
}

/// Interop residual: a passphrase-protected (S2K-encrypted) RSA secret key
/// generated by real GnuPG must import into the git-gpg key store and decrypt
/// git-gpg-produced ciphertext when the correct passphrase is supplied.
#[test]
fn gpg_protected_secret_key_imports_and_decrypts_with_passphrase() {
    if !gpg_available() {
        println!("skipping interop test: gpg not available");
        return;
    }

    let temp = tempfile::tempdir().expect("create temp dir");
    let gpg_home = temp.path().join("gnupg");
    let tool_home = temp.path().join("tool-gnupg");
    std::fs::create_dir_all(&gpg_home).expect("create GNUPGHOME");

    // Generate a passphrase-protected RSA key in the isolated GNUPGHOME.
    gpg(
        &gpg_home,
        &[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "test-pass",
            "--quick-generate-key",
            "Test User <interop@example.com>",
            "rsa2048",
        ],
    )
    .expect("generate protected gpg key");

    let listing = gpg(&gpg_home, &["--with-colons", "--list-keys", "interop@example.com"])
        .expect("list gpg keys");
    let fingerprint = listing
        .lines()
        .find(|line| line.starts_with("fpr:"))
        .and_then(|line| line.split(':').nth(9))
        .expect("no fingerprint in gpg listing");

    gpg(
        &gpg_home,
        &[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "test-pass",
            "--quick-add-key",
            fingerprint,
            "rsa2048",
            "encr",
            "never",
        ],
    )
    .expect("add encryption subkey");

    // Export the secret key exactly as a real user would hand it to us
    // (the export keeps the S2K passphrase protection in place).
    let secret_armored = gpg(
        &gpg_home,
        &[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "test-pass",
            "--armor",
            "--export-secret-keys",
            "interop@example.com",
        ],
    )
    .expect("export protected secret key from gpg");
    let key_file = temp.path().join("secret-key.asc");
    std::fs::write(&key_file, &secret_armored).expect("write secret key file");

    // Import through cmd_import into the tool-owned key store.
    let files = vec![key_file.to_string_lossy().to_string()];
    cmd_import(temp.path(), &files, &tool_home).expect("import protected gpg secret key");

    // Finding the key must work WITHOUT the passphrase (parsing never
    // unlocks the secret material).
    let secret_key = find_private_key_by_email(&tool_home, "interop@example.com")
        .expect("find imported protected secret key");

    let plaintext = b"protected interop payload";
    let ciphertext = encrypt_to_gpg_key(plaintext, &secret_key.to_public_key())
        .expect("encrypt to imported key");

    // Without the passphrase the ciphertext must not decrypt.
    assert!(
        decrypt_with_gpg_key(&ciphertext, &secret_key, None).is_err(),
        "the protected key must not decrypt with an empty passphrase"
    );
    // With the wrong passphrase it must not decrypt either.
    assert!(
        decrypt_with_gpg_key(&ciphertext, &secret_key, Some("wrong-pass")).is_err(),
        "the protected key must not decrypt with the wrong passphrase"
    );
    // With the correct passphrase it must decrypt.
    let decrypted = decrypt_with_gpg_key(&ciphertext, &secret_key, Some("test-pass"))
        .expect("decrypt with the correct passphrase");
    assert_eq!(
        decrypted, plaintext,
        "round-trip through the imported protected key must preserve bytes"
    );
}
