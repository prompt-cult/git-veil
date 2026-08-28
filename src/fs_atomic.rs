//! Crash-safe atomic file replacement for all git-veil state writes.
//!
//! Every durable state file this tool writes (keyring, trust.json,
//! tracked.json, the secret-keys store, ciphertext `.secret` files,
//! restored plaintext) goes through [`write_atomic`]. A plain
//! `fs::write` truncates the target in place, so a crash mid-write
//! leaves half-written state — for a secrets tool the worst case is a
//! torn secret-keys store (bricks ALL private-key access, fail-closed)
//! or a torn plaintext/ciphertext pair (data loss). The write-temp-then-
//! rename sequence below is atomic on POSIX and Windows same-volume, so
//! the target is always either the old content or the new content,
//! never a mix.
//!
//! The key stores are APPENDS (secret-keys.pgp, public-keys.pgp): their
//! atomic-append shape is read-existing + `write_atomic` of the whole
//! accumulated content. The O(n) rewrite per append is the accepted
//! trade — these stores hold a handful of armoured key blocks
//! (kilobytes), and a torn store of private keys bricks all private-key
//! access, so a partial write must never be possible.

use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

/// Atomically replaces the file at `path` with `bytes`.
///
/// Sequence: write to `<path>.tmp-<pid>` in the SAME directory (same
/// volume, so the rename can never degrade into a copy), fsync the file,
/// rename it over the target, then best-effort fsync the parent
/// directory so the rename itself survives a crash (directory fsync is
/// not portable — errors there are ignored by design).
///
/// On any failure the original target is untouched and the temp file is
/// removed. Note the temp name is per-target (`<name>.tmp-<pid>`), so
/// two different files never collide even within one process.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .with_context(|| format!("Cannot atomically write to a path with no file name: {}", path.display()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_path = parent.join(format!(
        "{}.tmp-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    let result = (|| -> Result<()> {
        let mut tmp = File::create(&tmp_path)
            .with_context(|| format!("Failed to create temp file {}", tmp_path.display()))?;
        tmp.write_all(bytes)
            .with_context(|| format!("Failed to write temp file {}", tmp_path.display()))?;
        tmp.sync_all()
            .with_context(|| format!("Failed to fsync temp file {}", tmp_path.display()))?;
        drop(tmp);
        fs::rename(&tmp_path, path)
            .with_context(|| format!("Failed to atomically replace {}", path.display()))?;
        // Best-effort durability of the rename itself; several platforms
        // (and some filesystems) reject fsync on directories.
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        // Never leave a stale temp behind on a failed write.
        let _ = fs::remove_file(&tmp_path);
    }
    result
}
