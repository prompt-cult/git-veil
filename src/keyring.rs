use anyhow::{Context, Result};

use crate::exit_codes::{coded, ExitCode};

pub const BEGIN_MARKER: &str = "-----BEGIN GIT-VEIL KEYRING-----";
pub const END_MARKER: &str = "-----END GIT-VEIL KEYRING-----";

/// The `version:` line prefix inside the keyring block. The line is part of
/// the signed payload, so the monotonic counter it carries cannot be forged
/// without the owner key. See "Keyring format and freshness" in
/// docs/design.md.
const VERSION_PREFIX: &str = "version:";

#[derive(Debug, Clone)]
pub struct KeyringEntry {
    pub email: String,
    /// The bech32 X25519 public key encoding of the principal's key.
    pub public_key: String,
}

#[derive(Debug, Clone)]
pub struct Keyring {
    pub entries: Vec<KeyringEntry>,
    pub signature: Option<String>,
    /// Monotonic counter inside the signed payload, bumped by add-key and
    /// remove-key. `None` means the keyring has no version line. Such
    /// keyrings count as version 0 for rollback comparisons.
    pub version: Option<u64>,
}

impl Default for Keyring {
    fn default() -> Self {
        Self::new()
    }
}

impl Keyring {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            signature: None,
            version: None,
        }
    }

    pub fn parse(content: &str) -> Result<Self> {
        let begin_idx = content
            .find(BEGIN_MARKER)
            .context("Missing BEGIN GIT-VEIL KEYRING marker")?;
        let end_idx = content
            .find(END_MARKER)
            .context("Missing END GIT-VEIL KEYRING marker")?;

        // The END marker must come strictly after the full BEGIN marker.
        // Anything else, END before BEGIN or an END overlapping the BEGIN
        // region, is a misordered keyring. The keyring is committed repo
        // content and therefore attacker-writable, so this is rejected as
        // a parse error, never a slicing panic.
        if end_idx < begin_idx + BEGIN_MARKER.len() {
            return Err(coded(
                ExitCode::KeyParseFailure,
                "Malformed keyring: END GIT-VEIL KEYRING marker precedes or overlaps the BEGIN marker",
            ));
        }

        let keyring_section = &content[begin_idx + BEGIN_MARKER.len()..end_idx];
        let mut version: Option<u64> = None;
        let mut entries: Vec<KeyringEntry> = Vec::new();
        for line in keyring_section.lines() {
            if line.trim().is_empty() {
                continue;
            }
            // The freshness counter is part of the signed payload and is
            // parsed strictly. It is attacker-writable repo content, so a
            // malformed version line is a refusal (code 62), never a silent
            // skip that would let a rollback slip through as an "entry"
            // parse error later.
            if let Some(stem) = line.strip_prefix(VERSION_PREFIX) {
                if version.is_some() {
                    return Err(coded(
                        ExitCode::KeyParseFailure,
                        "Malformed keyring: duplicate version line",
                    ));
                }
                let n = stem.trim().parse::<u64>().map_err(|_| {
                    coded(
                        ExitCode::KeyParseFailure,
                        format!("Malformed keyring version line: {}", line),
                    )
                })?;
                version = Some(n);
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() != 2 {
                return Err(coded(
                    ExitCode::KeyParseFailure,
                    format!("Malformed keyring entry: {}", line),
                ));
            }
            entries.push(KeyringEntry {
                email: parts[0].to_string(),
                public_key: parts[1].to_string(),
            });
        }

        let after_end = &content[end_idx + END_MARKER.len()..];
        let sig_begin = "-----BEGIN GIT-VEIL SIGNATURE-----";
        let sig_end = "-----END GIT-VEIL SIGNATURE-----";
        let signature = if let (Some(sig_begin_idx), Some(sig_end_idx)) =
            (after_end.find(sig_begin), after_end.find(sig_end))
        {
            let sig_section = &after_end[sig_begin_idx..sig_end_idx + sig_end.len()];
            Some(sig_section.to_string())
        } else {
            None
        };

        Ok(Self {
            entries,
            signature,
            version,
        })
    }

    pub fn serialize(&self) -> String {
        let mut result = String::new();
        result.push_str(BEGIN_MARKER);
        result.push('\n');
        if let Some(n) = self.version {
            result.push_str(&format!("{}{}\n", VERSION_PREFIX, n));
        }
        for entry in &self.entries {
            result.push_str(&format!("{}:{}\n", entry.email, entry.public_key));
        }
        result.push_str(END_MARKER);
        result.push('\n');
        if let Some(ref sig) = self.signature {
            result.push_str(sig);
            result.push('\n');
        }
        result
    }

    /// Adds an entry, or updates the existing entry in place when the email
    /// already exists (matched case-insensitively. The first-seen stored
    /// casing is preserved). Clears the signature so the keyring gets
    /// re-signed.
    ///
    /// # Format constraint
    ///
    /// The serialized keyring line format is `email:public-key` (the
    /// bech32 X25519 public key encoding) with `:` as the field separator,
    /// so the email must not contain `:`. A colon would produce a 3-field
    /// line that every subsequent [`Keyring::parse`] rejects with
    /// "Malformed keyring entry", bricking the signed keyring. This is
    /// rejected here with an error naming the offending email. On
    /// rejection nothing is mutated.
    pub fn add_entry(&mut self, email: String, public_key: String) -> Result<()> {
        if email.contains(':') {
            anyhow::bail!(
                "Invalid keyring email: emails must not contain a colon \
                 because it is the keyring line field separator"
            );
        }
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.email.eq_ignore_ascii_case(&email))
        {
            existing.public_key = public_key;
        } else {
            self.entries.push(KeyringEntry { email, public_key });
        }
        self.signature = None;
        Ok(())
    }

    /// Bumps the monotonic freshness counter for a re-sign. The new version
    /// is current + 1, and a versionless keyring counts as 0. Called by
    /// add-key and remove-key before signing, so the bump is covered by the
    /// new signature. Errors at u64::MAX rather than overflowing. A
    /// poisoned ring must produce a clean refusal, never a panic.
    pub fn bump_version(&mut self) -> Result<()> {
        let next = self.version.unwrap_or(0).checked_add(1).ok_or_else(|| {
            anyhow::anyhow!("keyring version exhausted. Re-sign at a lower version is required.")
        })?;
        self.version = Some(next);
        Ok(())
    }

    /// Finds the entry whose email matches the given email
    /// case-insensitively, consistent with every other email comparison in
    /// this codebase.
    pub fn find_by_email(&self, email: &str) -> Option<&KeyringEntry> {
        self.entries
            .iter()
            .find(|e| e.email.eq_ignore_ascii_case(email))
    }

    /// Removes the entry whose email matches the given email
    /// case-insensitively. Returns true if an entry was removed. Clearing the
    /// signature forces a re-sign, like add_entry.
    pub fn remove_entry(&mut self, email: &str) -> bool {
        let len_before = self.entries.len();
        self.entries
            .retain(|e| !e.email.eq_ignore_ascii_case(email));
        let removed = self.entries.len() != len_before;
        if removed {
            self.signature = None;
        }
        removed
    }

    pub fn list_emails(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.email.as_str()).collect()
    }
}
