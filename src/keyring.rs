use anyhow::{Context, Result};


pub const BEGIN_MARKER: &str = "-----BEGIN GIT-VEIL KEYRING-----";
pub const END_MARKER: &str = "-----END GIT-VEIL KEYRING-----";

#[derive(Debug, Clone)]
pub struct KeyringEntry {
    pub email: String,
    pub recipient: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct Keyring {
    pub entries: Vec<KeyringEntry>,
    pub signature: Option<String>,
}

impl Keyring {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            signature: None,
        }
    }

    pub fn parse(content: &str) -> Result<Self> {
        let begin_idx = content
            .find(BEGIN_MARKER)
            .context("Missing BEGIN GIT-VEIL KEYRING marker")?;
        let end_idx = content
            .find(END_MARKER)
            .context("Missing END GIT-VEIL KEYRING marker")?;

        // The END marker must come strictly after the full BEGIN marker:
        // anything else (END before BEGIN, or an END overlapping the BEGIN
        // region) is a misordered keyring. The keyring is committed repo
        // content and therefore attacker-writable, so this is rejected as a
        // parse error — never a slicing panic.
        if end_idx < begin_idx + BEGIN_MARKER.len() {
            anyhow::bail!(
                "Malformed keyring: END GIT-VEIL KEYRING marker precedes or overlaps the BEGIN marker"
            );
        }

        let keyring_section = &content[begin_idx + BEGIN_MARKER.len()..end_idx];
        let entries: Vec<KeyringEntry> = keyring_section
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() != 3 {
                    anyhow::bail!("Malformed keyring entry: {}", line);
                }
                Ok(KeyringEntry {
                    email: parts[0].to_string(),
                    recipient: parts[1].to_string(),
                    fingerprint: parts[2].to_string(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

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

        Ok(Self { entries, signature })
    }

    pub fn serialize(&self) -> String {
        let mut result = String::new();
        result.push_str(BEGIN_MARKER);
        result.push('\n');
        for entry in &self.entries {
            result.push_str(&format!(
                "{}:{}:{}\n",
                entry.email, entry.recipient, entry.fingerprint
            ));
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
    /// already exists (matched case-insensitively; the first-seen stored
    /// casing is preserved). Clears the signature so the keyring gets
    /// re-signed.
    ///
    /// # Format constraint
    ///
    /// The serialized keyring line format is `email:recipient:fingerprint`
    /// with `:` as the field separator, so the email MUST NOT contain `:`.
    /// A colon would produce a 4-field line that every subsequent
    /// [`Keyring::parse`] rejects with "Malformed keyring entry", bricking
    /// the signed keyring. This is rejected here with an error naming the
    /// offending email; on rejection nothing is mutated.
    pub fn add_entry(
        &mut self,
        email: String,
        recipient: String,
        fingerprint: String,
    ) -> Result<()> {
        if email.contains(':') {
            anyhow::bail!(
                "Invalid keyring email '{}': emails must not contain ':' \
                 because it is the keyring line field separator",
                email
            );
        }
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.email.eq_ignore_ascii_case(&email))
        {
            existing.recipient = recipient;
            existing.fingerprint = fingerprint;
        } else {
            self.entries.push(KeyringEntry {
                email,
                recipient,
                fingerprint,
            });
        }
        self.signature = None;
        Ok(())
    }

    /// Finds the entry whose email matches the given email
    /// case-insensitively, consistent with every other email comparison in
    /// this codebase (see `check_email_in_identities`).
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

    pub fn extract_fingerprints(&self) -> Vec<&str> {
        self.entries
            .iter()
            .map(|e| e.fingerprint.as_str())
            .collect()
    }
}
