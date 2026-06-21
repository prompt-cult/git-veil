use anyhow::{Context, Result};

pub const BEGIN_MARKER: &str = "-----BEGIN GIT-GPG KEYRING-----";
pub const END_MARKER: &str = "-----END GIT-GPG KEYRING-----";
pub const SIG_BEGIN: &str = "-----BEGIN PGP SIGNATURE-----";
pub const SIG_END: &str = "-----END PGP SIGNATURE-----";

#[derive(Debug, Clone)]
pub struct KeyringEntry {
    pub email: String,
    pub base64_key: String,
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
            .context("Missing BEGIN GIT-GPG KEYRING marker")?;
        let end_idx = content
            .find(END_MARKER)
            .context("Missing END GIT-GPG KEYRING marker")?;

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
                    base64_key: parts[1].to_string(),
                    fingerprint: parts[2].to_string(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let after_end = &content[end_idx + END_MARKER.len()..];
        let signature = if let (Some(sig_begin), Some(sig_end)) =
            (after_end.find(SIG_BEGIN), after_end.find(SIG_END))
        {
            let sig_section = &after_end[sig_begin..sig_end + SIG_END.len()];
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
            result.push_str(&format!("{}:{}:{}\n", entry.email, entry.base64_key, entry.fingerprint));
        }
        result.push_str(END_MARKER);
        result.push('\n');
        if let Some(ref sig) = self.signature {
            result.push_str(sig);
            result.push('\n');
        }
        result
    }

    pub fn add_entry(&mut self, email: String, base64_key: String, fingerprint: String) {
        self.entries.push(KeyringEntry {
            email,
            base64_key,
            fingerprint,
        });
        self.signature = None;
    }

    pub fn find_by_email(&self, email: &str) -> Option<&KeyringEntry> {
        self.entries.iter().find(|e| e.email == email)
    }

    pub fn list_emails(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.email.as_str()).collect()
    }

    pub fn extract_fingerprints(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.fingerprint.as_str()).collect()
    }
}
