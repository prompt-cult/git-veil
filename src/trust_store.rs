use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustStore {
    #[serde(default)]
    pub trusted_keys: HashMap<String, String>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self {
            trusted_keys: HashMap::new(),
        }
    }

    pub fn add_trust(&mut self, repo_id: String, fingerprint: String) {
        self.trusted_keys.insert(repo_id, fingerprint);
    }

    pub fn get_trusted_fingerprint(&self, repo_id: &str) -> Option<&str> {
        self.trusted_keys.get(repo_id).map(|s| s.as_str())
    }

    pub fn serialize(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    pub fn deserialize(content: &str) -> Result<Self> {
        let store: TrustStore = serde_json::from_str(content)?;
        Ok(store)
    }

    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let content = self.serialize()?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let content = fs::read_to_string(path)?;
        Self::deserialize(&content)
    }
}
