use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use crate::Keyring;

/// Initialises a new git-gpg repository structure.
pub fn cmd_init() -> Result<()> {
    let git_gpg_dir = PathBuf::from(".git-gpg");
    let secrets_dir = git_gpg_dir.join("secrets");
    
    // Create directories
    fs::create_dir_all(&git_gpg_dir).context("Failed to create .git-gpg directory")?;
    fs::create_dir_all(&secrets_dir).context("Failed to create .git-gpg/secrets directory")?;
    
    // Create empty keyring
    let keyring = Keyring::new();
    let keyring_content = keyring.serialize();
    fs::write(git_gpg_dir.join("keyring"), keyring_content)
        .context("Failed to create keyring file")?;
    
    // Create empty trust.json
    fs::write(git_gpg_dir.join("trust.json"), "{}")
        .context("Failed to create trust.json")?;
    
    // Create empty tracked.json
    fs::write(git_gpg_dir.join("tracked.json"), r#"{"files":[]}"#)
        .context("Failed to create tracked.json")?;
    
    // Add .git-gpg/secrets to .gitignore if not already present
    let gitignore_path = PathBuf::from(".gitignore");
    let gitignore_content = if gitignore_path.exists() {
        fs::read_to_string(&gitignore_path)?
    } else {
        String::new()
    };
    
    if !gitignore_content.contains(".git-gpg/secrets") {
        let mut updated = gitignore_content;
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(".git-gpg/secrets\n");
        fs::write(&gitignore_path, updated).context("Failed to update .gitignore")?;
    }
    
    println!("✓ git-gpg initialized");
    Ok(())
}
