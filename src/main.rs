//! git-gpg - A Rust-based Git secret management tool using pure Rust OpenPGP
//!
//! This tool provides a bash-free, zero-C-dependency alternative to git-secret.
//! It uses the `pgp` crate which implements RFC 4880 / RFC 9580 (OpenPGP) with pure Rust.

use clap::{Parser, Subcommand};
use pgp::composed::{
    Deserializable, EncryptionCaps, KeyType, Message, MessageBuilder,
    SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::Password;
use std::fs;
use std::path::PathBuf;
use anyhow::{Context, Result};
use rand::thread_rng;

/// Configuration directory
const CONFIG_DIR: &str = ".git-gpg";
/// Secrets directory (gitignored)
const SECRETS_DIR: &str = "secrets";
/// Public key file
const PUBLIC_KEY_FILE: &str = "public.key";
/// Private key file
const PRIVATE_KEY_FILE: &str = "private.key";
/// Config file
const CONFIG_FILE: &str = "config.json";

#[derive(Debug, clap::Parser)]
#[command(name = "git-gpg")]
#[command(about = "Git secret management using pure Rust OpenPGP")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize git-gpg in the current repository
    Init,

    /// Add a file to be encrypted
    Add {
        /// File(s) to add
        #[arg(required = true)]
        files: Vec<String>,
    },

    /// Remove a file from encryption tracking
    Remove {
        /// File(s) to remove
        #[arg(required = true)]
        files: Vec<String>,
    },

    /// List all encrypted files
    List,

    /// Hide - encrypt all tracked files
    Hide,

    /// Reveal - decrypt all tracked files
    Reveal,

    /// Generate a new OpenPGP key pair
    #[command(name = "keygen", alias = "key-gen")]
    KeyGen {
        /// Name for the key
        #[arg(short, long, default_value = "git-gpg user")]
        name: String,

        /// Email for the key
        #[arg(short, long, default_value = "git-gpg@example.com")]
        email: String,

        /// Key type: ed25519 (default), rsa4096
        #[arg(short, long, default_value = "ed25519")]
        key_type: String,
    },

    /// Export public key
    ExportPubkey,

    /// Export private key
    ExportPrivkey,

    /// Clean - remove all git-gpg metadata
    Clean,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct Config {
    encrypted_files: Vec<PathBuf>,
}

impl Config {
    fn path() -> PathBuf {
        PathBuf::from(CONFIG_DIR).join(CONFIG_FILE)
    }

    fn load() -> Result<Self> {
        if !Self::path().exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(Self::path())?;
        Ok(serde_json::from_str(&content)?)
    }

    fn save(&self) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(Self::path(), content)?;
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init()?,
        Commands::Add { files } => cmd_add(files)?,
        Commands::Remove { files } => cmd_remove(files)?,
        Commands::List => cmd_list()?,
        Commands::Hide => cmd_hide()?,
        Commands::Reveal => cmd_reveal()?,
        Commands::KeyGen { name, email, key_type } => cmd_keygen(&name, &email, &key_type)?,
        Commands::ExportPubkey => cmd_export_pubkey()?,
        Commands::ExportPrivkey => cmd_export_privkey()?,
        Commands::Clean => cmd_clean()?,
    }

    Ok(())
}

fn cmd_init() -> Result<()> {
    fs::create_dir_all(CONFIG_DIR)?;

    let secrets_dir = PathBuf::from(CONFIG_DIR).join(SECRETS_DIR);
    fs::create_dir_all(&secrets_dir)?;
    fs::write(secrets_dir.join(".gitkeep"), "")?;

    let gitignore_path = PathBuf::from(".gitignore");
    let secrets_pattern = format!("{}/{}", CONFIG_DIR, SECRETS_DIR);

    if gitignore_path.exists() {
        let content = fs::read_to_string(&gitignore_path)?;
        if !content.contains(&secrets_pattern) {
            fs::write(&gitignore_path, format!("{}\n{}", content, secrets_pattern))?;
        }
    } else {
        fs::write(gitignore_path, secrets_pattern)?;
    }

    Config::default().save()?;

    println!("✓ git-gpg initialized");
    println!("  Next: Generate a key pair with 'git-gpg keygen'");
    Ok(())
}

fn cmd_add(files: Vec<String>) -> Result<()> {
    let mut config = Config::load()?;
    let count = files.len();

    for file in &files {
        let path = fs::canonicalize(file)?;
        if !config.encrypted_files.contains(&path) {
            config.encrypted_files.push(path);
        }
    }

    config.save()?;
    println!("✓ Added {} file(s)", count);
    Ok(())
}

fn cmd_remove(files: Vec<String>) -> Result<()> {
    let mut config = Config::load()?;
    let count = files.len();

    for file in &files {
        let path = fs::canonicalize(file)?;
        config.encrypted_files.retain(|p| p != &path);
    }

    config.save()?;
    println!("✓ Removed {} file(s)", count);
    Ok(())
}

fn cmd_list() -> Result<()> {
    let config = Config::load()?;

    if config.encrypted_files.is_empty() {
        println!("No files are being tracked");
    } else {
        println!("Tracked files:");
        for file in &config.encrypted_files {
            println!("  - {}", file.display());
        }
    }

    Ok(())
}

fn cmd_hide() -> Result<()> {
    let config = Config::load()?;
    let public_key = load_public_key()?;
    let secrets_dir = PathBuf::from(CONFIG_DIR).join(SECRETS_DIR);
    let current_dir = std::env::current_dir()?;
    fs::create_dir_all(&secrets_dir)?;

    for file_path in &config.encrypted_files {
        let content = fs::read(file_path)?;
        let encrypted = encrypt_data(&content, &public_key)?;
        let encrypted_path = encrypted_path_for(&secrets_dir, &current_dir, file_path)?;

        if let Some(parent) = encrypted_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&encrypted_path, encrypted)?;
        fs::remove_file(file_path)?;

        println!("  Encrypted: {}", file_path.display());
    }

    println!("✓ Files hidden");
    Ok(())
}

fn cmd_reveal() -> Result<()> {
    let config = Config::load()?;
    let private_key = load_private_key()?;
    let secrets_dir = PathBuf::from(CONFIG_DIR).join(SECRETS_DIR);
    let current_dir = std::env::current_dir()?;

    for file_path in &config.encrypted_files {
        let encrypted_path = encrypted_path_for(&secrets_dir, &current_dir, file_path)?;

        if !encrypted_path.exists() {
            anyhow::bail!("Encrypted file not found: {}", encrypted_path.display());
        }

        let encrypted_data = fs::read_to_string(&encrypted_path)?;
        let decrypted = decrypt_data(&encrypted_data, &private_key)?;

        fs::write(file_path, decrypted)?;
        fs::remove_file(&encrypted_path)?;

        println!("  Decrypted: {}", file_path.display());
    }

    println!("✓ Files revealed");
    Ok(())
}

fn cmd_keygen(name: &str, email: &str, key_type: &str) -> Result<()> {
    let mut rng = thread_rng();

    let (signed_secret_key, public_key) = match key_type {
        "ed25519" => {
            let encrypt_subkey = SubkeyParamsBuilder::default()
                .key_type(KeyType::X25519)
                .can_encrypt(EncryptionCaps::All)
                .build()
                .context("build encrypt subkey params")?;

            let secret_key_params = SecretKeyParamsBuilder::default()
                .key_type(KeyType::Ed25519)
                .can_certify(true)
                .can_sign(true)
                .primary_user_id(format!("{} <{}>", name, email))
                .passphrase(None)
                .subkeys(vec![encrypt_subkey])
                .build()
                .context("build key params")?;

            let signed_secret_key = secret_key_params
                .generate(&mut rng)
                .context("generate key")?;

            let public_key = signed_secret_key.to_public_key();
            (signed_secret_key, public_key)
        }
        "rsa4096" => {
            let encrypt_subkey = SubkeyParamsBuilder::default()
                .key_type(KeyType::Rsa(4096))
                .can_encrypt(EncryptionCaps::All)
                .build()
                .context("build encrypt subkey params")?;

            let secret_key_params = SecretKeyParamsBuilder::default()
                .key_type(KeyType::Rsa(4096))
                .can_certify(true)
                .can_sign(true)
                .primary_user_id(format!("{} <{}>", name, email))
                .passphrase(None)
                .subkeys(vec![encrypt_subkey])
                .build()
                .context("build key params")?;

            let signed_secret_key = secret_key_params
                .generate(&mut rng)
                .context("generate key")?;

            let public_key = signed_secret_key.to_public_key();
            (signed_secret_key, public_key)
        }
        _ => anyhow::bail!("Unknown key type: {}. Use 'ed25519' or 'rsa4096'", key_type),
    };

    let pubkey_armored = public_key
        .to_armored_string(Default::default())
        .context("armor public key")?;
    let privkey_armored = signed_secret_key
        .to_armored_string(Default::default())
        .context("armor private key")?;

    fs::create_dir_all(CONFIG_DIR)?;
    fs::write(
        PathBuf::from(CONFIG_DIR).join(PUBLIC_KEY_FILE),
        pubkey_armored,
    )?;
    fs::write(
        PathBuf::from(CONFIG_DIR).join(PRIVATE_KEY_FILE),
        privkey_armored,
    )?;

    println!("✓ Key pair generated");
    println!("  Public key:  {}/{}", CONFIG_DIR, PUBLIC_KEY_FILE);
    println!("  Private key: {}/{}", CONFIG_DIR, PRIVATE_KEY_FILE);

    Ok(())
}

fn cmd_export_pubkey() -> Result<()> {
    let public_key = load_public_key()?;
    let armored = public_key
        .to_armored_string(Default::default())
        .context("armor public key")?;
    print!("{}", armored);
    Ok(())
}

fn cmd_export_privkey() -> Result<()> {
    let private_key = load_private_key()?;
    let armored = private_key
        .to_armored_string(Default::default())
        .context("armor private key")?;
    print!("{}", armored);
    Ok(())
}

fn cmd_clean() -> Result<()> {
    if PathBuf::from(CONFIG_DIR).exists() {
        fs::remove_dir_all(CONFIG_DIR)?;
    }

    let gitignore_path = PathBuf::from(".gitignore");
    if gitignore_path.exists() {
        let updated = remove_gitignore_entry(&fs::read_to_string(&gitignore_path)?);
        fs::write(&gitignore_path, updated)?;
    }

    println!("✓ Cleaned");
    Ok(())
}

// ========== Helper Functions ==========

fn find_encryption_subkey(
    public_key: &SignedPublicKey,
) -> Result<&pgp::composed::SignedPublicSubKey> {
    public_key
        .public_subkeys
        .iter()
        .find(|sk| {
            sk.signatures
                .iter()
                .any(|sig| sig.key_flags().encrypt_comms() || sig.key_flags().encrypt_storage())
        })
        .context("No encryption subkey found")
}

fn load_public_key() -> Result<SignedPublicKey> {
    let path = PathBuf::from(CONFIG_DIR).join(PUBLIC_KEY_FILE);
    if !path.exists() {
        anyhow::bail!("Public key not found at {}", path.display());
    }
    let armored = fs::read_to_string(path)?;
    let (key, _headers) = SignedPublicKey::from_string(&armored).context("parse public key")?;
    Ok(key)
}

fn load_private_key() -> Result<SignedSecretKey> {
    let path = PathBuf::from(CONFIG_DIR).join(PRIVATE_KEY_FILE);
    if !path.exists() {
        anyhow::bail!("Private key not found at {}", path.display());
    }
    let armored = fs::read_to_string(path)?;
    let (key, _headers) = SignedSecretKey::from_string(&armored).context("parse private key")?;
    Ok(key)
}

fn encrypted_path_for(secrets_dir: &std::path::Path, current_dir: &std::path::Path, file_path: &std::path::Path) -> Result<PathBuf> {
    let relative_path = file_path.strip_prefix(current_dir)?;
    let file_name = relative_path
        .file_name()
        .context("tracked file must have a file name")?;
    let armored_name = format!("{}.asc", file_name.to_string_lossy());
    let relative_dir = relative_path.parent().unwrap_or_else(|| std::path::Path::new(""));
    Ok(secrets_dir.join(relative_dir).join(armored_name))
}

fn remove_gitignore_entry(content: &str) -> String {
    let filtered = content
        .lines()
        .filter(|line| *line != ".git-gpg/secrets")
        .collect::<Vec<_>>()
        .join("\n");

    if filtered.is_empty() {
        String::new()
    } else {
        format!("{}\n", filtered)
    }
}

fn encrypt_data(data: &[u8], public_key: &SignedPublicKey) -> Result<String> {
    let mut rng = thread_rng();

    let encryption_subkey = find_encryption_subkey(public_key)?;

    let builder = MessageBuilder::from_bytes("file", data.to_vec());
    let mut builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder
        .encrypt_to_key(&mut rng, &encryption_subkey.key)
        .context("encrypt to key")?;

    builder
        .to_armored_string(&mut rng, Default::default())
        .context("armor encrypted message")
}

fn decrypt_data(ciphertext: &str, private_key: &SignedSecretKey) -> Result<Vec<u8>> {
    let passphrase = Password::empty();

    let message =
        Message::from_string(ciphertext).context("parse message")?;

    let mut decrypted = message
        .0
        .decrypt(&passphrase, private_key)
        .context("decrypt message")?;

    decrypted
        .as_data_vec()
        .context("extract plaintext")
}
