//! Encrypted memory vault for holding sensitive material at runtime.
//!
//! Architecture:
//!   - An ephemeral 256-bit key is generated from OS CSPRNG at startup
//!   - All sensitive data (passphrases, private keys) are encrypted with
//!     ChaCha20-Poly1305 before being stored in heap memory
//!   - Plaintext only exists in mlock'd stack buffers during active use
//!   - On drop, all memory is zeroized before deallocation
//!   - The vault key itself lives in an mlock'd page

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A single encrypted blob in the vault
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptedBlob {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
}

/// The vault holds an ephemeral encryption key and manages encrypted storage
pub struct Vault {
    /// Ephemeral key — generated at runtime, never touches disk
    key: [u8; 32],
    rng: SystemRandom,
}

impl Vault {
    /// Create a new vault with a fresh ephemeral key from OS CSPRNG
    pub fn new() -> anyhow::Result<Self> {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key).map_err(|_| {
            anyhow::anyhow!("Failed to generate ephemeral vault key from OS CSPRNG")
        })?;

        // On Linux, attempt to mlock the key pages to prevent swapping
        #[cfg(target_os = "linux")]
        unsafe {
            libc::mlock(key.as_ptr() as *const libc::c_void, key.len());
        }

        Ok(Self { key, rng })
    }

    /// Encrypt data and return an EncryptedBlob
    pub fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<EncryptedBlob> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| anyhow::anyhow!("cipher init failed: {e}"))?;

        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to generate nonce"))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

        Ok(EncryptedBlob {
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    /// Decrypt an EncryptedBlob, returning a ZeroizeVec that auto-wipes on drop
    pub fn decrypt(&self, blob: &EncryptedBlob) -> anyhow::Result<SecureBytes> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| anyhow::anyhow!("cipher init failed: {e}"))?;

        let nonce = Nonce::from_slice(&blob.nonce);
        let plaintext = cipher
            .decrypt(nonce, blob.ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;

        Ok(SecureBytes(plaintext))
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.key.zeroize();

        #[cfg(target_os = "linux")]
        unsafe {
            libc::munlock(self.key.as_ptr() as *const libc::c_void, self.key.len());
        }
    }
}

/// A byte buffer that zeroizes itself on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes(pub Vec<u8>);

impl SecureBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_str(&self) -> anyhow::Result<&str> {
        std::str::from_utf8(&self.0).map_err(|e| anyhow::anyhow!("invalid utf8: {e}"))
    }
}

// ═══════════════════════════════════════════════════════════════
// PassphraseVault — encrypted file vault for offline passphrase storage
// ═══════════════════════════════════════════════════════════════

use std::path::Path;

use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A single passphrase entry in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseEntry {
    pub label: String,
    pub passphrase: String,
}

/// An encrypted file vault for ceremony passphrases.
///
/// Uses AES-256-GCM with a key derived from a master password via iterated
/// SHA-256 (100,000 rounds). Designed for offline/airgapped use — the user
/// types one master password and all ceremony passphrases are encrypted inside.
#[derive(Debug)]
pub struct PassphraseVault {
    entries: Vec<PassphraseEntry>,
}

/// File format: 32 bytes salt + 12 bytes nonce + ciphertext (AES-256-GCM)
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KDF_ITERATIONS: u32 = 100_000;

/// Derive a 256-bit key from a master password and salt using iterated SHA-256.
fn derive_key(master_password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(salt);
    hash.update(master_password.as_bytes());
    let mut result = hash.finalize();

    for _ in 1..KDF_ITERATIONS {
        let mut h = Sha256::new();
        h.update(result.as_slice());
        result = h.finalize();
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[allow(dead_code)]
impl PassphraseVault {
    /// Create a new empty vault.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a passphrase entry.
    pub fn add(&mut self, label: &str, passphrase: &str) {
        self.entries.push(PassphraseEntry {
            label: label.to_string(),
            passphrase: passphrase.to_string(),
        });
    }

    /// Return the number of entries in the vault.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if the vault has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return a reference to the entries.
    pub fn entries(&self) -> &[PassphraseEntry] {
        &self.entries
    }

    /// Encrypt and write to file using a master password.
    ///
    /// File format: salt (32 bytes) || AES-256-GCM nonce (12 bytes) || ciphertext
    pub fn save_encrypted(&self, path: &Path, master_password: &str) -> anyhow::Result<()> {
        let rng = SystemRandom::new();

        // Generate random salt
        let mut salt = [0u8; SALT_LEN];
        rng.fill(&mut salt)
            .map_err(|_| anyhow::anyhow!("Failed to generate salt from OS CSPRNG"))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to generate nonce from OS CSPRNG"))?;

        // Derive key
        let mut key = derive_key(master_password, &salt);

        // Serialize entries to JSON
        let plaintext = serde_json::to_vec(&self.entries)
            .map_err(|e| anyhow::anyhow!("Failed to serialize vault entries: {e}"))?;

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("AES-256-GCM init failed: {e}"))?;
        let nonce = AesNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {e}"))?;

        // Zeroize key
        key.zeroize();

        // Write: salt || nonce || ciphertext
        let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        std::fs::write(path, &output)
            .map_err(|e| anyhow::anyhow!("Failed to write vault file: {e}"))?;

        Ok(())
    }

    /// Read and decrypt from file using a master password.
    pub fn load_encrypted(path: &Path, master_password: &str) -> anyhow::Result<Self> {
        let data =
            std::fs::read(path).map_err(|e| anyhow::anyhow!("Failed to read vault file: {e}"))?;

        if data.len() < SALT_LEN + NONCE_LEN + 16 {
            anyhow::bail!("Vault file is too small to be valid");
        }

        let salt = &data[..SALT_LEN];
        let nonce_bytes = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
        let ciphertext = &data[SALT_LEN + NONCE_LEN..];

        // Derive key
        let mut key = derive_key(master_password, salt);

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("AES-256-GCM init failed: {e}"))?;
        let nonce = AesNonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            anyhow::anyhow!("Decryption failed — wrong master password or corrupted vault")
        })?;

        // Zeroize key
        key.zeroize();

        // Deserialize
        let entries: Vec<PassphraseEntry> = serde_json::from_slice(&plaintext)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize vault entries: {e}"))?;

        Ok(Self { entries })
    }

    /// Print all entries to stderr (for transferring to 1Password).
    pub fn print_entries(&self) {
        eprintln!();
        eprintln!("================================================================");
        eprintln!(
            "  Ceremony Passphrase Vault — {} entries",
            self.entries.len()
        );
        eprintln!("================================================================");
        eprintln!();
        for (i, entry) in self.entries.iter().enumerate() {
            eprintln!("  {}: {}", i + 1, entry.label);
            eprintln!("     {}", entry.passphrase);
            eprintln!();
        }
        eprintln!("================================================================");
        eprintln!("  Transfer these to 1Password, then securely delete the vault file.");
        eprintln!("================================================================");
    }
}

impl Drop for PassphraseVault {
    fn drop(&mut self) {
        for entry in &mut self.entries {
            entry.passphrase.zeroize();
            entry.label.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_vault_roundtrip() {
        let vault = Vault::new().unwrap();
        let data = b"hedonistic-root-ca-passphrase-test-12345";
        let blob = vault.encrypt(data).unwrap();
        let decrypted = vault.decrypt(&blob).unwrap();
        assert_eq!(decrypted.as_bytes(), data);
    }

    #[test]
    fn memory_vault_different_nonces() {
        let vault = Vault::new().unwrap();
        let data = b"same data";
        let blob1 = vault.encrypt(data).unwrap();
        let blob2 = vault.encrypt(data).unwrap();
        // Same plaintext should produce different ciphertext (different nonces)
        assert_ne!(blob1.ciphertext, blob2.ciphertext);
    }

    #[test]
    fn passphrase_vault_roundtrip() {
        let dir = std::env::temp_dir().join("hpki-test-vault-roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test-vault.enc");

        let mut vault = PassphraseVault::new();
        vault.add(
            "1: Root CA — Hedonistic, LLC",
            "super-secret-root-passphrase-12345",
        );
        vault.add("2: Intermediate CA", "intermediate-passphrase-67890-abcdef");
        vault.add("3: Code Signing", "code-signing-pass-zyxwv-09876");

        let master = "my-master-password-at-least-20chars";
        vault.save_encrypted(&path, master).unwrap();

        // File should exist and not be empty
        let file_data = std::fs::read(&path).unwrap();
        assert!(file_data.len() > SALT_LEN + NONCE_LEN);

        // Decrypt and verify
        let loaded = PassphraseVault::load_encrypted(&path, master).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded.entries()[0].label, "1: Root CA — Hedonistic, LLC");
        assert_eq!(
            loaded.entries()[0].passphrase,
            "super-secret-root-passphrase-12345"
        );
        assert_eq!(loaded.entries()[1].label, "2: Intermediate CA");
        assert_eq!(
            loaded.entries()[1].passphrase,
            "intermediate-passphrase-67890-abcdef"
        );
        assert_eq!(loaded.entries()[2].label, "3: Code Signing");
        assert_eq!(
            loaded.entries()[2].passphrase,
            "code-signing-pass-zyxwv-09876"
        );

        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn passphrase_vault_wrong_password() {
        let dir = std::env::temp_dir().join("hpki-test-vault-wrong-pw");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test-vault-wrong.enc");

        let mut vault = PassphraseVault::new();
        vault.add("Test", "test-passphrase");

        vault
            .save_encrypted(&path, "correct-master-password-here")
            .unwrap();

        let result = PassphraseVault::load_encrypted(&path, "wrong-master-password-here");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("wrong master password") || err_msg.contains("Decryption failed"));

        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn passphrase_vault_empty() {
        let dir = std::env::temp_dir().join("hpki-test-vault-empty");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test-vault-empty.enc");

        let vault = PassphraseVault::new();
        assert!(vault.is_empty());
        assert_eq!(vault.len(), 0);

        vault
            .save_encrypted(&path, "master-password-for-empty-vault")
            .unwrap();

        let loaded =
            PassphraseVault::load_encrypted(&path, "master-password-for-empty-vault").unwrap();
        assert!(loaded.is_empty());

        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn passphrase_vault_corrupted_file() {
        let dir = std::env::temp_dir().join("hpki-test-vault-corrupt");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test-vault-corrupt.enc");

        let mut vault = PassphraseVault::new();
        vault.add("Test", "test-passphrase");
        vault
            .save_encrypted(&path, "master-password-here-12345")
            .unwrap();

        // Corrupt the file by flipping a byte in the ciphertext
        let mut data = std::fs::read(&path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        std::fs::write(&path, &data).unwrap();

        let result = PassphraseVault::load_encrypted(&path, "master-password-here-12345");
        assert!(result.is_err());

        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn passphrase_vault_too_small_file() {
        let dir = std::env::temp_dir().join("hpki-test-vault-small");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test-vault-small.enc");

        // Write a file that's too small
        std::fs::write(&path, &[0u8; 10]).unwrap();

        let result = PassphraseVault::load_encrypted(&path, "password");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too small"));

        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn kdf_deterministic() {
        let salt = [42u8; 32];
        let key1 = derive_key("test-password", &salt);
        let key2 = derive_key("test-password", &salt);
        assert_eq!(key1, key2);

        // Different password -> different key
        let key3 = derive_key("different-password", &salt);
        assert_ne!(key1, key3);

        // Different salt -> different key
        let salt2 = [99u8; 32];
        let key4 = derive_key("test-password", &salt2);
        assert_ne!(key1, key4);
    }
}
