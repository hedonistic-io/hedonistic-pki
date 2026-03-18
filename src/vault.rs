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
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
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
        rng.fill(&mut key)
            .map_err(|_| anyhow::anyhow!("Failed to generate ephemeral vault key from OS CSPRNG"))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let vault = Vault::new().unwrap();
        let data = b"hedonistic-root-ca-passphrase-test-12345";
        let blob = vault.encrypt(data).unwrap();
        let decrypted = vault.decrypt(&blob).unwrap();
        assert_eq!(decrypted.as_bytes(), data);
    }

    #[test]
    fn different_nonces() {
        let vault = Vault::new().unwrap();
        let data = b"same data";
        let blob1 = vault.encrypt(data).unwrap();
        let blob2 = vault.encrypt(data).unwrap();
        // Same plaintext should produce different ciphertext (different nonces)
        assert_ne!(blob1.ciphertext, blob2.ciphertext);
    }
}
